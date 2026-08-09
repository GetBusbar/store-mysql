// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The MySQL/MariaDB backend for busbar's durable governance store. Targets the common SQL subset
//! supported by MySQL 8.0.16+, MariaDB, and Aurora MySQL — one plugin, protocol-compatible with all
//! three, same reasoning as busbar's Valkey store covering any server that speaks the standard RESP
//! protocol: broad coverage via standard SQL, not three separate builds.
//!
//! Schema and design notes (every decision here traces to the locked cross-backend contract this
//! plugin was designed against — see the sibling store-postgres/store-sqlite/store-valkey repos for
//! the same contract's other physical realizations):
//!
//! - `api_keys`, not `keys`: `KEYS` is a MySQL/MariaDB reserved word. Renamed here specifically —
//!   Postgres/SQLite/Valkey keep `keys`.
//! - `store_sequence`: a single-row revision counter, bumped FIRST in every control-plane
//!   transaction (mint/revoke/rotate/delete), before touching `api_keys`/`credentials`/`denylist`.
//!   This fixed lock order (`store_sequence` -> `api_keys` -> `credentials` -> `denylist`) is what
//!   makes deadlock across the admin plane structurally impossible.
//! - `ascii_bin` collation on every opaque identifier column (`id`, `key_id`, `public_id`,
//!   `key_group`, `bucket_id`): MySQL's default collation is case-INSENSITIVE + PAD SPACE, a real
//!   security-relevant footgun for a credential lookup handle. Byte-exact comparison, matching
//!   Postgres/SQLite's default behavior.
//! - `rows_affected()` reports "rows CHANGED", not "rows MATCHED" — an idempotent no-op UPDATE
//!   (disabling an already-disabled key) returns 0, indistinguishable from "not found" by row count
//!   alone. Every conditional mutation here does an explicit `SELECT ... FOR UPDATE` existence/state
//!   check first, never relies on the affected-row count to tell "not found" from "no-op".
//! - JSON columns (`allowed_pools`, `labels`) are NEVER byte-compared or hashed after a round trip:
//!   MySQL 8's native JSON type normalizes on write (reorders keys, strips whitespace); MariaDB
//!   stores JSON as `LONGTEXT`, byte-identical. Canonicalize in the caller before hashing if ever
//!   needed — this store never does.
//! - Boot-time invariant probes (see [`MysqlStore::connect`]) hard-fail rather than warn: MySQL
//!   < 8.0.16 and Aurora MySQL 2.x PARSE `CHECK` constraints but ENFORCE none — a schema that
//!   *looks* validated can silently accept garbage. A live functional probe (attempt a CHECK
//!   violation, confirm it's rejected) is the only way to catch this; a version-string check alone
//!   is not sufficient since parsing-without-enforcing doesn't show up as a version mismatch.

use mysql::prelude::*;
use mysql::{params, Opts, Pool, PooledConn, TxOpts};

use busbar_api::{
    AuditRecord, CredentialMeta, CredentialSecret, McpCallRecord, MeteringDelta, MeteringRow,
    ModelTokens, ModelTokensDelta, ScopeRef, SecretForm, Store, StoreError, StoreResult,
    TaskEventRow, TaskRow, TierTokens, UsageDelta, UsageLedger, VirtualKey,
};

type MeteringRowTuple = (
    String,
    String,
    String,
    u64,
    u64,
    u64,
    u64,
    u64,
    u64,
    String,
    String,
);
type AuditRowTuple = (u64, u64, String, String, String, String, String, String);

/// `(principal, seq, ts, prev_hash, hash, body)` as selected by `list_mcp_calls`.
type McpCallRowTuple = (String, u64, u64, String, String, String);

/// `(task_id, context_id, principal, direction, state, agent_id, artifact_cursor, push_callback,
/// created_at, updated_at)` as selected by `get_task`/`list_tasks`.
type TaskRowTuple = (
    String,
    String,
    String,
    String,
    String,
    String,
    u64,
    String,
    u64,
    u64,
);

/// `(task_id, seq, ts, kind, context_id, principal, agent_id, state, request_id, prev_hash, hash)`
/// as selected by `list_task_events`.
type TaskEventRowTuple = (
    String,
    u64,
    u64,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

/// The CLOSED set of terminal task states the retention sweep is allowed to drop, matching the
/// tokens the trait's `TaskRow::state` documents. Closed in the SAFE direction on purpose: a state
/// token minted by a NEWER engine than this build is not in the list, so it is never swept — the
/// failure mode of guessing wrong is a row kept too long, not work destroyed.
const TERMINAL_TASK_STATES: [&str; 4] = ["completed", "failed", "canceled", "rejected"];

fn store_err<E: std::fmt::Display>(e: E) -> StoreError {
    StoreError(e.to_string())
}

/// Numeric, not the original `&str`: `try_init_schema` needs to compare "the version this database
/// was AT before this boot" against this constant to decide which one-time migration steps below
/// have already run, and `"1" < "2"` string-comparison stops being safe the moment version numbers
/// reach two digits.
/// v4: the durable MCP TOOL-CALL LOG (`mcp_calls`). PURELY ADDITIVE and needs no migration step —
/// the table and its index are new, so their `SCHEMA` statements (run on every boot, with the
/// duplicate-object error swallowed) are the entire migration. Nothing is dropped and no existing
/// row is touched, which is why no `V4_*` constant joins the two below.
/// v5: the durable A2A TASK STORE (`tasks`, `task_events`). Additive on exactly the same terms as
/// v4 — two new tables and one new index, so their `SCHEMA` statements ARE the migration, nothing is
/// dropped and no existing row is touched. No `V5_*` constant either, for the same reason.
const SCHEMA_VERSION: u32 = 5;

/// The version each one-time migration step targets crossing INTO — named so a gate reads as "did
/// this database predate step N" rather than a bare magic number, and so a future step can't be
/// accidentally gated on `< SCHEMA_VERSION` (wrong: that would re-fire EVERY prior step, not just
/// the newest one, every time SCHEMA_VERSION bumps again — each step must stay pinned to the one
/// version boundary it actually closes).
const V2_BILLABLE_REQUESTS_BACKFILL: u32 = 2;
const V3_KEY_GROUP_AT_USE_ASCII_BIN: u32 = 3;

const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS store_meta (
        k VARCHAR(191) PRIMARY KEY,
        v TEXT NOT NULL
    ) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS store_sequence (
        id INT PRIMARY KEY,
        revision BIGINT NOT NULL DEFAULT 0,
        CONSTRAINT ck_seq_singleton CHECK (id = 1)
    ) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS api_keys (
        id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
        name VARCHAR(256) NOT NULL DEFAULT '',
        key_group VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
        allowed_pools JSON NULL,
        labels JSON NOT NULL,
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        generation_hash VARCHAR(128) NOT NULL DEFAULT '',
        created_at BIGINT UNSIGNED NOT NULL,
        updated_at BIGINT UNSIGNED NOT NULL,
        expires_at BIGINT UNSIGNED NULL,
        deleted_at BIGINT UNSIGNED NULL,
        revision BIGINT NOT NULL DEFAULT 0,
        CONSTRAINT ck_api_keys_tombstone CHECK (deleted_at IS NULL OR enabled = FALSE),
        CONSTRAINT ck_api_keys_expiry CHECK (expires_at IS NULL OR expires_at > created_at),
        CONSTRAINT ck_api_keys_labels_json CHECK (JSON_VALID(labels)),
        CONSTRAINT ck_api_keys_pools_json CHECK (allowed_pools IS NULL OR JSON_VALID(allowed_pools))
    ) ENGINE=InnoDB",
    "CREATE INDEX idx_api_keys_revision ON api_keys (revision)",
    "CREATE INDEX idx_api_keys_group ON api_keys (key_group)",
    "CREATE TABLE IF NOT EXISTS credentials (
        id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
        key_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        kind VARCHAR(32) NOT NULL,
        slot TINYINT NOT NULL,
        public_id VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        secret TEXT NULL,
        secret_form VARCHAR(16) NOT NULL,
        created_at BIGINT UNSIGNED NOT NULL,
        updated_at BIGINT UNSIGNED NOT NULL,
        expires_at BIGINT UNSIGNED NULL,
        revoked_at BIGINT UNSIGNED NULL,
        revoke_reason VARCHAR(512) NULL,
        revision BIGINT NOT NULL DEFAULT 0,
        CONSTRAINT ck_cred_kind CHECK (kind IN ('sigv4')),
        CONSTRAINT ck_cred_slot CHECK (slot IN (0,1)),
        CONSTRAINT ck_cred_form CHECK (secret_form IN ('none','recoverable','digest')),
        CONSTRAINT ck_cred_form_null CHECK ((secret_form = 'none') = (secret IS NULL)),
        CONSTRAINT ck_cred_sigv4_recov CHECK (kind <> 'sigv4' OR secret_form = 'recoverable'),
        CONSTRAINT uq_cred_public UNIQUE (kind, public_id),
        CONSTRAINT uq_cred_slot UNIQUE (key_id, kind, slot),
        CONSTRAINT fk_cred_key FOREIGN KEY (key_id) REFERENCES api_keys(id) ON DELETE CASCADE
    ) ENGINE=InnoDB",
    "CREATE INDEX idx_cred_revision ON credentials (revision)",
    "CREATE TABLE IF NOT EXISTS denylist (
        sub VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
        reason VARCHAR(512) NOT NULL DEFAULT '',
        revoked_at BIGINT UNSIGNED NOT NULL,
        expires_at BIGINT UNSIGNED NOT NULL,
        revoked_generation VARCHAR(128) NULL,
        revision BIGINT NOT NULL DEFAULT 0
    ) ENGINE=InnoDB",
    "CREATE INDEX idx_denylist_revision ON denylist (revision)",
    "CREATE INDEX idx_denylist_expires ON denylist (expires_at)",
    "CREATE TABLE IF NOT EXISTS usage_windows (
        window_start BIGINT UNSIGNED NOT NULL,
        bucket_scope VARCHAR(8) NOT NULL,
        bucket_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        model VARCHAR(256) NOT NULL,
        requests BIGINT UNSIGNED NOT NULL DEFAULT 0,
        billable_requests BIGINT UNSIGNED NOT NULL DEFAULT 0,
        tokens_input BIGINT UNSIGNED NOT NULL DEFAULT 0,
        tokens_output BIGINT UNSIGNED NOT NULL DEFAULT 0,
        tokens_cache_read BIGINT UNSIGNED NOT NULL DEFAULT 0,
        tokens_cache_write BIGINT UNSIGNED NOT NULL DEFAULT 0,
        PRIMARY KEY (window_start, bucket_scope, bucket_id, model),
        CONSTRAINT ck_uw_scope CHECK (bucket_scope IN ('key','group','global'))
    ) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS usage_metering (
        bucket CHAR(10) NOT NULL,
        key_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        provider VARCHAR(128) NOT NULL,
        model VARCHAR(256) NOT NULL,
        key_group_at_use VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
        pricing_version VARCHAR(64) NOT NULL DEFAULT '',
        requests BIGINT UNSIGNED NOT NULL DEFAULT 0,
        billable_requests BIGINT UNSIGNED NOT NULL DEFAULT 0,
        tokens_input BIGINT UNSIGNED NOT NULL DEFAULT 0,
        tokens_output BIGINT UNSIGNED NOT NULL DEFAULT 0,
        tokens_cache_read BIGINT UNSIGNED NOT NULL DEFAULT 0,
        tokens_cache_write BIGINT UNSIGNED NOT NULL DEFAULT 0,
        PRIMARY KEY (key_id, bucket, model, provider),
        CONSTRAINT fk_metering_key FOREIGN KEY (key_id) REFERENCES api_keys(id) ON DELETE RESTRICT
    ) ENGINE=InnoDB",
    "CREATE INDEX idx_metering_bucket ON usage_metering (bucket)",
    "CREATE TABLE IF NOT EXISTS audit_log (
        seq BIGINT PRIMARY KEY,
        ts BIGINT UNSIGNED NOT NULL,
        action VARCHAR(64) NOT NULL,
        resource VARCHAR(255) NOT NULL DEFAULT '',
        outcome VARCHAR(32) NOT NULL,
        principal VARCHAR(255) NOT NULL DEFAULT '',
        prev_hash CHAR(64) NOT NULL DEFAULT '',
        hash CHAR(64) NOT NULL DEFAULT ''
    ) ENGINE=InnoDB",
    "CREATE INDEX idx_audit_resource_seq ON audit_log (resource, seq)",
    // The DURABLE MCP TOOL-CALL LOG. A DIFFERENT POPULATION from audit_log, kept in its own table
    // on purpose: audit_log is the low-rate admin MUTATION log whose engine-side working set is a
    // bounded ring, while a tool call is data-plane traffic at request rate. Pouring one into the
    // other means a busy afternoon of tool calls evicts every admin row from the ring, so the
    // question of who changed a registration becomes unanswerable exactly when an incident makes
    // somebody ask.
    //
    // The chain is scoped to the PRINCIPAL, which is why (principal, seq) is the primary key and
    // not a global counter: a global chain would serialise every caller behind one append and would
    // make one caller's evidence unverifiable without possessing every other caller's rows.
    //
    // SHAPE: opaque body plus only the columns a query needs. principal and ts are the index
    // columns (scoped read, and the retention sweep's age key). The CHAIN COLUMNS -- seq,
    // prev_hash, hash -- are REAL columns rather than being buried in the body, because the engine
    // establishes durability by READING THE CHAIN BACK and verifying it; a digest reachable only by
    // decoding an opaque payload forces a deserialise per verify and cannot be constrained or
    // indexed by the database. The store NEVER computes or recomputes a digest -- it persists what
    // it was handed and returns it verbatim.
    //
    // principal is VARCHAR(191), not the 255 audit_log uses for its own principal column: this one
    // is half of a PRIMARY KEY, and 191 is the utf8mb4 length that keeps a keyed column inside the
    // index limit on the older/utf8mb4-3072-byte configurations this store still supports (the same
    // reason store_meta.k is 191).
    "CREATE TABLE IF NOT EXISTS mcp_calls (
        principal VARCHAR(191) NOT NULL,
        seq BIGINT UNSIGNED NOT NULL,
        ts BIGINT UNSIGNED NOT NULL,
        prev_hash CHAR(64) NOT NULL DEFAULT '',
        hash CHAR(64) NOT NULL DEFAULT '',
        body TEXT NOT NULL,
        -- Carried now, written by nothing yet, and deliberately so: adding a column to a populated
        -- table later is a rewrite, whereas carrying it from the first migration is free. `version`
        -- is the compare-and-swap slot an optimistic-concurrency write would test; `expires_at` is
        -- the per-row sweep deadline. Retention today goes by `ts` (see purge_mcp_calls_before).
        expires_at BIGINT UNSIGNED NULL,
        version BIGINT UNSIGNED NOT NULL DEFAULT 0,
        PRIMARY KEY (principal, seq)
    ) ENGINE=InnoDB",
    // The retention sweep's access path: purge_mcp_calls_before deletes by ts across every
    // principal. No IF NOT EXISTS -- MySQL has no such form for CREATE INDEX; a re-run's duplicate
    // error is swallowed by try_init_schema, exactly as it is for idx_audit_resource_seq.
    "CREATE INDEX idx_mcp_calls_ts ON mcp_calls (ts)",
    // THE DURABLE A2A TASK STORE. A2A is async BY DESIGN: a task spans turns, can sit interrupted
    // waiting on a human, and can outlive the process that started it. An in-memory task table
    // therefore loses every in-flight task on restart, which is the difference between a resume that
    // is real and one that is nominal.
    //
    // Every TaskRow field is a REAL column rather than an opaque body, and that is the opposite of
    // the shape mcp_calls uses, for a reason: mcp_calls is written once and read back whole, whereas
    // these rows are the working set the engine QUERIES -- the retention sweep filters on
    // (state, updated_at), the boot rehydrate partitions on state, and a stale artifact_cursor
    // decides whether a resubscribe replays delivered artifacts or skips undelivered ones. A field
    // reachable only by decoding a blob can be neither indexed nor constrained.
    //
    // Every u64 is BIGINT UNSIGNED, as every other u64 in this schema already is, so the FULL u64
    // range round-trips and there is no value the contract can hand this backend that it must refuse
    // or silently mangle. Signed BIGINT would wrap `artifact_cursor` negative past i64::MAX and clamp
    // it back on read -- a row that does not read back as itself, with no error ever reported.
    //
    // `state` is deliberately UNCONSTRAINED (no CHECK, no ENUM): a task state token minted by a
    // NEWER engine than the one this schema was written against must store and read back verbatim.
    // Only the retention sweep's TERMINAL_TASK_STATES list is a closed set, and it is closed in the
    // safe direction -- an unrecognised token is never swept.
    //
    // COLLATE utf8mb4_bin on `task_id` and `state`, and it is load-bearing on both. This schema's
    // default collation is utf8mb4_0900_ai_ci -- CASE- AND ACCENT-INSENSITIVE -- under which
    // `'Completed' IN ('completed', ...)` is TRUE and two task ids differing only in case COLLIDE
    // ON THE PRIMARY KEY. That defeats both guarantees this table is supposed to make: the terminal
    // set would sweep a state token it does not actually recognise (the exact failure the closed set
    // exists to prevent), and two distinct tasks would silently upsert onto one row, losing one of
    // them. Binary rather than `CHARACTER SET ascii` because a task id is an opaque
    // protocol-supplied string: ascii would HARD-FAIL a non-ASCII id under STRICT_ALL_TABLES,
    // whereas utf8mb4_bin stores the full range and still compares exactly. Same class of bug the
    // v3 migration closed for `usage_metering.key_group_at_use`.
    //
    // The other columns keep the default collation on purpose: this store only ever stores them and
    // returns them verbatim, and never compares one against a literal.
    "CREATE TABLE IF NOT EXISTS tasks (
        task_id VARCHAR(191) COLLATE utf8mb4_bin NOT NULL,
        context_id VARCHAR(191) NOT NULL DEFAULT '',
        principal VARCHAR(191) NOT NULL DEFAULT '',
        direction VARCHAR(16) NOT NULL DEFAULT '',
        state VARCHAR(64) COLLATE utf8mb4_bin NOT NULL DEFAULT '',
        agent_id VARCHAR(191) NOT NULL DEFAULT '',
        artifact_cursor BIGINT UNSIGNED NOT NULL DEFAULT 0,
        -- TEXT, not VARCHAR(n): a push callback is an operator-supplied URL with no length this
        -- schema can honestly bound, and under STRICT_ALL_TABLES a guessed-too-short ceiling is a
        -- hard write failure on a task that was otherwise fine. Never indexed, never matched on.
        push_callback TEXT NOT NULL,
        created_at BIGINT UNSIGNED NOT NULL,
        updated_at BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY (task_id)
    ) ENGINE=InnoDB",
    // The retention sweep's access path -- purge_tasks_before filters on exactly (state, updated_at)
    // -- in that column order, because the sweep names a closed set of states and then a range on
    // updated_at, and an index is only usable for a range on its LAST consulted column.
    "CREATE INDEX idx_tasks_state_updated ON tasks (state, updated_at)",
    // PER-TASK PROVENANCE, hash-chained WITHIN a task. Per-task rather than one global chain because
    // tasks are concurrent and long-lived: a global chain would serialise every task transition
    // behind one append and would make one task's provenance unverifiable without possessing every
    // other tenant's events. The chain columns -- seq, prev_hash, hash -- are REAL columns for the
    // same reason they are in mcp_calls: durability here is established by READING THE CHAIN BACK,
    // and this store NEVER computes or recomputes a digest.
    //
    // NO FOREIGN KEY to `tasks`, deliberately, even though the purge cascade below is exactly what
    // one would buy. An FK would also impose an ORDER on the writes -- no event could be appended
    // before its task row existed -- and the engine is under no such obligation: a `task.submitted`
    // event and the first `put_task` are two independent write-throughs and the contract states no
    // ordering between them. A DELETE trigger, which is how store-sqlite gets the cascade without
    // the ordering constraint, is not available here either: creating one needs SUPER (ER_NOT_SUPER,
    // 1419) on any server with binary logging on, which the mysql:8 image CI runs has by default and
    // the app-level `busbar` user does not hold. So the cascade lives in `purge_tasks_before`, in the
    // same transaction as the parent delete -- see that method.
    "CREATE TABLE IF NOT EXISTS task_events (
        task_id VARCHAR(191) COLLATE utf8mb4_bin NOT NULL,
        seq BIGINT UNSIGNED NOT NULL,
        ts BIGINT UNSIGNED NOT NULL,
        kind VARCHAR(64) NOT NULL DEFAULT '',
        context_id VARCHAR(191) NOT NULL DEFAULT '',
        principal VARCHAR(191) NOT NULL DEFAULT '',
        agent_id VARCHAR(191) NOT NULL DEFAULT '',
        state VARCHAR(64) NOT NULL DEFAULT '',
        request_id VARCHAR(191) NOT NULL DEFAULT '',
        prev_hash CHAR(64) NOT NULL DEFAULT '',
        hash CHAR(64) NOT NULL DEFAULT '',
        PRIMARY KEY (task_id, seq)
    ) ENGINE=InnoDB",
];

/// MySQL/MariaDB-backed [`Store`]. A single mutex-guarded pooled connection is used for all control-
/// plane (keys/credentials/denylist) work — low frequency, correctness over throughput; usage/audit
/// writes go through the same pool without an explicit app-level mutex since the pool itself
/// serializes checkouts safely.
pub struct MysqlStore {
    pool: Pool,
}

impl MysqlStore {
    /// Connect, create the schema if absent, and run the boot-time invariant probes. Hard-fails
    /// (returns `Err`, never silently degrades) if the server can't actually enforce what the schema
    /// declares — see the module doc for why a version check alone is insufficient.
    ///
    /// The pool is capped small (8 connections) — this store is control-plane-frequency (key/
    /// credential CRUD) plus write-behind usage flush, not a high-fan-out OLTP workload, and an
    /// unbounded pool across many `MysqlStore::connect()` calls (e.g. one per test, or a multi-
    /// process fleet booting simultaneously) is what exhausts MySQL's default `max_connections`.
    pub fn connect(url: &str) -> StoreResult<Self> {
        let opts = Opts::from_url(url).map_err(store_err)?;
        let opts = mysql::OptsBuilder::from_opts(opts)
            .pool_opts(mysql::PoolOpts::default().with_constraints(
                mysql::PoolConstraints::new(1, 8).expect("1 <= 8 is a valid pool constraint"),
            ))
            // ESTABLISH strict mode on every connection this pool ever creates -- including a
            // reconnect after a dropped connection, or the pool growing past the one connection
            // `probe_invariants` (below) checks at boot -- rather than verifying it once and
            // trusting every future connection inherits the same posture. Appends (never replaces)
            // to whatever sql_mode the server/session already carries, so an operator's other
            // modes survive. CHECK-constraint enforcement (the other boot-probe invariant) is a
            // server-wide, not session-scoped, property -- it can't diverge per connection the way
            // sql_mode can, so the one-time probe below remains sufficient for that half.
            .init(vec![
                "SET SESSION sql_mode = CONCAT(@@sql_mode, ',STRICT_ALL_TABLES')",
            ]);
        let pool = Pool::new(opts).map_err(store_err)?;

        Self::init_schema(&pool)?;

        let mut conn = pool.get_conn().map_err(store_err)?;
        Self::probe_invariants(&mut conn)?;
        drop(conn);

        Ok(Self { pool })
    }

    /// Schema creation, retried on deadlock. Concurrent `CREATE TABLE`/`CREATE INDEX` from more than
    /// one connection (a multi-node fleet booting simultaneously against a fresh database, or —
    /// exactly this crate's own parallel test suite — is a REAL scenario, not just a test artifact:
    /// MySQL's metadata locking can genuinely deadlock two concurrent DDL statements against the
    /// same schema (`ERROR 1213`). A bounded retry-with-backoff is the correct response (the losing
    /// transaction is safe to retry — DDL here is idempotent via the `IF NOT EXISTS`/duplicate-error
    /// swallowing below), not a crash.
    fn init_schema(pool: &Pool) -> StoreResult<()> {
        const MAX_ATTEMPTS: u32 = 5;
        for attempt in 1..=MAX_ATTEMPTS {
            match Self::try_init_schema(pool) {
                Ok(()) => return Ok(()),
                Err(e) if attempt < MAX_ATTEMPTS && e.0.contains("Deadlock found") => {
                    std::thread::sleep(std::time::Duration::from_millis(50 * attempt as u64));
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        unreachable!("loop always returns on the final attempt")
    }

    /// v2 one-time backfill, closing the SAME `hydrate_budgets` billing bug store-postgres's own v6
    /// backfill closes (busbarAI core's `crates/busbar/src/governance/state.rs`): pre-v2 rows may
    /// have `billable_requests = 0` alongside a real, positive `requests` count purely because this
    /// store didn't track the split before v2, never because of a genuine refund/discount. Trusting
    /// `billable_requests` unconditionally (as `hydrate_budgets` now does) needs those historical
    /// rows backfilled once, here, at the source — never re-derived from `requests` at read time by
    /// a heuristic (that heuristic is exactly the bug being closed). Only fires when crossing INTO v2
    /// from a database that genuinely predates it (`prior_version < 2` and `prior_version > 0`, i.e.
    /// `store_meta` already existed with an old value) — a brand-new v1-absent database has no
    /// pre-migration rows and must not run this pointless no-op.
    ///
    /// Takes `prior_version` as an explicit argument rather than reading `store_meta` itself, purely
    /// so the migration tests can call this directly with a hardcoded version and never have to
    /// mutate the single GLOBAL `store_meta.schema_version` row the whole shared test-server
    /// suite reads/writes on every `connect()`. Mutating that row instead races: any concurrently
    /// running test's own `connect()` unconditionally overwrites `schema_version` back to current,
    /// clobbering another test's deliberately-lowered marker.
    ///
    /// Also takes `table` rather than hardcoding `usage_windows`, again purely for test isolation:
    /// unlike store-postgres's own equivalent test (which runs each migration test against its own
    /// throwaway DATABASE), the CI `busbar` MySQL user has no `CREATE DATABASE` privilege (confirmed:
    /// `ERROR 1044 Access denied for user 'busbar'@'%' to database ...` — the official mysql image's
    /// `MYSQL_USER` mechanism only grants `ALL PRIVILEGES` on the one `MYSQL_DATABASE`, not globally)
    /// — table-level isolation within that one shared database is the only DDL this user can do, and
    /// it's real DDL the rest of this crate's suite already exercises freely. Production always calls
    /// this with `"usage_windows"`; the table parameter exists ONLY so a test can point it at a
    /// private scratch table instead of racing every other concurrently-running test's legitimate
    /// writes to the real, shared `usage_windows`.
    ///
    /// KNOWN, DOCUMENTED, NOT-YET-CLOSED GAP — and a lock is NOT the fix for it (see below): this
    /// UPDATE is UNSCOPED and assumes "a one-time
    /// boot migration runs before any concurrent traffic exists" — true for a full-fleet restart, but
    /// this store's own target topology is a ROLLING upgrade (README: multiple busbar nodes sharing
    /// one MySQL server). In a rolling upgrade, some nodes are ALREADY LIVE on v2 — genuinely writing
    /// `billable_requests > 0` via real traffic — while another node is still booting and about to
    /// run this backfill. If live traffic reaches a still-pre-v2 row before this UPDATE does, the
    /// predicate (`billable_requests = 0 AND requests > 0`) no longer matches it, and that row's
    /// PRE-v2 historical `requests` are PERMANENTLY never reclassified as billable — a silent,
    /// unrepairable billing undercount, i.e. exactly the `hydrate_budgets` bug class this migration
    /// exists to close, reintroduced by a race in the migration itself. A `GET_LOCK` does not close
    /// it: a lock can only serialize NODES STILL BOOTING against each other, and the backfill's own
    /// re-run is already idempotent, so that case was never unsafe in the first place. It does
    /// nothing about a node that is ALREADY LIVE and never enters this function at all, which is the
    /// actual race. Closing this for real needs pre-v2 rows to be identifiable by something live
    /// traffic cannot change (a captured `window_start`/time cutoff, or a per-row provenance
    /// marker), which is a schema redesign rather than a lock. OPERATIONAL MITIGATION
    /// until that redesign lands: either pause the whole fleet briefly for a v1->v2 upgrade
    /// specifically (not required for any OTHER version bump), or re-run this same predicate as a
    /// manual reconciliation query after a rolling upgrade completes — safe to do since the
    /// predicate is idempotent (a row already at `billable_requests > 0` never matches it again).
    /// See `characterize_v2_backfill_loses_a_row_to_a_racing_live_write` below for a reproduction.
    fn run_v2_backfill_if_needed(
        conn: &mut PooledConn,
        prior_version: u32,
        table: &str,
    ) -> StoreResult<()> {
        if prior_version > 0 && prior_version < V2_BILLABLE_REQUESTS_BACKFILL {
            // Batched (LIMIT 5000 per statement, looped until exhausted), matching the same
            // bounded-batch convention purge_windows_before/purge_metering_before already use
            // elsewhere in this file -- an unbounded single UPDATE across the whole table risks
            // holding its lock/scan for a long time on a large production table, worse than
            // necessary even for a one-time migration.
            loop {
                conn.query_drop(format!(
                    "UPDATE {table} SET billable_requests = requests \
                     WHERE billable_requests = 0 AND requests > 0 LIMIT 5000"
                ))
                .map_err(store_err)?;
                if conn.affected_rows() < 5000 {
                    break;
                }
            }
        }
        Ok(())
    }

    /// v3: `usage_metering.key_group_at_use` shipped in v1.0.0 without `ascii_bin` (inherited
    /// MySQL's default case-INSENSITIVE collation) -- a real gap against this crate's own stated
    /// invariant that every opaque identifier/group-name column gets byte-exact comparison. The
    /// The `CREATE TABLE IF NOT EXISTS` declaration above only affects a FRESH database; any
    /// database created by a pre-v3 release already has the table at the wrong collation, so a real
    /// `ALTER TABLE` is required to close it on upgrade.
    /// Idempotent: MODIFY COLUMN to the same collation it's already at is a harmless no-op on a
    /// database created fresh (already ascii_bin) or one already migrated past v3.
    ///
    /// Same `table` parameter for test isolation as `run_v2_backfill_if_needed` -- see that
    /// function's doc comment for why (no `CREATE DATABASE` privilege in CI).
    fn run_v3_ascii_bin_fix_if_needed(
        conn: &mut PooledConn,
        prior_version: u32,
        table: &str,
    ) -> StoreResult<()> {
        if prior_version > 0 && prior_version < V3_KEY_GROUP_AT_USE_ASCII_BIN {
            conn.query_drop(format!(
                "ALTER TABLE {table} MODIFY COLUMN key_group_at_use \
                 VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT ''"
            ))
            .map_err(store_err)?;
        }
        Ok(())
    }

    /// Read the version this database was AT before this boot from `store_meta`, tolerating "no row
    /// yet" (a genuinely fresh database, or one already at v2 that never needed a marker written
    /// pre-v2) as version 0, but propagating any OTHER query failure (a connection blip, a lock
    /// timeout) instead of silently treating it identically to "fresh install" -- collapsing those
    /// two outcomes previously meant a transient failure here permanently marked a possibly-
    /// unmigrated database as migrated (schema_version still got written unconditionally right
    /// after). A stored value that fails to parse as a version number is ALSO now a hard error
    /// rather than a silent 0 -- a corrupt marker is exactly the kind of "looks fine, isn't" state
    /// this store's own boot-probe philosophy (module doc, above) says must hard-fail, not warn.
    /// Takes `table` rather than hardcoding `store_meta`, purely for test isolation -- same reason
    /// `run_v2_backfill_if_needed` takes its own `table` param (see that function's doc comment):
    /// `store_meta` is a single shared row the whole test binary's `connect()` calls race on.
    /// Production always calls this with `"store_meta"`.
    fn read_prior_version(conn: &mut PooledConn, table: &str) -> StoreResult<u32> {
        match conn
            .query_first::<Option<String>, _>(format!(
                "SELECT v FROM {table} WHERE k = 'schema_version'"
            ))
            .map_err(store_err)?
            .flatten()
        {
            None => Ok(0),
            Some(v) => v.parse().map_err(|e| {
                store_err(format!(
                    "store_meta.schema_version is corrupt (not a valid version number): {v:?} ({e})"
                ))
            }),
        }
    }

    fn try_init_schema(pool: &Pool) -> StoreResult<()> {
        let mut conn = pool.get_conn().map_err(store_err)?;

        // `read_prior_version` needs `store_meta` to already exist -- create it FIRST (SCHEMA[0],
        // `IF NOT EXISTS` so harmless to re-run when the full loop below reaches it again) so a
        // genuinely fresh database's read is a real "no row" (Ok(None) -> version 0), not a
        // "table doesn't exist" query ERROR that read_prior_version's error-propagation would now
        // (correctly, for every OTHER failure) treat as a hard failure.
        conn.query_drop(SCHEMA[0]).map_err(store_err)?;
        let prior_version = Self::read_prior_version(&mut conn, "store_meta")?;

        for stmt in SCHEMA {
            // IF NOT EXISTS on tables; CREATE INDEX has no IF NOT EXISTS in MySQL/MariaDB, so a
            // "duplicate key name" error on re-run (schema already applied) is swallowed here —
            // every other error propagates.
            if let Err(e) = conn.query_drop(*stmt) {
                let msg = e.to_string();
                if !(msg.contains("Duplicate key name") || msg.contains("already exists")) {
                    return Err(store_err(format!(
                        "schema init failed: {msg}\nstatement: {stmt}"
                    )));
                }
            }
        }

        Self::run_v2_backfill_if_needed(&mut conn, prior_version, "usage_windows")?;
        Self::run_v3_ascii_bin_fix_if_needed(&mut conn, prior_version, "usage_metering")?;

        conn.query_drop(
            "INSERT INTO store_meta (k, v) VALUES ('schema_version', :v) \
             ON DUPLICATE KEY UPDATE v = :v"
                .replace(':', "?")
                .replace("?v", &format!("'{SCHEMA_VERSION}'")),
        )
        .map_err(store_err)?;
        conn.query_drop(
            "INSERT INTO store_sequence (id, revision) VALUES (1, 0) \
             ON DUPLICATE KEY UPDATE id = id",
        )
        .map_err(store_err)?;

        Ok(())
    }

    /// A rejected probe INSERT is proof of CHECK enforcement ONLY if it's the SPECIFIC
    /// CHECK-violation error this schema's two target engines actually produce -- MySQL 8.0.16+'s
    /// `ER_CHECK_CONSTRAINT_VIOLATED` (3819) or MariaDB's `ER_CONSTRAINT_FAILED` (4025). Any other
    /// error (a lock timeout, a connection blip) is inconclusive and must never be silently read as
    /// "enforced" -- that was the bug: the prior code treated ANY error as proof.
    fn is_check_constraint_violation(e: &mysql::Error) -> bool {
        matches!(e, mysql::Error::MySqlError(inner) if inner.code == 3819 || inner.code == 4025)
    }

    /// Live functional probes for the two failure modes a schema-shape check cannot catch:
    /// (1) `CHECK` constraints parsed but not enforced (MySQL < 8.0.16, Aurora MySQL 2.x);
    /// (2) `STRICT_ALL_TABLES` not in `sql_mode` (a VARCHAR/BIGINT overflow silently truncates
    ///     instead of erroring). (1) is probed via a session-private `TEMPORARY` table (never the
    ///     real shared schema — zero contention with real traffic or another node's simultaneous
    ///     probe), dropped immediately after; no probe row ever touches real data.
    fn probe_invariants(conn: &mut PooledConn) -> StoreResult<()> {
        let sql_mode: String = conn
            .query_first("SELECT @@sql_mode")
            .map_err(store_err)?
            .unwrap_or_default();
        if !sql_mode.contains("STRICT_ALL_TABLES") && !sql_mode.contains("STRICT_TRANS_TABLES") {
            return Err(store_err(format!(
                "boot probe failed: sql_mode does not include STRICT_ALL_TABLES/STRICT_TRANS_TABLES \
                 (got '{sql_mode}') — a truncated write would silently corrupt data instead of \
                 erroring. Set `SET GLOBAL sql_mode='STRICT_ALL_TABLES';` on this server."
            )));
        }

        // Session-private TEMPORARY table -- zero contention with real traffic or another node's
        // simultaneous boot probe (unlike probing the real, shared `store_sequence` singleton row,
        // which a concurrent live control-plane transaction, or another node probing at the same
        // moment, could genuinely lock -- producing a lock-wait-timeout/deadlock error that has
        // nothing to do with CHECK enforcement and would be misread as "unexpected failure"
        // below). Auto-dropped at session end regardless; explicitly dropped here too.
        conn.query_drop(
            "CREATE TEMPORARY TABLE busbar_check_probe (\
                id INT PRIMARY KEY, CONSTRAINT ck_probe CHECK (id = 1)\
             ) ENGINE=InnoDB",
        )
        .map_err(store_err)?;
        let probe_result = conn.query_drop("INSERT INTO busbar_check_probe (id) VALUES (999)");
        let _ = conn.query_drop("DROP TEMPORARY TABLE busbar_check_probe");

        // ER_CHECK_CONSTRAINT_VIOLATED (3819, MySQL 8.0.16+) / ER_CONSTRAINT_FAILED (4025,
        // MariaDB) -- the two vendor-specific codes this schema's CHECK enforcement actually
        // produces on the two engines this store targets (module doc: "MySQL 8.0.16+, MariaDB, and
        // Aurora MySQL"). Any OTHER error is inconclusive and hard-fails rather than being silently
        // read as "enforced" -- with the temp-table probe above having zero contention with real
        // traffic, there's no remaining benign reason left for a different error here.
        let rejected = match probe_result {
            Ok(()) => false,
            Err(ref e) if Self::is_check_constraint_violation(e) => true,
            Err(e) => {
                return Err(store_err(format!(
                    "boot probe failed: could not determine whether CHECK constraints are enforced \
                     — the probe INSERT failed for an unexpected reason instead of the expected \
                     CHECK violation (MySQL code 3819 / MariaDB code 4025): {e}"
                )));
            }
        };
        if !rejected {
            return Err(store_err(
                "boot probe failed: a CHECK constraint violation was NOT rejected — this server \
                 parses CHECK constraints but does not enforce them (MySQL < 8.0.16, or Aurora MySQL \
                 2.x). Every CHECK in this schema (tombstone invariants, credential-kind allowlist, \
                 secret-form consistency) is silently unenforced. Upgrade to MySQL >= 8.0.16, MariaDB, \
                 or Aurora MySQL 3.x.",
            ));
        }
        Ok(())
    }

    fn conn(&self) -> StoreResult<PooledConn> {
        self.pool.get_conn().map_err(store_err)
    }

    /// Bump `store_sequence` and return the new revision. MUST be the first statement of every
    /// control-plane transaction (mint/revoke/rotate/delete) — this fixed lock order
    /// (store_sequence -> api_keys -> credentials -> denylist) is what makes deadlock across the
    /// admin plane structurally impossible. Never call this outside an active transaction.
    fn bump_revision(tx: &mut mysql::Transaction<'_>) -> StoreResult<u64> {
        tx.query_drop("UPDATE store_sequence SET revision = revision + 1 WHERE id = 1")
            .map_err(store_err)?;
        tx.query_first("SELECT revision FROM store_sequence WHERE id = 1")
            .map_err(store_err)?
            .ok_or_else(|| store_err("store_sequence row missing"))
    }

    fn row_to_key(mut row: mysql::Row) -> StoreResult<VirtualKey> {
        let id: String = row
            .take("id")
            .ok_or_else(|| store_err("missing column: id"))?;
        let generation_hash: String = row
            .take("generation_hash")
            .ok_or_else(|| store_err("missing column: generation_hash"))?;
        let name: String = row
            .take("name")
            .ok_or_else(|| store_err("missing column: name"))?;
        let allowed_pools_json: Option<String> = row.take("allowed_pools").unwrap_or(None);
        let labels_json: String = row
            .take("labels")
            .ok_or_else(|| store_err("missing column: labels"))?;
        let enabled: bool = row
            .take("enabled")
            .ok_or_else(|| store_err("missing column: enabled"))?;
        let created_at: u64 = row
            .take("created_at")
            .ok_or_else(|| store_err("missing column: created_at"))?;
        let key_group: String = row
            .take("key_group")
            .ok_or_else(|| store_err("missing column: key_group"))?;
        let expires_at: Option<u64> = row.take("expires_at").unwrap_or(None);
        let deleted_at: Option<u64> = row.take("deleted_at").unwrap_or(None);
        let revision: u64 = row
            .take("revision")
            .ok_or_else(|| store_err("missing column: revision"))?;

        // `allowed_pools` is stored as a JSON array of bare pool-name strings (matching the
        // wire/storage shape used pre-generalization and by `busbar_api`'s own `allowed_scopes_wire`
        // serde shim) — every entry is `kind: "pool"` by construction, since "pool" is the only
        // registered scope kind today.
        let allowed_scopes: Option<Vec<ScopeRef>> = match allowed_pools_json {
            Some(s) => {
                let pools: Vec<String> = serde_json::from_str(&s).map_err(store_err)?;
                Some(pools.into_iter().map(ScopeRef::pool).collect())
            }
            None => None,
        };
        let labels = serde_json::from_str(&labels_json).map_err(store_err)?;

        Ok(VirtualKey {
            id,
            generation_hash,
            name,
            allowed_scopes,
            enabled,
            created_at,
            group: if key_group.is_empty() {
                None
            } else {
                Some(key_group)
            },
            labels,
            expires_at,
            deleted_at,
            revision,
        })
    }

    /// Reads its columns by NAME, not position — safe to call after the caller has already
    /// `row.take()`n an extra column (e.g. `secret`) out of a wider `SELECT`, which a positional
    /// `mysql::from_row_opt` tuple conversion cannot tolerate (it requires an exact column count
    /// match and errors on any row shape it doesn't recognize as a valid conversion target).
    fn row_to_cred_meta(mut row: mysql::Row) -> StoreResult<CredentialMeta> {
        let id: String = row
            .take("id")
            .ok_or_else(|| store_err("missing column: id"))?;
        let key_id: String = row
            .take("key_id")
            .ok_or_else(|| store_err("missing column: key_id"))?;
        let kind: String = row
            .take("kind")
            .ok_or_else(|| store_err("missing column: kind"))?;
        let slot: i8 = row
            .take("slot")
            .ok_or_else(|| store_err("missing column: slot"))?;
        let public_id: String = row
            .take("public_id")
            .ok_or_else(|| store_err("missing column: public_id"))?;
        let secret_form: String = row
            .take("secret_form")
            .ok_or_else(|| store_err("missing column: secret_form"))?;
        let created_at: u64 = row
            .take("created_at")
            .ok_or_else(|| store_err("missing column: created_at"))?;
        let updated_at: u64 = row
            .take("updated_at")
            .ok_or_else(|| store_err("missing column: updated_at"))?;
        let expires_at: Option<u64> = row.take("expires_at").unwrap_or(None);
        let revoked_at: Option<u64> = row.take("revoked_at").unwrap_or(None);
        let revoke_reason: Option<String> = row.take("revoke_reason").unwrap_or(None);
        let revision: u64 = row
            .take("revision")
            .ok_or_else(|| store_err("missing column: revision"))?;

        Ok(CredentialMeta {
            id,
            key_id,
            kind,
            slot: slot as u8,
            public_id,
            secret_form: parse_secret_form(&secret_form)?,
            created_at,
            updated_at,
            expires_at,
            revoked_at,
            revoke_reason,
            revision,
        })
    }
}

fn parse_secret_form(s: &str) -> StoreResult<SecretForm> {
    match s {
        "none" => Ok(SecretForm::None),
        "recoverable" => Ok(SecretForm::Recoverable),
        "digest" => Ok(SecretForm::Digest),
        other => Err(store_err(format!("unknown secret_form '{other}' in store"))),
    }
}

fn secret_form_str(f: &SecretForm) -> &'static str {
    match f {
        SecretForm::None => "none",
        SecretForm::Recoverable => "recoverable",
        SecretForm::Digest => "digest",
    }
}

/// Serializes `allowed_scopes` down to the `allowed_pools` column's JSON-array-of-bare-strings
/// shape (every entry is `kind: "pool"` by construction today — see `row_to_key`'s matching
/// deserialization for the full rationale).
fn scopes_to_pools_json(scopes: &Option<Vec<ScopeRef>>) -> StoreResult<Option<String>> {
    scopes
        .as_ref()
        .map(|list| {
            let bare: Vec<&str> = list.iter().map(|s| s.value.as_str()).collect();
            serde_json::to_string(&bare)
        })
        .transpose()
        .map_err(store_err)
}

impl Store for MysqlStore {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        let mut conn = self.conn()?;
        let mut tx = conn
            .start_transaction(TxOpts::default())
            .map_err(store_err)?;
        let rev = Self::bump_revision(&mut tx)?;

        // TOMBSTONE PRECONDITION (see `Store::put_key`): a live-shaped write must not overwrite a
        // tombstoned row, which would reissue an id the contract says is never reissued and revive
        // every token minted before the delete.
        //
        // `ON DUPLICATE KEY UPDATE` takes no WHERE, so unlike the other SQL backends this cannot
        // ride on the upsert itself. `SELECT ... FOR UPDATE` inside the transaction is equivalent
        // here and is the idiom this file already uses for exactly this problem (`delete_key`,
        // `revoke_credential`, `put_credential`'s slot guard): the row lock is held to commit, so
        // the test and the write are atomic and a concurrent `delete_key` cannot land in between.
        // Ordered AFTER `bump_revision` to keep the crate's fixed lock order, store_sequence before
        // api_keys.
        if key.deleted_at.is_none() {
            let existing: Option<(Option<u64>,)> = tx
                .exec_first(
                    "SELECT deleted_at FROM api_keys WHERE id = :id FOR UPDATE",
                    params! { "id" => &key.id },
                )
                .map_err(store_err)?;
            if let Some((Some(_),)) = existing {
                tx.rollback().map_err(store_err)?;
                return Err(store_err(format!(
                    "put_key: '{}' is tombstoned and its id is never reissued; refusing to clear \
                     the tombstone",
                    key.id
                )));
            }
        }

        let pools_json = scopes_to_pools_json(&key.allowed_scopes)?;
        let labels_json = serde_json::to_string(&key.labels).map_err(store_err)?;
        let group = key.group.clone().unwrap_or_default();

        tx.exec_drop(
            "INSERT INTO api_keys
                (id, name, key_group, allowed_pools, labels, enabled, generation_hash,
                 created_at, updated_at, expires_at, deleted_at, revision)
             VALUES (:id, :name, :key_group, :pools, :labels, :enabled, :gen, :created, :updated,
                     :expires, :deleted, :rev)
             ON DUPLICATE KEY UPDATE
                name = VALUES(name), key_group = VALUES(key_group), allowed_pools = VALUES(allowed_pools),
                labels = VALUES(labels), enabled = VALUES(enabled), generation_hash = VALUES(generation_hash),
                updated_at = VALUES(updated_at), expires_at = VALUES(expires_at),
                deleted_at = VALUES(deleted_at), revision = VALUES(revision)",
            params! {
                "id" => &key.id,
                "name" => &key.name,
                "key_group" => &group,
                "pools" => &pools_json,
                "labels" => &labels_json,
                "enabled" => key.enabled,
                "gen" => &key.generation_hash,
                "created" => key.created_at,
                "updated" => key.created_at,
                "expires" => key.expires_at,
                "deleted" => key.deleted_at,
                "rev" => rev,
            },
        )
        .map_err(store_err)?;

        tx.commit().map_err(store_err)
    }

    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        let mut conn = self.conn()?;
        let row: Option<mysql::Row> = conn
            .exec_first(
                "SELECT id, generation_hash, name, allowed_pools, labels, enabled, created_at, \
                 key_group, expires_at, deleted_at, revision FROM api_keys WHERE id = :id",
                params! { "id" => id },
            )
            .map_err(store_err)?;
        row.map(Self::row_to_key).transpose()
    }

    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        let mut conn = self.conn()?;
        let rows: Vec<mysql::Row> = conn
            .query(
                "SELECT id, generation_hash, name, allowed_pools, labels, enabled, created_at, \
                 key_group, expires_at, deleted_at, revision FROM api_keys",
            )
            .map_err(store_err)?;
        rows.into_iter().map(Self::row_to_key).collect()
    }

    fn list_keys_since(&self, since: u64) -> StoreResult<Vec<VirtualKey>> {
        let mut conn = self.conn()?;
        let rows: Vec<mysql::Row> = conn
            .exec(
                "SELECT id, generation_hash, name, allowed_pools, labels, enabled, created_at, \
                 key_group, expires_at, deleted_at, revision FROM api_keys WHERE revision > :since",
                params! { "since" => since },
            )
            .map_err(store_err)?;
        rows.into_iter().map(Self::row_to_key).collect()
    }

    /// TOMBSTONE, not row removal — see the trait doc. Cascades credential destruction, sets
    /// enabled=false + deleted_at, all in ONE transaction with ONE revision stamp on the api_keys
    /// row, so a hydrator reading a consistent snapshot can never observe the tombstone without the
    /// credentials already gone (the hard-delete-invisible-to-hydration fix).
    fn delete_key(&self, id: &str) -> StoreResult<()> {
        let mut conn = self.conn()?;
        let mut tx = conn
            .start_transaction(TxOpts::default())
            .map_err(store_err)?;

        // bump_revision FIRST, matching the crate's fixed lock order (store_sequence before
        // api_keys) — the existence/state check below still runs before any write, it just
        // acquires its FOR UPDATE lock second. A no-op path (unknown id / already tombstoned)
        // rolls the transaction back, so the revision it consumed is never observably committed;
        // per the locked design, gaps in the sequence are harmless, only inversions are fatal.
        let rev = Self::bump_revision(&mut tx)?;

        // Explicit existence/state check — rows_affected() alone can't distinguish
        // "not found" from "already tombstoned, no-op" (both report 0 rows changed).
        let existing: Option<(Option<u64>,)> = tx
            .exec_first(
                "SELECT deleted_at FROM api_keys WHERE id = :id FOR UPDATE",
                params! { "id" => id },
            )
            .map_err(store_err)?;
        let Some((deleted_at,)) = existing else {
            tx.rollback().map_err(store_err)?;
            // NOT the same case as already-tombstoned below. "Already tombstoned" means the
            // operator's intent is satisfied and the evidence is on disk; "no such id" means
            // nothing was touched, and Ok(()) there tells an operator who typo'd an id that a key
            // was revoked when none was.
            return Err(store_err(format!("delete_key: unknown id '{id}'")));
        };
        if deleted_at.is_some() {
            tx.rollback().map_err(store_err)?;
            return Ok(()); // already tombstoned: idempotent no-op per the trait doc
        }

        let now = crate_now();

        tx.exec_drop(
            "DELETE FROM credentials WHERE key_id = :id",
            params! { "id" => id },
        )
        .map_err(store_err)?;

        tx.exec_drop(
            "UPDATE api_keys SET enabled = FALSE, deleted_at = :now, updated_at = :now, revision = :rev \
             WHERE id = :id",
            params! { "now" => now, "rev" => rev, "id" => id },
        )
        .map_err(store_err)?;

        tx.commit().map_err(store_err)
    }

    fn scrub_key(&self, id: &str) -> StoreResult<()> {
        let mut conn = self.conn()?;
        let mut tx = conn
            .start_transaction(TxOpts::default())
            .map_err(store_err)?;

        // bump_revision FIRST — see delete_key's comment on the fixed lock order.
        let rev = Self::bump_revision(&mut tx)?;

        let existing: Option<(Option<u64>,)> = tx
            .exec_first(
                "SELECT deleted_at FROM api_keys WHERE id = :id FOR UPDATE",
                params! { "id" => id },
            )
            .map_err(store_err)?;
        match existing {
            None => {
                tx.rollback().map_err(store_err)?;
                Err(store_err(format!("scrub_key: unknown id '{id}'")))
            }
            Some((None,)) => {
                tx.rollback().map_err(store_err)?;
                Err(store_err(format!(
                    "scrub_key: key '{id}' is not tombstoned — delete_key first"
                )))
            }
            Some((Some(_),)) => {
                let now = crate_now();
                tx.exec_drop(
                    "UPDATE api_keys SET name = '', labels = '{}', updated_at = :now, revision = :rev \
                     WHERE id = :id",
                    params! { "now" => now, "rev" => rev, "id" => id },
                )
                .map_err(store_err)?;
                tx.commit().map_err(store_err)
            }
        }
    }

    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
        let mut conn = self.conn()?;
        let rows: Vec<(String, u64, u64, u64, u64)> = conn
            .exec(
                "SELECT model, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write \
                 FROM usage_windows WHERE bucket_id = :b AND window_start = :w AND model <> ''",
                params! { "b" => bucket_id, "w" => window_start },
            )
            .map_err(store_err)?;
        // `SUM()` with no GROUP BY always returns exactly one row, even when zero rows match the
        // WHERE clause — it returns SQL NULL for each aggregate, not an empty result set. So
        // `exec_first::<(u64, u64)>` is NEVER `None` here (that would require zero rows, which
        // never happens); instead it was a `Some(Row)` whose columns are NULL for a bucket/window
        // with no usage yet, and mysql_common's `FromRow` for a non-Option tuple PANICS trying to
        // convert NULL into `u64` (confirmed: this crashed the freshly-restarted process during
        // governance boot's budget hydration on a brand-new store, well before it enforced
        // `STRICT_ALL_TABLES` any differently — this is a Rust-side conversion bug, not a sql_mode
        // issue). `COALESCE(..., 0)` makes MySQL itself hand back 0 for the empty-aggregate case,
        // matching Postgres/SQLite's "no row yet" -> 0 semantics.
        let totals: Option<(u64, u64)> = conn
            .exec_first(
                "SELECT COALESCE(SUM(requests), 0), COALESCE(SUM(billable_requests), 0) \
                 FROM usage_windows WHERE bucket_id = :b AND window_start = :w",
                params! { "b" => bucket_id, "w" => window_start },
            )
            .map_err(store_err)?;
        let (requests, billable_requests) = totals.unwrap_or((0, 0));

        Ok(UsageLedger {
            requests,
            billable_requests,
            models: rows
                .into_iter()
                .map(
                    |(model, input, output, cache_read, cache_write)| ModelTokens {
                        model,
                        tokens: TierTokens {
                            input,
                            output,
                            cache_read,
                            cache_write,
                        },
                    },
                )
                .collect(),
        })
    }

    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        let mut tx = conn
            .start_transaction(TxOpts::default())
            .map_err(store_err)?;
        // `bucket_scope` is named EXPLICITLY even though this path only ever writes 'key'. The
        // primary key is (window_start, bucket_scope, bucket_id, model), so a predicate that skips
        // `bucket_scope` cannot use the key beyond its first column: InnoDB then takes a next-key
        // lock running to the index supremum, and two DELETEs for DIFFERENT windows both end up
        // holding the gap at the end of the index and then both try to insert into it. That is a
        // genuine deadlock between unrelated writers, and it is what MySQL's own deadlock record
        // showed. Naming the scope lets the range close on (window_start, 'key', bucket_id, ...).
        tx.exec_drop(
            "DELETE FROM usage_windows \
             WHERE window_start = :w AND bucket_scope = 'key' AND bucket_id = :b",
            params! { "b" => bucket_id, "w" => window_start },
        )
        .map_err(store_err)?;
        // The request counters belong to the WINDOW, not to any one model, so they live on a single
        // reserved `model = ''` sentinel row and the per-model rows carry tokens only. Written onto
        // every per-model row instead, `get_usage`'s `SUM(requests)` returned the count multiplied by
        // the number of models, and a ledger with no model breakdown wrote nothing at all and
        // discarded its counters. store-sqlite uses the same sentinel for the same reason.
        tx.exec_drop(
            "INSERT INTO usage_windows
                (window_start, bucket_scope, bucket_id, model, requests, billable_requests)
             VALUES (:w, 'key', :b, '', :req, :breq)
             ON DUPLICATE KEY UPDATE
                requests = VALUES(requests), billable_requests = VALUES(billable_requests)",
            params! {
                "w" => window_start, "b" => bucket_id,
                "req" => ledger.requests, "breq" => ledger.billable_requests,
            },
        )
        .map_err(store_err)?;
        // Insert the per-model rows in a DETERMINISTIC order. The primary key orders by model name,
        // so two transactions writing overlapping windows in caller order can acquire the same rows
        // in opposite orders and deadlock. Sorting makes the acquisition order identical for every
        // writer, which is the same discipline the control-plane paths get from taking the
        // `store_sequence` row lock first.
        let mut models: Vec<&ModelTokens> = ledger.models.iter().collect();
        models.sort_by(|a, b| a.model.cmp(&b.model));
        for m in models {
            tx.exec_drop(
                "INSERT INTO usage_windows
                    (window_start, bucket_scope, bucket_id, model,
                     tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
                 VALUES (:w, 'key', :b, :model, :ti, :to_, :cr, :cw)",
                params! {
                    "w" => window_start, "b" => bucket_id, "model" => &m.model,
                    "ti" => m.tokens.input, "to_" => m.tokens.output,
                    "cr" => m.tokens.cache_read, "cw" => m.tokens.cache_write,
                },
            )
            .map_err(store_err)?;
        }
        tx.commit().map_err(store_err)
    }

    fn add_usage(&self, bucket_id: &str, window_start: u64, delta: &UsageDelta) -> StoreResult<()> {
        let mut conn = self.conn()?;
        let mut tx = conn
            .start_transaction(TxOpts::default())
            .map_err(store_err)?;

        // Pre-dedupe by (bucket_id, window_start, model) — a batch with duplicate PKs in one
        // multi-row upsert would hit "cannot affect row a second time" on Postgres and undefined
        // last-writer-wins on MySQL; the caller is trusted to flush one model at most once per
        // call here (this is the per-delta path, not a batch upsert), so this loop just applies
        // each model delta as its own upsert.
        // The window's request counters accumulate ONCE, on the reserved `model = ''` sentinel row,
        // not once per model. Applied inside the per-model loop instead, a single delta added its
        // request count once for every model it carried, and a delta with no models recorded
        // nothing. This is the fleet flush primitive, so both errors compounded permanently across
        // every node and every flush interval.
        tx.exec_drop(
            "INSERT INTO usage_windows
                (window_start, bucket_scope, bucket_id, model, requests, billable_requests)
             VALUES (:w, 'key', :b, '', GREATEST(0, :req), GREATEST(0, :breq))
             ON DUPLICATE KEY UPDATE
                requests = GREATEST(0, CAST(requests AS SIGNED) + :req),
                billable_requests = GREATEST(0, CAST(billable_requests AS SIGNED) + :breq)",
            params! {
                "w" => window_start, "b" => bucket_id,
                "req" => delta.requests, "breq" => delta.billable_requests,
            },
        )
        .map_err(store_err)?;
        // Deterministic order, same reason as `put_usage`: the primary key orders by model name, so
        // caller-order inserts from two concurrent flushes can deadlock on overlapping windows.
        let mut models: Vec<&ModelTokensDelta> = delta.models.iter().collect();
        models.sort_by(|a, b| a.model.cmp(&b.model));
        for m in models {
            // The VALUES(...) row constructor is type-checked against the target UNSIGNED columns
            // even on rows where ON DUPLICATE KEY UPDATE will fire instead of the INSERT -- MySQL
            // validates the whole statement's row shape up front. A refund delta's negative i64
            // would out-of-range error there even though it's never actually inserted as-is. Clamp
            // each VALUES(...) literal at 0 with its own `GREATEST(0, :x)` (a negative delta on a
            // brand-new, never-charged row is nonsensical anyway); the UPDATE arithmetic below still
            // uses the RAW (possibly negative) bound value, which is where the real floor-at-0 signed
            // accumulation happens.
            tx.exec_drop(
                "INSERT INTO usage_windows
                    (window_start, bucket_scope, bucket_id, model,
                     tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
                 VALUES (:w, 'key', :b, :model,
                         GREATEST(0, :ti), GREATEST(0, :to_), GREATEST(0, :cr), GREATEST(0, :cw))
                 ON DUPLICATE KEY UPDATE
                    tokens_input = GREATEST(0, CAST(tokens_input AS SIGNED) + :ti),
                    tokens_output = GREATEST(0, CAST(tokens_output AS SIGNED) + :to_),
                    tokens_cache_read = GREATEST(0, CAST(tokens_cache_read AS SIGNED) + :cr),
                    tokens_cache_write = GREATEST(0, CAST(tokens_cache_write AS SIGNED) + :cw)",
                params! {
                    "w" => window_start, "b" => bucket_id, "model" => &m.model,
                    "ti" => m.tokens.input, "to_" => m.tokens.output,
                    "cr" => m.tokens.cache_read, "cw" => m.tokens.cache_write,
                },
            )
            .map_err(store_err)?;
        }
        tx.commit().map_err(store_err)
    }

    fn add_metering(&self, delta: &MeteringDelta) -> StoreResult<()> {
        let bucket = format!("{:010}", delta.bucket); // matches the CHAR(10) 'YYYY-MM-DD'-shaped bucket
        let mut conn = self.conn()?;
        conn.exec_drop(
            "INSERT INTO usage_metering
                (bucket, key_id, provider, model, key_group_at_use, pricing_version,
                 requests, billable_requests, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
             VALUES (:bucket, :key, :provider, :model, :grp, :pv, :req, :breq, :ti, :to_, :cr, :cw)
             ON DUPLICATE KEY UPDATE
                requests = requests + VALUES(requests),
                billable_requests = billable_requests + VALUES(billable_requests),
                tokens_input = tokens_input + VALUES(tokens_input),
                tokens_output = tokens_output + VALUES(tokens_output),
                tokens_cache_read = tokens_cache_read + VALUES(tokens_cache_read),
                tokens_cache_write = tokens_cache_write + VALUES(tokens_cache_write)",
            params! {
                "bucket" => &bucket, "key" => &delta.key_id, "provider" => &delta.provider,
                "model" => &delta.model, "grp" => &delta.key_group_at_use, "pv" => &delta.pricing_version,
                "req" => delta.requests, "breq" => delta.billable_requests,
                "ti" => delta.tokens_input, "to_" => delta.tokens_output,
                "cr" => delta.tokens_cache_read, "cw" => delta.tokens_cache_write,
            },
        )
        .map_err(store_err)
    }

    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        let bucket_s = format!("{bucket:010}");
        let mut conn = self.conn()?;
        let rows: Vec<MeteringRowTuple> = conn
            .exec(
                "SELECT key_id, model, provider, tokens_input, tokens_output, tokens_cache_read, \
                 tokens_cache_write, requests, billable_requests, key_group_at_use, pricing_version \
                 FROM usage_metering WHERE bucket = :b",
                params! { "b" => &bucket_s },
            )
            .map_err(store_err)?;
        Ok(rows
            .into_iter()
            .map(
                |(
                    key_id,
                    model,
                    provider,
                    tokens_input,
                    tokens_output,
                    tokens_cache_read,
                    tokens_cache_write,
                    requests,
                    billable_requests,
                    key_group_at_use,
                    pricing_version,
                )| MeteringRow {
                    key_id,
                    model,
                    provider,
                    tokens_input,
                    tokens_output,
                    tokens_cache_read,
                    tokens_cache_write,
                    requests,
                    billable_requests,
                    key_group_at_use,
                    pricing_version,
                },
            )
            .collect())
    }

    fn purge_windows_before(&self, before: u64) -> StoreResult<u64> {
        // Batched AND LOOPED. The batch bound keeps any single DELETE's lock footprint and undo log
        // small, which is why it is here; without the loop it also silently capped the purge at one
        // batch, so a retention backlog larger than the cap was never swept and each tick returned a
        // nonzero count that looked like progress. The contract is "purge every window below the
        // cutoff", and the returned figure is the total actually deleted.
        const BATCH: u64 = 5000;
        let mut conn = self.conn()?;
        let mut total = 0u64;
        loop {
            conn.exec_drop(
                "DELETE FROM usage_windows WHERE window_start < :b LIMIT 5000",
                params! { "b" => before },
            )
            .map_err(store_err)?;
            let n = conn.affected_rows();
            total += n;
            if n < BATCH {
                break;
            }
        }
        Ok(total)
    }

    fn purge_metering_before(&self, bucket: &str) -> StoreResult<u64> {
        // The `bucket` column is CHAR(10) and BOTH the write path (`add_metering`) and the read path
        // (`list_metering`) zero-pad into it. Only this method compared the caller's string as given,
        // so the obvious caller (a u64 bucket rendered the obvious way) matched zero of its own rows
        // and got a successful purge of nothing. Pad the same way when the input is numeric; a
        // non-numeric value is passed through unchanged so an already-padded caller still works.
        let padded = match bucket.trim().parse::<u64>() {
            Ok(n) => format!("{n:010}"),
            Err(_) => bucket.to_string(),
        };
        let mut conn = self.conn()?;
        conn.exec_drop(
            "DELETE FROM usage_metering WHERE bucket = :b",
            params! { "b" => &padded },
        )
        .map_err(store_err)?;
        Ok(conn.affected_rows())
    }

    fn put_credential(&self, secret: &CredentialSecret) -> StoreResult<()> {
        let mut conn = self.conn()?;
        let mut tx = conn
            .start_transaction(TxOpts::default())
            .map_err(store_err)?;
        let rev = Self::bump_revision(&mut tx)?;
        let m = &secret.meta;

        // Slot-occupied-by-a-LIVE-credential guard: an explicit slot pointed at a live credential
        // must fail loudly, not silently clobber a working credential mid-overlap-window.
        let occupied: Option<(Option<u64>,)> = tx
            .exec_first(
                "SELECT revoked_at FROM credentials WHERE key_id = :k AND kind = :kind AND slot = :s FOR UPDATE",
                params! { "k" => &m.key_id, "kind" => &m.kind, "s" => m.slot },
            )
            .map_err(store_err)?;
        if let Some((None,)) = occupied {
            tx.rollback().map_err(store_err)?;
            return Err(store_err(format!(
                "put_credential: slot {} for key {} kind {} holds a LIVE credential — revoke it first",
                m.slot, m.key_id, m.kind
            )));
        }

        // `credentials` has THREE unique keys total: `id` (PRIMARY KEY), `uq_cred_public
        // UNIQUE(kind, public_id)`, and `uq_cred_slot UNIQUE(key_id, kind, slot)` (checked above).
        // A single `INSERT ... ON DUPLICATE KEY UPDATE` fires its UPDATE on ANY of the 3, but its
        // SET list only ever touches `id`/`public_id`/`secret`/etc, never `key_id`/`slot` -- so a
        // collision on `id` OR `public_id` against an UNRELATED row (different key_id/slot) would
        // silently overwrite that row's identity/secret while leaving it pointed at the WRONG
        // key/slot. Branching INSERT-vs-UPDATE off the slot guard above (the only unique key that
        // legitimately gets reused, when reclaiming a revoked slot) instead of a blanket upsert
        // means a collision on `id` or `public_id` now surfaces as a real MySQL 1062 duplicate-key
        // error rather than a silent cross-row overwrite.
        if occupied.is_some() {
            // A revoked row already holds this exact (key_id, kind, slot) -- reclaim it in place.
            tx.exec_drop(
                "UPDATE credentials SET
                    id = :id, public_id = :pub, secret = :secret, secret_form = :form,
                    updated_at = :updated, expires_at = :expires, revoked_at = NULL,
                    revoke_reason = NULL, revision = :rev
                 WHERE key_id = :key AND kind = :kind AND slot = :slot",
                params! {
                    "id" => &m.id, "key" => &m.key_id, "kind" => &m.kind, "slot" => m.slot,
                    "pub" => &m.public_id, "secret" => &secret.secret,
                    "form" => secret_form_str(&m.secret_form),
                    "updated" => m.updated_at, "expires" => m.expires_at, "rev" => rev,
                },
            )
        } else {
            tx.exec_drop(
                "INSERT INTO credentials
                    (id, key_id, kind, slot, public_id, secret, secret_form, created_at, updated_at,
                     expires_at, revoked_at, revoke_reason, revision)
                 VALUES (:id, :key, :kind, :slot, :pub, :secret, :form, :created, :updated, :expires,
                         NULL, NULL, :rev)",
                params! {
                    "id" => &m.id, "key" => &m.key_id, "kind" => &m.kind, "slot" => m.slot,
                    "pub" => &m.public_id, "secret" => &secret.secret,
                    "form" => secret_form_str(&m.secret_form),
                    "created" => m.created_at, "updated" => m.updated_at, "expires" => m.expires_at,
                    "rev" => rev,
                },
            )
        }
        .map_err(store_err)?;

        tx.commit().map_err(store_err)
    }

    fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        let mut tx = conn
            .start_transaction(TxOpts::default())
            .map_err(store_err)?;
        let rev = Self::bump_revision(&mut tx)?;

        let pools_json = scopes_to_pools_json(&key.allowed_scopes)?;
        let labels_json = serde_json::to_string(&key.labels).map_err(store_err)?;
        let group = key.group.clone().unwrap_or_default();

        tx.exec_drop(
            "INSERT INTO api_keys
                (id, name, key_group, allowed_pools, labels, enabled, generation_hash,
                 created_at, updated_at, expires_at, deleted_at, revision)
             VALUES (:id, :name, :key_group, :pools, :labels, :enabled, :gen, :created, :updated,
                     :expires, NULL, :rev)",
            params! {
                "id" => &key.id, "name" => &key.name, "key_group" => &group, "pools" => &pools_json,
                "labels" => &labels_json, "enabled" => key.enabled, "gen" => &key.generation_hash,
                "created" => key.created_at, "updated" => key.created_at, "expires" => key.expires_at,
                "rev" => rev,
            },
        )
        .map_err(store_err)?;

        let m = &secret.meta;
        tx.exec_drop(
            "INSERT INTO credentials
                (id, key_id, kind, slot, public_id, secret, secret_form, created_at, updated_at,
                 expires_at, revoked_at, revoke_reason, revision)
             VALUES (:id, :key, :kind, :slot, :pub, :secret, :form, :created, :updated, :expires,
                     NULL, NULL, :rev)",
            params! {
                "id" => &m.id, "key" => &m.key_id, "kind" => &m.kind, "slot" => m.slot,
                "pub" => &m.public_id, "secret" => &secret.secret,
                "form" => secret_form_str(&m.secret_form),
                "created" => m.created_at, "updated" => m.updated_at, "expires" => m.expires_at,
                "rev" => rev,
            },
        )
        .map_err(store_err)?;

        tx.commit().map_err(store_err)
    }

    fn list_credentials(&self, key_id: &str) -> StoreResult<Vec<CredentialMeta>> {
        let mut conn = self.conn()?;
        let rows: Vec<mysql::Row> = conn
            .exec(
                "SELECT id, key_id, kind, slot, public_id, secret_form, created_at, updated_at, \
                 expires_at, revoked_at, revoke_reason, revision FROM credentials WHERE key_id = :k",
                params! { "k" => key_id },
            )
            .map_err(store_err)?;
        rows.into_iter().map(Self::row_to_cred_meta).collect()
    }

    fn lookup_credential_secret(
        &self,
        kind: &str,
        public_id: &str,
    ) -> StoreResult<Option<CredentialSecret>> {
        let mut conn = self.conn()?;
        let row: Option<(mysql::Row, Option<String>)> = conn
            .exec_first(
                "SELECT id, key_id, kind, slot, public_id, secret_form, created_at, updated_at, \
                 expires_at, revoked_at, revoke_reason, revision, secret FROM credentials \
                 WHERE kind = :kind AND public_id = :pub",
                params! { "kind" => kind, "pub" => public_id },
            )
            .map_err(store_err)
            .and_then(|r: Option<mysql::Row>| {
                r.map(|mut row| {
                    let secret: Option<String> = row.take("secret");
                    Ok((row, secret))
                })
                .transpose()
            })?;

        match row {
            None => Ok(None),
            Some((row, secret)) => {
                let meta = Self::row_to_cred_meta(row)?;
                Ok(Some(CredentialSecret {
                    meta,
                    secret: secret.unwrap_or_default(),
                }))
            }
        }
    }

    fn revoke_credential(&self, id: &str, reason: &str) -> StoreResult<()> {
        let mut conn = self.conn()?;
        let mut tx = conn
            .start_transaction(TxOpts::default())
            .map_err(store_err)?;
        let rev = Self::bump_revision(&mut tx)?;

        // Explicit existence check, matching every other conditional mutation in this file
        // (e.g. put_credential's slot guard): `rows_affected()` alone can't distinguish "id
        // doesn't exist" from "id exists but already revoked" -- the `AND revoked_at IS NULL`
        // clause below makes both cases match zero rows. Without this, revoking an unknown/
        // typo'd id silently reported success.
        let existing: Option<(Option<u64>,)> = tx
            .exec_first(
                "SELECT revoked_at FROM credentials WHERE id = :id FOR UPDATE",
                params! { "id" => id },
            )
            .map_err(store_err)?;
        if existing.is_none() {
            tx.rollback().map_err(store_err)?;
            return Err(store_err(format!(
                "revoke_credential: unknown credential id {id}"
            )));
        }

        let now = crate_now();
        tx.exec_drop(
            "UPDATE credentials SET revoked_at = :now, revoke_reason = :reason, updated_at = :now, \
             revision = :rev WHERE id = :id AND revoked_at IS NULL",
            params! { "now" => now, "reason" => reason, "rev" => rev, "id" => id },
        )
        .map_err(store_err)?;
        tx.commit().map_err(store_err)
    }

    fn list_credentials_since(&self, since: u64) -> StoreResult<Vec<CredentialSecret>> {
        let mut conn = self.conn()?;
        let rows: Vec<mysql::Row> = conn
            .exec(
                "SELECT id, key_id, kind, slot, public_id, secret_form, created_at, updated_at, \
                 expires_at, revoked_at, revoke_reason, revision, secret FROM credentials \
                 WHERE revision > :since",
                params! { "since" => since },
            )
            .map_err(store_err)?;
        rows.into_iter()
            .map(|mut row| {
                let secret: Option<String> = row.take("secret");
                let meta = Self::row_to_cred_meta(row)?;
                Ok(CredentialSecret {
                    meta,
                    secret: secret.unwrap_or_default(),
                })
            })
            .collect()
    }

    fn append_audit(&self, entry: &AuditRecord) -> StoreResult<()> {
        // `ON DUPLICATE KEY UPDATE seq = seq` kept the stored record and said nothing, which is
        // right for ONE of the two ways a seq collides and wrong for the other. Compare them and
        // let the difference decide (see the trait contract):
        //   identical -> the write-through retrying after a lost commit ACK. Common, benign, Ok.
        //   different -> two records claiming one chain position: a forked or tampered log, and the
        //                single most important thing an audit store can report.
        //
        // INSERT FIRST, and deliberately with NO preceding `SELECT ... FOR UPDATE`.
        //
        // The obvious shape — take a row lock, look, then insert — DEADLOCKS here, and measurably:
        // `SELECT ... FOR UPDATE` on a MISSING row takes a next-key/gap lock under REPEATABLE READ
        // (which is what `TxOpts::default()` leaves the server on). Two appends of DIFFERENT, both
        // new seqs land in the same gap; the gap locks are mutually compatible, but each side's
        // following INSERT needs an insert-intention lock that conflicts with the other's gap lock.
        // Four threads appending 200 distinct seqs each produced 39 deadlocks that way against 0
        // for the plain autocommit insert. `append_audit` is also the one control-plane path that
        // does not call `bump_revision`, so it sits OUTSIDE the `store_sequence` serialization that
        // makes every other admin-plane transaction deadlock-free — it has no other protection.
        //
        // A bare INSERT takes only an insert-intention lock and no gap lock, so the ordinary path
        // keeps the baseline's concurrency exactly, and the read only happens on the rare collision.
        //
        // The loop covers the row being deleted between the insert and the read-back: the seq is
        // free again, so inserting is the right move. Bounded, and exhausting the bound is an error
        // rather than a success, so no path here returns Ok without the record being stored.
        const MAX_ATTEMPTS: u32 = 3;
        let mut conn = self.conn()?;
        for _ in 0..MAX_ATTEMPTS {
            conn.exec_drop(
                "INSERT INTO audit_log (seq, ts, action, resource, outcome, principal, prev_hash, hash) \
                 VALUES (:seq, :ts, :action, :resource, :outcome, :principal, :prev, :hash) \
                 ON DUPLICATE KEY UPDATE seq = seq",
                params! {
                    "seq" => entry.seq, "ts" => entry.ts, "action" => &entry.action,
                    "resource" => &entry.resource, "outcome" => &entry.outcome,
                    "principal" => &entry.principal, "prev" => &entry.prev_hash, "hash" => &entry.hash,
                },
            )
            .map_err(store_err)?;
            // 1 = inserted. 0 = the seq was already occupied and `seq = seq` changed nothing.
            if conn.affected_rows() == 1 {
                return Ok(());
            }
            let existing: Option<AuditRowTuple> = conn
                .exec_first(
                    "SELECT seq, ts, action, resource, outcome, principal, prev_hash, hash \
                     FROM audit_log WHERE seq = :seq",
                    params! { "seq" => entry.seq },
                )
                .map_err(store_err)?;
            let Some((seq, ts, action, resource, outcome, principal, prev_hash, hash)) = existing
            else {
                continue; // gone between the insert and the read: the seq is free, try again
            };
            let stored = AuditRecord {
                seq,
                ts,
                action,
                resource,
                outcome,
                principal,
                prev_hash,
                hash,
            };
            if stored == *entry {
                return Ok(());
            }
            return Err(store_err(format!(
                "append_audit: seq {} already holds a DIFFERENT record; the audit chain has forked \
                 (stored action '{}', incoming '{}')",
                entry.seq, stored.action, entry.action
            )));
        }
        Err(store_err(format!(
            "append_audit: seq {} kept being freed between the insert and the read-back after \
             {MAX_ATTEMPTS} attempts; something is deleting audit rows concurrently and the record \
             was NOT stored",
            entry.seq
        )))
    }

    fn list_audit(&self) -> StoreResult<Vec<AuditRecord>> {
        let mut conn = self.conn()?;
        let rows: Vec<AuditRowTuple> = conn
            .query("SELECT seq, ts, action, resource, outcome, principal, prev_hash, hash FROM audit_log ORDER BY seq")
            .map_err(store_err)?;
        Ok(rows
            .into_iter()
            .map(
                |(seq, ts, action, resource, outcome, principal, prev_hash, hash)| AuditRecord {
                    seq,
                    ts,
                    action,
                    resource,
                    outcome,
                    principal,
                    prev_hash,
                    hash,
                },
            )
            .collect())
    }

    fn list_audit_tail(&self, limit: u64) -> StoreResult<Vec<AuditRecord>> {
        let mut conn = self.conn()?;
        let rows: Vec<AuditRowTuple> = conn
            .exec(
                "SELECT seq, ts, action, resource, outcome, principal, prev_hash, hash FROM audit_log \
                 ORDER BY seq DESC LIMIT :limit",
                params! { "limit" => limit },
            )
            .map_err(store_err)?;
        let mut out: Vec<AuditRecord> = rows
            .into_iter()
            .map(
                |(seq, ts, action, resource, outcome, principal, prev_hash, hash)| AuditRecord {
                    seq,
                    ts,
                    action,
                    resource,
                    outcome,
                    principal,
                    prev_hash,
                    hash,
                },
            )
            .collect();
        out.reverse(); // DESC LIMIT then reverse = the last N, oldest-first
        Ok(out)
    }

    fn add_denylist(&self, sub: &str, reason: &str) -> StoreResult<()> {
        let mut conn = self.conn()?;
        let mut tx = conn
            .start_transaction(TxOpts::default())
            .map_err(store_err)?;
        let rev = Self::bump_revision(&mut tx)?;
        let now = crate_now();
        let max_ttl: u64 = 90 * 24 * 3600; // matches the 90d default token expiry ceiling documented in admin-api.md
        tx.exec_drop(
            "INSERT INTO denylist (sub, reason, revoked_at, expires_at, revision) \
             VALUES (:sub, :reason, :now, :expires, :rev) \
             ON DUPLICATE KEY UPDATE
                reason = VALUES(reason), revoked_at = VALUES(revoked_at),
                expires_at = GREATEST(expires_at, VALUES(expires_at)), revision = VALUES(revision)",
            params! {
                "sub" => sub, "reason" => reason, "now" => now, "expires" => now + max_ttl, "rev" => rev,
            },
        )
        .map_err(store_err)?;
        tx.commit().map_err(store_err)
    }

    fn put_task(&self, task: &TaskRow) -> StoreResult<()> {
        // UPSERT BY task_id: the engine writes through on EVERY state transition, so a second write
        // for one task must REPLACE the row, never append a second one for the same id.
        //
        // No `affected_rows` check follows, deliberately. MySQL reports 1 for an insert, 2 for a row
        // it actually changed and 0 for an update that changed nothing, so the number cannot tell
        // "stored" from "failed" here — correctness rests on the statement succeeding, not on a
        // count whose three values all mean the write landed.
        let mut conn = self.conn()?;
        conn.exec_drop(
            "INSERT INTO tasks (task_id, context_id, principal, direction, state, agent_id, \
             artifact_cursor, push_callback, created_at, updated_at) \
             VALUES (:task_id, :context_id, :principal, :direction, :state, :agent_id, \
             :artifact_cursor, :push_callback, :created_at, :updated_at) \
             ON DUPLICATE KEY UPDATE \
                context_id = VALUES(context_id), principal = VALUES(principal), \
                direction = VALUES(direction), state = VALUES(state), \
                agent_id = VALUES(agent_id), artifact_cursor = VALUES(artifact_cursor), \
                push_callback = VALUES(push_callback), created_at = VALUES(created_at), \
                updated_at = VALUES(updated_at)",
            params! {
                "task_id" => &task.task_id, "context_id" => &task.context_id,
                "principal" => &task.principal, "direction" => &task.direction,
                "state" => &task.state, "agent_id" => &task.agent_id,
                "artifact_cursor" => task.artifact_cursor,
                "push_callback" => &task.push_callback,
                "created_at" => task.created_at, "updated_at" => task.updated_at,
            },
        )
        .map_err(store_err)
    }

    fn get_task(&self, task_id: &str) -> StoreResult<Option<TaskRow>> {
        // No principal filter, deliberately: the contract puts the caller-scoping check ENGINE-side,
        // because an authorization check living in the backend is one an unauthorized reader
        // bypasses by configuring a different backend.
        let mut conn = self.conn()?;
        let row: Option<TaskRowTuple> = conn
            .exec_first(
                "SELECT task_id, context_id, principal, direction, state, agent_id, \
                 artifact_cursor, push_callback, created_at, updated_at FROM tasks \
                 WHERE task_id = :task_id",
                params! { "task_id" => task_id },
            )
            .map_err(store_err)?;
        Ok(row.map(row_to_task))
    }

    fn list_tasks(&self) -> StoreResult<Vec<TaskRow>> {
        // UNFILTERED, terminal rows included. The boot rehydrate wants the active rows, the
        // retention sweep wants the terminal ones and the scoped listing wants one principal's; a
        // store that pre-filtered for any one of those would break the other two.
        let mut conn = self.conn()?;
        let rows: Vec<TaskRowTuple> = conn
            .query(
                "SELECT task_id, context_id, principal, direction, state, agent_id, \
                 artifact_cursor, push_callback, created_at, updated_at FROM tasks ORDER BY task_id",
            )
            .map_err(store_err)?;
        Ok(rows.into_iter().map(row_to_task).collect())
    }

    fn purge_tasks_before(&self, before: u64) -> StoreResult<u64> {
        // TERMINAL ONLY, and STRICTLY older than the cutoff. An interrupted task waiting on a human
        // is exactly the row that legitimately sits still for a long time; compacting it is losing
        // the work, not reclaiming space. The IN list is the CLOSED terminal set, so a state token
        // minted by a newer engine than this build is never dropped.
        //
        // The events go with the task, in the SAME TRANSACTION as the parent delete. That cascade is
        // load-bearing rather than tidiness: `purge_tasks_before` is the ONLY retention method the
        // contract gives this data, so a purge that left the events behind would leave `task_events`
        // with no bound anywhere in the trait. It is done here in application code because neither
        // way of pushing it into the schema is available (see the `task_events` DDL): a foreign key
        // would impose a write ORDER the contract never states, and a DELETE trigger needs SUPER on
        // a binlog-enabled server, which the app-level user does not hold. One transaction is what
        // makes the pair atomic anyway — a crash between the two statements cannot leave a task
        // whose chain has been half-swept.
        let placeholders = (0..TERMINAL_TASK_STATES.len())
            .map(|i| format!(":s{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let mut args: Vec<(String, mysql::Value)> = vec![("before".to_string(), before.into())];
        for (i, state) in TERMINAL_TASK_STATES.iter().enumerate() {
            args.push((format!("s{i}"), (*state).into()));
        }

        let mut conn = self.conn()?;
        let mut tx = conn
            .start_transaction(TxOpts::default())
            .map_err(store_err)?;
        tx.exec_drop(
            format!(
                "DELETE te FROM task_events te JOIN tasks t ON te.task_id = t.task_id \
                 WHERE t.updated_at < :before AND t.state IN ({placeholders})"
            ),
            args.clone(),
        )
        .map_err(store_err)?;
        tx.exec_drop(
            format!("DELETE FROM tasks WHERE updated_at < :before AND state IN ({placeholders})"),
            args,
        )
        .map_err(store_err)?;
        // Read BEFORE the commit: `affected_rows` reports the LAST statement executed on this
        // connection, and the COMMIT itself is one. This is the count the DELETE actually performed,
        // never an estimate.
        let removed = tx.affected_rows();
        tx.commit().map_err(store_err)?;
        Ok(removed)
    }

    fn append_task_event(&self, event: &TaskEventRow) -> StoreResult<()> {
        // UPSERT ON (task_id, seq), and this is where the task-event contract genuinely DIFFERS from
        // `append_mcp_call`'s: that one treats an occupied slot holding a DIFFERENT record as a fork
        // and refuses it, while this one is specified to upsert so the engine's write-through is
        // idempotent on replay — "rejecting or duplicating a replayed `seq` breaks the chain the
        // engine will verify on read". Copying the call log's fork check here would be wrong in a
        // way that looks right, so it is stated rather than left to be inferred from the SQL.
        //
        // As in `put_task`, no `affected_rows` check: ON DUPLICATE KEY UPDATE returns 2 for a row it
        // changed and 0 for a replay identical to what is already stored, and 0 is a SUCCESS here.
        let mut conn = self.conn()?;
        conn.exec_drop(
            "INSERT INTO task_events (task_id, seq, ts, kind, context_id, principal, agent_id, \
             state, request_id, prev_hash, hash) \
             VALUES (:task_id, :seq, :ts, :kind, :context_id, :principal, :agent_id, :state, \
             :request_id, :prev_hash, :hash) \
             ON DUPLICATE KEY UPDATE \
                ts = VALUES(ts), kind = VALUES(kind), context_id = VALUES(context_id), \
                principal = VALUES(principal), agent_id = VALUES(agent_id), \
                state = VALUES(state), request_id = VALUES(request_id), \
                prev_hash = VALUES(prev_hash), hash = VALUES(hash)",
            params! {
                "task_id" => &event.task_id, "seq" => event.seq, "ts" => event.ts,
                "kind" => &event.kind, "context_id" => &event.context_id,
                "principal" => &event.principal, "agent_id" => &event.agent_id,
                "state" => &event.state, "request_id" => &event.request_id,
                "prev_hash" => &event.prev_hash, "hash" => &event.hash,
            },
        )
        .map_err(store_err)
    }

    fn list_task_events(&self, task_id: &str) -> StoreResult<Vec<TaskEventRow>> {
        // Oldest-first by seq — the order the engine's chain verifier reads — and the scope is the
        // one task, because the chain is per-task.
        let mut conn = self.conn()?;
        let rows: Vec<TaskEventRowTuple> = conn
            .exec(
                "SELECT task_id, seq, ts, kind, context_id, principal, agent_id, state, \
                 request_id, prev_hash, hash FROM task_events WHERE task_id = :task_id ORDER BY seq",
                params! { "task_id" => task_id },
            )
            .map_err(store_err)?;
        Ok(rows.into_iter().map(row_to_task_event).collect())
    }

    fn append_mcp_call(&self, record: &McpCallRecord) -> StoreResult<()> {
        let body = mcp_call_body(record);
        let mut conn = self.conn()?;
        // INSERT IGNORE makes the insert atomic against a concurrent writer. Reading the incumbent
        // AFTERWARDS is safe without a transaction precisely because this table is never rewritten:
        // a row that exists cannot change under us, so what we read is what collided.
        conn.exec_drop(
            "INSERT IGNORE INTO mcp_calls (principal, seq, ts, prev_hash, hash, body) \
             VALUES (:principal, :seq, :ts, :prev, :hash, :body)",
            params! {
                "principal" => &record.principal, "seq" => record.seq, "ts" => record.ts,
                "prev" => &record.prev_hash, "hash" => &record.hash, "body" => &body,
            },
        )
        .map_err(store_err)?;
        if conn.affected_rows() == 1 {
            return Ok(());
        }
        let existing: Option<(u64, String, String, String)> = conn
            .exec_first(
                "SELECT ts, prev_hash, hash, body FROM mcp_calls WHERE principal = :principal AND seq = :seq",
                params! { "principal" => &record.principal, "seq" => record.seq },
            )
            .map_err(store_err)?;
        if let Some((e_ts, e_prev, e_hash, e_body)) = existing {
            // BYTE-IDENTICAL is the at-least-once retry and is success. DIFFERENT is a forked or
            // tampered log and is an error: overwriting would destroy exactly the case worth
            // reporting, and this store never restates a digest it was handed.
            if e_ts == record.ts
                && e_prev == record.prev_hash
                && e_hash == record.hash
                && e_body == body
            {
                return Ok(());
            }
        }
        // Names the sequence and nothing else — it must not echo stored (or caller) content back.
        Err(StoreError(format!(
            "mcp call log fork: a different record is already persisted at sequence {} for this principal",
            record.seq
        )))
    }

    fn list_mcp_calls(&self, principal: &str) -> StoreResult<Vec<McpCallRecord>> {
        let mut conn = self.conn()?;
        let rows: Vec<McpCallRowTuple> = conn
            .exec(
                "SELECT principal, seq, ts, prev_hash, hash, body FROM mcp_calls \
                 WHERE principal = :principal ORDER BY seq",
                params! { "principal" => principal },
            )
            .map_err(store_err)?;
        Ok(rows.into_iter().map(row_to_mcp_call).collect())
    }

    fn list_mcp_call_principals(&self) -> StoreResult<Vec<String>> {
        let mut conn = self.conn()?;
        conn.query("SELECT DISTINCT principal FROM mcp_calls ORDER BY principal")
            .map_err(store_err)
    }

    fn purge_mcp_calls_before(&self, before: u64) -> StoreResult<u64> {
        // STRICTLY less-than, matching the contract's wording: a row exactly at the cutoff is kept.
        // `affected_rows` reports what the DELETE actually removed, so the count is one performed.
        let mut conn = self.conn()?;
        conn.exec_drop(
            "DELETE FROM mcp_calls WHERE ts < :before",
            params! { "before" => before },
        )
        .map_err(store_err)?;
        Ok(conn.affected_rows())
    }

    fn list_denylist(&self) -> StoreResult<Vec<String>> {
        let mut conn = self.conn()?;
        conn.query("SELECT sub FROM denylist").map_err(store_err)
    }
}

fn crate_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The non-indexed payload of a call record, as stored in `mcp_calls.body`. `principal`, `seq`,
/// `ts`, `prev_hash` and `hash` are deliberately NOT duplicated here: they are real columns, and a
/// value stored in two places is a value that can disagree with itself. `serde_json`'s object keys
/// are ordered, so this encoding is deterministic — which is what makes the byte comparison in
/// `append_mcp_call`'s replay check meaningful.
fn mcp_call_body(record: &McpCallRecord) -> String {
    serde_json::json!({
        "server": record.server,
        "tool": record.tool,
        "outcome": record.outcome,
        "reason": record.reason,
        "tool_digest": record.tool_digest,
        "pin_generation": record.pin_generation,
        "request_id": record.request_id,
    })
    .to_string()
}

/// Rebuild a record from its columns plus its opaque body. The CHAIN comes from the columns, which
/// is the point of their being columns: what the engine verifies is what the database holds in a
/// field it can constrain, not a value recovered by decoding a payload.
/// No clamping and no fallback anywhere in here, unlike `row_to_mcp_call`'s tolerant body decode:
/// every field is a real, NOT NULL column of a known type, so a row that fails to decode is a schema
/// that is not what this build thinks it is — and the driver reports that rather than this function
/// papering over it with a default. The u64s round-trip exactly because the columns are
/// `BIGINT UNSIGNED`.
fn row_to_task(row: TaskRowTuple) -> TaskRow {
    let (
        task_id,
        context_id,
        principal,
        direction,
        state,
        agent_id,
        artifact_cursor,
        push_callback,
        created_at,
        updated_at,
    ) = row;
    TaskRow {
        task_id,
        context_id,
        principal,
        direction,
        state,
        agent_id,
        artifact_cursor,
        push_callback,
        created_at,
        updated_at,
    }
}

fn row_to_task_event(row: TaskEventRowTuple) -> TaskEventRow {
    let (
        task_id,
        seq,
        ts,
        kind,
        context_id,
        principal,
        agent_id,
        state,
        request_id,
        prev_hash,
        hash,
    ) = row;
    TaskEventRow {
        task_id,
        seq,
        ts,
        kind,
        context_id,
        principal,
        agent_id,
        state,
        request_id,
        prev_hash,
        hash,
    }
}

fn row_to_mcp_call(row: McpCallRowTuple) -> McpCallRecord {
    let (principal, seq, ts, prev_hash, hash, body) = row;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    McpCallRecord {
        principal,
        seq,
        ts,
        prev_hash,
        hash,
        server: s("server"),
        tool: s("tool"),
        outcome: s("outcome"),
        reason: s("reason"),
        tool_digest: s("tool_digest"),
        pin_generation: v
            .get("pin_generation")
            .and_then(|x| x.as_u64())
            .unwrap_or(0),
        request_id: s("request_id"),
    }
}

#[cfg(test)]
mod tests;
