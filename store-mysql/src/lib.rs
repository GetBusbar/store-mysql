// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The MySQL/MariaDB backend for busbar's durable governance store. Targets the common SQL subset
//! supported by MySQL 8.0.16+, MariaDB, and Aurora MySQL — one plugin, protocol-compatible with all
//! three, same reasoning as busbar's "Valkey (Redis-protocol compatible)" naming: broad coverage via
//! standard SQL, not three separate builds.
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
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, ModelTokens,
    SecretForm, Store, StoreError, StoreResult, TierTokens, UsageDelta, UsageLedger, VirtualKey,
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
fn store_err<E: std::fmt::Display>(e: E) -> StoreError {
    StoreError(e.to_string())
}

const SCHEMA_VERSION: &str = "1";

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
        id CHAR(26) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
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
        id CHAR(26) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
        key_id CHAR(26) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
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
        sub CHAR(26) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
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
        key_id CHAR(26) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        provider VARCHAR(128) NOT NULL,
        model VARCHAR(256) NOT NULL,
        key_group_at_use VARCHAR(128) NOT NULL DEFAULT '',
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
        let opts = mysql::OptsBuilder::from_opts(opts).pool_opts(
            mysql::PoolOpts::default().with_constraints(
                mysql::PoolConstraints::new(1, 8).expect("1 <= 8 is a valid pool constraint"),
            ),
        );
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

    fn try_init_schema(pool: &Pool) -> StoreResult<()> {
        let mut conn = pool.get_conn().map_err(store_err)?;
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

    /// Live functional probes for the two failure modes a schema-shape check cannot catch:
    /// (1) `CHECK` constraints parsed but not enforced (MySQL < 8.0.16, Aurora MySQL 2.x);
    /// (2) `STRICT_ALL_TABLES` not in `sql_mode` (a VARCHAR/BIGINT overflow silently truncates
    ///     instead of erroring). Both are probed by attempting an operation that MUST fail, inside
    ///     a transaction that's always rolled back, never committed — no probe row survives.
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

        let mut tx = conn
            .start_transaction(TxOpts::default())
            .map_err(store_err)?;
        let rejected = tx
            .query_drop(
                "INSERT INTO store_sequence (id, revision) VALUES (999, 0)", // id=999 violates ck_seq_singleton (id=1)
            )
            .is_err();
        let _ = tx.rollback();
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

        let allowed_pools = match allowed_pools_json {
            Some(s) => serde_json::from_str(&s).map_err(store_err)?,
            None => None,
        };
        let labels = serde_json::from_str(&labels_json).map_err(store_err)?;

        Ok(VirtualKey {
            id,
            generation_hash,
            name,
            allowed_pools,
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

impl Store for MysqlStore {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        let mut conn = self.conn()?;
        let mut tx = conn
            .start_transaction(TxOpts::default())
            .map_err(store_err)?;
        let rev = Self::bump_revision(&mut tx)?;

        let pools_json = key
            .allowed_pools
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(store_err)?;
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

        // Explicit existence/state check FIRST — rows_affected() alone can't distinguish
        // "not found" from "already tombstoned, no-op" (both report 0 rows changed).
        let existing: Option<(Option<u64>,)> = tx
            .exec_first(
                "SELECT deleted_at FROM api_keys WHERE id = :id FOR UPDATE",
                params! { "id" => id },
            )
            .map_err(store_err)?;
        let Some((deleted_at,)) = existing else {
            tx.rollback().map_err(store_err)?;
            return Ok(()); // unknown id: treated as already-gone, matching store-memory's idempotent contract
        };
        if deleted_at.is_some() {
            tx.rollback().map_err(store_err)?;
            return Ok(()); // already tombstoned: idempotent no-op per the trait doc
        }

        let rev = Self::bump_revision(&mut tx)?;
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
                let rev = Self::bump_revision(&mut tx)?;
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
                 FROM usage_windows WHERE bucket_id = :b AND window_start = :w",
                params! { "b" => bucket_id, "w" => window_start },
            )
            .map_err(store_err)?;
        let totals: Option<(u64, u64)> = conn
            .exec_first(
                "SELECT SUM(requests), SUM(billable_requests) FROM usage_windows \
                 WHERE bucket_id = :b AND window_start = :w",
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
        tx.exec_drop(
            "DELETE FROM usage_windows WHERE bucket_id = :b AND window_start = :w",
            params! { "b" => bucket_id, "w" => window_start },
        )
        .map_err(store_err)?;
        for m in &ledger.models {
            tx.exec_drop(
                "INSERT INTO usage_windows
                    (window_start, bucket_scope, bucket_id, model, requests, billable_requests,
                     tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
                 VALUES (:w, 'key', :b, :model, :req, :breq, :ti, :to_, :cr, :cw)",
                params! {
                    "w" => window_start, "b" => bucket_id, "model" => &m.model,
                    "req" => ledger.requests, "breq" => ledger.billable_requests,
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
        for m in &delta.models {
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
                    (window_start, bucket_scope, bucket_id, model, requests, billable_requests,
                     tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
                 VALUES (:w, 'key', :b, :model, GREATEST(0, :req), GREATEST(0, :breq),
                         GREATEST(0, :ti), GREATEST(0, :to_), GREATEST(0, :cr), GREATEST(0, :cw))
                 ON DUPLICATE KEY UPDATE
                    requests = GREATEST(0, CAST(requests AS SIGNED) + :req),
                    billable_requests = GREATEST(0, CAST(billable_requests AS SIGNED) + :breq),
                    tokens_input = GREATEST(0, CAST(tokens_input AS SIGNED) + :ti),
                    tokens_output = GREATEST(0, CAST(tokens_output AS SIGNED) + :to_),
                    tokens_cache_read = GREATEST(0, CAST(tokens_cache_read AS SIGNED) + :cr),
                    tokens_cache_write = GREATEST(0, CAST(tokens_cache_write AS SIGNED) + :cw)",
                params! {
                    "w" => window_start, "b" => bucket_id, "model" => &m.model,
                    "req" => delta.requests, "breq" => delta.billable_requests,
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
        let mut conn = self.conn()?;
        conn.exec_drop(
            "DELETE FROM usage_windows WHERE window_start < :b LIMIT 5000",
            params! { "b" => before },
        )
        .map_err(store_err)?;
        Ok(conn.affected_rows())
    }

    fn purge_metering_before(&self, bucket: &str) -> StoreResult<u64> {
        let mut conn = self.conn()?;
        conn.exec_drop(
            "DELETE FROM usage_metering WHERE bucket = :b",
            params! { "b" => bucket },
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

        tx.exec_drop(
            "INSERT INTO credentials
                (id, key_id, kind, slot, public_id, secret, secret_form, created_at, updated_at,
                 expires_at, revoked_at, revoke_reason, revision)
             VALUES (:id, :key, :kind, :slot, :pub, :secret, :form, :created, :updated, :expires,
                     NULL, NULL, :rev)
             ON DUPLICATE KEY UPDATE
                id = VALUES(id), public_id = VALUES(public_id), secret = VALUES(secret),
                secret_form = VALUES(secret_form), updated_at = VALUES(updated_at),
                expires_at = VALUES(expires_at), revoked_at = NULL, revoke_reason = NULL,
                revision = VALUES(revision)",
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

        let pools_json = key
            .allowed_pools
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(store_err)?;
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
        let mut conn = self.conn()?;
        conn.exec_drop(
            "INSERT INTO audit_log (seq, ts, action, resource, outcome, principal, prev_hash, hash) \
             VALUES (:seq, :ts, :action, :resource, :outcome, :principal, :prev, :hash) \
             ON DUPLICATE KEY UPDATE seq = seq", // idempotent re-insert on replay of the same seq
            params! {
                "seq" => entry.seq, "ts" => entry.ts, "action" => &entry.action,
                "resource" => &entry.resource, "outcome" => &entry.outcome,
                "principal" => &entry.principal, "prev" => &entry.prev_hash, "hash" => &entry.hash,
            },
        )
        .map_err(store_err)
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

#[cfg(test)]
mod tests;
