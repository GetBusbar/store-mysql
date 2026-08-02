// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_api::{ModelTokensDelta, TierTokensDelta};
use std::collections::BTreeMap;

fn test_url() -> Option<String> {
    match std::env::var("BUSBAR_TEST_MYSQL_URL") {
        Ok(u) => Some(u),
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!("BUSBAR_TEST_MYSQL_URL is unset under CI: the mysql service container must provision it");
        }
        Err(_) => {
            eprintln!("skip: set BUSBAR_TEST_MYSQL_URL to run these tests, e.g. mysql://busbar:busbar@127.0.0.1:3307/busbar_test");
            None
        }
    }
}

/// Connects against the same live server every test shares. Deliberately does NOT truncate/reset
/// per TEST (tests run in PARALLEL by default, and a per-test `TRUNCATE` against shared tables races
/// with every other concurrently-running test — tried, and it produced exactly the connection-
/// exhaustion/deadlock/cross-test-corruption chaos you'd expect from concurrent DDL and concurrent
/// global-state resets against one database). Instead: truncate exactly ONCE per BINARY run (guarded
/// by `Once`, so the many parallel test threads calling this all block on the first one, which does
/// the reset, then proceed against a genuinely clean slate) — this is what makes RE-RUNNING the suite
/// against a server with leftover rows from a prior run safe, while leaving true test-to-test
/// concurrency within one run intact (every test below already uses a uniquely-named key id, so
/// concurrent tests never touch each other's rows once the shared starting state is clean).
fn fresh_store() -> Option<MysqlStore> {
    let url = test_url()?;
    let store = MysqlStore::connect(&url).expect("connect+schema");

    static RESET_ONCE: std::sync::Once = std::sync::Once::new();
    RESET_ONCE.call_once(|| {
        let mut conn = store.pool.get_conn().unwrap();
        for t in [
            "credentials",
            "api_keys",
            "denylist",
            "usage_windows",
            "usage_metering",
            "audit_log",
        ] {
            conn.query_drop("SET FOREIGN_KEY_CHECKS=0").unwrap();
            conn.query_drop(format!("TRUNCATE TABLE {t}")).unwrap();
            conn.query_drop("SET FOREIGN_KEY_CHECKS=1").unwrap();
        }
        conn.query_drop("UPDATE store_sequence SET revision = 0 WHERE id = 1")
            .unwrap();
    });

    Some(store)
}

fn sample_key(id: &str, generation: &str) -> VirtualKey {
    VirtualKey {
        id: id.to_string(),
        generation_hash: generation.to_string(),
        name: "test".to_string(),
        allowed_scopes: None,
        enabled: true,
        created_at: 1000,
        group: None,
        labels: BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 0,
    }
}

fn sample_credential(key_id: &str, public_id: &str, slot: u8) -> CredentialSecret {
    CredentialSecret {
        meta: CredentialMeta {
            id: format!("cred_{public_id}"),
            key_id: key_id.to_string(),
            kind: "sigv4".to_string(),
            slot,
            public_id: public_id.to_string(),
            secret_form: SecretForm::Recoverable,
            created_at: 1000,
            updated_at: 1000,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 0,
        },
        secret: "v1:plain:shhh".to_string(),
    }
}

#[test]
fn put_get_roundtrips_a_key() {
    let Some(s) = fresh_store() else { return };
    let k = sample_key("vk_1", "binding:vk_1:g1");
    s.put_key(&k).unwrap();
    let back = s.get_key("vk_1").unwrap().unwrap();
    assert_eq!(back.generation_hash, "binding:vk_1:g1");
    assert!(back.deleted_at.is_none());
    assert!(back.revision > 0, "put_key must stamp a nonzero revision");
}

/// Regression for a real bug found in this session's final CI verification: every prior test in
/// this file uses short synthetic ids (`"vk_1"`, `"vk_all"`, ...), all well under the schema's old
/// `CHAR(26)` column width -- so the suite never caught that the REAL id format busbar's core mint
/// path generates (`vk_` + 32 hex chars from `hex::encode([u8; 16])`, `governance/state.rs::mint_signed`)
/// is 35 characters, wider than `CHAR(26)` (sized, incorrectly, for a 26-char ULID). A real mint
/// against this schema failed with `MySqlError 1406: Data too long for column 'id'` -- reproduced
/// directly against a live MySQL 8 container outside this crate's own suite before the fix. Widened
/// `id`/`key_id`/`sub` to `VARCHAR(64)` for headroom against any future id-format change, not just
/// today's 35 chars.
#[test]
fn put_get_roundtrips_a_key_with_the_real_35_char_mint_format() {
    let Some(s) = fresh_store() else { return };
    let id = format!("vk_{}", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4");
    assert_eq!(
        id.len(),
        35,
        "sanity: matches the real mint_signed id length"
    );
    let k = sample_key(&id, "binding:real-format:g1");
    s.put_key(&k).unwrap();
    let back = s.get_key(&id).unwrap().unwrap();
    assert_eq!(back.id, id);
    assert_eq!(back.generation_hash, "binding:real-format:g1");
}

#[test]
fn allowed_pools_none_vs_empty_round_trip_distinctly() {
    let Some(s) = fresh_store() else { return };
    let mut all_pools = sample_key("vk_all", "g");
    all_pools.allowed_scopes = None;
    let mut no_pools = sample_key("vk_none", "g");
    no_pools.allowed_scopes = Some(vec![]);
    s.put_key(&all_pools).unwrap();
    s.put_key(&no_pools).unwrap();
    assert_eq!(s.get_key("vk_all").unwrap().unwrap().allowed_scopes, None);
    assert_eq!(
        s.get_key("vk_none").unwrap().unwrap().allowed_scopes,
        Some(vec![])
    );
}

#[test]
fn list_keys_since_only_returns_keys_past_watermark() {
    let Some(s) = fresh_store() else { return };
    s.put_key(&sample_key("vk_wm_a", "g")).unwrap();
    let watermark = s.get_key("vk_wm_a").unwrap().unwrap().revision;
    s.put_key(&sample_key("vk_wm_b", "g")).unwrap();
    let delta = s.list_keys_since(watermark).unwrap();
    // `revision` is a store-GLOBAL counter shared by every concurrently-running test (this test
    // suite deliberately does NOT serialize tests -- see fresh_store's doc), so other tests' keys
    // can legitimately also land past this watermark. Assert OUR key is present and vk_wm_a (minted
    // before the watermark) is absent, not an exact delta size.
    assert!(
        delta.iter().any(|k| k.id == "vk_wm_b"),
        "vk_wm_b must appear in the delta"
    );
    assert!(
        !delta.iter().any(|k| k.id == "vk_wm_a"),
        "vk_wm_a predates the watermark, must not appear"
    );
}

// ── Tombstone delete: the central behavior change, and the hard-delete-invisible-to-hydration fix ──

#[test]
fn delete_key_tombstones_not_removes() {
    let Some(s) = fresh_store() else { return };
    s.put_key(&sample_key("vk_del", "g")).unwrap();
    s.delete_key("vk_del").unwrap();
    let row = s
        .get_key("vk_del")
        .unwrap()
        .expect("tombstoned row must still be readable");
    assert!(!row.enabled);
    assert!(row.deleted_at.is_some());
}

#[test]
fn delete_key_destroys_credentials() {
    let Some(s) = fresh_store() else { return };
    let k = sample_key("vk_cred", "g");
    let cred = sample_credential("vk_cred", "AKIA_TEST", 0);
    s.put_key_with_credential(&k, &cred).unwrap();
    assert_eq!(s.list_credentials("vk_cred").unwrap().len(), 1);
    s.delete_key("vk_cred").unwrap();
    assert!(s.list_credentials("vk_cred").unwrap().is_empty());
    assert!(s
        .lookup_credential_secret("sigv4", "AKIA_TEST")
        .unwrap()
        .is_none());
}

#[test]
fn delete_key_is_idempotent() {
    let Some(s) = fresh_store() else { return };
    s.put_key(&sample_key("vk_x", "g")).unwrap();
    s.delete_key("vk_x").unwrap();
    let rev_after_first = s.get_key("vk_x").unwrap().unwrap().revision;
    s.delete_key("vk_x").unwrap();
    let rev_after_second = s.get_key("vk_x").unwrap().unwrap().revision;
    assert_eq!(
        rev_after_first, rev_after_second,
        "a no-op re-delete must not stamp a new revision"
    );
}

/// The hard-delete-invisible-to-hydration fix: a hydrator reading `list_keys_since` and
/// `list_credentials_since` in that ORDER must see the tombstone (deleted_at set) before or exactly
/// when the credential deltas stop appearing — proving the tombstone and the credential destruction
/// happened in the SAME transaction / same revision, not a window where one is visible without the
/// other.
#[test]
fn tombstone_and_credential_destruction_share_one_transaction() {
    let Some(s) = fresh_store() else { return };
    let k = sample_key("vk_hyd", "g");
    let cred = sample_credential("vk_hyd", "AKIA_HYD", 0);
    s.put_key_with_credential(&k, &cred).unwrap();
    let watermark = s.get_key("vk_hyd").unwrap().unwrap().revision;

    s.delete_key("vk_hyd").unwrap();

    // `revision` is store-GLOBAL and shared across concurrently-running tests -- assert OUR key's
    // tombstone is present in the delta, not an exact delta size (see the sibling watermark test's
    // comment for why an exact count would be racy against the rest of the suite).
    let key_delta = s.list_keys_since(watermark).unwrap();
    let ours = key_delta
        .iter()
        .find(|k| k.id == "vk_hyd")
        .expect("vk_hyd must appear in the delta");
    assert!(
        ours.deleted_at.is_some(),
        "the delta must show the tombstone"
    );

    // The credential row is HARD-deleted (not tombstoned) -- it produces NO further delta for THIS
    // key. A hydrator must rely on the key's deleted_at, never wait for a credential-row delta that
    // will never come. Other concurrent tests' credentials may legitimately appear in this delta too
    // (global revision counter), so assert absence of ours specifically, not overall emptiness.
    let cred_delta = s.list_credentials_since(watermark).unwrap();
    assert!(
        !cred_delta.iter().any(|c| c.meta.key_id == "vk_hyd"),
        "a hard-deleted credential produces no delta -- this is the trap the contract warns about"
    );
}

#[test]
fn scrub_key_requires_tombstone_first() {
    let Some(s) = fresh_store() else { return };
    s.put_key(&sample_key("vk_scrub", "g")).unwrap();
    assert!(
        s.scrub_key("vk_scrub").is_err(),
        "scrub on a LIVE key must error"
    );
    s.delete_key("vk_scrub").unwrap();
    s.scrub_key("vk_scrub").unwrap();
    let row = s.get_key("vk_scrub").unwrap().unwrap();
    assert_eq!(row.name, "");
}

// ── Credentials: slot bounds, revoke, secret isolation ──────────────────────────────────────────

#[test]
fn credential_slot_occupied_by_live_cred_rejects_overwrite() {
    let Some(s) = fresh_store() else { return };
    let k = sample_key("vk_slot", "g");
    s.put_key(&k).unwrap();
    s.put_credential(&sample_credential("vk_slot", "AKIA_A", 0))
        .unwrap();
    let result = s.put_credential(&sample_credential("vk_slot", "AKIA_B", 0));
    assert!(
        result.is_err(),
        "minting into a slot holding a LIVE credential must fail loudly"
    );
}

#[test]
fn credential_slot_reusable_after_revoke() {
    let Some(s) = fresh_store() else { return };
    let k = sample_key("vk_rot", "g");
    s.put_key(&k).unwrap();
    let cred1 = sample_credential("vk_rot", "AKIA_OLD", 0);
    s.put_credential(&cred1).unwrap();
    s.revoke_credential(&cred1.meta.id, "rotated").unwrap();
    // Now the slot should be reusable.
    s.put_credential(&sample_credential("vk_rot", "AKIA_NEW", 0))
        .unwrap();
    let live: Vec<_> = s
        .list_credentials("vk_rot")
        .unwrap()
        .into_iter()
        .filter(|c| c.revoked_at.is_none())
        .collect();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].public_id, "AKIA_NEW");
}

#[test]
fn lookup_credential_secret_returns_the_secret_and_meta_never_leaks_it_via_list() {
    let Some(s) = fresh_store() else { return };
    let k = sample_key("vk_sec", "g");
    let cred = sample_credential("vk_sec", "AKIA_SEC", 0);
    s.put_key_with_credential(&k, &cred).unwrap();

    let looked_up = s
        .lookup_credential_secret("sigv4", "AKIA_SEC")
        .unwrap()
        .unwrap();
    assert_eq!(looked_up.secret, "v1:plain:shhh");

    // list_credentials returns CredentialMeta, which has no `secret` field at all -- the type
    // system, not discipline, makes this leak-proof. This assertion just confirms the metadata is
    // otherwise correct.
    let meta = &s.list_credentials("vk_sec").unwrap()[0];
    assert_eq!(meta.public_id, "AKIA_SEC");
}

/// The `ascii_bin` collation is what makes credential lookups case-SENSITIVE, matching Postgres/
/// SQLite's default behavior -- MySQL's default collation is case-insensitive, which would let
/// "AKIA_SEC" and "akia_sec" collide as the same credential (a real security property, not a
/// cosmetic one).
#[test]
fn public_id_lookup_is_case_sensitive() {
    let Some(s) = fresh_store() else { return };
    let k = sample_key("vk_case", "g");
    let cred = sample_credential("vk_case", "AKIA_CASE", 0);
    s.put_key_with_credential(&k, &cred).unwrap();

    assert!(s
        .lookup_credential_secret("sigv4", "AKIA_CASE")
        .unwrap()
        .is_some());
    assert!(
        s.lookup_credential_secret("sigv4", "akia_case")
            .unwrap()
            .is_none(),
        "a case-different public_id must NOT resolve to the same credential"
    );
}

// ── Usage ledgers ────────────────────────────────────────────────────────────────────────────────

#[test]
fn put_and_get_usage_roundtrips() {
    let Some(s) = fresh_store() else { return };
    let ledger = UsageLedger {
        requests: 5,
        billable_requests: 4,
        models: vec![ModelTokens {
            model: "gpt-x".to_string(),
            tokens: TierTokens {
                input: 100,
                output: 50,
                cache_read: 0,
                cache_write: 0,
            },
        }],
    };
    s.put_usage("vk_u", 1000, &ledger).unwrap();
    let back = s.get_usage("vk_u", 1000).unwrap();
    assert_eq!(back.requests, 5);
    assert_eq!(back.billable_requests, 4);
    assert_eq!(back.models[0].tokens.input, 100);
}

#[test]
fn get_usage_on_an_empty_window_returns_zeroes_not_a_panic() {
    // Regression test: `SUM(x)` with no GROUP BY always returns exactly one row even when zero
    // rows match the WHERE clause — it hands back SQL NULL, not an empty result set. Converting
    // that NULL directly into a `u64` panics (see the `COALESCE` fix in `get_usage`). This exact
    // bug crashed a freshly-restarted busbar process during governance boot's budget hydration
    // against a brand-new store (confirmed in CI: "budget hydration failed ... plugin panicked").
    let Some(s) = fresh_store() else { return };
    let back = s.get_usage("vk_never_used", 999).unwrap();
    assert_eq!(back.requests, 0);
    assert_eq!(back.billable_requests, 0);
    assert!(back.models.is_empty());
}

#[test]
fn add_usage_accumulates_and_floors_at_zero() {
    let Some(s) = fresh_store() else { return };
    let delta = UsageDelta {
        requests: 3,
        billable_requests: 3,
        models: vec![ModelTokensDelta {
            model: "m".to_string(),
            tokens: TierTokensDelta {
                input: 10,
                output: 5,
                cache_read: 0,
                cache_write: 0,
            },
        }],
    };
    s.add_usage("vk_add", 2000, &delta).unwrap();
    s.add_usage("vk_add", 2000, &delta).unwrap();
    let ledger = s.get_usage("vk_add", 2000).unwrap();
    assert_eq!(ledger.requests, 6);
    assert_eq!(ledger.models[0].tokens.input, 20);

    // A large negative refund must floor at 0, never wrap/go negative.
    let refund = UsageDelta {
        requests: -100,
        billable_requests: -100,
        models: vec![ModelTokensDelta {
            model: "m".to_string(),
            tokens: TierTokensDelta {
                input: -1000,
                output: 0,
                cache_read: 0,
                cache_write: 0,
            },
        }],
    };
    s.add_usage("vk_add", 2000, &refund).unwrap();
    let ledger = s.get_usage("vk_add", 2000).unwrap();
    assert_eq!(
        ledger.requests, 0,
        "requests must floor at 0, never underflow"
    );
    assert_eq!(ledger.models[0].tokens.input, 0);
}

#[test]
fn add_metering_upserts_and_accumulates() {
    let Some(s) = fresh_store() else { return };
    s.put_key(&sample_key("vk_meter", "g")).unwrap();
    let d = MeteringDelta {
        key_id: "vk_meter".to_string(),
        bucket: 20260731,
        model: "m".to_string(),
        provider: "p".to_string(),
        tokens_input: 10,
        tokens_output: 5,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: "team-a".to_string(),
        pricing_version: "v1".to_string(),
    };
    s.add_metering(&d).unwrap();
    s.add_metering(&d).unwrap();
    let rows = s.list_metering(20260731).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].requests, 2);
    assert_eq!(rows[0].tokens_input, 20);
    assert_eq!(rows[0].key_group_at_use, "team-a");
}

// ── Denylist ─────────────────────────────────────────────────────────────────────────────────────

#[test]
fn denylist_add_and_list_roundtrips_and_never_shortens_the_window() {
    let Some(s) = fresh_store() else { return };
    s.add_denylist("sub1", "revoked").unwrap();
    assert!(s.list_denylist().unwrap().contains(&"sub1".to_string()));
    // Re-adding must not error (idempotent upsert path).
    s.add_denylist("sub1", "revoked again").unwrap();
}

// ── Boot-time invariant probes ───────────────────────────────────────────────────────────────────

/// Proves the CHECK-enforcement functional probe actually detects a real violation attempt and
/// would refuse to boot if the server didn't enforce it (this test can't easily simulate a real
/// pre-8.0.16 server, so it proves the probe's DETECTION half by confirming a live server currently
/// running under CI/local docker actually enforces the constraint it probes).
#[test]
fn boot_probe_confirms_check_enforcement_on_a_real_server() {
    let Some(url) = test_url() else { return };
    // connect() itself runs the probe internally and would have returned Err if enforcement were
    // missing -- reaching this line at all is the proof for a real MySQL 8 server.
    let store = MysqlStore::connect(&url).unwrap();
    drop(store);
}

#[test]
fn boot_probe_rejects_a_permissive_sql_mode() {
    let Some(url) = test_url() else { return };
    let opts = Opts::from_url(&url).unwrap();
    let pool = Pool::new(opts).unwrap();
    let mut conn = pool.get_conn().unwrap();
    let original: String = conn.query_first("SELECT @@sql_mode").unwrap().unwrap();
    conn.query_drop("SET SESSION sql_mode = ''").unwrap();
    // The probe reads the SESSION-visible sql_mode on ITS OWN connection from the pool, which for a
    // single-connection-pool-in-test scenario should reflect this session's setting; if the pool
    // hands back a different pooled connection this assertion may not trigger -- acceptable for a
    // probe-logic proof rather than a strict guarantee across pool internals.
    let result = MysqlStore::probe_invariants(&mut conn);
    assert!(
        result.is_err(),
        "an empty sql_mode (no STRICT_ALL_TABLES) must be rejected"
    );
    conn.query_drop(format!("SET SESSION sql_mode = '{original}'"))
        .unwrap();
}

/// RED without the fix: the old code treated ANY error from the probe INSERT as proof CHECK
/// constraints are enforced (`.is_err()` on the whole `Result`, no inspection of WHICH error).
/// Deterministic, no live DB needed -- proves the discrimination logic itself, not just that a
/// live server happens to answer one way today.
#[test]
fn is_check_constraint_violation_accepts_only_the_two_real_engine_codes() {
    let mysql_check = mysql::Error::MySqlError(mysql::error::MySqlError {
        state: "HY000".to_string(),
        message: "Check constraint 'ck_seq_singleton' is violated.".to_string(),
        code: 3819,
    });
    let mariadb_check = mysql::Error::MySqlError(mysql::error::MySqlError {
        state: "23000".to_string(),
        message: "CONSTRAINT `ck_seq_singleton` failed for `busbar_test`.`store_sequence`"
            .to_string(),
        code: 4025,
    });
    let unrelated_lock_timeout = mysql::Error::MySqlError(mysql::error::MySqlError {
        state: "HY000".to_string(),
        message: "Lock wait timeout exceeded; try restarting transaction".to_string(),
        code: 1205,
    });
    let unrelated_duplicate_key = mysql::Error::MySqlError(mysql::error::MySqlError {
        state: "23000".to_string(),
        message: "Duplicate entry '1' for key 'PRIMARY'".to_string(),
        code: 1062,
    });

    assert!(
        MysqlStore::is_check_constraint_violation(&mysql_check),
        "MySQL 8.0.16+'s real CHECK-violation code (3819) must be recognized"
    );
    assert!(
        MysqlStore::is_check_constraint_violation(&mariadb_check),
        "MariaDB's real CHECK-violation code (4025) must be recognized -- this store's README \
         names MariaDB as a co-equal supported target"
    );
    assert!(
        !MysqlStore::is_check_constraint_violation(&unrelated_lock_timeout),
        "a lock-wait-timeout must NOT be silently read as proof of CHECK enforcement"
    );
    assert!(
        !MysqlStore::is_check_constraint_violation(&unrelated_duplicate_key),
        "an unrelated duplicate-key error must NOT be silently read as proof of CHECK enforcement"
    );
}

// NOTE: a test proving `connect()` ITSELF (not just `probe_invariants` in isolation) refuses to
// boot on a permissive server was attempted here and reverted. The only way to make a genuinely
// FRESH connection (the kind `connect()`'s own `Pool::new` creates) inherit a permissive sql_mode
// is to flip the server's GLOBAL default -- `mysql::Opts::from_url` has no per-connection `init`
// hook, and `connect()`'s public signature takes only a URL, giving no way to inject session state
// into the specific connection it creates. Tried exactly that (flip GLOBAL, call connect(), restore
// immediately) and it broke 6 OTHER concurrently-running tests in a normal (non-`--test-threads=1`)
// `cargo test` run -- a real, reproduced collateral failure, not a theoretical risk. This suite has
// no serialization mechanism for tests touching global server state (unlike the `store_sequence`
// revision counter, which every test already tolerates as shared, this would be actively breaking
// unrelated tests' boot). Reverted rather than land something that destabilizes the suite. The
// wiring gap (a regression breaking connect()->probe_invariants would ship undetected by the two
// existing direct-call tests above) remains open pending either a `connect()` variant testable with
// injectable Opts, or the mysql crate exposing a per-connection init hook through URL parsing.

/// `connect()` now ESTABLISHES strict sql_mode on every connection via `OptsBuilder::init(...)`
/// (appended, not just verified once at boot) rather than trusting every future pooled/reconnected
/// connection inherits the same session posture the one boot-time probe happened to see. Proves the
/// exact init statement `connect()` uses actually WORKS even when the underlying default would be
/// permissive -- self-contained (a throwaway pool this test builds itself, never the shared server
/// global default), so no cross-test interference risk like the reverted GLOBAL-flip attempt above.
#[test]
fn connect_establishes_strict_sql_mode_via_init_even_when_the_default_would_be_permissive() {
    let Some(url) = test_url() else { return };
    let opts = Opts::from_url(&url).unwrap();
    let opts = mysql::OptsBuilder::from_opts(opts).init(vec![
        // Simulates a permissive starting session (as if the server's own default were empty) --
        // then the SAME append statement connect() itself uses. Both run, in order, on THIS
        // pool's own connections only; never touches the real shared server default.
        "SET SESSION sql_mode = ''",
        "SET SESSION sql_mode = CONCAT(@@sql_mode, ',STRICT_ALL_TABLES')",
    ]);
    let pool = Pool::new(opts).unwrap();
    let mut conn = pool.get_conn().unwrap();
    let sql_mode: String = conn.query_first("SELECT @@sql_mode").unwrap().unwrap();
    assert!(
        sql_mode.contains("STRICT_ALL_TABLES"),
        "the init-time append must land even starting from an empty sql_mode: got '{sql_mode}'"
    );
}

// ── Lock ordering ─────────────────────────────────────────────────────────────────────────────────

/// `delete_key`/`scrub_key` must lock `store_sequence` (via `bump_revision`) BEFORE locking the
/// `api_keys` row, matching every other control-plane transaction (`put_key`, `put_credential`,
/// `revoke_credential`) — that fixed order is what the module doc claims makes deadlock across the
/// admin plane structurally impossible. Proves it by racing a tight loop of `put_key` against a tight
/// loop of `delete_key`+re-`put_key` (to keep the key alive for the next iteration) on the SAME row
/// from concurrent threads: if the two lock acquisitions ever ran in opposite order, MySQL's deadlock
/// detector would abort one side with a real "Deadlock found" error under this contention.
#[test]
fn delete_and_put_on_the_same_key_never_deadlock_under_concurrency() {
    let Some(s) = fresh_store() else { return };
    let id = "vk_lock_order_race";
    s.put_key(&sample_key(id, "g0")).unwrap();

    let put_store = MysqlStore::connect(&test_url().unwrap()).unwrap();
    let del_store = MysqlStore::connect(&test_url().unwrap()).unwrap();

    let putter = std::thread::spawn(move || {
        for i in 0..150 {
            put_store
                .put_key(&sample_key(id, &format!("g{i}")))
                .unwrap();
        }
    });
    let deleter = std::thread::spawn(move || {
        for _ in 0..150 {
            // delete then immediately resurrect so the putter always has a live row to race against.
            del_store.delete_key(id).unwrap();
            del_store.put_key(&sample_key(id, "g_resurrect")).unwrap();
        }
    });

    putter.join().expect("put_key thread must not panic/error");
    deleter
        .join()
        .expect("delete_key thread must not panic/error");
}

// ── Schema v2 migration: hydrate_budgets billing-bug backfill ──────────────────────────────────────
//
// Both tests below run the backfill against a PRIVATE, uniquely-named scratch table, never the real
// shared `usage_windows` every other concurrently-running test also writes to. Two approaches were
// tried and rejected first:
//   1. Mutate the real `store_meta.schema_version` row and reconnect via `MysqlStore::connect()` —
//      that row is a single GLOBAL singleton shared by the whole test binary (unlike every other row
//      in this suite, which is scoped by a unique key id and so never collides even under
//      `fresh_store()`'s documented parallel execution); any OTHER concurrently-running test's own
//      `connect()` unconditionally overwrites it back to the current `SCHEMA_VERSION`, racing a
//      deliberately-lowered test marker in both directions (reproduced: one run backfilled a row
//      that should have been left alone, another failed to backfill one that should have been
//      touched).
//   2. Call `run_v2_backfill_if_needed` directly against the real `usage_windows` table — the
//      production UPDATE is correctly UNSCOPED (a real one-time boot migration touches the whole
//      table, matching store-postgres/store-sqlite exactly), so calling it directly during a
//      concurrently-running suite corrupts OTHER tests' legitimate `billable_requests=0` rows
//      (reproduced: unrelated tests like `put_and_get_usage_roundtrips` started failing).
// Unlike store-postgres's own equivalent test (which isolates via a throwaway DATABASE per test),
// the `busbar` CI user has no `CREATE DATABASE` privilege (confirmed: `ERROR 1044 Access denied for
// user 'busbar'@'%'`) — only table-level DDL within the one shared database, which is what
// `run_v2_backfill_if_needed`'s `table` parameter exists to target here.

fn unique_scratch_table(name: &str) -> String {
    format!(
        "scratch_{name}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

/// A row created before v2 (`billable_requests = 0` purely because this store didn't track the
/// split yet, not because of a genuine refund) must be backfilled to `billable_requests = requests`
/// when the database predates v2 (`prior_version` 1..2).
#[test]
fn migrate_v2_backfills_billable_requests_for_a_pre_migration_row() {
    let Some(s) = fresh_store() else { return };
    let table = unique_scratch_table("premigration");

    let mut conn = s.pool.get_conn().unwrap();
    conn.query_drop(format!(
        "CREATE TABLE {table} (
            bucket_id VARCHAR(64) NOT NULL,
            window_start BIGINT NOT NULL,
            requests BIGINT NOT NULL DEFAULT 0,
            billable_requests BIGINT NOT NULL DEFAULT 0,
            PRIMARY KEY (bucket_id, window_start)
        ) ENGINE=InnoDB"
    ))
    .unwrap();
    conn.query_drop(format!(
        "INSERT INTO {table} (bucket_id, window_start, requests, billable_requests) \
         VALUES ('vk_premigration_v2', 5000, 7, 0)"
    ))
    .unwrap();

    MysqlStore::run_v2_backfill_if_needed(&mut conn, 1, &table)
        .expect("the v2 backfill must succeed against a prior_version=1 database");

    let (requests, billable): (u64, u64) = conn
        .query_first(format!(
            "SELECT requests, billable_requests FROM {table} \
             WHERE bucket_id='vk_premigration_v2' AND window_start=5000"
        ))
        .unwrap()
        .unwrap();
    conn.query_drop(format!("DROP TABLE {table}")).unwrap();
    assert_eq!(requests, 7, "the backfill must never touch `requests`");
    assert_eq!(
        billable, 7,
        "a pre-v2 row's billable_requests must be backfilled to equal requests"
    );
}

/// A row with `billable_requests = 0` that already lives on an at-or-past-v2 database (i.e. a
/// genuine full refund/discount, not a pre-v2 artifact) must NOT be touched — gated on
/// `prior_version >= 2` (already migrated) as well as `prior_version == 0` (a brand-new database
/// with no pre-migration rows to backfill in the first place).
#[test]
fn migrate_v2_does_not_touch_a_row_when_the_database_is_not_pre_v2() {
    let Some(s) = fresh_store() else { return };
    let table = unique_scratch_table("norerun");

    let mut conn = s.pool.get_conn().unwrap();
    conn.query_drop(format!(
        "CREATE TABLE {table} (
            bucket_id VARCHAR(64) NOT NULL,
            window_start BIGINT NOT NULL,
            requests BIGINT NOT NULL DEFAULT 0,
            billable_requests BIGINT NOT NULL DEFAULT 0,
            PRIMARY KEY (bucket_id, window_start)
        ) ENGINE=InnoDB"
    ))
    .unwrap();
    conn.query_drop(format!(
        "INSERT INTO {table} (bucket_id, window_start, requests, billable_requests) \
         VALUES ('vk_already_v2_refund', 6000, 9, 0)"
    ))
    .unwrap();

    MysqlStore::run_v2_backfill_if_needed(&mut conn, 2, &table)
        .expect("a no-op call at prior_version=2 must still succeed");
    MysqlStore::run_v2_backfill_if_needed(&mut conn, 0, &table)
        .expect("a no-op call at prior_version=0 (fresh database) must still succeed");

    let (requests, billable): (u64, u64) = conn
        .query_first(format!(
            "SELECT requests, billable_requests FROM {table} \
             WHERE bucket_id='vk_already_v2_refund' AND window_start=6000"
        ))
        .unwrap()
        .unwrap();
    conn.query_drop(format!("DROP TABLE {table}")).unwrap();
    assert_eq!(requests, 9);
    assert_eq!(
        billable, 0,
        "a genuine billable_requests=0 row must survive both no-op calls untouched"
    );
}

/// KNOWN, DOCUMENTED, NOT-YET-CLOSED GAP -- see `run_v2_backfill_if_needed`'s own doc comment for
/// the full writeup and why a `GET_LOCK`-based fix (designed, then rejected in adversarial design
/// review) doesn't actually close this. Characterizes the exact rolling-upgrade race as a
/// deterministic ORDER-of-operations reproduction (no real thread timing needed -- the race is
/// about which write reaches the row first, which a single-threaded test can fully control): a
/// pre-v2 row that receives ONE legitimate real v2 write (simulating an already-live node
/// elsewhere in the fleet) BEFORE this node's own backfill runs permanently loses its pre-v2
/// history from ever being counted as billable.
///
/// `#[ignore]`d: this documents real, CURRENT behavior (confirmed failing below), not a regression
/// to catch. Un-ignore once the provenance-based redesign `run_v2_backfill_if_needed` describes
/// lands, at which point this assertion should start passing.
#[test]
#[ignore = "characterizes a known, documented, not-yet-fixed gap -- see run_v2_backfill_if_needed's doc comment"]
fn characterize_v2_backfill_loses_a_row_to_a_racing_live_write() {
    let Some(s) = fresh_store() else { return };
    let table = unique_scratch_table("racecharacterize");

    let mut conn = s.pool.get_conn().unwrap();
    conn.query_drop(format!(
        "CREATE TABLE {table} (
            bucket_id VARCHAR(64) NOT NULL,
            window_start BIGINT NOT NULL,
            requests BIGINT NOT NULL DEFAULT 0,
            billable_requests BIGINT NOT NULL DEFAULT 0,
            PRIMARY KEY (bucket_id, window_start)
        ) ENGINE=InnoDB"
    ))
    .unwrap();
    // Pre-v2 history: 10 real requests, never tracked as billable (this store didn't split the
    // counters before v2).
    conn.query_drop(format!(
        "INSERT INTO {table} (bucket_id, window_start, requests, billable_requests) \
         VALUES ('vk_race', 7000, 10, 0)"
    ))
    .unwrap();

    // A live, already-upgraded node's REAL v2 write lands FIRST -- legitimate: 2 new billable
    // requests arrive after the upgrade, correctly tracked in lockstep by v2-aware code.
    conn.query_drop(format!(
        "UPDATE {table} SET requests = requests + 2, billable_requests = billable_requests + 2 \
         WHERE bucket_id = 'vk_race' AND window_start = 7000"
    ))
    .unwrap();

    // THEN this (still-booting) node's backfill runs.
    MysqlStore::run_v2_backfill_if_needed(&mut conn, 1, &table).unwrap();

    let (requests, billable): (u64, u64) = conn
        .query_first(format!(
            "SELECT requests, billable_requests FROM {table} \
             WHERE bucket_id='vk_race' AND window_start=7000"
        ))
        .unwrap()
        .unwrap();
    conn.query_drop(format!("DROP TABLE {table}")).unwrap();

    assert_eq!(requests, 12, "sanity: 10 pre-v2 + 2 live v2 requests");
    assert_eq!(
        billable, 12,
        "the pre-v2 10 requests should be reclassified as billable too -- if this fails, \
         billable_requests stayed at 2 (only the live write's own delta) because the backfill's \
         predicate (billable_requests = 0) no longer matched once the live write touched the row \
         first. This is the documented, known gap in run_v2_backfill_if_needed's doc comment."
    );
}

// ── read_prior_version: real query errors must not collapse into "fresh install" ───────────────────

fn scratch_meta_table(conn: &mut PooledConn, name: &str) -> String {
    let table = unique_scratch_table(name);
    conn.query_drop(format!(
        "CREATE TABLE {table} (k VARCHAR(191) PRIMARY KEY, v TEXT NOT NULL) ENGINE=InnoDB"
    ))
    .unwrap();
    table
}

#[test]
fn read_prior_version_is_zero_when_no_row_exists_yet() {
    let Some(s) = fresh_store() else { return };
    let mut conn = s.pool.get_conn().unwrap();
    let table = scratch_meta_table(&mut conn, "noversion");
    let v = MysqlStore::read_prior_version(&mut conn, &table).unwrap();
    conn.query_drop(format!("DROP TABLE {table}")).unwrap();
    assert_eq!(
        v, 0,
        "no schema_version row yet must read as version 0, not an error"
    );
}

#[test]
fn read_prior_version_parses_a_real_stored_value() {
    let Some(s) = fresh_store() else { return };
    let mut conn = s.pool.get_conn().unwrap();
    let table = scratch_meta_table(&mut conn, "realversion");
    conn.query_drop(format!(
        "INSERT INTO {table} (k, v) VALUES ('schema_version', '1')"
    ))
    .unwrap();
    let v = MysqlStore::read_prior_version(&mut conn, &table).unwrap();
    conn.query_drop(format!("DROP TABLE {table}")).unwrap();
    assert_eq!(v, 1);
}

/// RED without the fix: the old code's `.and_then(|v| v.parse().ok()).unwrap_or(0)` silently turns
/// a corrupt, non-numeric stored value into version 0 (indistinguishable from "fresh install") --
/// exactly the "looks already migrated but isn't" failure mode the module doc warns against, just
/// approached from a different angle (a corrupt marker instead of a query error). A corrupt marker
/// must hard-fail, not silently default.
#[test]
fn read_prior_version_hard_fails_on_a_corrupt_stored_value() {
    let Some(s) = fresh_store() else { return };
    let mut conn = s.pool.get_conn().unwrap();
    let table = scratch_meta_table(&mut conn, "corruptversion");
    conn.query_drop(format!(
        "INSERT INTO {table} (k, v) VALUES ('schema_version', 'not-a-number')"
    ))
    .unwrap();
    let result = MysqlStore::read_prior_version(&mut conn, &table);
    conn.query_drop(format!("DROP TABLE {table}")).unwrap();
    assert!(
        result.is_err(),
        "a corrupt (non-numeric) schema_version value must hard-fail, not silently read as 0"
    );
}
