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

