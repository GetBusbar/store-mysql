// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_api::{McpCallRecord, ModelTokensDelta, TaskEventRow, TaskRow, TierTokensDelta};
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

    ensure_reset(&store);
    Some(store)
}

/// The one-time table wipe, as its own barrier so a test can join it WITHOUT paying for another
/// `MysqlStore::connect`.
///
/// It TRUNCATEs `audit_log`, `api_keys`, `usage_windows` and friends, and `Once` fires it at whatever
/// moment the FIRST caller arrives. Under parallel tests that moment can land in the middle of
/// another test's run — so a test that writes rows without having joined this barrier can have them
/// wiped underneath it. That is exactly what happened: tests reaching the store through
/// `MysqlStore::connect` directly never participated, and lost rows mid-run
/// (`concurrent_appends_of_distinct_seqs_never_deadlock` 10/16, plus `add_usage_...` and a
/// conformance check).
///
/// `Once::call_once` also BLOCKS concurrent callers until the wipe completes, which is the property
/// that makes joining it sufficient: every participant either does the truncate or waits for it, and
/// none of them has written anything yet.
fn ensure_reset(store: &MysqlStore) {
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
}

/// `purge_windows_before` is UNSCOPED by contract: it deletes every window below the cutoff, across
/// every bucket. That is correct for a retention sweep and incompatible with this suite's usual
/// isolation-by-unique-id, so the purge test and the tests that read a window back must not run at
/// the same time. They cannot be isolated by a throwaway database either: the CI user has no
/// CREATE DATABASE privilege (see the note above the backfill tests). One shared lock, held only by
/// the handful of tests that care, keeps the rest of the suite parallel.
static USAGE_WINDOWS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The two tests that build a WHOLE schema from nothing against their own throwaway database (the
/// v2 real-wiring test and the v4->v5 task-store migration) run ~25 DDL statements apiece. MySQL 8's
/// data dictionary is shared ACROSS databases, so that DDL contends even though the two databases do
/// not — and `init_schema`'s deadlock retry, which exists for exactly this, was observed exhausting
/// all five attempts (`ERROR 1213` on `CREATE INDEX idx_api_keys_revision`) when both ran at once on
/// a loaded machine. Serialising just these two keeps the DDL burst from overlapping without costing
/// the rest of the suite any parallelism.
static FRESH_DATABASE_DDL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_fresh_database_ddl() -> std::sync::MutexGuard<'static, ()> {
    FRESH_DATABASE_DDL_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn lock_usage_windows() -> std::sync::MutexGuard<'static, ()> {
    USAGE_WINDOWS_LOCK.lock().unwrap_or_else(|e| e.into_inner())
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
    let _guard = lock_usage_windows();
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

/// The request counters are per-WINDOW, not per-model, and must round-trip as themselves whatever
/// the model breakdown looks like.
///
/// The existing round-trip test uses exactly one model, which is the one arity where a per-model
/// duplication is invisible: `SUM` over a single row returns the value unchanged. With N models,
/// writing the whole `ledger.requests` onto each row and summing them back returns N times the real
/// count, and budget hydration reads the window as N times its real usage.
#[test]
fn usage_request_counters_do_not_multiply_with_the_model_count() {
    let _guard = lock_usage_windows();
    let Some(s) = fresh_store() else { return };
    let model = |name: &str| ModelTokens {
        model: name.to_string(),
        tokens: TierTokens {
            input: 10,
            output: 5,
            cache_read: 0,
            cache_write: 0,
        },
    };
    let ledger = UsageLedger {
        requests: 7,
        billable_requests: 3,
        models: vec![model("gpt-x"), model("gpt-y"), model("gpt-z")],
    };
    s.put_usage("vk_multimodel", 1_000_101, &ledger).unwrap();

    let back = s.get_usage("vk_multimodel", 1_000_101).unwrap();
    assert_eq!(
        back.requests, 7,
        "requests is a per-window counter: three models in one window is still seven requests"
    );
    assert_eq!(back.billable_requests, 3, "same for billable_requests");
    assert_eq!(back.models.len(), 3, "every model must still round-trip");

    // add_usage accumulates against the same window, and must add the delta ONCE, not once per
    // model. This is the fleet flush primitive, so an N-times error here compounds permanently.
    s.add_usage(
        "vk_multimodel",
        1_000_101,
        &busbar_api::UsageDelta {
            requests: 2,
            billable_requests: 1,
            models: vec![
                busbar_api::ModelTokensDelta {
                    model: "gpt-x".to_string(),
                    tokens: busbar_api::TierTokensDelta {
                        input: 1,
                        output: 1,
                        cache_read: 0,
                        cache_write: 0,
                    },
                },
                busbar_api::ModelTokensDelta {
                    model: "gpt-y".to_string(),
                    tokens: busbar_api::TierTokensDelta {
                        input: 1,
                        output: 1,
                        cache_read: 0,
                        cache_write: 0,
                    },
                },
            ],
        },
    )
    .unwrap();
    let after = s.get_usage("vk_multimodel", 1_000_101).unwrap();
    assert_eq!(
        after.requests, 9,
        "one delta of two requests must add two, not two per model"
    );
    assert_eq!(after.billable_requests, 4);
}

/// A ledger carrying request counters but NO per-model breakdown must still record those counters.
/// The write path deletes the window first and then inserts one row per model, so an empty model
/// list erased the window and reported success, discarding the requests with it. That shape is
/// real: a window whose requests were all refunded to zero tokens still has a request count.
#[test]
fn usage_with_no_model_breakdown_still_records_its_request_counters() {
    let _guard = lock_usage_windows();
    let Some(s) = fresh_store() else { return };
    let ledger = UsageLedger {
        requests: 4,
        billable_requests: 2,
        models: vec![],
    };
    s.put_usage("vk_nomodels", 1_000_102, &ledger).unwrap();
    let back = s.get_usage("vk_nomodels", 1_000_102).unwrap();
    assert_eq!(
        back.requests, 4,
        "a ledger with no model breakdown still carries request counters, and they must persist"
    );
    assert_eq!(back.billable_requests, 2);
}

/// `purge_metering_before` must match the rows `add_metering` actually wrote. The bucket column is
/// `CHAR(10)` and both the write and the read zero-pad into it; only the purge compared the caller's
/// raw string, so a caller passing the unpadded form matched nothing and got a successful purge of
/// zero rows. A retention sweep that reports success having deleted nothing is the shape this whole
/// release has been chasing.
#[test]
fn purge_metering_before_matches_the_padding_the_write_path_uses() {
    let Some(s) = fresh_store() else { return };
    s.put_key(&sample_key("vk_purge_meter", "g")).unwrap();
    let bucket = 20_260_731u64;
    s.add_metering(&MeteringDelta {
        key_id: "vk_purge_meter".to_string(),
        bucket,
        model: "m".to_string(),
        provider: "p".to_string(),
        tokens_input: 1,
        tokens_output: 1,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
    })
    .unwrap();
    assert!(
        s.list_metering(bucket)
            .unwrap()
            .iter()
            .any(|r| r.key_id == "vk_purge_meter"),
        "precondition: the metering row must exist"
    );

    // The caller has a u64 bucket and renders it the obvious way. That is the form the trait's
    // `&str` parameter invites, and it must reach the padded rows.
    let purged = s.purge_metering_before(&bucket.to_string()).unwrap();
    assert!(
        purged >= 1,
        "the purge must actually match the stored rows, got {purged} deleted"
    );
    assert!(
        !s.list_metering(bucket)
            .unwrap()
            .iter()
            .any(|r| r.key_id == "vk_purge_meter"),
        "the named bucket must be gone after the purge"
    );
}

/// `purge_windows_before` must purge EVERY window below the cutoff, not one capped batch. The
/// contract is "purge every window whose window_start < before"; a single `LIMIT 5000` statement
/// leaves a backlog larger than the cap permanently un-swept while returning a nonzero count each
/// tick that looks like progress.
#[test]
fn purge_windows_before_sweeps_past_a_single_batch() {
    let _guard = lock_usage_windows();
    let Some(s) = fresh_store() else { return };
    // Well clear of every other test's windows, and above the batch size so one capped statement
    // cannot finish the job.
    let base = 7_000_000u64;
    let n = 5_200u64;
    {
        let mut conn = s.pool.get_conn().unwrap();
        let mut sql = String::from(
            "INSERT INTO usage_windows (window_start, bucket_scope, bucket_id, model, requests) VALUES ",
        );
        for i in 0..n {
            if i > 0 {
                sql.push(',');
            }
            sql.push_str(&format!("({}, 'key', 'vk_purge_sweep', '', 1)", base + i));
        }
        conn.query_drop(sql).unwrap();
    }

    let purged = s.purge_windows_before(base + n).unwrap();
    assert!(
        purged >= n,
        "every window below the cutoff must be purged and counted, not just one capped batch: \
         expected at least {n}, got {purged}"
    );
    let left: u64 = {
        let mut conn = s.pool.get_conn().unwrap();
        conn.query_first("SELECT COUNT(*) FROM usage_windows WHERE bucket_id = 'vk_purge_sweep'")
            .unwrap()
            .unwrap_or(0)
    };
    assert_eq!(left, 0, "no window below the cutoff may survive the purge");
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
    // Reads a usage window back, so it has to be serialised against the UNSCOPED
    // `purge_windows_before` like the other window-reading tests. It was missed when that lock was
    // introduced, which left it losing its rows to a concurrent purge about 1 run in 18.
    let _guard = lock_usage_windows();
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

/// Treating ANY error from the probe INSERT as proof CHECK constraints are enforced (`.is_err()`
/// on the whole `Result`, with no inspection of WHICH error) would pass for the wrong reason. This
/// is deterministic and needs no live DB: it proves the discrimination logic itself, not that a
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
///
/// The deleter used to keep the row alive by re-`put_key`ing a LIVE key straight over the tombstone
/// it had just written. That is the resurrection `Store::put_key` now refuses, so the loop clears the
/// tombstone with a raw hard DELETE instead — test scaffolding, not a store operation, and
/// deliberately not `delete_key`, whose lock ordering is the thing under test and must keep running
/// against a real live row every iteration.
///
/// The putter now tolerates the tombstone refusal, because it races: whether its live write lands or
/// is refused depends on which side holds the row, and both outcomes are correct. What it does NOT
/// tolerate is a deadlock, which is the entire point of the test, so the error is matched rather than
/// swallowed. Unwrapping unconditionally would have made a lock-order regression indistinguishable
/// from an ordinary lost race.
#[test]
fn delete_and_put_on_the_same_key_never_deadlock_under_concurrency() {
    let Some(s) = fresh_store() else { return };
    let id = "vk_lock_order_race";
    let _ = s.delete_key(id);
    {
        let mut c = s.conn().expect("conn");
        let _ = c.exec_drop(
            "DELETE FROM api_keys WHERE id = :id",
            params! { "id" => id },
        );
    }
    s.put_key(&sample_key(id, "g0")).unwrap();

    let put_store = MysqlStore::connect(&test_url().unwrap()).unwrap();
    let del_store = MysqlStore::connect(&test_url().unwrap()).unwrap();
    let raw_url = test_url().unwrap();

    let putter = std::thread::spawn(move || {
        for i in 0..150 {
            if let Err(e) = put_store.put_key(&sample_key(id, &format!("g{i}"))) {
                let msg = e.to_string();
                assert!(
                    msg.contains("is tombstoned"),
                    "the only acceptable loss of this race is the tombstone refusal; a deadlock \
                     means the fixed lock order broke: {msg}"
                );
            }
        }
    });
    let deleter = std::thread::spawn(move || {
        let clear = MysqlStore::connect(&raw_url).unwrap();
        for _ in 0..150 {
            // `delete_key` is what this test exists to exercise: it must take store_sequence before
            // the api_keys row, every iteration, against a genuinely live row.
            if let Err(e) = del_store.delete_key(id) {
                let msg = e.to_string();
                assert!(
                    msg.contains("unknown id"),
                    "delete_key must only ever lose this race by finding the row already cleared: \
                     {msg}"
                );
            }
            // Scaffolding: drop the tombstone so the next iteration races a live row again.
            let mut c = clear.conn().expect("conn");
            let _ = c.exec_drop(
                "DELETE FROM api_keys WHERE id = :id",
                params! { "id" => id },
            );
            let _ = del_store.put_key(&sample_key(id, "g_relive"));
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
//      concurrently-running suite corrupts OTHER tests' legitimate `billable_requests=0` rows,
//      which shows up as unrelated failures in tests like `put_and_get_usage_roundtrips`.
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

fn scratch_collation(conn: &mut PooledConn, table: &str, column: &str) -> String {
    conn.query_first(format!(
        "SELECT COLLATION_NAME FROM information_schema.COLUMNS \
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '{table}' AND COLUMN_NAME = '{column}'"
    ))
    .unwrap()
    .expect("column exists")
}

/// A `usage_metering`-shaped table created before v3 (v1.0.0 shipped `key_group_at_use` without
/// `ascii_bin`, inheriting MySQL's case-insensitive default) must have its collation corrected to
/// `ascii_bin` when the database predates v3 (`prior_version` 1..3).
#[test]
fn migrate_v3_fixes_key_group_at_use_collation_for_a_pre_migration_table() {
    let Some(s) = fresh_store() else { return };
    let table = unique_scratch_table("premigration_v3");

    let mut conn = s.pool.get_conn().unwrap();
    // The pre-v3 shape: no explicit collation, so it inherits the database default (utf8mb4_*, NOT
    // ascii_bin) -- exactly what a real v1.0.0-created `usage_metering` table has today.
    conn.query_drop(format!(
        "CREATE TABLE {table} (key_group_at_use VARCHAR(128) NOT NULL DEFAULT '') ENGINE=InnoDB"
    ))
    .unwrap();
    let before = scratch_collation(&mut conn, &table, "key_group_at_use");
    assert_ne!(
        before, "ascii_bin",
        "the scratch table must start on a non-ascii_bin collation, or this test proves nothing"
    );

    MysqlStore::run_v3_ascii_bin_fix_if_needed(&mut conn, 1, &table)
        .expect("the v3 ascii_bin fix must succeed against a prior_version=1 database");

    let after = scratch_collation(&mut conn, &table, "key_group_at_use");
    conn.query_drop(format!("DROP TABLE {table}")).unwrap();
    assert_eq!(
        after, "ascii_bin",
        "a pre-v3 table's key_group_at_use collation must be corrected to ascii_bin"
    );
}

/// A table already at-or-past v3 (already `ascii_bin`, or a fresh v3+ install) must not have the
/// migration re-run pointlessly — gated on `prior_version >= 3` as well as `prior_version == 0`.
#[test]
fn migrate_v3_does_not_touch_a_table_when_the_database_is_not_pre_v3() {
    let Some(s) = fresh_store() else { return };
    let table = unique_scratch_table("norerun_v3");

    let mut conn = s.pool.get_conn().unwrap();
    conn.query_drop(format!(
        "CREATE TABLE {table} (
            key_group_at_use VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT ''
        ) ENGINE=InnoDB"
    ))
    .unwrap();

    MysqlStore::run_v3_ascii_bin_fix_if_needed(&mut conn, 3, &table)
        .expect("a no-op call at prior_version=3 must still succeed");
    MysqlStore::run_v3_ascii_bin_fix_if_needed(&mut conn, 0, &table)
        .expect("a no-op call at prior_version=0 (fresh database) must still succeed");

    let after = scratch_collation(&mut conn, &table, "key_group_at_use");
    conn.query_drop(format!("DROP TABLE {table}")).unwrap();
    assert_eq!(
        after, "ascii_bin",
        "both no-op calls must leave the collation untouched"
    );
}

/// KNOWN, DOCUMENTED, NOT-YET-CLOSED GAP -- see `run_v2_backfill_if_needed`'s own doc comment for
/// the full writeup, including why a `GET_LOCK` does not close it. Characterizes the exact
/// rolling-upgrade race as a
/// deterministic ORDER-of-operations reproduction (no real thread timing needed -- the race is
/// about which write reaches the row first, which a single-threaded test can fully control): a
/// pre-v2 row that receives ONE legitimate real v2 write (simulating an already-live node
/// elsewhere in the fleet) BEFORE this node's own backfill runs permanently loses its pre-v2
/// history from ever being counted as billable.
///
/// `#[ignore]`d: it documents real, CURRENT behavior rather than guarding a regression, so it
/// fails today by design. Un-ignore once the provenance-based redesign
/// `run_v2_backfill_if_needed` describes lands, at which point the assertion starts passing.
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

/// The two tests above prove `run_v2_backfill_if_needed` works correctly called DIRECTLY with a
/// hand-supplied `prior_version`/`table` -- neither ever goes through `try_init_schema`'s REAL
/// wiring: reading `prior_version` from the actual `store_meta.schema_version` row and calling the
/// backfill with the real hardcoded table name `"usage_windows"`. A regression that reordered that
/// real read (e.g. moved it after the SCHEMA loop / the `schema_version` write) or typo'd the real
/// table name would ship undetected by either test above.
///
/// Exercises the REAL public `MysqlStore::connect()` entry point (which internally calls the real,
/// unparameterized `try_init_schema`) against a DEDICATED, throwaway database -- not the shared
/// `busbar_test` every other test in this suite uses -- so this can safely pre-seed a real pre-v2
/// `store_meta.schema_version='1'` row without racing any other concurrently-running test's own
/// `connect()` calls (the documented reason `run_v2_backfill_if_needed` takes an explicit
/// `prior_version` instead of reading the shared row itself). Needs `root` to `CREATE DATABASE`
/// (same constraint as the app-level `busbar` CI user lacking that privilege, documented on the
/// migration tests above) -- real CI has `root`/`busbar` available with matching credentials (see
/// `plugin-ci.yml`'s own "set strict sql_mode" step, which already connects as root).
#[test]
fn try_init_schema_real_wiring_backfills_a_genuinely_pre_v2_database() {
    let _ddl_guard = lock_fresh_database_ddl();
    let Some(url) = test_url() else { return };
    let db_name = format!(
        "busbar_wiring_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let root_url = url.replacen("busbar:busbar@", "root:busbar@", 1);
    let root_opts = Opts::from_url(&root_url).unwrap();
    let root_pool = Pool::new(root_opts).unwrap();
    let mut root_conn = root_pool.get_conn().unwrap();
    root_conn
        .query_drop(format!("CREATE DATABASE {db_name}"))
        .unwrap();
    root_conn
        .query_drop(format!(
            "GRANT ALL PRIVILEGES ON {db_name}.* TO 'busbar'@'%'"
        ))
        .unwrap();

    // Point the app-level busbar user at the fresh dedicated database (swap the path component of
    // the URL, keep the same host/port/credentials). `url` is only a transitive dep (via `mysql`),
    // so plain string surgery on the last path segment instead of a proper URL crate.
    let dedicated_url = {
        let cut = url
            .rfind('/')
            .expect("test_url() must be a mysql:// URL with a /database path");
        format!("{}/{db_name}", &url[..cut])
    };

    // Boot ONCE to create the real schema for real via try_init_schema, then hand-seed a genuine
    // pre-v2 marker directly in the real store_meta row (safe here -- this database has no other
    // concurrent user) and a pre-v2-shaped row in the real usage_windows table.
    let store1 = MysqlStore::connect(&dedicated_url).expect("first boot must create the schema");
    {
        let mut conn = store1.pool.get_conn().unwrap();
        conn.query_drop("UPDATE store_meta SET v = '1' WHERE k = 'schema_version'")
            .unwrap();
        conn.query_drop(
            "INSERT INTO usage_windows \
             (window_start, bucket_scope, bucket_id, model, requests, billable_requests) \
             VALUES (9000, 'key', 'vk_wiring', 'gpt', 5, 0)",
        )
        .unwrap();
    }
    drop(store1);

    // Reconnect -- THIS is the real try_init_schema call under test: it must read prior_version=1
    // from the real store_meta row (not a hand-supplied one) and run the backfill against the
    // real, hardcoded "usage_windows" table name (not a scratch table a test pointed it at).
    let store2 = MysqlStore::connect(&dedicated_url).expect("second boot (the real migration)");
    let mut conn = store2.pool.get_conn().unwrap();
    let (requests, billable): (u64, u64) = conn
        .query_first(
            "SELECT requests, billable_requests FROM usage_windows \
             WHERE bucket_id = 'vk_wiring' AND window_start = 9000",
        )
        .unwrap()
        .unwrap();
    drop(store2);

    root_conn
        .query_drop(format!("DROP DATABASE {db_name}"))
        .unwrap();

    assert_eq!(requests, 5);
    assert_eq!(
        billable, 5,
        "try_init_schema's REAL wiring (real store_meta read, real \"usage_windows\" table name) \
         must have backfilled this pre-v2 row -- a regression to either would leave billable_requests \
         at 0, undetected by the two tests above that bypass this wiring entirely"
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

/// A `.and_then(|v| v.parse().ok()).unwrap_or(0)` read would silently turn a corrupt, non-numeric
/// stored value into version 0, indistinguishable from "fresh install" -- the same
/// "looks already migrated but isn't" failure mode the module doc warns about, reached via a
/// corrupt marker instead of a query error. A corrupt marker must hard-fail, not silently
/// default.
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

/// `revoke_credential` must reject an unknown/typo'd id loudly, not silently return `Ok(())`.
/// An unconditional `UPDATE ... WHERE id=:id` that never checks for a matched row cannot produce
/// the `Err` this asserts.
#[test]
fn revoke_credential_rejects_an_unknown_id() {
    let Some(s) = fresh_store() else { return };
    let err = s
        .revoke_credential("cred_does_not_exist_anywhere", "cleanup")
        .unwrap_err();
    assert!(
        err.to_string().contains("unknown credential id"),
        "must name the real reason: {err}"
    );
}

/// `put_credential` must reject a `public_id` collision against a DIFFERENT credential's id, not
/// silently corrupt the unrelated row via `ON DUPLICATE KEY UPDATE`, which would overwrite that
/// row's `id`/`secret` and leave its `key_id`/`slot` untouched.
#[test]
fn put_credential_rejects_a_public_id_collision_against_a_different_credential() {
    let Some(s) = fresh_store() else { return };
    let k1 = sample_key("vk_pubcol_a", "g");
    let k2 = sample_key("vk_pubcol_b", "g");
    s.put_key(&k1).unwrap();
    s.put_key(&k2).unwrap();
    s.put_credential(&sample_credential("vk_pubcol_a", "AKIA_SHARED_PUBID", 0))
        .unwrap();

    // A genuinely NEW credential (different id, different key_id/slot) reusing the SAME
    // public_id must be rejected, not silently take over the first credential's identity.
    // (sample_credential derives `id` from `public_id`, so force a DIFFERENT id explicitly --
    // otherwise this would collide on the PRIMARY KEY too and test the wrong path.)
    let mut colliding = sample_credential("vk_pubcol_b", "AKIA_SHARED_PUBID", 0);
    colliding.meta.id = "cred_genuinely_different_id".to_string();
    let err = s.put_credential(&colliding).unwrap_err();
    // A real MySQL duplicate-key rejection on `uq_cred_public` -- dropping the blanket
    // `ON DUPLICATE KEY UPDATE` (see put_credential's own comment) means MySQL's own constraint
    // now catches this collision directly, same as the PRIMARY KEY case below.
    assert!(
        (err.to_string().contains("Duplicate entry") || err.to_string().contains("1062"))
            && err.to_string().contains("uq_cred_public"),
        "must be a real duplicate-key rejection on the public_id unique key: {err}"
    );

    // The FIRST credential must be completely untouched by the rejected attempt.
    let untouched = s
        .lookup_credential_secret("sigv4", "AKIA_SHARED_PUBID")
        .unwrap()
        .unwrap();
    assert_eq!(untouched.meta.key_id, "vk_pubcol_a");
}

/// `put_credential` must also reject a PRIMARY KEY (`id`) collision against a row that belongs to
/// a DIFFERENT `key_id`/`slot` -- the third of the table's 3 unique keys, and the one a
/// public_id-only guard does not cover. `ON DUPLICATE KEY UPDATE`'s SET list never touches
/// `key_id`/`slot`, so without this guard the statement silently overwrites the existing row's
/// secret material while leaving it attached to the WRONG key/slot.
#[test]
fn put_credential_rejects_an_id_collision_against_a_different_key_or_slot() {
    let Some(s) = fresh_store() else { return };
    let k1 = sample_key("vk_idcol_a", "g");
    let k2 = sample_key("vk_idcol_b", "g");
    s.put_key(&k1).unwrap();
    s.put_key(&k2).unwrap();
    let original = sample_credential("vk_idcol_a", "AKIA_IDCOL_ORIG", 0);
    s.put_credential(&original).unwrap();

    // Same `id` as `original` (sample_credential derives id from public_id, so force a real
    // collision by reusing original's id directly), but a DIFFERENT key_id/slot/public_id.
    let mut colliding = sample_credential("vk_idcol_b", "AKIA_IDCOL_NEW", 1);
    colliding.meta.id = original.meta.id.clone();
    let err = s.put_credential(&colliding).unwrap_err();
    // MySQL's own PRIMARY KEY constraint surfaces this now (a real 1062 duplicate-entry error),
    // since the INSERT path no longer silently upserts across an id collision.
    assert!(
        err.to_string().contains("Duplicate entry") || err.to_string().contains("1062"),
        "must be a real duplicate-key rejection, not a silent corruption: {err}"
    );

    // The ORIGINAL credential must be completely untouched.
    let untouched = s
        .lookup_credential_secret("sigv4", "AKIA_IDCOL_ORIG")
        .unwrap()
        .unwrap();
    assert_eq!(untouched.meta.key_id, "vk_idcol_a");
    assert_eq!(untouched.meta.slot, 0);
}

/// Real proof that `delete_key`'s tombstone-write and credential-destroy are ONE atomic
/// transaction, not two: a concurrent connection contends for the SAME row lock `delete_key`
/// holds for its whole transaction. InnoDB row locks are held for the full transaction, not
/// released between statements, so a racer that observes the row after finding it locked can
/// only ever see the FULLY-before or FULLY-after state -- never a window with one half done and
/// not the other. If `delete_key` were split into two transactions, the row lock would release
/// after the first commits, letting a racer that lands in that gap observe the broken
/// intermediate state, which the assertion below would then catch.
#[test]
fn tombstone_and_credential_destruction_are_never_observed_apart() {
    let Some(s) = fresh_store() else { return };
    let k = sample_key("vk_atomicrace", "g");
    let cred = sample_credential("vk_atomicrace", "AKIA_ATOMICRACE", 0);
    s.put_key_with_credential(&k, &cred).unwrap();

    let pool = s.pool.clone();
    let observed = std::sync::Arc::new(std::sync::Mutex::new(None));
    let observed2 = observed.clone();

    let racer = std::thread::spawn(move || {
        let mut conn = pool.get_conn().unwrap();
        // Bias toward the interesting (contended) case: repeatedly probe with a near-zero lock
        // wait until we find the row genuinely locked (proof delete_key's transaction is
        // mid-flight), then switch to a normal blocking wait so we observe the state EXACTLY as
        // the lock releases -- never a state from before delete_key started.
        for _ in 0..500 {
            let mut probe = conn.start_transaction(mysql::TxOpts::default()).unwrap();
            // NOWAIT (MySQL 8.0.1+) errors instantly instead of blocking -- a real non-blocking
            // probe, unlike innodb_lock_wait_timeout (whose minimum valid value is 1 second).
            let busy = probe
                .exec_first::<Option<u64>, _, _>(
                    "SELECT deleted_at FROM api_keys WHERE id = :id FOR UPDATE NOWAIT",
                    params! { "id" => "vk_atomicrace" },
                )
                .is_err();
            let _ = probe.rollback();
            if busy {
                break;
            }
            std::thread::sleep(std::time::Duration::from_micros(200));
        }
        conn.query_drop("SET innodb_lock_wait_timeout = 50")
            .unwrap();
        let mut tx = conn.start_transaction(mysql::TxOpts::default()).unwrap();
        let tombstoned: Option<u64> = tx
            .exec_first(
                "SELECT deleted_at FROM api_keys WHERE id = :id FOR UPDATE",
                params! { "id" => "vk_atomicrace" },
            )
            .unwrap()
            .flatten();
        let cred_count: i64 = tx
            .exec_first(
                "SELECT COUNT(*) FROM credentials WHERE key_id = :id",
                params! { "id" => "vk_atomicrace" },
            )
            .unwrap()
            .unwrap();
        let _ = tx.rollback();
        *observed2.lock().unwrap() = Some((tombstoned.is_some(), cred_count));
    });

    s.delete_key("vk_atomicrace").unwrap();
    racer.join().unwrap();

    let (tombstoned, cred_count) = observed.lock().unwrap().unwrap();
    assert!(
        (tombstoned && cred_count == 0) || (!tombstoned && cred_count == 1),
        "observed tombstoned={tombstoned} cred_count={cred_count} -- a window where one half of \
         delete_key committed without the other means it is NOT one atomic transaction"
    );
}

/// The shared `Store` contract conformance suite (`busbar-plugin-testkit`) — the four behaviours the
/// fleet used to settle differently per backend. Kept in the testkit rather than written out here so
/// a future ruling reaches every backend at once instead of being hand-copied and drifting again.
///
/// Fixtures are namespaced per process AND per check, and hard-reset first. Per-process because this
/// suite runs against a SHARED live database that is not reset between tests and CI can point more
/// than one binary at it; per-check because these run in parallel and `reset` clears every id in the
/// namespace it is given, so one shared namespace would have each check deleting the others' rows
/// mid-run.
mod conformance {
    use super::{test_url, MysqlStore};
    use busbar_plugin_testkit::store_conformance as conf;
    use mysql::params;
    use mysql::prelude::Queryable;

    fn ns(check: &str) -> String {
        format!("vk_c{}{}", std::process::id(), check)
    }

    fn reset(store: &MysqlStore, ns: &str, seq: u64) {
        let mut conn = store.conn().expect("conn");
        for id in conf::key_ids(ns) {
            let _ = conn.exec_drop(
                "DELETE FROM credentials WHERE key_id = :id",
                params! { "id" => &id },
            );
            let _ = conn.exec_drop(
                "DELETE FROM api_keys WHERE id = :id",
                params! { "id" => &id },
            );
        }
        for id in conf::credential_ids(ns) {
            let _ = conn.exec_drop(
                "DELETE FROM credentials WHERE id = :id",
                params! { "id" => &id },
            );
        }
        let _ = conn.exec_drop(
            "DELETE FROM audit_log WHERE seq = :seq",
            params! { "seq" => seq },
        );
    }

    /// ONE store shared by all four checks.
    ///
    /// `MysqlStore::connect` re-runs the schema DDL and the invariant probes on EVERY call, and this
    /// module's checks run in parallel with sibling tests that hold `SELECT ... FOR UPDATE`
    /// transactions open. Connecting four more times mid-suite made those siblings fail with
    /// `ERROR 1412 (Table definition has changed, please retry transaction)` about one run in six.
    /// Connecting once, behind a `OnceLock`, removes the extra DDL entirely; the checks stay
    /// isolated from each other through their per-check namespaces, not through separate
    /// connections.
    fn shared_store() -> Option<&'static MysqlStore> {
        static STORE: std::sync::OnceLock<Option<MysqlStore>> = std::sync::OnceLock::new();
        STORE
            .get_or_init(|| {
                let url = test_url()?;
                let s = MysqlStore::connect(&url).expect("connect");
                // Same barrier as every other test: without it the one-time TRUNCATE can land in
                // the middle of a conformance check and delete the rows it just wrote.
                super::ensure_reset(&s);
                Some(s)
            })
            .as_ref()
    }

    fn setup(check: &str, seq: u64) -> Option<(&'static MysqlStore, String)> {
        let store = shared_store()?;
        let ns = ns(check);
        reset(store, &ns, seq);
        Some((store, ns))
    }

    #[test]
    fn put_key_does_not_resurrect_a_tombstone() {
        let Some((store, ns)) = setup("put", 0) else {
            return;
        };
        conf::assert_put_key_does_not_resurrect_a_tombstone(store, &ns);
    }

    #[test]
    fn delete_key_unknown_id_is_an_error() {
        let Some((store, ns)) = setup("del", 0) else {
            return;
        };
        conf::assert_delete_key_unknown_id_is_an_error(store, &ns);
    }

    #[test]
    fn revoke_credential_unknown_id_is_an_error() {
        let Some((store, ns)) = setup("rev", 0) else {
            return;
        };
        conf::assert_revoke_credential_unknown_id_is_an_error(store, &ns);
    }

    #[test]
    fn append_audit_duplicate_seq_is_ok_when_identical_and_an_error_when_different() {
        let seq = 910_000_000u64 + (std::process::id() as u64 % 1_000_000);
        let Some((store, _ns)) = setup("aud", seq) else {
            return;
        };
        conf::assert_append_audit_duplicate_seq(store, seq);
    }
}

/// Concurrent appends of DIFFERENT seqs must not deadlock.
///
/// The duplicate-seq comparison was first written as `SELECT ... FOR UPDATE` then INSERT. Under
/// REPEATABLE READ (what `TxOpts::default()` leaves the server on) a `FOR UPDATE` on a MISSING row
/// takes a next-key/gap lock; two appends of different, both-new seqs land in the same gap, and each
/// side's following INSERT needs an insert-intention lock that conflicts with the other's gap lock.
/// Four threads over 200 distinct seqs each produced 39 `ERROR 1213` deadlocks that way, against 0
/// for the plain insert it replaced. `append_audit` is also the one control-plane path that does not
/// call `bump_revision`, so it sits outside the `store_sequence` serialization that keeps every other
/// admin-plane transaction deadlock-free.
///
/// A durable audit write-through failing under ordinary multi-node load defeats the whole point of
/// the durable sink, so this pins it.
#[test]
fn concurrent_appends_of_distinct_seqs_never_deadlock() {
    // ONE store, shared by every thread, instead of one `connect()` per worker.
    //
    // `MysqlStore::connect` re-runs the whole schema DDL on every call (`init_schema`), and doing
    // that mid-suite makes sibling tests holding `SELECT ... FOR UPDATE` fail with
    // `ERROR 1412 (Table definition has changed, please retry transaction)`. An earlier version of
    // this test connected six extra times and took a suite that was 20/20 clean to 3/20 failing --
    // while the commit adding it claimed to have REMOVED mid-suite connects. The pool inside one
    // store is what provides the concurrency here; extra stores only bought extra DDL.
    let Some(url) = test_url() else { return };
    let base = 940_000_000u64 + (std::process::id() as u64 % 100_000) * 1_000;
    let shared = std::sync::Arc::new(MysqlStore::connect(&url).expect("connect"));
    // Join the one-time wipe barrier before writing anything, or it can fire mid-run and truncate
    // `audit_log` underneath these 200 appends.
    ensure_reset(&shared);
    {
        let store = std::sync::Arc::clone(&shared);
        let mut conn = store.conn().expect("conn");
        let _ = conn.exec_drop(
            "DELETE FROM audit_log WHERE seq >= :lo AND seq < :hi",
            params! { "lo" => base, "hi" => base + 1_000 },
        );
    }

    let threads: Vec<_> = (0..4u64)
        .map(|t| {
            let store = std::sync::Arc::clone(&shared);
            std::thread::spawn(move || {
                for i in 0..50u64 {
                    let seq = base + t * 100 + i;
                    let rec = AuditRecord {
                        seq,
                        ts: 1_700_000_000,
                        action: "key.mint".into(),
                        resource: format!("key:vk_{seq}"),
                        outcome: "applied".into(),
                        principal: "admin".into(),
                        prev_hash: String::new(),
                        hash: format!("h{seq}"),
                    };
                    if let Err(e) = store.append_audit(&rec) {
                        let msg = e.to_string();
                        assert!(
                            !msg.contains("Deadlock") && !msg.contains("1213"),
                            "concurrent appends of DISTINCT seqs deadlocked: {msg}"
                        );
                        panic!("append_audit failed unexpectedly: {msg}");
                    }
                }
            })
        })
        .collect();
    for h in threads {
        h.join().expect("no append thread may fail");
    }

    let mut conn = shared.conn().expect("conn");
    let n: Option<u64> = conn
        .exec_first(
            "SELECT COUNT(*) FROM audit_log WHERE seq >= :lo AND seq < :hi",
            params! { "lo" => base, "hi" => base + 1_000 },
        )
        .unwrap();
    assert_eq!(n, Some(200), "every distinct append must be durably stored");
    let _ = conn.exec_drop(
        "DELETE FROM audit_log WHERE seq >= :lo AND seq < :hi",
        params! { "lo" => base, "hi" => base + 1_000 },
    );
}

// ── THE DURABLE MCP TOOL-CALL LOG ────────────────────────────────────────────────────────────
//
// The property under test is not "the write returned Ok" — the trait's default `append_mcp_call`
// returns `Ok(())` and keeps nothing, so a write's return value is worthless as evidence of
// durability. The only honest way to know a deployment has durable call evidence is to READ IT
// BACK, and the only honest way to know it survives a deploy is to read it back on a NEW
// CONNECTION after the writing store is gone.

fn sample_call(principal: &str, seq: u64, ts: u64, prev_hash: &str, hash: &str) -> McpCallRecord {
    McpCallRecord {
        principal: principal.to_string(),
        seq,
        ts,
        server: "srv".to_string(),
        tool: "srv_read_file".to_string(),
        outcome: "dispatched".to_string(),
        reason: String::new(),
        tool_digest: format!("sha256:tool{seq}"),
        pin_generation: 3,
        request_id: format!("req-{seq}"),
        prev_hash: prev_hash.to_string(),
        hash: hash.to_string(),
    }
}

/// The live MySQL server is SHARED across tests, so each test owns its own principal ids and clears
/// them first — the isolation-by-unique-id discipline the rest of this file uses.
fn reset_calls(store: &MysqlStore, principals: &[&str]) {
    let mut conn = store.conn().expect("conn");
    for p in principals {
        conn.exec_drop(
            "DELETE FROM mcp_calls WHERE principal = :p",
            params! { "p" => *p },
        )
        .expect("clear this test's own rows");
    }
}

/// THE TEST THAT MATTERS. A round-trip on one live handle cannot distinguish a backend that wrote
/// to the server from one holding a HashMap behind the same trait. So this DROPS the store —
/// closing its pool entirely — then connects a genuinely new one and verifies the per-principal
/// hash chain still links from the rows the server hands back.
#[test]
fn an_mcp_call_chain_survives_dropping_the_store_and_reconnecting() {
    let Some(url) = test_url() else { return };
    let p = "vk_mcp_restart";
    {
        let store = MysqlStore::connect(&url).expect("connect");
        reset_calls(&store, &[p]);
        store
            .append_mcp_call(&sample_call(p, 1, 2_000_000_100, "", "h1"))
            .unwrap();
        store
            .append_mcp_call(&sample_call(p, 2, 2_000_000_200, "h1", "h2"))
            .unwrap();
        store
            .append_mcp_call(&sample_call(p, 3, 2_000_000_300, "h2", "h3"))
            .unwrap();
        drop(store);
    }

    // A genuinely new store and pool — nothing carried over in this process.
    let reopened = MysqlStore::connect(&url).expect("reconnect");
    let got = reopened.list_mcp_calls(p).unwrap();

    assert_eq!(
        got.len(),
        3,
        "the call log must survive a reconnect; got {} records back, which is the \
         accept-and-keep-nothing behaviour this backend exists to replace",
        got.len()
    );
    assert_eq!(
        got[0].prev_hash, "",
        "seq 1 opens the chain with an empty prev_hash"
    );
    for w in got.windows(2) {
        assert_eq!(
            w[1].prev_hash, w[0].hash,
            "the per-principal chain must still link after a reconnect: seq {} carries prev_hash \
             {:?} but seq {} persisted hash {:?}",
            w[1].seq, w[1].prev_hash, w[0].seq, w[0].hash
        );
    }
    assert_eq!(got.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1, 2, 3]);
    // The non-indexed payload must round-trip verbatim too.
    assert_eq!(got[2].tool_digest, "sha256:tool3");
    assert_eq!(got[2].request_id, "req-3");
    assert_eq!(got[1].tool, "srv_read_file");
    assert_eq!(got[1].pin_generation, 3);
    reset_calls(&reopened, &[p]);
}

/// The boot enumeration: a restart has to resume a chain for a principal this process has not yet
/// seen, so the store must be able to name every principal holding records.
#[test]
fn mcp_call_principals_are_enumerable_after_a_reconnect() {
    let Some(url) = test_url() else { return };
    let (a, b) = ("vk_mcp_enum_a", "vk_mcp_enum_b");
    {
        let store = MysqlStore::connect(&url).expect("connect");
        reset_calls(&store, &[a, b]);
        store
            .append_mcp_call(&sample_call(a, 1, 2_000_000_100, "", "a1"))
            .unwrap();
        store
            .append_mcp_call(&sample_call(b, 1, 2_000_000_100, "", "b1"))
            .unwrap();
        store
            .append_mcp_call(&sample_call(a, 2, 2_000_000_101, "a1", "a2"))
            .unwrap();
        drop(store);
    }
    let reopened = MysqlStore::connect(&url).expect("reconnect");
    let principals = reopened.list_mcp_call_principals().unwrap();
    for want in [a, b] {
        assert_eq!(
            principals.iter().filter(|p| p.as_str() == want).count(),
            1,
            "{want} must be enumerable after a reconnect, exactly once"
        );
    }
    // The chain scope is the principal: a scoped read returns only its own.
    assert_eq!(reopened.list_mcp_calls(a).unwrap().len(), 2);
    assert_eq!(reopened.list_mcp_calls(b).unwrap().len(), 1);
    assert!(
        reopened
            .list_mcp_calls("vk_mcp_nonexistent")
            .unwrap()
            .is_empty(),
        "a principal with no records reads back empty, not an error"
    );
    reset_calls(&reopened, &[a, b]);
}

/// Retention must ACTUALLY DELETE and report a real count — a purge that returns a number it did
/// not perform is worse than one that reports nothing purged.
#[test]
fn purge_mcp_calls_before_deletes_and_returns_a_real_count() {
    let Some(url) = test_url() else { return };
    let store = MysqlStore::connect(&url).expect("connect");
    let p = "vk_mcp_purge";
    reset_calls(&store, &[p]);
    // Retention is GLOBAL by `ts` — it is not scoped to a principal, and cannot be. Against the
    // SHARED live server that means this test's cutoffs would delete every other test's rows if the
    // timestamps overlapped, so the suite bands them: this test owns the low band and every other
    // test sits ABOVE the highest cutoff used here.
    store
        .append_mcp_call(&sample_call(p, 1, 1_000_000_100, "", "h1"))
        .unwrap();
    store
        .append_mcp_call(&sample_call(p, 2, 1_000_000_200, "h1", "h2"))
        .unwrap();
    store
        .append_mcp_call(&sample_call(p, 3, 1_000_000_300, "h2", "h3"))
        .unwrap();

    let purged = store.purge_mcp_calls_before(1_000_000_200).unwrap();
    assert!(
        purged >= 1,
        "purge must report rows it actually removed; got {purged}"
    );
    assert_eq!(
        store
            .list_mcp_calls(p)
            .unwrap()
            .iter()
            .map(|r| r.seq)
            .collect::<Vec<_>>(),
        vec![2, 3],
        "rows at or after the cutoff must remain — `before` is strictly less-than, so the row \
         exactly at the cutoff is kept"
    );
    let rest = store.purge_mcp_calls_before(1_000_001_000).unwrap();
    assert!(
        rest >= 2,
        "the remaining two rows must actually be removed; got {rest}"
    );
    assert!(store.list_mcp_calls(p).unwrap().is_empty());
}

/// A record arriving on a `(principal, seq)` that already has one is settled the way the contract
/// settles it: BYTE-IDENTICAL is the retry and succeeds; DIFFERENT is a forked or tampered log and
/// is an error. Overwriting would destroy the second case instead of reporting it.
#[test]
fn a_replayed_mcp_call_is_idempotent_but_a_forked_one_is_refused() {
    let Some(url) = test_url() else { return };
    let store = MysqlStore::connect(&url).expect("connect");
    let p = "vk_mcp_replay";
    reset_calls(&store, &[p]);

    let rec = sample_call(p, 1, 2_000_000_100, "", "h1");
    store.append_mcp_call(&rec).unwrap();
    store
        .append_mcp_call(&rec)
        .expect("an identical replay is the at-least-once retry and must succeed");
    assert_eq!(
        store.list_mcp_calls(p).unwrap().len(),
        1,
        "a replay must not duplicate the row"
    );

    let forked = sample_call(p, 1, 2_000_000_100, "", "DIFFERENT");
    let err = store
        .append_mcp_call(&forked)
        .expect_err("a different record at an occupied (principal, seq) is a fork and must error");
    assert!(
        !format!("{err}").contains("DIFFERENT"),
        "the error must not echo stored content back"
    );
    assert_eq!(
        store.list_mcp_calls(p).unwrap()[0].hash,
        "h1",
        "the refused fork must not have overwritten the record already on record"
    );

    // A differing non-indexed payload under an identical digest is a fork too, not a silent accept.
    let mut tampered = sample_call(p, 1, 2_000_000_100, "", "h1");
    tampered.tool = "srv_other_tool".to_string();
    store
        .append_mcp_call(&tampered)
        .expect_err("a payload that differs under an identical digest is a fork and must error");
    reset_calls(&store, &[p]);
}

// ── THE DURABLE A2A TASK STORE ────────────────────────────────────────────────────────────────
//
// A2A is async by design: a task spans turns, can sit interrupted waiting on a human, and can
// outlive the process that started it. So the property under test is not "put_task returned Ok" —
// the trait's default `put_task` returns `Ok(())` and keeps nothing, and `get_task` answers `None`
// for everything, which is a backend that accepts every in-flight task and loses all of them on the
// next deploy. The only honest proof is to READ THE TASK BACK THROUGH A RESTART, and against a live
// server "a restart" means dropping the store — closing its pool entirely — and connecting a
// genuinely new one.

/// Timestamps are BANDED, for the same reason the MCP call-log tests band theirs. `purge_tasks_before`
/// is GLOBAL by `(state, updated_at)` and cannot be scoped to a task or a principal, so against the
/// SHARED live server a purge test's cutoff would delete every other test's terminal rows if the
/// timestamps overlapped. Everything below the top of this band belongs to the purge tests; every
/// other task test writes ABOVE it.
const TASK_PURGE_BAND_TOP: u64 = 1_000_100_000;
const TASK_LIVE_TS: u64 = 2_000_000_000;

/// The two purge tests share the low band and both assert EXACT counts, so they cannot run at the
/// same time as each other — the same unscoped-retention problem `USAGE_WINDOWS_LOCK` exists for.
/// One lock held by the handful of tests that care keeps the rest of the suite parallel.
static TASK_PURGE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_task_purge() -> std::sync::MutexGuard<'static, ()> {
    TASK_PURGE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn sample_task(task_id: &str, state: &str, updated_at: u64) -> TaskRow {
    TaskRow {
        task_id: task_id.to_string(),
        context_id: format!("ctx-{task_id}"),
        principal: "vk_a".to_string(),
        direction: "inbound".to_string(),
        state: state.to_string(),
        agent_id: "planner".to_string(),
        artifact_cursor: 7,
        push_callback: "https://example.test/push".to_string(),
        created_at: 100,
        updated_at,
    }
}

fn sample_event(task_id: &str, seq: u64, kind: &str, prev_hash: &str, hash: &str) -> TaskEventRow {
    TaskEventRow {
        task_id: task_id.to_string(),
        seq,
        // Saturating: the full-range test deliberately passes `u64::MAX` as `seq`, and a helper that
        // panicked on its own arithmetic would hide the behaviour under test.
        ts: seq.saturating_add(TASK_LIVE_TS),
        kind: kind.to_string(),
        context_id: format!("ctx-{task_id}"),
        principal: "vk_a".to_string(),
        agent_id: "planner".to_string(),
        state: "working".to_string(),
        request_id: format!("req-{seq}"),
        prev_hash: prev_hash.to_string(),
        hash: hash.to_string(),
    }
}

/// The live MySQL server is SHARED across tests, so each test owns its own task ids and clears them
/// first — the isolation-by-unique-id discipline the rest of this file uses.
fn reset_tasks(store: &MysqlStore, task_ids: &[&str]) {
    let mut conn = store.conn().expect("conn");
    for id in task_ids {
        conn.exec_drop(
            "DELETE FROM task_events WHERE task_id = :id",
            params! { "id" => *id },
        )
        .expect("clear this test's own events");
        conn.exec_drop(
            "DELETE FROM tasks WHERE task_id = :id",
            params! { "id" => *id },
        )
        .expect("clear this test's own tasks");
    }
}

/// THE TEST THAT MATTERS. A round-trip on one live handle cannot distinguish a backend that wrote to
/// the server from one holding a HashMap behind the same trait, and it cannot distinguish either
/// from the trait's accept-and-keep-nothing defaults. So this DROPS the store — closing its pool
/// entirely — then connects a genuinely new one and reads the task back off the server.
#[test]
fn an_in_flight_task_survives_dropping_the_store_and_reconnecting() {
    let Some(url) = test_url() else { return };
    let (t1, t2) = ("t_restart_1", "t_restart_2");
    {
        let store = MysqlStore::connect(&url).expect("connect");
        reset_tasks(&store, &[t1, t2]);
        store
            .put_task(&sample_task(t1, "working", TASK_LIVE_TS + 200))
            .unwrap();
        // The write-through on a state transition REPLACES the row rather than appending a second
        // one — an interrupted task waiting on a human is what a restart has to find.
        let mut interrupted = sample_task(t1, "input-required", TASK_LIVE_TS + 300);
        interrupted.artifact_cursor = 12;
        store.put_task(&interrupted).unwrap();
        store
            .put_task(&sample_task(t2, "submitted", TASK_LIVE_TS + 210))
            .unwrap();
        drop(store);
    }

    // A genuinely new store and pool — nothing carried over in this process.
    let reopened = MysqlStore::connect(&url).expect("reconnect");
    let got = reopened.get_task(t1).unwrap().expect(
        "an in-flight task must survive a restart; got None back after reconnecting, which is the \
         accept-and-keep-nothing default this backend exists to replace",
    );

    // Every field a resume reads has to come back verbatim — not merely a row with the right id.
    assert_eq!(got.state, "input-required", "the LAST state must win");
    assert_eq!(
        got.artifact_cursor, 12,
        "the artifact cursor is where a resubscribe resumes; a stale one replays or loses the gap"
    );
    assert_eq!(
        got.context_id,
        format!("ctx-{t1}"),
        "the resume key is the context id"
    );
    assert_eq!(got.principal, "vk_a");
    assert_eq!(got.direction, "inbound");
    assert_eq!(got.agent_id, "planner");
    assert_eq!(got.push_callback, "https://example.test/push");
    assert_eq!(got.created_at, 100);
    assert_eq!(got.updated_at, TASK_LIVE_TS + 300);

    // UPSERT, not append: two writes for one task_id leave ONE row.
    let mine = reopened
        .list_tasks()
        .unwrap()
        .into_iter()
        .filter(|t| t.task_id == t1 || t.task_id == t2)
        .map(|t| t.task_id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        mine.into_iter().collect::<Vec<_>>(),
        vec![t1.to_string(), t2.to_string()],
        "put_task upserts by task_id; a second write for the same id must replace, never append"
    );

    assert!(
        reopened.get_task("t_nonexistent_task").unwrap().is_none(),
        "an unknown task id reads back None, not an error"
    );
    reset_tasks(&reopened, &[t1, t2]);
}

/// `list_tasks` is deliberately UNFILTERED. The boot rehydrate wants the active rows, the retention
/// sweep wants the terminal ones and the scoped listing wants one principal's; a store that
/// pre-filtered for any one of those would break the other two. Pinned across a reconnect because
/// the boot rehydrate is precisely the caller that only ever sees the post-restart answer.
///
/// Filtered to this test's OWN ids on the way out, not asserted as the whole table: the live server
/// is shared and `list_tasks` is genuinely global, so an exact-set assertion here would be an
/// assertion about what every other concurrently-running test happens to have written.
#[test]
fn list_tasks_returns_every_row_including_terminal_ones_after_a_reconnect() {
    let Some(url) = test_url() else { return };
    let ids = [
        "t_list_active",
        "t_list_waiting",
        "t_list_done",
        "t_list_failed",
    ];
    {
        let store = MysqlStore::connect(&url).expect("connect");
        reset_tasks(&store, &ids);
        store
            .put_task(&sample_task(ids[0], "working", TASK_LIVE_TS + 200))
            .unwrap();
        store
            .put_task(&sample_task(ids[1], "input-required", TASK_LIVE_TS + 201))
            .unwrap();
        store
            .put_task(&sample_task(ids[2], "completed", TASK_LIVE_TS + 202))
            .unwrap();
        store
            .put_task(&sample_task(ids[3], "failed", TASK_LIVE_TS + 203))
            .unwrap();
        drop(store);
    }
    let reopened = MysqlStore::connect(&url).expect("reconnect");
    let all = reopened.list_tasks().unwrap();
    let mut mine = all
        .iter()
        .filter(|t| ids.contains(&t.task_id.as_str()))
        .map(|t| t.task_id.clone())
        .collect::<Vec<_>>();
    mine.sort();
    let mut want = ids.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    want.sort();
    assert_eq!(
        mine,
        want,
        "list_tasks is unfiltered: terminal rows are returned too, and every row survives a \
         reconnect. Got {} rows back in total, which is the accept-and-keep-nothing default this \
         backend exists to replace",
        all.len()
    );
    reset_tasks(&reopened, &ids);
}

/// The per-task provenance chain, read back off the server after a reconnect. Per-TASK rather than
/// one global chain, so the scope of a read is one task and the links have to hold within it.
///
/// Note what this test does NOT do: it never calls `put_task`. That is deliberate. A `task.submitted`
/// event and the first `put_task` are two independent write-throughs and the contract states no
/// ordering between them, so appending an event for a task with no row yet has to WORK — which is
/// why `task_events` carries no foreign key to `tasks` (see the schema).
#[test]
fn a_task_event_chain_survives_a_reconnect_and_still_links() {
    let Some(url) = test_url() else { return };
    let (t1, t2) = ("t_chain_1", "t_chain_2");
    {
        let store = MysqlStore::connect(&url).expect("connect");
        reset_tasks(&store, &[t1, t2]);
        store
            .append_task_event(&sample_event(t1, 1, "task.submitted", "", "e1"))
            .unwrap();
        store
            .append_task_event(&sample_event(t1, 2, "task.working", "e1", "e2"))
            .unwrap();
        store
            .append_task_event(&sample_event(t1, 3, "task.interrupted", "e2", "e3"))
            .unwrap();
        // A second task's chain is independent — it must not leak into the first one's read.
        store
            .append_task_event(&sample_event(t2, 1, "task.submitted", "", "f1"))
            .unwrap();
        drop(store);
    }
    let reopened = MysqlStore::connect(&url).expect("reconnect");
    let got = reopened.list_task_events(t1).unwrap();
    assert_eq!(
        got.len(),
        3,
        "the provenance chain must survive a reconnect; got {} events back, which is the \
         accept-and-keep-nothing default this backend exists to replace",
        got.len()
    );
    assert_eq!(
        got.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![1, 2, 3],
        "oldest-first by seq, which is the order the chain verifier reads"
    );
    assert_eq!(got[0].prev_hash, "", "seq 1 opens the chain");
    for w in got.windows(2) {
        assert_eq!(
            w[1].prev_hash, w[0].hash,
            "the per-task chain must still link after a reconnect: seq {} carries prev_hash {:?} \
             but seq {} persisted hash {:?}",
            w[1].seq, w[1].prev_hash, w[0].seq, w[0].hash
        );
    }
    // Every field round-trips, including the join key that is deliberately NOT chained.
    assert_eq!(got[2].kind, "task.interrupted");
    assert_eq!(got[2].request_id, "req-3");
    assert_eq!(got[1].context_id, format!("ctx-{t1}"));
    assert_eq!(got[1].principal, "vk_a");
    assert_eq!(got[1].agent_id, "planner");
    assert_eq!(got[1].state, "working");
    assert_eq!(got[1].ts, TASK_LIVE_TS + 2);
    // The scope of a read is one task.
    assert_eq!(reopened.list_task_events(t2).unwrap().len(), 1);
    assert!(
        reopened
            .list_task_events("t_unknown_chain")
            .unwrap()
            .is_empty(),
        "a task with no events reads back empty, not an error"
    );
    reset_tasks(&reopened, &[t1, t2]);
}

/// A replayed `(task_id, seq)` UPSERTS. This is where the task-event contract genuinely DIFFERS from
/// `append_mcp_call`'s, and a backend that copied the call log's fork check would be wrong in a way
/// that looks right: the contract says a store "must upsert on that pair — the write-through is
/// idempotent on replay, and rejecting or duplicating a replayed `seq` breaks the chain the engine
/// will verify on read". So neither a duplicate row nor an error, on either an identical replay or a
/// corrected one.
#[test]
fn a_replayed_task_event_upserts_rather_than_duplicating_or_erroring() {
    let Some(url) = test_url() else { return };
    let store = MysqlStore::connect(&url).expect("connect");
    let t = "t_replay_event";
    reset_tasks(&store, &[t]);

    let e = sample_event(t, 1, "task.submitted", "", "e1");
    store.append_task_event(&e).unwrap();
    store
        .append_task_event(&e)
        .expect("an identical replay must succeed, not be rejected as a fork");
    assert_eq!(
        store.list_task_events(t).unwrap().len(),
        1,
        "a replay must not duplicate the row"
    );

    // A rewritten event at the same seq REPLACES, per the contract's "must upsert on that pair".
    let mut corrected = sample_event(t, 1, "task.submitted", "", "e1-corrected");
    corrected.state = "submitted".to_string();
    store.append_task_event(&corrected).unwrap();
    let got = store.list_task_events(t).unwrap();
    assert_eq!(got.len(), 1, "an upsert replaces; it does not append");
    assert_eq!(got[0].hash, "e1-corrected");
    assert_eq!(got[0].state, "submitted");
    reset_tasks(&store, &[t]);
}

/// Retention drops TERMINAL rows only, strictly older than the cutoff, and returns a count it
/// actually performed. An interrupted task waiting on a human is exactly the row that legitimately
/// sits still for a long time; compacting it is losing the work, not reclaiming space.
#[test]
fn purge_tasks_before_drops_only_terminal_rows_and_returns_a_real_count() {
    let Some(url) = test_url() else { return };
    let _guard = lock_task_purge();
    let store = MysqlStore::connect(&url).expect("connect");
    // Own the whole low band for the duration of the lock: a previous run's leftovers would
    // otherwise be counted by the exact-count assertions below.
    clear_purge_band(&store);

    let old = 1_000_000_100;
    let terminal = ["completed", "failed", "canceled", "rejected"];
    for state in terminal {
        store
            .put_task(&sample_task(&format!("t_purge_old_{state}"), state, old))
            .unwrap();
    }
    // Old, and NOT terminal — never dropped, no matter how old. `unrecognised-state` stands in for a
    // token a NEWER engine emits that this build has never heard of: the terminal set is CLOSED, so
    // an unknown token is kept rather than swept.
    // `Completed` (capital C) is NOT the terminal token `completed`, and the difference has to
    // survive the SQL. Under this schema's default collation (utf8mb4_0900_ai_ci, case-insensitive)
    // `'Completed' IN ('completed', ...)` is TRUE, so a state token a newer engine minted would be
    // swept by a terminal set that never recognised it — which is what the utf8mb4_bin collation on
    // `tasks.state` exists to stop.
    for state in [
        "input-required",
        "auth-required",
        "working",
        "submitted",
        "unrecognised-state",
        "Completed",
    ] {
        store
            .put_task(&sample_task(&format!("t_purge_old_{state}"), state, old))
            .unwrap();
    }
    // Terminal but at the cutoff exactly, and terminal but newer — both kept.
    store
        .put_task(&sample_task(
            "t_purge_at_cutoff",
            "completed",
            1_000_000_200,
        ))
        .unwrap();
    store
        .put_task(&sample_task("t_purge_newer", "completed", 1_000_000_300))
        .unwrap();

    let purged = store.purge_tasks_before(1_000_000_200).unwrap();
    assert_eq!(
        purged, 4,
        "only the four TERMINAL rows strictly older than the cutoff go, and the count must be one \
         actually performed rather than a guess"
    );
    let mut left = store
        .list_tasks()
        .unwrap()
        .into_iter()
        .filter(|t| t.updated_at < TASK_PURGE_BAND_TOP)
        .map(|t| t.task_id)
        .collect::<Vec<_>>();
    left.sort();
    assert_eq!(
        left,
        vec![
            "t_purge_at_cutoff",
            "t_purge_newer",
            "t_purge_old_Completed",
            "t_purge_old_auth-required",
            "t_purge_old_input-required",
            "t_purge_old_submitted",
            "t_purge_old_unrecognised-state",
            "t_purge_old_working",
        ],
        "an active or interrupted task is never dropped by retention, an unrecognised state token \
         is never dropped at all (`Completed` is not `completed`), and `before` is strictly \
         less-than so a row exactly at the cutoff is kept"
    );
    assert_eq!(
        store.purge_tasks_before(1_000_000_200).unwrap(),
        0,
        "re-running the same purge removes nothing"
    );
    clear_purge_band(&store);
}

/// Retention has to bound the EVENT table too. The trait offers no `purge_task_events_before`, so if
/// purging a task left its provenance behind, `task_events` would grow without any bound the
/// contract provides a way to apply. Dropping a task therefore drops the chain that belongs to it —
/// and drops nothing belonging to any other task.
#[test]
fn purging_a_task_takes_its_provenance_chain_with_it_and_no_other() {
    let Some(url) = test_url() else { return };
    let _guard = lock_task_purge();
    let store = MysqlStore::connect(&url).expect("connect");
    clear_purge_band(&store);

    let (gone, stays) = ("t_cascade_gone", "t_cascade_stays");
    store
        .put_task(&sample_task(gone, "completed", 1_000_000_100))
        .unwrap();
    store
        .put_task(&sample_task(stays, "working", 1_000_000_100))
        .unwrap();
    store
        .append_task_event(&sample_event(gone, 1, "task.submitted", "", "g1"))
        .unwrap();
    store
        .append_task_event(&sample_event(gone, 2, "task.completed", "g1", "g2"))
        .unwrap();
    store
        .append_task_event(&sample_event(stays, 1, "task.submitted", "", "s1"))
        .unwrap();

    assert_eq!(
        store.purge_tasks_before(1_000_000_200).unwrap(),
        1,
        "exactly the one terminal task in this band is swept, and the count must be one actually \
         performed — 0 here is the accept-and-keep-nothing default this backend exists to replace"
    );
    assert!(
        store.list_task_events(gone).unwrap().is_empty(),
        "the purged task's events go with it; otherwise task_events grows unbounded, because the \
         contract offers no other way to purge them"
    );
    assert_eq!(
        store.list_task_events(stays).unwrap().len(),
        1,
        "another task's chain must be untouched by that purge"
    );
    reset_tasks(&store, &[gone, stays]);
    clear_purge_band(&store);
}

/// Every `u64` field of both rows round-trips at the FULL range, `u64::MAX` included. That is a
/// property of the schema, not an accident: these columns are `BIGINT UNSIGNED`, the same choice
/// every other u64 in this store already gets, so there is no value the contract can hand this
/// backend that it has to refuse or silently mangle. A signed `BIGINT` would have needed a
/// range guard here, and an artifact cursor that wrapped negative and clamped back on read would
/// either replay delivered artifacts or skip undelivered ones with no error ever reported.
#[test]
fn the_task_store_round_trips_the_full_u64_range() {
    let Some(url) = test_url() else { return };
    let store = MysqlStore::connect(&url).expect("connect");
    let t = "t_full_range";
    reset_tasks(&store, &[t]);

    let mut task = sample_task(t, "working", u64::MAX);
    task.artifact_cursor = u64::MAX;
    task.created_at = u64::MAX;
    store
        .put_task(&task)
        .expect("BIGINT UNSIGNED holds the whole u64 range; nothing here needs refusing");
    let got = store.get_task(t).unwrap().expect(
        "the task must read back at all before its range can be checked; None here is the \
         accept-and-keep-nothing default this backend exists to replace",
    );
    assert_eq!(got.artifact_cursor, u64::MAX, "the cursor must not wrap");
    assert_eq!(got.created_at, u64::MAX);
    assert_eq!(got.updated_at, u64::MAX);

    let mut ev = sample_event(t, u64::MAX, "task.submitted", "", "e1");
    ev.ts = u64::MAX;
    store.append_task_event(&ev).expect("seq/ts hold u64::MAX");
    let events = store.list_task_events(t).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].seq, u64::MAX);
    assert_eq!(events[0].ts, u64::MAX);

    reset_tasks(&store, &[t]);
}

/// Two task ids differing only in CASE are two different tasks, and the primary key has to agree.
/// Under this schema's default collation (utf8mb4_0900_ai_ci) they compare EQUAL, so the second
/// `put_task` would upsert onto the first one's row and one of the two tasks would simply be gone —
/// silently, with the write reporting success. `tasks.task_id` is `utf8mb4_bin` to stop exactly that.
#[test]
fn task_ids_differing_only_in_case_are_distinct_tasks() {
    let Some(url) = test_url() else { return };
    let store = MysqlStore::connect(&url).expect("connect");
    let (lower, upper) = ("t_case_variant", "T_CASE_VARIANT");
    reset_tasks(&store, &[lower, upper]);

    store
        .put_task(&sample_task(lower, "working", TASK_LIVE_TS + 1))
        .unwrap();
    store
        .put_task(&sample_task(upper, "completed", TASK_LIVE_TS + 2))
        .expect("a case-different id is a different task, not an upsert onto the first");

    let a = store.get_task(lower).unwrap().expect("the lower-case task");
    let b = store.get_task(upper).unwrap().expect("the upper-case task");
    assert_eq!(a.task_id, lower, "an exact-match lookup must not case-fold");
    assert_eq!(b.task_id, upper);
    assert_eq!(
        a.state, "working",
        "the second put must not have overwritten the first task's row"
    );
    assert_eq!(b.state, "completed");

    // The per-task event chains are scoped just as exactly.
    store
        .append_task_event(&sample_event(lower, 1, "task.submitted", "", "l1"))
        .unwrap();
    store
        .append_task_event(&sample_event(upper, 1, "task.submitted", "", "u1"))
        .unwrap();
    assert_eq!(store.list_task_events(lower).unwrap()[0].hash, "l1");
    assert_eq!(
        store.list_task_events(upper).unwrap()[0].hash,
        "u1",
        "a case-different task id is a different chain, not the same (task_id, seq) slot"
    );

    reset_tasks(&store, &[lower, upper]);
}

/// The band the purge tests own, cleared wholesale. Safe only under `lock_task_purge`, and correct
/// only because every non-purge task test writes above `TASK_PURGE_BAND_TOP`.
fn clear_purge_band(store: &MysqlStore) {
    let mut conn = store.conn().expect("conn");
    conn.exec_drop(
        "DELETE FROM task_events WHERE task_id IN (SELECT task_id FROM tasks WHERE updated_at < :top)",
        params! { "top" => TASK_PURGE_BAND_TOP },
    )
    .expect("clear the purge band's events");
    conn.exec_drop(
        "DELETE FROM tasks WHERE updated_at < :top",
        params! { "top" => TASK_PURGE_BAND_TOP },
    )
    .expect("clear the purge band");
}

/// The v4 -> v5 crossing is additive: a real v4 database gains `tasks` and `task_events` and keeps
/// every row it already had. Runs the REAL `MysqlStore::connect` wiring (real `store_meta` read,
/// real table names) against a DEDICATED throwaway database, for the same reason
/// `try_init_schema_real_wiring_backfills_a_genuinely_pre_v2_database` does: seeding a pre-v5
/// `schema_version` marker in the shared `busbar_test` would race every other test's `connect()`.
#[test]
fn migrate_v4_to_v5_adds_the_task_store_without_wiping_data() {
    let _ddl_guard = lock_fresh_database_ddl();
    let Some(url) = test_url() else { return };
    let db_name = format!(
        "busbar_taskmig_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let root_url = url.replacen("busbar:busbar@", "root:busbar@", 1);
    let root_pool = Pool::new(Opts::from_url(&root_url).unwrap()).unwrap();
    let mut root_conn = root_pool.get_conn().unwrap();
    root_conn
        .query_drop(format!("CREATE DATABASE {db_name}"))
        .unwrap();
    root_conn
        .query_drop(format!(
            "GRANT ALL PRIVILEGES ON {db_name}.* TO 'busbar'@'%'"
        ))
        .unwrap();
    let dedicated_url = {
        let cut = url
            .rfind('/')
            .expect("test_url() must be a mysql:// URL with a /database path");
        format!("{}/{db_name}", &url[..cut])
    };

    // Boot once to build the real schema, then rewind this database to a genuine v4: drop the two
    // new tables and put the marker back. Safe here — this database has no other concurrent user.
    let store1 = MysqlStore::connect(&dedicated_url).expect("first boot must create the schema");
    {
        let mut conn = store1.pool.get_conn().unwrap();
        conn.query_drop("DROP TABLE task_events").unwrap();
        conn.query_drop("DROP TABLE tasks").unwrap();
        conn.query_drop("UPDATE store_meta SET v = '4' WHERE k = 'schema_version'")
            .unwrap();
        conn.query_drop(
            "INSERT INTO api_keys (id, name, key_group, allowed_pools, labels, enabled, \
             generation_hash, created_at, updated_at, revision) \
             VALUES ('vk_v4', 'n', '', NULL, '{}', 1, 'g1', 0, 0, 0)",
        )
        .unwrap();
    }
    drop(store1);

    let store2 = MysqlStore::connect(&dedicated_url).expect("a v4 database must migrate to v5");
    let survived = store2.get_key("vk_v4").unwrap().is_some();
    store2
        .put_task(&sample_task("t_v5", "working", TASK_LIVE_TS))
        .expect("the newly created tasks table must be writable after the migration");
    store2
        .append_task_event(&sample_event("t_v5", 1, "task.submitted", "", "e1"))
        .expect("the newly created task_events table must be writable after the migration");
    let task_back = store2.get_task("t_v5").unwrap().is_some();
    let events_back = store2.list_task_events("t_v5").unwrap().len();
    drop(store2);

    root_conn
        .query_drop(format!("DROP DATABASE {db_name}"))
        .unwrap();

    assert!(
        survived,
        "a real v4 key must survive the v4->v5 crossing; the migration is purely additive"
    );
    assert!(task_back, "the migrated tasks table must read back");
    assert_eq!(
        events_back, 1,
        "the migrated task_events table must read back"
    );
}
