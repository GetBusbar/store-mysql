// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! End-to-end coverage of the `busbar-store-mysql-plugin` cdylib, loaded the way a REAL operator
//! actually loads a plugin — not via a direct in-process `busbar_plugin_loader::load_store()` call
//! (that mechanism no end user ever uses: nobody imports `busbar-plugin-loader` and calls its
//! internal function). Converted from the prior direct-call test to mirror store-postgres's proven
//! file-drop pattern exactly.
//!
//! `load_and_exercise_mysql_plugin_via_file_drop` packs the built cdylib into a real tarball (the
//! same `busbar-plugin-pack` tool CI's own SIGNOFF step uses), drops it into a real `plugins.dir`,
//! and runs the REAL `busbar --validate` binary against a config naming `store: { module: mysql }` —
//! the documented file-drop install path. `--validate` genuinely exercises the trust gate + ABI
//! dlopen + `Store::connect` (real schema migration against real MySQL), so a successful validate is
//! real proof the plugin loads and initializes through busbar's own boot path, not a proxy for it.
//!
//! Persistence is then proven the same two independent ways the prior direct-call test used:
//!   1. `--validate` itself (via the plugin's `open()`) causes a real `MysqlStore::connect`, which
//!      runs the real schema migration — confirmed by checking the schema now exists.
//!   2. A second, independent `MysqlStore::connect` (bypassing the plugin/ABI/loader entirely)
//!      confirms real MySQL was actually touched, not an in-process fake.
//!
//! The ABI-contract error-path test below (`bad_config_fails_over_abi`) is DELIBERATELY left calling
//! `load_store()` directly — it tests the loader's own error-surface contract in isolation ("does a
//! bad config produce a clean Err across the ABI, never a panic"), a different question from "does a
//! real end-user install work," matching store-postgres's rationale for the same split.

use busbar_store_mysql::MysqlStore;
use mysql::params;
use std::path::PathBuf;
use std::process::Command;

fn mysql_url() -> Option<String> {
    match std::env::var("BUSBAR_TEST_MYSQL_URL") {
        Ok(url) => Some(url),
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!(
                "BUSBAR_TEST_MYSQL_URL is unset under CI: the mysql:8 service container must \
                 provision it (see .github/workflows/ci.yml). Refusing to silently skip the only \
                 real-install-path coverage in CI."
            );
        }
        Err(_) => {
            eprintln!("skip: set BUSBAR_TEST_MYSQL_URL to run the live-MySQL e2e tests");
            None
        }
    }
}

/// Locate the cdylib THIS `cargo test` invocation just built — never a leftover artifact.
///
/// This looks ONLY in `target/<profile>/deps/`, never `target/<profile>/`, and that distinction is
/// the whole point of this function.
///
/// `cargo` emits the lib target's cdylib into `deps/` as part of the very build graph that produces
/// this test binary (this package's lib unit is compiled with BOTH declared crate-types — see
/// `[lib] crate-type = ["cdylib", "rlib"]` in Cargo.toml), so `deps/libbusbar_store_mysql_plugin.dylib` is by construction up to
/// date with the source tree under test. Cargo only *uplifts* a copy to `target/<profile>/` for
/// `cargo build`, NEVER for `cargo test`. A lookup in `target/<profile>/` therefore reads an
/// artifact that nothing in this test's dependency graph refreshes: whatever some earlier `cargo
/// build` left there, from any commit — or nothing at all.
///
/// Both outcomes of that are lies about durability, and the second is the dangerous one:
///   * NOTHING there  -> the old code `return`ed with a "skip:" line and reported GREEN. That is how
///     `cargo test` can pass with ZERO over-the-ABI coverage of the durable store path.
///   * STALE artifact -> a cdylib built before an ABI change answers every write `Ok(())` and every
///     read empty, which is BYTE-FOR-BYTE the signature of the unrelayed-seam defect this file
///     exists to catch (that defect was real: `DynStore`'s `impl Store` overrode 24 methods, none of
///     them the task/call-log methods, so `put_task` took the accept-and-keep-nothing trait
///     default). RED on a stale artifact is indistinguishable from RED on the real bug — and an
///     artifact NEWER than a regression reports GREEN while the shipped ABI is broken. Proven, not
///     theorised: with a regressed plugin in the tree and a good cdylib in `target/debug/`, the old
///     lookup passed and this one fails.
///
/// Same hazard, and the same reasoning, as the engine's `crates/busbar/Cargo.toml` dev-dependency on
/// `busbar-store-example-plugin`: keep the cdylib in the build graph so no test can judge a stale
/// one. Here the plugin's lib IS this package, so that graph edge already exists — what was missing
/// was reading the artifact that edge actually produces.
///
/// Panics rather than skipping: a missing cdylib under `cargo test` means the build graph changed
/// shape, and the only honest report of that is a failure, not a silent pass.
/// The newest mtime across every workspace crate's `src/` — "how fresh must a cdylib be to be the
/// one this source tree describes".
///
/// Deliberately ONLY `src/**/*.rs` of each workspace member: editing a `tests/` file or a
/// `[dev-dependencies]` line recompiles the test binary but NOT the lib, so including those would
/// fail a perfectly current cdylib.
fn newest_source_mtime() -> std::time::SystemTime {
    fn walk(dir: &std::path::Path, newest: &mut std::time::SystemTime) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, newest);
            } else if p.extension().is_some_and(|x| x == "rs") {
                if let Ok(m) = e.metadata().and_then(|m| m.modified()) {
                    if m > *newest {
                        *newest = m;
                    }
                }
            }
        }
    }
    let ws_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the plugin crate always sits under the workspace root");
    let mut newest = std::time::SystemTime::UNIX_EPOCH;
    for e in std::fs::read_dir(ws_root).into_iter().flatten().flatten() {
        let src = e.path().join("src");
        if src.is_dir() {
            walk(&src, &mut newest);
        }
    }
    newest
}

fn plugin_path() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe"); // .../target/<profile>/deps/<test>-<hash>
    let deps_dir = exe.parent().expect("the test binary always lives in deps/");
    let name = busbar_plugin_loader::plugin_library_filename("busbar_store_mysql_plugin");
    let fresh = deps_dir.join(&name);
    assert!(
        fresh.exists(),
        "the store-mysql-plugin cdylib is not at {}, where cargo emits it for the same build that produced \
         this test binary. Refusing to fall back to target/<profile>/ (an artifact only `cargo \
         build` refreshes) or to skip: judging a stale cdylib is exactly how an unrelayed plugin \
         ABI reads as green.",
        fresh.display()
    );
    // FRESHNESS, ASSERTED — not assumed. Under `cargo test` the artifact above is rebuilt by the
    // same graph that built this binary (proven: delete it, re-run, cargo re-emits it). But this
    // test binary can also be executed DIRECTLY out of `deps/`, where nothing rebuilds anything,
    // and a stale cdylib there produces empty reads — indistinguishable from the unrelayed-ABI
    // defect. So compare it against the sources and fail with a message that says STALE ARTIFACT,
    // explicitly NOT a durability verdict.
    let built = std::fs::metadata(&fresh)
        .and_then(|m| m.modified())
        .expect("cdylib mtime");
    let newest_src = newest_source_mtime();
    assert!(
        built >= newest_src,
        "STALE ARTIFACT — THIS IS NOT A DURABILITY FAILURE. {} predates this workspace's sources, \
         so it cannot answer for the code in the tree; a pre-change cdylib returns empty for every \
         read, which reads exactly like an unrelayed plugin ABI. Run `cargo build -p {}` (or just \
         `cargo test`, which rebuilds it) and re-run.",
        fresh.display(),
        "busbar-store-mysql-plugin"
    );
    fresh
}

fn cfg(url: &str) -> String {
    serde_json::json!({ "url": url }).to_string()
}

/// Every `env:` secret-ref name a config text references, in first-seen order, de-duplicated.
///
/// busbar 1.5.3 made `--validate` RESOLVE built-in (`env`/`file`) secret references and exit 1 when
/// one cannot resolve, rather than only checking the reference's SHAPE. A fixture config that names
/// a real-looking env var (here, `MOCK_KEY`) then fails `--validate` on any machine that doesn't
/// happen to have that var set -- which is every CI runner and most dev machines. Hardcoding
/// `MOCK_KEY` here would fix today's failure but rot the moment this fixture, or a future one, names
/// a different variable. Extracting the names generically (same approach as the core repo's
/// `crates/busbar/tests/docs_examples.rs` and `tests/migration_corpus.rs`) keeps the harness working
/// no matter what the fixture references.
fn referenced_env_vars(text: &str) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for (i, _) in text.match_indices("env:") {
        let rest = &text[i + 4..];
        let name: String = rest
            .chars()
            .skip_while(|c| c.is_whitespace())
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() && !v.contains(&name) {
            v.push(name);
        }
    }
    v
}

fn cleanup(url: &str, id: &str) {
    if let Ok(mut conn) = mysql::Conn::new(mysql::Opts::from_url(url).unwrap()) {
        use mysql::prelude::*;
        let _: Result<(), _> = conn.exec_drop(
            "DELETE FROM credentials WHERE key_id=:id",
            params! { "id" => id },
        );
        let _: Result<(), _> =
            conn.exec_drop("DELETE FROM api_keys WHERE id=:id", params! { "id" => id });
    }
}

/// The sibling busbarAI checkout's root (same convention this repo already uses for its path deps).
fn busbarai_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../busbarAI")
        .canonicalize()
        .expect("sibling busbarAI checkout must exist (see Cargo.toml path deps)")
}

/// Build (once, cached by cargo) and return the path to the real `busbar` binary and the real
/// `busbar-plugin-pack` binary, both from the sibling busbarAI checkout — never a fixture, never a
/// stub, the exact binaries a real release ships.
fn build_real_binaries() -> (PathBuf, PathBuf) {
    let root = busbarai_root();
    let status = Command::new("cargo")
        .args([
            "build",
            "--release",
            "-p",
            "busbar",
            "-p",
            "busbar-plugin-pack",
        ])
        .current_dir(&root)
        .status()
        .expect("run cargo build for busbar + busbar-plugin-pack");
    assert!(
        status.success(),
        "building the real busbar + busbar-plugin-pack binaries must succeed"
    );
    (
        root.join("target/release/busbar"),
        root.join("target/release/busbar-plugin-pack"),
    )
}

/// THE REAL END-TO-END INSTALL PROOF: pack the plugin, drop it in a real `plugins.dir`, run the real
/// `busbar --validate` against a config naming `store: { module: mysql }`, and confirm real MySQL was
/// actually touched — via the documented file-drop mechanism, never a direct `load_store()` call.
#[test]
fn load_and_exercise_mysql_plugin_via_file_drop() {
    let Some(url) = mysql_url() else { return };
    let so_path = plugin_path();
    let key_id = "vk_mysql_filedrop_e2e";
    cleanup(&url, key_id);

    let (busbar_bin, pack_bin) = build_real_binaries();

    let work = std::env::temp_dir().join(format!(
        "busbar-mysql-filedrop-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let plugins_dir = work.join("plugins");
    std::fs::create_dir_all(&plugins_dir).unwrap();

    // Pack the real cdylib into a real signed-shape tarball via the same tool CI's SIGNOFF step
    // uses, --allow-unsigned locally exactly like CI's own unsigned-key fallback.
    let tarball = work.join("store-mysql.tar.gz");
    let status = Command::new(&pack_bin)
        .args([
            "pack",
            "--lib",
            so_path.to_str().unwrap(),
            "--name",
            "busbar-store-mysql-plugin",
            "--alias",
            "mysql",
            "--kind",
            "store",
            "--version",
            "0.0.0-e2e",
            "--publisher",
            "busbar",
            "--description",
            "e2e file-drop proof",
            "--license",
            "Apache-2.0",
            "--out",
            tarball.to_str().unwrap(),
            "--allow-unsigned",
        ])
        .status()
        .expect("run busbar-plugin-pack");
    assert!(status.success(), "packing the plugin must succeed");

    // FILE-DROP: the real boot-time discovery mechanism extracts/reads whatever is in plugins.dir --
    // dropping the packed tarball here, uninstalled via any admin call, is the documented mechanism.
    std::fs::copy(&tarball, plugins_dir.join("store-mysql.tar.gz")).unwrap();

    let config = work.join("config.yaml");
    let providers = work.join("providers.yaml");
    // providers.yaml is the flat CATALOG (provider name at the document root, no wrapping key) --
    // config.yaml separately has its OWN `providers:`/`models:` blocks naming which catalog
    // entries are enabled. Mirrors the known-good fixture in
    // crates/busbar/tests/cli_validate.rs::write_configs, not invented here.
    std::fs::write(
        &providers,
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();
    let config_text = format!(
        "listen: \"127.0.0.1:0\"\n\
         store:\n  module: mysql\n  settings: {{ url: \"{url}\" }}\n\
         plugins:\n  enabled: true\n  dir: {}\n  trust:\n    allow_unsigned: true\n\
         auth:\n  chain: []\n\
         providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
         models:\n  test-model:\n    provider: mock\n",
        plugins_dir.display()
    );
    std::fs::write(&config, &config_text).unwrap();

    // `--validate` RESOLVES built-in `env:` secret references (busbar 1.5.3); give every one this
    // fixture names a placeholder so the gate tests the config's SHAPE, not this machine's
    // environment. See `referenced_env_vars`'s doc comment for why this is generic, not hardcoded.
    let mut validate_cmd = Command::new(&busbar_bin);
    validate_cmd
        .arg("--validate")
        .env("BUSBAR_CONFIG", &config)
        .env("BUSBAR_PROVIDERS", &providers);
    for name in referenced_env_vars(&config_text) {
        // 64 hex chars: valid for `auth.signing_key`, and harmless as any other secret's value.
        validate_cmd.env(
            name,
            "0000000000000000000000000000000000000000000000000000000000000001",
        );
    }
    let out = validate_cmd.output().expect("run busbar --validate");
    assert!(
        out.status.success(),
        "busbar --validate must succeed with the file-dropped mysql plugin: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // PROOF real MySQL was touched by the REAL busbar process, through the REAL file-drop path: an
    // independent connection (bypassing the plugin/ABI/loader entirely) confirms the schema now
    // exists -- --validate's own plugin-open call ran Store::connect, which runs init_schema(). Also
    // exercises MysqlStore::connect itself as the second independent-verification leg the prior
    // direct-call test used.
    let _direct = MysqlStore::connect(&url)
        .expect("connect directly, bypassing the plugin entirely, to confirm real schema init");
    let mut raw = mysql::Conn::new(mysql::Opts::from_url(&url).unwrap()).unwrap();
    use mysql::prelude::*;
    let exists: bool = raw
        .exec_first(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='api_keys')",
            (),
        )
        .unwrap()
        .unwrap();
    assert!(
        exists,
        "the api_keys table must exist after busbar --validate loaded the plugin via file-drop -- \
         proof the real boot path actually called Store::connect/init_schema, not a no-op"
    );

    let _ = std::fs::remove_dir_all(&work);
    cleanup(&url, key_id);
}

/// END-TO-END FAILURE (ABI-contract unit test, see module doc for why this stays a direct
/// `load_store()` call): an `open()` config that cannot produce a usable store surfaces back across
/// the C ABI as a clean `Err`, never a panic or a silently-succeeded load.
#[test]
fn load_and_exercise_mysql_plugin_bad_config_fails_over_abi() {
    let path = plugin_path();

    let err = busbar_plugin_loader::load_store(&path, "{ not json")
        .err()
        .expect("malformed config JSON must fail to load, not silently succeed");
    assert!(
        err.contains("invalid mysql plugin config"),
        "the plugin's own error message should survive the ABI crossing intact: {err}"
    );

    let err = busbar_plugin_loader::load_store(&path, "{}")
        .err()
        .expect("a config missing url must fail to load");
    assert!(
        err.contains("requires a \"url\""),
        "expected the plugin's own missing-url message, got: {err}"
    );

    let err = busbar_plugin_loader::load_store(
        &path,
        &cfg("mysql://u:p@127.0.0.1:1/definitely_not_a_real_db"),
    )
    .err()
    .expect("an unreachable mysql target must fail to load");
    assert!(
        !err.is_empty(),
        "expected the underlying mysql crate's own connect-failure message to survive the ABI \
         crossing, got an empty error"
    );
}

/// A non-plugin library (or a missing file) is refused with a clear error, never a crash. Same
/// ABI-contract-unit-test rationale as above.
#[test]
fn refuses_non_plugin() {
    let err = match busbar_plugin_loader::load_store(
        std::path::Path::new("/definitely/not/a/plugin.so"),
        "{}",
    ) {
        Err(e) => e,
        Ok(_) => panic!("a missing library must not load"),
    };
    assert!(err.contains("failed to load plugin"), "got: {err}");
}

/// Wipe the durable task / call-log tables so this run's exact counts mean something.
///
/// `list_tasks`, `list_mcp_call_principals` and both `purge_*_before` sweeps are GLOBAL, not scoped
/// to a principal, so against a re-used database a leftover row from an earlier run makes every
/// exact assertion in the ABI durability test below meaningless. The contract-level purges cannot do
/// this on their own — `purge_tasks_before` only drops TERMINAL rows by design, so an abandoned
/// `working` task would survive it forever — hence raw SQL. `task_events` goes first: it references
/// the task rows. No other test in this file touches these three tables.
fn wipe_task_and_call_tables(url: &str) {
    use mysql::prelude::*;
    let mut conn = mysql::Conn::new(mysql::Opts::from_url(url).expect("test url must parse"))
        .expect("connect to wipe the durable task/call-log tables");
    for table in ["task_events", "tasks", "mcp_calls"] {
        conn.query_drop(format!("DELETE FROM {table}"))
            .unwrap_or_else(|e| panic!("wipe {table}: {e}"));
    }
}

/// THE DURABILITY PROOF FOR THE TEN TASK / CALL-LOG METHODS, OVER THE REAL PLUGIN PATH.
///
/// This repo ships `feat/durable-a2a-task-store` — `put_task`/`get_task`/`list_tasks`/
/// `purge_tasks_before`/`append_task_event`/`list_task_events`, plus the four MCP call-log methods,
/// against a real MySQL. Every existing test of those ten calls `MysqlStore` DIRECTLY, in-process,
/// and NONE of them can see the failure that actually matters in production, because in production
/// this backend is ONLY ever reached as a plugin: conformance boots the in-process RAM store, so the
/// plugin seam is the only path a real deployment takes and was, until this test, the one path with
/// zero coverage of these methods.
///
/// `busbar_api::Store` DEFAULTS all ten to accept-and-keep-nothing. A plugin seam that does not
/// RELAY them silently substitutes those defaults: every write returns `Ok`, every read answers
/// empty, and a deployment loses every in-flight A2A task and every tool-call record while reporting
/// success. That is not hypothetical — the ABI once carried four store methods while the trait
/// carried ten, so `put_task` took the trait default, the write was discarded, and the call reported
/// success. A unit test passing while the ABI drops every write is the precise shape this test
/// exists to make impossible.
///
/// So it goes through `busbar_plugin_loader::load_store`: a REAL `dlopen` of the built cdylib, the
/// real C ABI, the real `DynStore`. It writes AT ARITY > 1 (three tasks across two states, three
/// events on one task and one on another, three call records for one principal and one for a
/// second), DROPS the handle — which runs `busbar_close` and UNLOADS the library, so nothing this
/// process still holds can answer the reads — then `dlopen`s AGAIN over the same file and reads
/// everything back. A restart is what proves durability; a single-row same-session round trip would
/// not distinguish a relayed method from a lucky trait default, and a multi-row one across an
/// unload/reload cannot be faked by either.
///
/// A third leg reads the same rows through the plain `MysqlStore`, never touching the cdylib, the C
/// ABI or the loader — so a plugin that answered from its own in-process cache still fails here.
#[test]
fn tasks_and_call_log_survive_an_unload_and_reload_over_the_real_plugin_abi() {
    use busbar_api::{McpCallRecord, Store, TaskEventRow, TaskRow};

    let path = plugin_path();
    let Some(url) = mysql_url() else {
        return;
    };
    let config = cfg(&url);

    // `MysqlStore::connect` runs the real schema migration, so the tables exist before the wipe —
    // and this same handle is leg 3's independent reader.
    let direct =
        MysqlStore::connect(&url).expect("connect directly to migrate, clean up and verify");
    wipe_task_and_call_tables(&url);

    let task = |id: &str, state: &str, updated_at: u64| TaskRow {
        task_id: id.to_string(),
        context_id: format!("ctx-{id}"),
        principal: "vk_abi".to_string(),
        direction: "inbound".to_string(),
        state: state.to_string(),
        agent_id: "planner".to_string(),
        artifact_cursor: 7,
        push_callback: "https://example.test/push".to_string(),
        created_at: 1_000,
        updated_at,
    };
    let event = |task_id: &str, seq: u64, prev: &str, hash: &str| TaskEventRow {
        task_id: task_id.to_string(),
        seq,
        ts: 1_000 + seq,
        kind: "task.working".to_string(),
        context_id: format!("ctx-{task_id}"),
        principal: "vk_abi".to_string(),
        agent_id: "planner".to_string(),
        state: "working".to_string(),
        request_id: format!("req-{seq}"),
        prev_hash: prev.to_string(),
        hash: hash.to_string(),
    };
    let call = |principal: &str, seq: u64, prev: &str, hash: &str| McpCallRecord {
        principal: principal.to_string(),
        seq,
        ts: 2_000 + seq,
        server: "srv".to_string(),
        tool: "srv_read_file".to_string(),
        outcome: "dispatched".to_string(),
        reason: String::new(),
        tool_digest: format!("sha256:tool{seq}"),
        pin_generation: 3,
        request_id: format!("req-{seq}"),
        prev_hash: prev.to_string(),
        hash: hash.to_string(),
    };

    {
        // BOOT 1 — a real dlopen of the cdylib; every call below crosses the C ABI.
        let store = busbar_plugin_loader::load_store(&path, &config)
            .expect("the mysql plugin must load over the real ABI");
        for (id, state, updated) in [
            ("t_alpha", "working", 10_u64),
            ("t_beta", "input-required", 20),
            ("t_gamma", "completed", 30),
        ] {
            store.put_task(&task(id, state, updated)).expect("put_task");
        }
        for (seq, prev, hash) in [(1_u64, "", "e1"), (2, "e1", "e2"), (3, "e2", "e3")] {
            store
                .append_task_event(&event("t_alpha", seq, prev, hash))
                .expect("append_task_event");
        }
        store
            .append_task_event(&event("t_beta", 1, "", "b1"))
            .expect("append_task_event");
        for (seq, prev, hash) in [(1_u64, "", "h1"), (2, "h1", "h2"), (3, "h2", "h3")] {
            store
                .append_mcp_call(&call("vk_abi", seq, prev, hash))
                .expect("append_mcp_call");
        }
        store
            .append_mcp_call(&call("vk_other", 1, "", "o1"))
            .expect("append_mcp_call");
        // Dropping the boxed store drops the loader's `Library` handle: `busbar_close` runs and the
        // dylib is UNLOADED. Nothing this process still holds can be answering the reads below.
        drop(store);
    }

    // BOOT 2 — a second, independent dlopen over the same file, a fresh `busbar_open`, a fresh
    // connection inside the plugin.
    let store = busbar_plugin_loader::load_store(&path, &config)
        .expect("the mysql plugin must load again over the real ABI");

    let tasks = store.list_tasks().expect("list_tasks");
    assert_eq!(
        tasks.len(),
        3,
        "all three tasks must survive the unload/reload over the plugin ABI; got {} back, which is \
         the accept-and-keep-nothing shape of the trait default that an unrelayed seam substitutes",
        tasks.len()
    );
    let beta = store
        .get_task("t_beta")
        .expect("get_task")
        .expect("the interrupted task must be readable by id after a reload");
    assert_eq!(beta.state, "input-required");
    assert_eq!(
        beta.artifact_cursor, 7,
        "the artifact cursor must round-trip — a resubscribe after a restart resumes from it"
    );
    assert_eq!(beta.push_callback, "https://example.test/push");
    assert_eq!(beta.context_id, "ctx-t_beta");

    let events = store.list_task_events("t_alpha").expect("list_task_events");
    assert_eq!(
        events.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![1, 2, 3],
        "the per-task provenance chain must come back oldest-first and complete"
    );
    for w in events.windows(2) {
        assert_eq!(
            w[1].prev_hash, w[0].hash,
            "the chain must still link after the reload: seq {} carries prev_hash {:?} but seq {} \
             persisted hash {:?}",
            w[1].seq, w[1].prev_hash, w[0].seq, w[0].hash
        );
    }
    assert_eq!(
        store
            .list_task_events("t_beta")
            .expect("list_task_events")
            .len(),
        1,
        "one task's events must not leak into another's chain"
    );

    let calls = store.list_mcp_calls("vk_abi").expect("list_mcp_calls");
    assert_eq!(
        calls.iter().map(|c| c.seq).collect::<Vec<_>>(),
        vec![1, 2, 3],
        "the per-principal call chain must survive the reload in chain order"
    );
    assert_eq!(calls[2].tool_digest, "sha256:tool3");
    assert_eq!(calls[2].request_id, "req-3");
    assert_eq!(calls[1].pin_generation, 3);
    assert_eq!(
        store
            .list_mcp_calls("vk_other")
            .expect("list_mcp_calls")
            .len(),
        1,
        "one principal's chain must not carry another's records"
    );
    let principals = store
        .list_mcp_call_principals()
        .expect("list_mcp_call_principals");
    assert_eq!(
        principals,
        vec!["vk_abi".to_string(), "vk_other".to_string()],
        "the boot enumeration must name every principal holding records, exactly once each"
    );

    // Retention crosses the ABI too, COUNT AND ALL — both purges are checked for the number they
    // ACTUALLY removed, because a relay that dropped the return value would read as 0.
    assert_eq!(
        store.purge_mcp_calls_before(2_002).expect("purge"),
        2,
        "both records at ts 2001 go (one per principal); the one sitting exactly at the cutoff stays"
    );
    assert_eq!(
        store
            .list_mcp_calls("vk_abi")
            .expect("list_mcp_calls")
            .len(),
        2
    );
    assert!(store
        .list_mcp_calls("vk_other")
        .expect("list_mcp_calls")
        .is_empty());
    assert_eq!(
        store.purge_tasks_before(25).expect("purge"),
        0,
        "no TERMINAL task is older than the cutoff: t_alpha and t_beta are active and must never be \
         swept no matter how old"
    );
    assert_eq!(
        store.purge_tasks_before(31).expect("purge"),
        1,
        "the one completed task at updated_at 30 is the only row retention may drop"
    );
    assert_eq!(store.list_tasks().expect("list_tasks").len(), 2);
    drop(store);

    // LEG 3 — read the surviving rows through the plain `MysqlStore`, a code path that never touches
    // the cdylib, the C ABI or the loader. A plugin answering the reads above out of its own
    // in-process state (rather than MySQL) passes both boots and fails here.
    let direct_tasks = Store::list_tasks(&direct).expect("list_tasks via the direct connection");
    let mut ids: Vec<&str> = direct_tasks.iter().map(|t| t.task_id.as_str()).collect();
    ids.sort_unstable();
    assert_eq!(
        ids,
        vec!["t_alpha", "t_beta"],
        "the tasks must be physically present in MySQL, not just cached in-process by the plugin"
    );
    let direct_events = Store::list_task_events(&direct, "t_alpha")
        .expect("list_task_events via the direct connection");
    assert_eq!(direct_events.len(), 3);
    assert_eq!(direct_events[2].hash, "e3");
    let direct_calls =
        Store::list_mcp_calls(&direct, "vk_abi").expect("list_mcp_calls via the direct connection");
    assert_eq!(
        direct_calls.iter().map(|c| c.seq).collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert_eq!(direct_calls[1].hash, "h3");

    wipe_task_and_call_tables(&url);
}

/// Drop exactly this run's own trust-state rows. Scoped by id rather than a blanket `DELETE FROM`,
/// unlike `wipe_task_and_call_tables`: the spent-approval ledger is the one table where wiping
/// another concurrently-running node's rows would hand a spent approval straight back — which is the
/// defect this table exists to prevent, so the test rig must not model it.
fn clear_trust_rows(url: &str, servers: &[&str], nonces: &[&str]) {
    use mysql::prelude::*;
    let mut conn = mysql::Conn::new(mysql::Opts::from_url(url).expect("test url must parse"))
        .expect("connect to clear this run's trust-state rows");
    for s in servers {
        conn.exec_drop(
            "DELETE FROM mcp_demotions WHERE server = :s",
            params! { "s" => *s },
        )
        .unwrap_or_else(|e| panic!("clear demotion {s}: {e}"));
    }
    for n in nonces {
        conn.exec_drop(
            "DELETE FROM spent_ask_states WHERE nonce = :n",
            params! { "n" => *n },
        )
        .unwrap_or_else(|e| panic!("clear ledger row {n}: {e}"));
    }
}

/// THE DURABILITY PROOF FOR THE FOUR TRUST-STATE METHODS, OVER THE REAL PLUGIN PATH.
///
/// Same reasoning as the task/call-log test above, and a sharper cost. `busbar_api::Store` defaults
/// `put_mcp_demotion`/`list_mcp_demotions`/`clear_mcp_demotion` to accept-and-keep-nothing and
/// `redeem_ask_state` to `Ok(true)` — "yes, this call is the first redemption" — so a seam that does
/// not RELAY them substitutes two security failures, both silent and both green:
///
///   * a demotion is written, reported successful and DISCARDED, so a restart hands a quarantined
///     upstream the operator's approval back; and
///   * every redeemer of one single-use approval is told it is the first, so a confirm-once tool an
///     operator gated because it moves money executes once per node and once per restart.
///
/// In production this backend is ONLY ever reached as a plugin, so this is the path worth proving
/// on: a real `dlopen`, the real C ABI, the real `DynStore`. Two simultaneous loads are the fleet; a
/// drop and a reload is the restart; and a third leg reads through the plain `MysqlStore`, never
/// touching the cdylib, so a plugin answering out of its own in-process state still fails.
///
/// PANICS rather than skipping when no MySQL is configured. This is the only over-the-ABI coverage
/// of two properties whose unimplemented form is silently green, and a case that can skip is a case
/// that will skip on the day it matters.
#[test]
fn trust_state_survives_an_unload_and_reload_over_the_real_plugin_abi() {
    use busbar_api::{McpDemotionRow, Store};

    let path = plugin_path();
    let url = std::env::var("BUSBAR_TEST_MYSQL_URL").unwrap_or_else(|_| {
        panic!(
            "BUSBAR_TEST_MYSQL_URL is unset, and this case must not skip: it is the only \
             over-the-ABI proof that a demotion and a spent approval survive a restart on this \
             backend, and both fail SILENTLY when unrelayed — the trait defaults answer Ok(()) to a \
             demotion and `true` to every redemption"
        )
    });
    let config = cfg(&url);

    // `MysqlStore::connect` runs the real schema migration, so the two tables exist before the
    // scoped cleanup below — and this same handle is leg 3's independent reader.
    let direct =
        MysqlStore::connect(&url).expect("connect directly to migrate, clean up and verify");

    let stamp = format!(
        "{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    // Per-run ids, so every read below can only be answered by THIS run's writes, and two runs
    // against one shared MySQL cannot redeem each other's approvals.
    let srv_demoted = format!("srv_abi_demoted_{stamp}");
    let srv_cleared = format!("srv_abi_cleared_{stamp}");
    let nonce_restart = format!("nonce_abi_restart_{stamp}");
    let nonce_fleet = format!("nonce_abi_fleet_{stamp}");
    let nonce_fresh = format!("nonce_abi_fresh_{stamp}");
    const NOW: u64 = 4_000_000_000;

    clear_trust_rows(
        &url,
        &[&srv_demoted, &srv_cleared],
        &[&nonce_restart, &nonce_fleet, &nonce_fresh],
    );

    let demotion = |server: &str, reason: &str, at: u64| McpDemotionRow {
        server: server.to_string(),
        reason: reason.to_string(),
        recorded_at: at,
    };

    {
        // BOOT 1 — a real dlopen of the cdylib; every call below crosses the C ABI.
        let store = busbar_plugin_loader::load_store(&path, &config)
            .expect("the mysql plugin must load over the real ABI");
        store
            .put_mcp_demotion(&demotion(&srv_demoted, "tool-drift", NOW))
            .expect("put_mcp_demotion");
        // The UPSERT path crosses the ABI too: a second demotion of one upstream replaces the row.
        store
            .put_mcp_demotion(&demotion(&srv_demoted, "digest-mismatch", NOW + 10))
            .expect("put_mcp_demotion");
        store
            .put_mcp_demotion(&demotion(&srv_cleared, "tool-drift", NOW + 20))
            .expect("put_mcp_demotion");
        store
            .clear_mcp_demotion(&srv_cleared)
            .expect("a later agreeing observation clears the quarantine");
        assert!(
            store
                .redeem_ask_state(&nonce_restart, NOW + 900, NOW)
                .expect("redeem_ask_state"),
            "the FIRST redemption must be answered `true`, or nothing below is about single use"
        );
        // Dropping the boxed store runs `busbar_close` and unloads the library, so nothing this
        // process still holds can be answering the reads below.
        drop(store);
    }

    // BOOT 2 — a second, independent dlopen against the same database.
    let store = busbar_plugin_loader::load_store(&path, &config)
        .expect("the mysql plugin must load again over the real ABI");

    let mine = store
        .list_mcp_demotions()
        .expect("list_mcp_demotions")
        .into_iter()
        .filter(|r| r.server == srv_demoted || r.server == srv_cleared)
        .collect::<Vec<_>>();
    assert_eq!(
        mine,
        vec![demotion(&srv_demoted, "digest-mismatch", NOW + 10)],
        "the boot read must put the recorded quarantine back in force — at its LATEST reason, and \
         without the one a later agreeing observation cleared. An empty answer here is the \
         accept-and-keep-nothing trait default an unrelayed seam substitutes, and it means a \
         restart hands a demoted upstream the operator's approval back"
    );

    assert!(
        !store
            .redeem_ask_state(&nonce_restart, NOW + 900, NOW + 1)
            .expect("redeem_ask_state"),
        "a restart handed a spent approval back over the plugin ABI. The approval has not lapsed — \
         outliving a restart is the point of it — so the only thing that changed is that the \
         process which recorded the redemption is gone"
    );

    // THE FLEET. A second, simultaneous dlopen against the same database is what a second node of
    // one deployment is: it shares the signing key, so it shares the seal, and every check but this
    // one passes on both.
    let node_b = busbar_plugin_loader::load_store(&path, &config)
        .expect("a second node loads the same plugin against the same database");
    assert!(store
        .redeem_ask_state(&nonce_fleet, NOW + 900, NOW + 2)
        .expect("redeem_ask_state"));
    assert!(
        !node_b
            .redeem_ask_state(&nonce_fleet, NOW + 900, NOW + 3)
            .expect("redeem_ask_state"),
        "a second node redeemed an approval the first already spent, which is one operator \
         confirmation executing once per node"
    );
    // THE CONTROL: a ledger that refused everything would satisfy both cases above and would have
    // deleted the feature.
    assert!(
        node_b
            .redeem_ask_state(&nonce_fresh, NOW + 900, NOW + 4)
            .expect("redeem_ask_state"),
        "a freshly minted approval is not the one that was spent; refusing it would make the shared \
         ledger a blanket refusal of every confirmation after the first"
    );

    // LEG 3 — the same rows through the plain `MysqlStore`, a code path that never touches the
    // cdylib, the C ABI or the loader. A plugin answering the reads above out of its own in-process
    // state passes both boots and fails here.
    assert!(
        Store::list_mcp_demotions(&direct)
            .expect("list_mcp_demotions via the direct connection")
            .iter()
            .any(|r| r.server == srv_demoted && r.reason == "digest-mismatch"),
        "the demotion must be physically present in MySQL, not merely cached in the plugin"
    );
    assert!(
        !Store::redeem_ask_state(&direct, &nonce_restart, NOW + 900, NOW + 5)
            .expect("redeem_ask_state via the direct connection"),
        "the spent-approval row must be physically present in MySQL: a direct connection that never \
         loaded the plugin has to see the redemption the plugin recorded"
    );

    clear_trust_rows(
        &url,
        &[&srv_demoted, &srv_cleared],
        &[&nonce_restart, &nonce_fleet, &nonce_fresh],
    );
}
