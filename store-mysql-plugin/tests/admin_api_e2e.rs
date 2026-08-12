// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE prod-ready end-to-end bar for this plugin, driven the way a real OPERATOR installs and uses
//! it in production — never a file dropped onto disk before boot (see `e2e.rs` for that path, still
//! real and still kept as its own proof), but the REAL admin HTTP API. Mirrors
//! store-postgres-plugin's own `admin_api_e2e.rs` exactly (same wire shapes, same two-boot
//! restart-to-activate flow), adapted only where MySQL's real schema differs from Postgres':
//! `api_keys` (not `keys` — `KEYS` is a MySQL/MariaDB reserved word, see `busbar-store-mysql`'s own
//! module doc) and MySQL's `information_schema.tables` for the boot-time schema-existence poll.
//!
//!   1. Boot a real `busbar` process (no `--validate`) with its admin listener up and the compiled-in
//!      `memory` store active (`store:` block absent).
//!   2. `POST /api/v1/admin/plugins` with the REAL built cdylib, base64-encoded, guarded by a real
//!      `x-admin-token` — the exact wire shape `crates/busbar/src/admin/v1/json/handlers.rs`'s
//!      `install_plugin` uses.
//!   3. `GET /api/v1/admin/plugins?type=store` confirms the install landed in the real catalog.
//!   4. Stop that process, rewrite `config.yaml` to point `store: module: mysql` at the real MySQL,
//!      using the SAME plugins.dir the admin API itself wrote the tarball to in step 2.
//!   5. Boot a SECOND real `busbar` process against that config — its first-boot store resolution
//!      dlopens the admin-installed plugin and runs `Store::connect()`/schema init. Poll — via a RAW
//!      independent `mysql::Pool`, never `MysqlStore::connect` — for `api_keys` to appear.
//!   6. `POST /api/v1/admin/keys` (with `issue_aws_credential: true`) against this SECOND process.
//!   7. Independently verify — a fresh RAW `mysql::Pool`, bypassing the plugin/ABI/admin-API
//!      entirely — that both the `api_keys` and `credentials` rows actually landed.

use base64::Engine as _;
use mysql::params;
use mysql::prelude::*;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Fixed ed25519 signing secret (64 hex = 32 bytes) for this e2e test. 1.5.1 requires an
/// explicit signing key to mint virtual keys; busbar no longer auto-generates one.
const TEST_SIGNING_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct ChildGuard(Child, PathBuf);

impl ChildGuard {
    /// The child's captured output, formatted for a panic message. Never panics itself: this runs
    /// on the failure path, where a second unrelated panic would bury the first.
    fn output(&self) -> String {
        match std::fs::read_to_string(&self.1) {
            Ok(s) if s.trim().is_empty() => "  (the child produced no output)".to_string(),
            Ok(s) => s
                .lines()
                .map(|l| format!("  | {l}"))
                .collect::<Vec<_>>()
                .join("\n"),
            Err(e) => format!("  (could not read {}: {e})", self.1.display()),
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Spawn `busbar` with stdout+stderr captured to `log`, wrapped in a guard that knows where to find
/// them. Every boot goes through here so the capture cannot be forgotten on one added later.
///
/// A FILE, not `Stdio::piped()`: nothing reads the pipe while the child runs, so a child that
/// out-talked the pipe buffer would block forever on write and turn a clean failure into a hang.
///
/// This is not bookkeeping. Both boots ran with their output sent to /dev/null, so a failed boot
/// could report only an exit code: the qa-gate's store-mysql leg failed with exactly
/// "boot #1 exited before its admin listener came up (status: exit status: 1)" and nothing else,
/// which is not enough to act on. The sibling store-postgres harness already carries this fix and
/// documents having lost a gate leg to the same blindness.
fn spawn_busbar(cmd: &mut Command, log: PathBuf, what: &str) -> ChildGuard {
    let out = std::fs::File::create(&log)
        .unwrap_or_else(|e| panic!("create the {what} log at {}: {e}", log.display()));
    let err = out
        .try_clone()
        .unwrap_or_else(|e| panic!("dup the {what} log handle: {e}"));
    let child = cmd
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .unwrap_or_else(|e| panic!("spawn the real busbar for {what}: {e}"));
    ChildGuard(child, log)
}

/// Cleans up the REAL minted row (by its real random id) on drop -- including on panic-unwind, since
/// Rust runs local guards' `Drop` during a panicking stack unwind. The pre-test `cleanup()` call
/// below only ever targets a fixed, never-actually-used id (the admin API mints its own random one),
/// so without this guard a failed assertion between mint and test-end permanently leaks the minted
/// row: no future run's pre-test cleanup could ever find or remove it. Mirrors `ChildGuard` above.
struct CleanupGuard {
    url: String,
    id: String,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        cleanup(&self.url, &self.id);
    }
}

fn mysql_url() -> Option<String> {
    match std::env::var("BUSBAR_TEST_MYSQL_URL") {
        Ok(url) => Some(url),
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!(
                "BUSBAR_TEST_MYSQL_URL is unset under CI: the mysql:8 service container must \
                 provision it. Refusing to silently skip the only real-admin-API-install coverage \
                 in CI."
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
        let Ok(rd) = std::fs::read_dir(dir) else { return };
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

fn busbarai_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../busbarAI")
        .canonicalize()
        .expect("sibling busbarAI checkout must exist (see Cargo.toml path deps)")
}

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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn cleanup(url: &str, id: &str) {
    if let Ok(pool) = mysql::Pool::new(mysql::Opts::from_url(url).unwrap()) {
        if let Ok(mut conn) = pool.get_conn() {
            let _ = conn.exec_drop(
                "DELETE FROM credentials WHERE key_id=:id",
                params! { "id" => id },
            );
            let _ = conn.exec_drop("DELETE FROM api_keys WHERE id=:id", params! { "id" => id });
        }
    }
}

/// Proves `CleanupGuard` actually cleans up on a PANICKING exit, not just the normal-return path --
/// direct SQL against a real row, bypassing the (expensive, real-binary-building) full e2e flow, so
/// this stays fast. Regression coverage for the leaked-row-on-assertion-failure gap the guard closes.
#[test]
fn cleanup_guard_removes_the_row_even_when_the_scope_holding_it_panics() {
    let Some(url) = mysql_url() else { return };
    let id = format!(
        "vk_cleanupguard_panic_test_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let pool = mysql::Pool::new(mysql::Opts::from_url(&url).unwrap()).unwrap();
    let mut conn = pool.get_conn().unwrap();
    conn.exec_drop(
        "INSERT INTO api_keys \
         (id, name, key_group, allowed_pools, labels, enabled, generation_hash, \
          created_at, updated_at, expires_at, deleted_at, revision) \
         VALUES (:id, 'cleanup-guard-test', '', NULL, '{}', 1, '', 1000, 1000, NULL, NULL, 0)",
        params! { "id" => &id },
    )
    .unwrap();

    let exists = |conn: &mut mysql::PooledConn, id: &str| -> bool {
        conn.exec_first::<u8, _, _>(
            "SELECT 1 FROM api_keys WHERE id=:id",
            params! { "id" => id },
        )
        .unwrap()
        .is_some()
    };
    assert!(
        exists(&mut conn, &id),
        "sanity: the row must exist before the panic test"
    );

    // Run inside catch_unwind so this test itself doesn't fail -- the panic is the whole point (it's
    // what proves the guard's Drop actually fires during a real unwind, not just a clean return).
    let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = CleanupGuard {
            url: url.clone(),
            id: id.clone(),
        };
        panic!("deliberate panic while the guard is in scope -- proves Drop still runs");
    }));
    assert!(
        panic_result.is_err(),
        "the inner closure must have actually panicked"
    );

    assert!(
        !exists(&mut conn, &id),
        "CleanupGuard's Drop must have removed the row even though the scope panicked"
    );
}

fn wait_for_admin_listener(
    client: &reqwest::blocking::Client,
    admin_base: &str,
    token: &str,
    guard: &mut ChildGuard,
    what: &str,
) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if client
            .get(format!("{admin_base}/plugins"))
            .header("x-admin-token", token)
            .send()
            .is_ok()
        {
            return;
        }
        if let Ok(Some(status)) = guard.0.try_wait() {
            panic!(
                "{what} exited before its admin listener came up (status: {status})\n\
                 --- {what} output ---\n{}",
                guard.output()
            );
        }
        assert!(
            Instant::now() < deadline,
            "{what}'s admin listener never came up within 15s\n--- {what} output ---\n{}",
            guard.output()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// THE REAL END-TO-END PROOF: install the real cdylib over the real admin API, restart onto it,
/// mint a virtual key and AWS credential through the running instance over the same admin API, and
/// independently confirm both rows landed in real MySQL.
#[test]
fn install_over_admin_api_then_mint_a_key_and_verify_mysql_directly() {
    let Some(url) = mysql_url() else { return };
    let so_path = plugin_path();
    let key_id = "vk_mysql_adminapi_e2e";
    cleanup(&url, key_id);

    let (busbar_bin, pack_bin) = build_real_binaries();

    // Same pid+nanosecond-timestamp uniqueness pattern as store-mysql's own
    // `unique_scratch_table` (store-mysql/src/tests.rs) -- not shared, deliberately: that helper
    // lives inside `#[cfg(test)] mod tests`, invisible outside store-mysql's own test compilation
    // (cfg(test) doesn't cross a crate boundary), and promoting a 6-line helper to real `pub` API
    // just to dedupe it here would add public surface nobody else needs.
    let work = std::env::temp_dir().join(format!(
        "busbar-mysql-adminapi-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let plugins_dir = work.join("plugins");
    std::fs::create_dir_all(&plugins_dir).unwrap();

    let tarball_path = work.join("store-mysql.tar.gz");
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
            "admin-api e2e proof",
            "--license",
            "Apache-2.0",
            "--out",
            tarball_path.to_str().unwrap(),
            "--allow-unsigned",
        ])
        .status()
        .expect("run busbar-plugin-pack");
    assert!(status.success(), "packing the plugin must succeed");
    let tarball_bytes = std::fs::read(&tarball_path).unwrap();
    let file = "store-mysql.tar.gz";

    let admin_port = free_port();
    let admin_token = "smysql-adminapi-e2e-token";
    let admin_base = format!("http://127.0.0.1:{admin_port}/api/v1/admin");
    let client = reqwest::blocking::Client::new();

    let providers = work.join("providers.yaml");
    std::fs::write(
        &providers,
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();
    let providers_and_common = format!(
        "listen: \"127.0.0.1:0\"\n\
         admin_listen: \"127.0.0.1:{admin_port}\"\n\
         plugins:\n  enabled: true\n  dir: {}\n  trust:\n    allow_unsigned: true\n\
         identity-providers:\n  admin-tokens: {{ module: admin-tokens, token: {{ env: BUSBAR_ADMIN_TOKEN }} }}\n\
         auth:\n  chain: []\n  signing_key: {{ env: BUSBAR_SIGNING_KEY }}\n  admin_auth: [admin-tokens]\n\
         providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
         models:\n  test-model:\n    provider: mock\n",
        plugins_dir.display()
    );

    // BOOT #1: compiled-in `memory` store — the mysql plugin is not on disk yet.
    let config1 = work.join("config1.yaml");
    std::fs::write(&config1, &providers_and_common).unwrap();

    let mut guard1 = spawn_busbar(
        Command::new(&busbar_bin)
            .env("BUSBAR_CONFIG", &config1)
            .env("BUSBAR_PROVIDERS", &providers)
            .env("BUSBAR_ADMIN_TOKEN", admin_token)
            .env("BUSBAR_SIGNING_KEY", TEST_SIGNING_KEY)
            .env("BUSBAR_STATE_FILE", ""),
        work.join("boot1.log"),
        "boot #1 (memory store, admin listener up)",
    );
    wait_for_admin_listener(&client, &admin_base, admin_token, &mut guard1, "boot #1");

    // REAL ADMIN-API INSTALL.
    let install_body = serde_json::json!({
        "file": file,
        "tarball_b64": base64::engine::general_purpose::STANDARD.encode(&tarball_bytes),
    });
    let install_resp = client
        .post(format!("{admin_base}/plugins"))
        .header("x-admin-token", admin_token)
        .json(&install_body)
        .send()
        .unwrap();
    let install_status = install_resp.status();
    let install_body_text = install_resp.text().unwrap_or_default();
    assert_eq!(
        install_status.as_u16(),
        201,
        "plugin install must succeed over the real admin API: {install_body_text}"
    );
    assert!(
        plugins_dir.join(file).exists(),
        "the admin API's own install handler must have written the tarball to plugins.dir"
    );

    match client
        .post(format!("{admin_base}/plugins"))
        .json(&install_body)
        .send()
    {
        Ok(unauth) => assert_eq!(
            unauth.status().as_u16(),
            401,
            "plugin install without x-admin-token must be rejected with 401, not accepted"
        ),
        Err(e) => assert!(
            !e.is_status(),
            "an unauthenticated install must never be accepted: {e}"
        ),
    }

    let list: serde_json::Value = client
        .get(format!("{admin_base}/plugins?type=store"))
        .header("x-admin-token", admin_token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let items = list["items"].as_array().expect("plugins list has items");
    assert!(
        items
            .iter()
            .any(|p| p["target"] == file && p["name"] == "busbar-store-mysql-plugin"),
        "the installed mysql plugin must be listed in the real catalog: {items:?}"
    );

    // Install alone does NOT hot-swap the active store; a real restart activates it.
    drop(guard1);

    // BOOT #2: same plugins.dir, config now naming `store: module: mysql` against the real MySQL.
    let config2 = work.join("config2.yaml");
    std::fs::write(
        &config2,
        format!(
            "{providers_and_common}store:\n  module: mysql\n  settings: {{ url: \"{url}\" }}\n"
        ),
    )
    .unwrap();

    let mut guard2 = spawn_busbar(
        Command::new(&busbar_bin)
            .env("BUSBAR_CONFIG", &config2)
            .env("BUSBAR_PROVIDERS", &providers)
            .env("BUSBAR_ADMIN_TOKEN", admin_token)
            .env("BUSBAR_SIGNING_KEY", TEST_SIGNING_KEY)
            .env("BUSBAR_STATE_FILE", ""),
        work.join("boot2.log"),
        "boot #2 (mysql store, the admin-installed plugin)",
    );

    // Poll -- via a RAW independent mysql::Pool, never MysqlStore::connect -- for `api_keys` to
    // appear, the only genuine confirmation boot #2 dlopened the admin-installed plugin and ran
    // Store::connect()/schema init before ever handling a request.
    let deadline = Instant::now() + Duration::from_secs(15);
    let booted = loop {
        if let Ok(pool) = mysql::Pool::new(mysql::Opts::from_url(&url).unwrap()) {
            if let Ok(mut conn) = pool.get_conn() {
                if let Ok(Some(exists)) = conn.query_first::<bool, _>(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
                     WHERE table_schema = DATABASE() AND table_name = 'api_keys')",
                ) {
                    if exists {
                        break true;
                    }
                }
            }
        }
        if let Ok(Some(status)) = guard2.0.try_wait() {
            panic!("boot #2 exited before creating the mysql schema (status: {status})");
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        booted,
        "boot #2, restarted onto the admin-installed mysql plugin, must create the `api_keys` \
         table within 15s -- proof the real dlopen+connect path executed"
    );
    wait_for_admin_listener(&client, &admin_base, admin_token, &mut guard2, "boot #2");

    // REAL WORK, over the real admin API: mint a virtual key WITH an AWS-shaped credential.
    let mint_body = serde_json::json!({
        "name": "smysql-adminapi-e2e-key",
        "labels": {},
        "issue_aws_credential": true,
    });
    let mint_resp = client
        .post(format!("{admin_base}/keys"))
        .header("x-admin-token", admin_token)
        .json(&mint_body)
        .send()
        .unwrap();
    let mint_status = mint_resp.status();
    let mint_json: serde_json::Value = mint_resp.json().unwrap();
    // A panic message below must never dump `mint_json` verbatim -- it carries the real (albeit
    // test-generated) `aws_secret_access_key` value, and a failed assertion here would otherwise
    // leak it into CI logs. Redact before ever interpolating the body into an assertion message.
    let mut redacted_mint_json = mint_json.clone();
    if let Some(obj) = redacted_mint_json.as_object_mut() {
        if obj.contains_key("aws_secret_access_key") {
            obj.insert(
                "aws_secret_access_key".into(),
                serde_json::json!("<redacted>"),
            );
        }
    }
    assert_eq!(
        mint_status.as_u16(),
        201,
        "minting a key over the real admin API must succeed: {redacted_mint_json}"
    );
    let minted_id = mint_json["id"]
        .as_str()
        .expect("minted key response has an id")
        .to_string();
    // From here on a real row exists under `minted_id` -- this guard cleans it up on any exit path,
    // including a panicking assertion below, so a test failure can never permanently leak the row.
    let _cleanup_guard = CleanupGuard {
        url: url.clone(),
        id: minted_id.clone(),
    };
    let access_key_id = mint_json["aws_access_key_id"]
        .as_str()
        .expect("issue_aws_credential:true must return an aws_access_key_id")
        .to_string();
    assert!(
        mint_json["aws_secret_access_key"].is_string(),
        "issue_aws_credential:true must also return an aws_secret_access_key: {redacted_mint_json}"
    );

    // INDEPENDENT VERIFICATION: a fresh RAW mysql::Pool, bypassing the plugin/ABI/admin-API
    // entirely, confirms the key AND its credential actually landed in real MySQL.
    let pool = mysql::Pool::new(mysql::Opts::from_url(&url).unwrap())
        .expect("connect directly to confirm persistence, bypassing the plugin entirely");
    let mut conn = pool.get_conn().unwrap();
    let key_row: Option<(String, bool)> = conn
        .exec_first(
            "SELECT name, enabled FROM api_keys WHERE id=:id",
            params! { "id" => &minted_id },
        )
        .unwrap();
    let (stored_name, stored_enabled) =
        key_row.expect("the minted key must be a real row in the real api_keys table");
    assert_eq!(stored_name, "smysql-adminapi-e2e-key");
    assert!(stored_enabled);

    let cred_row: Option<(String, String)> = conn
        .exec_first(
            "SELECT kind, public_id FROM credentials WHERE key_id=:id",
            params! { "id" => &minted_id },
        )
        .unwrap();
    let (stored_kind, stored_public_id) = cred_row
        .expect("the minted AWS credential must be a real row in the real credentials table");
    assert_eq!(stored_kind, "sigv4");
    assert_eq!(
        stored_public_id, access_key_id,
        "the credential row's public_id must be the SAME access key id the admin API returned"
    );

    drop(guard2);
    drop(conn);
    let _ = std::fs::remove_dir_all(&work);
    // Real cleanup-of-the-minted-row now happens via `_cleanup_guard`'s Drop (fires here on the
    // normal path, and would already have fired on any earlier panicking return too).
}
