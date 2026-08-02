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

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
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

/// Checks BOTH the "uplifted" `<profile_dir>/<name>` copy and the raw `<profile_dir>/deps/<name>`
/// compiler output — a bare `cargo test --release` does NOT uplift the cdylib to the top-level
/// profile dir, only to `target/deps` (same fix already applied to store-postgres-plugin's,
/// auth-oidc-plugin's, and webrequest-hook's equivalent `plugin_path()` helpers).
fn plugin_path() -> Option<PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = busbar_plugin_loader::plugin_library_filename("busbar_store_mysql_plugin");
        let uplifted = profile_dir.join(&name);
        let raw = profile_dir.join("deps").join(&name);
        [uplifted, raw]
            .into_iter()
            .filter_map(|p| {
                std::fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .ok()
                    .map(|mtime| (p, mtime))
            })
            .max_by_key(|(_, mtime)| *mtime)
            .map(|(p, _)| p)
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "the store-mysql-plugin cdylib is not built under CI: `cargo test` must build it \
             (checked both the uplifted target dir and target/deps). Refusing to silently skip the \
             only over-the-ABI coverage of the durable MySQL store path."
        );
    }
    candidate
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
            let _ = conn.exec_drop(
                "DELETE FROM api_keys WHERE id=:id",
                params! { "id" => id },
            );
        }
    }
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
            panic!("{what} exited before its admin listener came up (status: {status})");
        }
        assert!(
            Instant::now() < deadline,
            "{what}'s admin listener never came up within 15s"
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
    let Some(so_path) = plugin_path() else {
        eprintln!("skip: store-mysql-plugin cdylib not built");
        return;
    };
    let key_id = "vk_mysql_adminapi_e2e";
    cleanup(&url, key_id);

    let (busbar_bin, pack_bin) = build_real_binaries();

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
         auth:\n  chain: []\n  admin_auth:\n  - admin-tokens: {{ token: {{ env: BUSBAR_ADMIN_TOKEN }} }}\n\
         providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
         models:\n  test-model:\n    provider: mock\n",
        plugins_dir.display()
    );

    // BOOT #1: compiled-in `memory` store — the mysql plugin is not on disk yet.
    let config1 = work.join("config1.yaml");
    std::fs::write(&config1, &providers_and_common).unwrap();

    let child1 = Command::new(&busbar_bin)
        .env("BUSBAR_CONFIG", &config1)
        .env("BUSBAR_PROVIDERS", &providers)
        .env("BUSBAR_ADMIN_TOKEN", admin_token)
        .env("BUSBAR_STATE_FILE", "")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the real busbar boot (memory store, admin listener up)");
    let mut guard1 = ChildGuard(child1);
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
        format!("{providers_and_common}store:\n  module: mysql\n  settings: {{ url: \"{url}\" }}\n"),
    )
    .unwrap();

    let child2 = Command::new(&busbar_bin)
        .env("BUSBAR_CONFIG", &config2)
        .env("BUSBAR_PROVIDERS", &providers)
        .env("BUSBAR_ADMIN_TOKEN", admin_token)
        .env("BUSBAR_STATE_FILE", "")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the real busbar boot (mysql store, the admin-installed plugin)");
    let mut guard2 = ChildGuard(child2);

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
    assert_eq!(
        mint_status.as_u16(),
        201,
        "minting a key over the real admin API must succeed: {mint_json}"
    );
    let minted_id = mint_json["id"]
        .as_str()
        .expect("minted key response has an id")
        .to_string();
    let access_key_id = mint_json["aws_access_key_id"]
        .as_str()
        .expect("issue_aws_credential:true must return an aws_access_key_id")
        .to_string();
    assert!(
        mint_json["aws_secret_access_key"].is_string(),
        "issue_aws_credential:true must also return an aws_secret_access_key: {mint_json}"
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
    let (stored_kind, stored_public_id) =
        cred_row.expect("the minted AWS credential must be a real row in the real credentials table");
    assert_eq!(stored_kind, "sigv4");
    assert_eq!(
        stored_public_id, access_key_id,
        "the credential row's public_id must be the SAME access key id the admin API returned"
    );

    drop(guard2);
    drop(conn);
    let _ = std::fs::remove_dir_all(&work);
    cleanup(&url, &minted_id);
}
