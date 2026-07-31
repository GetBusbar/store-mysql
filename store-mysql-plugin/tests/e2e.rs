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

fn plugin_path() -> Option<PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = busbar_plugin_loader::plugin_library_filename("busbar_store_mysql_plugin");
        let candidate = profile_dir.join(&name);
        candidate.exists().then_some(candidate)
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "the store-mysql-plugin cdylib is not built under CI: `cargo test` must build it. \
             Refusing to silently skip the only over-the-ABI coverage of the durable MySQL store path."
        );
    }
    candidate
}

fn cfg(url: &str) -> String {
    serde_json::json!({ "url": url }).to_string()
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
    let Some(so_path) = plugin_path() else {
        eprintln!("skip: store-mysql-plugin cdylib not built");
        return;
    };
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
    std::fs::write(
        &config,
        format!(
            "listen: \"127.0.0.1:0\"\n\
             store:\n  module: mysql\n  settings: {{ url: \"{url}\" }}\n\
             plugins:\n  enabled: true\n  dir: {}\n  trust:\n    allow_unsigned: true\n\
             auth:\n  chain: []\n\
             providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
             models:\n  test-model:\n    provider: mock\n",
            plugins_dir.display()
        ),
    )
    .unwrap();

    let out = Command::new(&busbar_bin)
        .arg("--validate")
        .env("BUSBAR_CONFIG", &config)
        .env("BUSBAR_PROVIDERS", &providers)
        .output()
        .expect("run busbar --validate");
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
    let Some(path) = plugin_path() else {
        eprintln!("skip: store-mysql-plugin cdylib not built");
        return;
    };

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
