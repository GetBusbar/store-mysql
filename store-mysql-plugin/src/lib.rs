// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **MySQL/MariaDB store as a droppable busbar plugin** — a `cdylib` exporting the store C ABI.
//! Build it, drop the resulting `.so`/`.dll`/`.dylib` into the engine's plugins folder, and set
//! `store: { module: mysql, settings: { url: "mysql://..." } }`; the engine loads it in-process at
//! boot. One MySQL/MariaDB behind a fleet of busbar nodes means shared virtual keys, budgets, and
//! usage across the cluster.
//!
//! All the SQL lives in the `busbar-store-mysql` `lib` crate (which a custom build can also link
//! statically). Here we only adapt the engine's JSON config into a `MysqlStore`.

use busbar_api::Store;
use busbar_store_mysql::MysqlStore;

/// Construct a MySQL/MariaDB store from the JSON config the engine passes through `open`:
///
/// ```json
/// { "url": "mysql://user:pass@host:3306/busbar" }
/// ```
fn open(cfg: &str) -> Result<Box<dyn Store>, String> {
    let v: serde_json::Value = if cfg.trim().is_empty() {
        serde_json::Value::Object(Default::default())
    } else {
        serde_json::from_str(cfg).map_err(|e| format!("invalid mysql plugin config: {e}"))?
    };
    let url = v
        .get("url")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            "mysql plugin config requires a \"url\" (a mysql:// connection string)".to_string()
        })?;
    let store = MysqlStore::connect(url).map_err(|e| e.0)?;
    Ok(Box::new(store))
}

busbar_plugin_sdk::export_store_plugin!(open);
