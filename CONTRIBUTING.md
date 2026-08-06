# Contributing to store-mysql

Thanks for your interest in improving `store-mysql`. This document covers
how to build, test, and submit changes.

## Ground rules

- Be respectful and constructive in all project spaces (see
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)).
- By contributing, you agree your contributions are licensed under the project's
  [Apache-2.0](LICENSE) license.
- Security issues go through [SECURITY.md](SECURITY.md), **not** public issues.

## Development setup

This repo is a 2-crate Rust workspace: `store-mysql/` is the library crate holding
the SQL and schema logic, and `store-mysql-plugin/` is the `cdylib` the engine
loads. You need a recent stable toolchain
(`rustup` recommended), and — until [busbarAI](https://github.com/GetBusbar/busbar)
ships publicly — a sibling checkout of it at `../busbarAI`, since this crate's
`Cargo.toml` points at busbar's crates as local path dependencies. See the
README's [Dependencies](README.md#dependencies) section for the exact layout;
CI checks out `GetBusbar/busbar` at the branch named in the reusable
`plugin-ci.yml` workflow reference in [`ci.yml`](.github/workflows/ci.yml).

The meaningful test coverage here needs a **live MySQL** — see the README's
[Testing](README.md#testing) section.
Locally, `cargo test` skips that coverage cleanly if `BUSBAR_TEST_MYSQL_URL`
is unset; set it to point at a real MySQL 8 (or MariaDB) database to exercise it:

```bash
export BUSBAR_TEST_MYSQL_URL=mysql://busbar:busbar@127.0.0.1:3307/busbar_test
cargo build --release                       # cdylib
cargo test                                   # unit tests + the e2e dlopen/live-MySQL test
cargo clippy --all-targets -- -D warnings    # lints must be clean
cargo fmt --all -- --check                   # format before committing
```

## Before you open a pull request

1. **`cargo fmt --all`** — code must be rustfmt-clean.
2. **`cargo clippy --all-targets -- -D warnings`** — no warnings.
3. **`cargo build && cargo test`** — green, including the live-MySQL suites in
   `store-mysql/src/tests.rs`, `store-mysql-plugin/tests/e2e.rs` and
   `store-mysql-plugin/tests/admin_api_e2e.rs`. They hard-fail under `CI` rather
   than silently skipping. Never let that coverage quietly vanish: point
   `BUSBAR_TEST_MYSQL_URL` at a real database before trusting a local green.
4. Add or update tests for any behavior change.
5. Update documentation (`README.md`, doc comments) when you change behavior or config.

## Architecture

This repo is a 2-crate Cargo workspace and brings everything it needs:

- `store-mysql-plugin/` is a thin adapter: it turns the engine's JSON `open`
  config into a `MysqlStore` and hands the trait object to
  [`busbar-plugin-sdk`](https://github.com/GetBusbar/busbar/tree/main/crates/plugin-sdk),
  which emits the C ABI symbols the loader resolves.
- `store-mysql/` is the real library crate: all the SQL, the schema, the
  migrations and their tests live here, in THIS repository. Most substantive
  changes belong here, not in the `busbarAI` monorepo.

## Commit & PR conventions

- Keep commits focused; squash noisy WIP commits before opening the PR.
- Write a clear PR description: what changed, why, and how it was verified.
- Reference any related issue.
- Stage files by name; avoid sweeping `git add -A` that pulls in unrelated changes.

## Questions

Open a discussion or issue. We're happy to help you get oriented.
