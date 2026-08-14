# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public issues, pull
requests, or discussions.**

Instead, report privately through either channel:

- Email **security@getbusbar.com**, or
- GitHub's [private vulnerability reporting](https://github.com/GetBusbar/store-mysql/security/advisories/new)
  (the **Security** tab on this repository).

Please include:

- A description of the issue and its potential impact.
- Steps to reproduce (proof-of-concept if available).
- Affected version / commit.
- Any suggested mitigation.

We aim to **acknowledge your report within 48 hours**, work with you on a fix, and
coordinate disclosure timing. Confirmed vulnerabilities are published as
[GitHub Security Advisories](https://github.com/GetBusbar/store-mysql/security/advisories),
through which we request and issue **CVE** identifiers. We credit reporters who wish to be
credited once a fix is released.

## Scope

`store-mysql` is a `kind: store` busbar plugin: it persists busbar's governance
data — virtual keys, budgets, and usage — in a shared MySQL/MariaDB database
behind a fleet of busbar nodes. Issues of particular interest include:

- SQL injection or any path where request-derived data reaches a query
  unparameterized.
- Connection-string (`url`) handling that could leak credentials into logs or
  error strings.
- Identifier-comparison gaps: opaque handles (credential lookup handles, key
  ids, group names) are stored with `ascii_bin` collation for byte-exact,
  case-sensitive comparison — anything that reintroduces MySQL's default
  case-insensitive matching on such a column is in scope.
- Cross-node data races that corrupt shared governance state (budgets, usage
  ledgers) under concurrent writers.
- A boot-probe bypass: the plugin refuses to start when `CHECK` constraints are
  unenforced or `sql_mode` is non-strict — anything that lets it run anyway and
  silently accept unvalidated data is in scope.
- A load-time config error surfacing as a silent success instead of a clean
  `Err` across the plugin ABI.

See busbar's own [threat model](https://github.com/GetBusbar/busbar/blob/main/THREAT_MODEL.md)
for the trust boundaries this plugin operates inside.

## Supported versions

This plugin is versioned independently of busbar. Security fixes are applied to
the latest `main` and the most recent tagged release of **this repository**. Pin
to a tag for production use.
