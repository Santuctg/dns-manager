# DNS Manager 0.6.6 — Multiple Source IP/CIDR

## Changes

- Logical firewall rules now support 1–32 source IP addresses or CIDRs.
- Add, remove, and edit sources in the existing Firewall rule dialog.
- Every source is normalized and checked for duplicates before persistence.
- Backward-compatible `source_cidr` requests/responses remain supported; `source_cidrs` is the canonical list.
- Deterministic UFW preview expansion emits a separate operation per source and protocol, capped at 512 operations per policy.
- Existing SSH safety checks, high-risk confirmation and 120-second emergency rollback remain in place.
- Existing 0.5.9–0.6.5 bug fixes are included.

## Database changes

Alembic migration `0010_firewall_rule_sources` adds the `firewall_rule_sources` table and backfills one ordered source for each existing firewall rule, preserving original IDs and `source_cidr` projection.

**Important:** Downgrading to 0009 discards additional source entries. Create a consistent SQLite backup before updating, and do not revert the application binary without considering migration compatibility.

## Upgrade safety

1. Retain a working SSH session. Back up the database consistently (SQLite `.backup` or Python `sqlite3.Connection.backup`) and preserve current UFW rules and 0.6.5 ZIP.
2. Install via the existing installer with the correct `DNS_MANAGER_INTERNAL_PROXY_IP`. The installer runs Alembic and restarts the privileged helper.
3. Verify application health, migration head `0010_firewall_rule_sources`, UFW status, and old rules. Installation **does not Apply** or modify existing active UFW policy.
4. Edit/add draft sources, then Preview and Validate. Check that every intended management IP is covered by the SSH allow rules. World-open `0.0.0.0/0` remains unless explicitly edited.
5. Perform high-risk Apply only from a maintained second SSH session. Keep firewall changes within the 120-second confirmation window only after connectivity is verified.

## Verification performed before packaging

- Full pytest: 394 passed.
- Python, JavaScript and shell syntax checks passed.
- Migration 0009→0010 exercised against an isolated SQLite database.
- Legacy and multi-source helper comment parsing, API CRUD, safety checks and rollback simulations tested.

## Outstanding live acceptance

Real UFW apply/rollback, mobile browser behavior and production upgrade validation **were not performed** in the build environment. Perform those acceptance steps before treating this package as fully production-validated.
