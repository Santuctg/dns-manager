# DNS Manager 0.6.6 — Multiple Source IP/CIDR Design Specification

**Date:** 2026-10-18  
**Target release:** 0.6.6  
**Baseline:** 0.6.5 (all existing 0.6.x UI fixes must remain)  
**Status:** Approved feature direction; implementation design for review

## 1. Outcome and boundaries

A user may maintain one *logical* firewall rule (action, protocol, ports, purpose, status, comment) with **one or more Source IP/CIDR entries**. A source entry may be one IPv4/IPv6 address or a valid IPv4/IPv6 CIDR. The UI offers Add IP/CIDR, edit and remove controls; a single logical rule expands into deterministic UFW operations for every source and protocol. No UFW changes occur on draft save. Existing Preview → Validate → Apply → Keep firewall changes / 120-second independent rollback, RBAC, CSRF, audit and rollback remain in place.

Non-goals: unrelated firewall redesign, UFW IP sets/ipset, per-source action/port overrides, automatically restricting existing world-open rules, changing nginx/dnsmasq/SSL or other product features.

## 2. Existing code and compatibility

Current `FirewallRule` in `app/models/firewall.py` stores a non-null `source_cidr: String(64)`; `FirewallRuleCreate/Update/Read` in `app/schemas/firewall.py`, `NormalizedFirewallRule`/`normalize_rule`/`validate_policy`/`build_preview` in `app/services/firewall_service.py`, and firewall API `_view/create/update` all expect one string. `app/templates/system.html` uses one input `name="source_cidr"`; `app/static/app.js` handles list/edit/submit with that key. Last migration is `0009_firewall_management`. `privileged/firewall_helper.py` handles a flat operations list keyed by `DNSMGR:` comments. The migration and API must be additive/compatible rather than abruptly replacing the single source field.

## 3. Persistence: additive source child table

Add Alembic revision `0010_firewall_rule_sources.py` after 0009. Add model `FirewallRuleSource` with:

- `id`: integer primary key
- `rule_id`: FK to `firewall_rules.id`, `ON DELETE CASCADE`, indexed, not null
- `source_cidr`: canonical CIDR string, max 64 chars, not null
- `sort_key`: integer, not null; normalized order preserves UI order
- unique constraint `(rule_id, source_cidr)`

`FirewallRule.sources` relationship uses ordered child rows, `cascade='all, delete-orphan'` and appropriate passive deletes. Migration backfills **exactly one** source child for each old rule from `firewall_rules.source_cidr`, idempotent within its migration transaction. Keep the legacy column, populated with the first source, as a compatibility projection; never use it as the authoritative source set in 0.6.6. Do not drop an existing column. Ensure reads of pre-migration DB go through normal Alembic startup before use; direct old 0.5.9 binaries after schema changes remain an explicit rollback concern.

## 4. API schema and normalized rule contract

Use `source_cidrs: list[str]` as the canonical multi-source request and response field, minimum 1, maximum **32** per logical rule. This cap limits accidental UFW explosion. For existing clients, a request containing only legacy `source_cidr` means a singleton list. If both keys appear, require normalized equality with the **first** list item, otherwise HTTP 422. For responses include both `source_cidrs` and `source_cidr` (first element) during compatibility window. A `source_cidrs: []` payload is invalid, including for a disabled rule; users should explicitly delete a rule instead.

Normalize every source with `ipaddress.ip_network(value, strict=False)`; host addresses become `/32` or `/128`. Reject malformed values, mixed blank inputs, duplicate normalized CIDRs (e.g. `10.1.2.3` and `10.1.2.3/32`), non-string input, over-limit length/list, and any entries containing commas/newlines as one value. Trim whitespace. Preserve entered ordering for the editor but canonicalize source addresses before persistence/audit/preview. Enforce canonical uniqueness in service layer and DB.

Changing a logical rule's sources is atomic: replace child rows in one DB transaction with desired-revision bump and full old/new audit metadata. Create/delete likewise maintain source children. Pydantic read serialization must explicitly assemble `source_cidrs` from relationship; do not rely on `FirewallRuleRead.model_validate()` to conjure non-model fields. The API list remains `rules:[...]` with the same logical IDs, so Edit/Delete operate on one logical rule.

## 5. Preview operation expansion and comment identity

For each **enabled** logical rule in ascending `(sort_key, id)` order, emit one operation for each source (ordered by child `sort_key`, then `id`) and protocol (`tcp` then `udp` when `both`). Use `source` equal to the canonical CIDR, and preserve existing `action`, `protocol`, `port` semantics. Enforce maximum expanded operations for all rules per policy (proposed **512**) to avoid UFW command floods; reject an oversized preview/apply before privileged mutation.

Every expanded operation needs a unique deterministic comment, e.g. `DNSMGR:<rule_id>:<source_ordinal>:<proto>`, where ordinal is zero-based stable for that preview. The privileged helper must accept this versioned format **and** legacy `DNSMGR:<rule_id>:<proto>` while reconciling, importing snapshots and rolling back. Snapshot restore must preserve exact operation payload/comments, not regenerate source indices. Verify comment length and helper allow-list; do not make prefix matching broader than DNSMGR-managed rules. No operations may be duplicated.

## 6. Firewall safety behavior

Apply **every** rule-level check per expanded source. Public `8500` prohibition, world-open SSH/DNS high-risk warnings, IPv4/IPv6 handling and allow/deny semantics must not inspect only the first CIDR. SSH-path validation is satisfied if at least one effective enabled TCP allow source covers the trusted current SSH source or explicitly supplied permitted management CIDR, under existing source-trust rules. `0.0.0.0/0` and `::/0` remain high-risk and **will not be removed automatically** when another source is added. Preserve explicit high-risk confirmation, pending revision and 120-second independent systemd rollback. Ensure incomplete apply restores previous exact managed rules and preserves unmanaged rules; avoid manual `ufw reset` or `ufw disable` for tests.

## 7. UI and accessibility

In the firewall dialog replace the single source control with repeatable labeled source rows plus Add IP/CIDR and Remove buttons. One required row initially; remove is disabled when only one row remains. Show inline client-side validation to assist, but server-side 422 remains authoritative. Edit pre-populates all sources. List table Source column displays one compact item per source, with safe wrapping/local horizontal scroll at narrow widths; don't split a CIDR token. Preserve `data-firewall-*` and other `data-*` action hooks used by existing JavaScript; only firewall-specific JS is changed. Display expanded operations count in Preview for operator clarity. Avoid exposing secrets; keep modal focus/scroll and the sequential-confirmation close fix.

## 8. Audit and rollback

Audit create/update/delete records canonical source arrays in `old`/`new`, preserving actor, timestamp, source IP, result. Apply/confirm/rollback audit uses existing revision model. Database transaction failure must leave logical rule and child set unchanged. Privileged helper rollback uses persisted pre-apply manifest, preserving legacy/modern comments and all source operations. A restart during the 120-second interval must not cancel systemd rollback. No unintended modification of unmanaged UFW entries.

## 9. Acceptance / security tests

1. Migration 0009→0010 preserves all existing rule IDs and old `source_cidr`, creates one ordered child per existing rule, and retains RBAC/other data.
2. Legacy single `source_cidr` POST/PUT works; multi list POST/PUT returns both `source_cidr` projection and `source_cidrs` array.
3. Invalid, empty, duplicate after normalization, contradictory legacy+new payloads, 33 sources, comma-separated source string → 422, no draft mutation.
4. `both` + 3 sources creates 6 deterministic operations with unique comments; repeated preview is byte-identical.
5. Mixed IPv4/IPv6 and `/0` high-risk classification checks every entry; public 8500 rejection checks every source; SSH safety checks every source and does not trust spoofed headers.
6. Edit/remove of one source persists atomically, updates revision exactly once, and produces complete audit old/new; deleting logical rule removes all sources.
7. UFW helper accepts legacy and versioned `DNSMGR` tags; reconcile works active and inactive; unrelated manual UFW entries stay untouched.
8. Partial helper failure, cancel/restart, timeout rollback, and confirm restore or retain correct multiple-source manifest without stale rules.
9. UI desktop/mobile modal supports add/remove and long CIDRs without overflow; existing modal resolver regression remains green.
10. Full existing suite plus new tests green, expected version `0.6.6`, release archive cumulative and verified; production upgrade verifies current SSH access and UFW status before/after.

## 10. Deployment and recovery

Create a SQLite consistent backup before upgrade (including WAL checkpoint/backup API), plus UFW status/show-added snapshot and existing app ZIP. Do not use a plain live database file copy. Apply migration via existing installer; test installed helper restarted. Prior to any high-risk firewall Apply, operator must verify allowed SSH management CIDRs include their active connection and retain a second session. Installer upgrading DB does **not** auto-apply new firewall policy. In case of UI regression, restore code while respecting migration forward-compatibility; DB downgrade to 0009 requires an explicitly tested reverse-migration and backup-based recovery, not an assumed safe downgrade. Existing applied UFW rules are not changed merely by installing 0.6.6.
