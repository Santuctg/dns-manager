# DNS Manager 0.6.6 Multiple Source IP/CIDR Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Support 1–32 canonical source IP/CIDR values per logical firewall rule while preserving existing API clients and every firewall safety invariant.

**Architecture:** Add a normalized `FirewallRuleSource` child table, retain the existing `source_cidr` as first-source projection, extend schemas/services to expand each source into safe deterministic UFW operations, and add repeatable source inputs to the existing dialog without changing unrelated modules.

**Tech Stack:** FastAPI, Pydantic v2, SQLAlchemy, Alembic/SQLite, vanilla JS/Jinja/CSS, UFW/systemd, pytest.

**Spec:** `docs/superpowers/specs/2026-10-18-dns-manager-multi-source-0.6.6-design.md`

## Global Constraints

- Baseline 0.6.5; target 0.6.6; cumulative installer/ZIP.
- Maximum **32** sources per logical rule, **512** expanded operations per policy.
- Preserve legacy `source_cidr` API and response projection, with canonical `source_cidrs` list.
- Keep RBAC `firewall.manage`, CSRF, trusted-source SSH path, 120-second independent rollback, audit, unmanaged UFW preservation.
- Preserve 0.5.9 modal close and inactive-UFW fixes and 0.6.0–0.6.5 UI fixes.
- No virtualenv, no UFW reset/disable during tests, no automatic policy Apply during install.
- Project may be deployed without `.git`; use isolated extracted source tree and versioned checkpoints instead of inventing Git history.

## Review Focus

1. Duplicate canonical CIDRs (`10.1.2.3`, `10.1.2.3/32`) must reject without mutation — Task 2.
2. High-risk SSH/DNS/open 8500 may be in the **second** source, not first — Task 3.
3. `both` + 3 sources → exactly 6 unique UFW comments, deterministic ordering — Task 4.
4. Removing one source and subsequently rolling back cannot resurrect stale source-specific managed rules — Tasks 4, 6.
5. Pre-0.6.6 source payload and legacy comments must stay valid during migration/reconciliation/rollback — Tasks 1, 2, 5, 6.

---

## Task 1: Data model and additive Alembic migration

**Files**
- Modify: `app/models/firewall.py`, `app/models/__init__.py`
- Create: `migrations/versions/0010_firewall_rule_sources.py`
- Test: `tests/integration/test_firewall_models.py` (create if absent), `tests/integration/test_database.py`

**Interfaces:** `FirewallRule.sources: list[FirewallRuleSource]`, `FirewallRuleSource(id, rule_id, source_cidr, sort_key)`; `FirewallRule.source_cidr` stays non-null projection.

- [ ] Write migration tests from a real 0009 fixture with at least two old firewall rules. Assert identical IDs, exactly one child per rule, canonical source values, child cascade-delete, uniqueness and no changes to non-firewall tables.
- [ ] Run `pytest -q tests/integration/test_firewall_models.py tests/integration/test_database.py`; verify new tests RED for missing table.
- [ ] Create child model + `0010` migration/backfill with `down_revision` matching 0009; add `FirewallRule.sources` ordered relationship.
- [ ] Run same tests GREEN, then full `pytest -q`; fix regressions.
- [ ] Checkpoint `0.6.6-task1-migration`; write down backup/restore requirements.

## Task 2: Contract normalization, API backward compatibility, transactional CRUD

**Files**
- Modify: `app/schemas/firewall.py`, `app/api/firewall.py`, `app/services/firewall_service.py`
- Test: `tests/integration/test_firewall_api.py`, `tests/unit/test_firewall_service.py`

**Interfaces:** `source_cidrs: list[str]` canonical list; `source_cidr: str` legacy/first source; explicit `serialize_firewall_rule(rule) -> dict` to read source relationship; `normalize_source_cidrs(payload) -> list[str]` used by API and service.

- [ ] Write RED API and unit tests for 1–32 IPv4/IPv6 sources, legacy-only POST/PUT, both-field equality, empty/malformed/duplicate/33-value/CSV-invalid 422, read projection and unchanged database after validation failure.
- [ ] Run targeted tests, verify RED for missing multi-source support.
- [ ] Extend Pydantic validators and normalization; canonicalize via `ip_network(...,strict=False)`; reject conflicting/duplicate source values.
- [ ] Update CREATE/UPDATE in one session transaction: replace children, synchronize first-source legacy projection, bump revision once, audit canonical before/after; update `_view`/CRUD reads to explicit serializer.
- [ ] Run focused tests GREEN, then full suite; checkpoint `0.6.6-task2-api`.

## Task 3: Per-source policy safety and SSH access validation

**Files**
- Modify: `app/services/firewall_service.py`
- Test: `tests/unit/test_firewall_service.py`, `tests/integration/test_firewall_api.py`, `tests/security/test_csrf.py`

**Interfaces:** `NormalizedFirewallRule` should carry canonical `source_cidrs` tuple while preserving compatibility helpers; `validate_policy(...)` must consider every source.

- [ ] Add RED tests with dangerous source deliberately placed second: world-open SSH/DNS triggers high-risk confirmation; open port 8500 rejected; IPv6 `/0` treated as world-open; SSH path covered by third CIDR accepted; no SSH path rejected.
- [ ] Add API test that untrusted spoofed forwarded header cannot satisfy management SSH check; verify CSRF/RBAC unchanged.
- [ ] Run targeted tests RED; implement per-source evaluation without only-first shortcuts.
- [ ] Run focused and full suites GREEN; checkpoint `0.6.6-task3-validation`.

## Task 4: Deterministic preview expansion and size cap

**Files**
- Modify: `app/services/firewall_service.py`
- Test: `tests/unit/test_firewall_service.py`, `tests/integration/test_firewall_api.py`

**Interfaces:** `build_preview(policy,rules) -> dict` unchanged externally; flat operations each carry `action, protocol, port, source, comment` with `DNSMGR:<id>:<ordinal>:<protocol>` tags.

- [ ] Write RED tests asserting three CIDRs + `both` → six operations, two previews equal, deterministic sorting, distinct comment names; 513 operations rejected **before** helper invocation; disabled rule → no operations.
- [ ] Run RED; implement stable source × protocol expansion and 512-operation cap.
- [ ] Run GREEN + full suite; checkpoint `0.6.6-task4-preview`.

## Task 5: Privileged helper validation and safe rule reconciliation

**Files**
- Modify (only if necessary): `privileged/firewall_helper.py`, `privileged/helper_server.py`
- Test: `tests/unit/test_firewall_helper.py`, `tests/integration/test_privileged_helper.py`

**Interfaces:** keep flat helper payload, recognize both legacy and versioned `DNSMGR:` rule comments; never delete other users' UFW rules.

- [ ] Write RED tests for helper accepting valid multi-source comments, rejecting malformed arbitrary command/comments, removing old+new managed tags in active/inactive UFW, preserving unmanaged rules.
- [ ] Run RED; update comment validator/reconciliation only as needed; preserve `show added` fallback.
- [ ] Run GREEN + full suite; checkpoint `0.6.6-task5-helper`.

## Task 6: Rollback, restart, and atomic consistency

**Files**
- Modify only if test proves required: `privileged/firewall_helper.py`, `app/api/firewall.py`, `app/services/firewall_service.py`
- Test: `tests/integration/test_firewall_api.py`, `tests/integration/test_privileged_helper.py`, `tests/unit/test_firewall_helper.py`

**Interfaces:** unchanged `apply/confirm/rollback` API and persisted rollback manifest structure containing flat expanded operations.

- [ ] Write RED integration tests for source removed before Apply then rollback; partial UFW add failure, helper restart with pending timer, confirmation preventing rollback; old managed comments and unmanaged entries remain handled.
- [ ] Run RED; fix only proved defects, preserving 120s systemd rollback architecture.
- [ ] Run GREEN + full suite; checkpoint `0.6.6-task6-rollback`.

## Task 7: Repeatable Add IP/CIDR firewall dialog and rule table

**Files**
- Modify: `app/templates/system.html`, `app/static/app.js`, `app/static/app.css`
- Test: `tests/integration/test_web_ui.py`; optional browser viewport tests in `tests/e2e/`

**Interfaces:** add `data-firewall-source-list`, `data-firewall-source-add`, `data-firewall-source-remove`; keep `data-firewall-form`, `data-firewall-dialog`, all existing action and confirmation hooks; submit `source_cidrs` array and optionally first-item legacy projection.

- [ ] Write RED template/JS tests for one initial source, adding/removing rows, disabling removal of last row, 32-source cap feedback, editing existing multi-source rule, escaped text, accessible labels, and mobile modal scrolling.
- [ ] Run UI tests RED; add repeatable labeled inputs and delegated handlers; change firewall-specific load/edit/save/render only. Do not touch global `actionModalResolver` logic.
- [ ] Add responsive source chip/list CSS and compact logical source rendering; preserve local table scroll.
- [ ] Run GREEN + UI suite + full suite; checkpoint `0.6.6-task7-ui`.

## Task 8: Version metadata, documentation and integration checks

**Files**
- Modify: `VERSION`, `tests/integration/test_packaging.py`
- Create: `docs/superpowers/specs/2026-10-18-dns-manager-multi-source-0.6.6-design.md`, `docs/superpowers/plans/2026-10-18-dns-manager-multi-source-0.6.6.md`
- Test: `tests/integration/test_packaging.py`

- [ ] Add spec/plan to source tree and release compatibility notes (migration forward/backward caveat, no auto-Apply).
- [ ] Change packaging test version expectation to `0.6.6` first; run `pytest -q tests/integration/test_packaging.py` and verify RED only for `0.6.5` actual version.
- [ ] Write `VERSION=0.6.6`; run packaging tests GREEN.
- [ ] Run `pytest -q` full suite; `python3 -m py_compile ...`; `bash -n packaging/install.sh`; `node --check app/static/app.js` where Node available. Check critical modal and inactive-UFW regression tests explicitly.
- [ ] Checkpoint `0.6.6-task8-release-candidate`.

## Task 9: Cumulative artifact, pre-production and live acceptance

**Files:** full source tree; ZIP output `dns-manager-multiple-source-0.6.6.zip`.

- [ ] Before building, inspect full source tree for DB files, backups, tokens, secrets, runtime/cache files; explicitly exclude secrets and caches. Retain top-level `dns-manager/` path and executable modes.
- [ ] Build ZIP; inspect the archive for `VERSION`, migration 0010, API/model/service/helper/UI/test/spec/plan, 0.5.9–0.6.5 fixes and helper service restart. Hash with SHA256.
- [ ] On staging or rollback-ready host, make consistent SQLite backup and UFW snapshots; apply existing installer, verify Alembic head `0010`, services/health, existing one-source rules and applied UFW remain unchanged **before explicit Apply**.
- [ ] Create draft multi-source test rules; verify Preview/Validate, SSH safety, 6-op `both` expansion and edit/delete; only explicitly Apply/Confirm under a second SSH session and known safe source set.
- [ ] Exercise rollback on a safe test/staging environment, verify no stale source rules, no unmanaged-rule loss, and 120-second fail-safe.
- [ ] Release only after full automated suite, staging checks, rollback acceptance and clean security review. Do not claim live-browser/mobile acceptance from structural tests alone.
