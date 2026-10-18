# DNS Manager 0.5.8 Security Firewall Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add safe, auditable, web-based UFW firewall management with structured rules, SSH lockout protection, DNS exposure warnings, privileged-helper enforcement, and independent emergency rollback.

**Architecture:** Persist desired managed firewall policy in SQLite, validate it in application code, and send only normalized structured payloads across the existing Unix-socket privileged-helper boundary. The root helper owns UFW inspection/reconciliation/snapshots and a systemd-backed 120-second rollback deadline; existing unmanaged UFW rules are preserved and the app process remains non-root.

**Tech Stack:** FastAPI, SQLAlchemy, Alembic, SQLite, Jinja2, vanilla JavaScript, systemd socket/service units, UFW, Python `ipaddress`, pytest.

**Spec:** `docs/superpowers/specs/2026-10-17-dns-manager-security-firewall-0.5.8-design.md`

## Global Constraints

- Target release is `0.5.8`; baseline is DNS Manager `0.5.7`.
- UFW is never enabled automatically by package installation.
- FastAPI/Gunicorn remains bound to `127.0.0.1:8500`; public exposure of port 8500 is rejected.
- No raw UFW command text, `shell=True`, user-controlled executable paths, or arbitrary command concatenation.
- DNS Manager owns only UFW rules with deterministic `DNSMGR:` comments; unmanaged rules must survive apply/rollback.
- Default permission is super-admin only through new `firewall.manage`; custom roles may be granted it explicitly.
- Mutating API endpoints require authenticated session, CSRF, and `firewall.manage`.
- World-open TCP/UDP 53 and SSH management-port rules require explicit high-risk confirmation.
- Restrictive apply requires a viable SSH allow path covering the trusted request source or an explicit management CIDR.
- Emergency rollback deadline is 120 seconds and must run independently of FastAPI/browser reachability.
- Preserve all 0.5.7 behavior: mappings, Hosted ACME SSL, backup upload/restore, role create/delete, direct-IP block, Nginx vhost dedup, and public `DNS_MANAGER_INTERNAL_PROXY_IP=157.15.20.132` support.

## Review Focus

1. **Proxy/source-IP trust:** forged public `X-Forwarded-For` must never satisfy SSH safety; only the local trusted Nginx hop/request client model may supply the effective source. Pin in Task 5 API tests.
2. **Dual-protocol rule semantics:** `protocol="both"` must become two deterministic managed rules without accidentally matching unmanaged rules. Pin in Task 4 helper reconciliation tests.
3. **Interrupted apply:** helper/UFW failure after partial mutation must restore the snapshot and must not advance applied revision. Pin in Tasks 4 and 6.
4. **Pending-confirmation restart:** helper/FastAPI restart while rollback is armed must leave the systemd rollback mechanism effective and observable. Pin in Task 6.
5. **IPv6/world-open detection:** `::/0` is treated as world-open exactly like `0.0.0.0/0`, while valid narrower IPv6 CIDRs remain accepted when UFW supports IPv6. Pin in Task 2 validation tests.

---

## File Structure

- `app/models/firewall.py` — policy/rule persistence and revision state.
- `app/schemas/firewall.py` — typed API payloads/responses.
- `app/services/firewall_service.py` — validation, risk analysis, preview model, SSH/source-IP safety, desired/applied revision transitions.
- `app/api/firewall.py` — authenticated/CSRF/RBAC firewall endpoints and audit integration.
- `privileged/firewall_helper.py` — fixed-path UFW/systemd operations, managed-rule reconciliation, snapshots, rollback timer lifecycle.
- `privileged/helper_server.py` — strict firewall helper command allow-list and nested payload validation.
- `app/services/privileged_helper.py` — typed firewall helper client calls.
- `app/templates/system.html`, `app/static/app.js`, `app/static/app.css`, `app/web.py` — System → Security firewall UI.
- `migrations/versions/0009_firewall_management.py` — tables + `firewall.manage` permission seed.
- `packaging/systemd/dns-manager-firewall-rollback@.service` — independent rollback unit invoked with a snapshot/revision token.
- `packaging/tmpfiles.d/dns-manager.conf`, `packaging/install.sh` — firewall state directory and package wiring.

---

### Task 1: Firewall persistence and RBAC migration

**Files:**
- Create: `app/models/firewall.py`
- Modify: `app/models/__init__.py`
- Create: `app/schemas/firewall.py`
- Create: `migrations/versions/0009_firewall_management.py`
- Modify: `app/services/auth_service.py`
- Test: `tests/integration/test_firewall_models.py`
- Test: `tests/integration/test_database.py`

**Interfaces:**
- Produces `FirewallPolicy`, `FirewallRule`, `FirewallRevision` SQLAlchemy models.
- Produces Pydantic types `FirewallPolicyUpdate`, `FirewallRuleCreate`, `FirewallRuleUpdate`, `FirewallRuleRead`, `FirewallPolicyRead`.
- Seeds permission name exactly `firewall.manage`; only `super_admin` receives it automatically.

- [ ] **Step 1: Write failing model/migration tests**
  - Assert one policy row can store desired enabled/default policies/current revision metadata.
  - Assert rules persist `action`, `protocol`, `port_start`, nullable `port_end`, `source_cidr`, `purpose`, `enabled`, `sort_key`, `comment`.
  - Assert migration seeds `firewall.manage` to `super_admin` but not `admin`/`viewer`.

- [ ] **Step 2: Run RED tests**
  - Run: `pytest tests/integration/test_firewall_models.py tests/integration/test_database.py -q`
  - Expected: FAIL because firewall tables/permission do not exist.

- [ ] **Step 3: Implement models, schemas, migration, and permission registry**
  - Use deterministic table names `firewall_policies`, `firewall_rules`, `firewall_revisions`.
  - Keep one active policy row; initialize `default_incoming='deny'`, `default_outgoing='allow'`, `enabled=False`.
  - Store desired/applied/pending revision numbers distinctly.

- [ ] **Step 4: Run GREEN tests**
  - Run: `pytest tests/integration/test_firewall_models.py tests/integration/test_database.py -q`
  - Expected: PASS.

- [ ] **Step 5: Commit**
  - `git add app/models app/schemas/firewall.py app/services/auth_service.py migrations/versions/0009_firewall_management.py tests/integration`
  - `git commit -m "feat: add firewall persistence and permission"`

---

### Task 2: Validation, risk analysis, and preview service

**Files:**
- Create: `app/services/firewall_service.py`
- Test: `tests/unit/test_firewall_service.py`

**Interfaces:**
- Produces `normalize_rule(...) -> NormalizedFirewallRule`.
- Produces `validate_policy(policy, rules, *, ssh_port: int, source_ip: str | None) -> FirewallValidationResult`.
- Produces `build_preview(policy, rules) -> FirewallPreview`.
- `FirewallValidationResult` exposes blocking errors, warnings, `requires_high_risk_confirmation`, and normalized rules.

- [ ] **Step 1: Write failing validation tests**
  - Reject malformed IPv4/IPv6 CIDR, ports outside `1..65535`, reversed ranges, unsupported action/protocol/purpose.
  - Reject any public exposure of port 8500.
  - Detect `0.0.0.0/0` and `::/0` allow to TCP/UDP 53 as critical Internet-open DNS.
  - Require high-risk confirmation for world-open DNS 53 or detected SSH port.
  - Accept narrower IPv6 CIDRs and normalize network notation.
  - Require SSH allow coverage when incoming default is restrictive/enabled.

- [ ] **Step 2: Run RED test**
  - Run: `pytest tests/unit/test_firewall_service.py -q`
  - Expected: FAIL because service is missing.

- [ ] **Step 3: Implement normalized domain types and validation**
  - Use Python `ipaddress.ip_network(..., strict=False)`.
  - Treat protocol `both` as a semantic rule here; expansion happens only in helper reconciliation.
  - Preview must contain deterministic normalized operations, never shell strings supplied by the user.

- [ ] **Step 4: Run GREEN test**
  - Run: `pytest tests/unit/test_firewall_service.py -q`
  - Expected: PASS.

- [ ] **Step 5: Commit**
  - `git add app/services/firewall_service.py tests/unit/test_firewall_service.py`
  - `git commit -m "feat: validate firewall policy and risks"`

---

### Task 3: Read-only firewall/security status detection

**Files:**
- Create: `privileged/firewall_helper.py`
- Modify: `privileged/helper_server.py`
- Modify: `app/services/privileged_helper.py`
- Modify: `app/services/health_service.py`
- Test: `tests/integration/test_privileged_helper.py`
- Test: `tests/integration/test_health.py`
- Test: `tests/unit/test_firewall_helper.py`

**Interfaces:**
- Helper command `firewall_status` accepts no user fields.
- `FirewallHelperOps.status() -> dict` reports UFW installed/active/defaults, managed/unmanaged counts, IPv6 state, detected SSH listener ports, and raw-safe findings needed by the app.
- App `PrivilegedHelper.firewall_status() -> dict` exposes the typed call.

- [ ] **Step 1: Write failing helper/status tests**
  - Fixed executable path `/usr/sbin/ufw` only.
  - UFW missing returns unavailable state, not an install attempt.
  - Detect SSH listener port(s), expected production port 2222.
  - Verify helper rejects any fields attached to `firewall_status`.

- [ ] **Step 2: Run RED tests**
  - Run: `pytest tests/unit/test_firewall_helper.py tests/integration/test_privileged_helper.py tests/integration/test_health.py -q`
  - Expected: FAIL for missing command/status integration.

- [ ] **Step 3: Implement read-only helper and health summary**
  - Use `subprocess.run([...], shell=False, ...)` with absolute paths and bounded timeout.
  - Do not mutate firewall state in this task.

- [ ] **Step 4: Run GREEN tests**
  - Run same command; expected PASS.

- [ ] **Step 5: Commit**
  - `git add privileged/firewall_helper.py privileged/helper_server.py app/services/privileged_helper.py app/services/health_service.py tests`
  - `git commit -m "feat: report firewall security status"`

---

### Task 4: Managed-rule reconciliation and snapshots

**Files:**
- Modify: `privileged/firewall_helper.py`
- Modify: `privileged/helper_server.py`
- Modify: `app/services/privileged_helper.py`
- Test: `tests/unit/test_firewall_helper.py`
- Test: `tests/integration/test_privileged_helper.py`

**Interfaces:**
- Helper command `firewall_preview` consumes normalized policy/rules and returns deterministic planned mutations.
- Internal `reconcile_managed_rules(payload) -> ApplyResult` owns only comments beginning `DNSMGR:`.
- Internal `write_snapshot(revision: int) -> SnapshotRef` writes root-owned state under `/var/lib/dns-manager/firewall/`.

- [ ] **Step 1: Write failing reconciliation tests**
  - Preserve arbitrary unmanaged UFW rules byte-for-byte/semantically.
  - Remove/replace only `DNSMGR:` rules.
  - Expand `protocol='both'` into deterministic TCP + UDP managed rules.
  - Snapshot occurs before first mutation.
  - Any mid-apply executor failure restores the snapshot.
  - Reject unknown nested keys and arbitrary command material.

- [ ] **Step 2: Run RED tests**
  - Run: `pytest tests/unit/test_firewall_helper.py tests/integration/test_privileged_helper.py -q`
  - Expected: FAIL for missing preview/reconciliation.

- [ ] **Step 3: Implement preview, reconciliation, and snapshot primitives**
  - Never call unconditional `ufw reset`.
  - Use deterministic comment format `DNSMGR:<rule-id>:<tcp|udp>`.
  - Fail closed if installed UFW output cannot be reconciled safely.

- [ ] **Step 4: Run GREEN tests**
  - Run same command; expected PASS.

- [ ] **Step 5: Commit**
  - `git add privileged/firewall_helper.py privileged/helper_server.py app/services/privileged_helper.py tests`
  - `git commit -m "feat: reconcile managed ufw rules safely"`

---

### Task 5: Firewall API CRUD, CSRF/RBAC, source-IP trust, and audit

**Files:**
- Create: `app/api/firewall.py`
- Modify: `app/main.py`
- Modify: `app/services/firewall_service.py`
- Test: `tests/integration/test_firewall_api.py`
- Test: `tests/security/test_csrf.py`
- Test: `tests/integration/test_audit.py`

**Interfaces:**
- Endpoints exactly:
  - `GET /api/v1/firewall/status`
  - `GET /api/v1/firewall/policy`
  - `PUT /api/v1/firewall/policy`
  - `POST /api/v1/firewall/rules`
  - `PUT /api/v1/firewall/rules/{rule_id}`
  - `DELETE /api/v1/firewall/rules/{rule_id}`
  - `POST /api/v1/firewall/preview`
  - `POST /api/v1/firewall/validate`
- Produces audit events `FIREWALL_RULE_CREATED`, `FIREWALL_RULE_UPDATED`, `FIREWALL_RULE_DELETED`, `FIREWALL_POLICY_UPDATED`.

- [ ] **Step 1: Write failing API/security tests**
  - `viewer`/`admin` without explicit permission receive 403; super-admin succeeds.
  - Every mutation without valid CSRF receives 403.
  - Forged external `X-Forwarded-For` cannot override trusted request source used for SSH safety.
  - Validation returns 422 for malformed fields and 409 for unsafe SSH path.
  - CRUD writes expected audit rows with normalized non-secret payloads.

- [ ] **Step 2: Run RED tests**
  - Run: `pytest tests/integration/test_firewall_api.py tests/security/test_csrf.py tests/integration/test_audit.py -q`
  - Expected: FAIL because routes are absent.

- [ ] **Step 3: Implement routes and trusted-source extraction**
  - Follow existing session-bound CSRF pattern.
  - Trust only the known local Nginx hop/request client model; do not trust arbitrary public forwarding headers.
  - Keep draft DB mutations separate from applied-revision state.

- [ ] **Step 4: Run GREEN tests**
  - Run same command; expected PASS.

- [ ] **Step 5: Commit**
  - `git add app/api/firewall.py app/main.py app/services/firewall_service.py tests`
  - `git commit -m "feat: add firewall policy api"`

---

### Task 6: Apply, 120-second emergency rollback, confirm, and explicit rollback

**Files:**
- Modify: `privileged/firewall_helper.py`
- Modify: `privileged/helper_server.py`
- Modify: `app/services/privileged_helper.py`
- Modify: `app/services/firewall_service.py`
- Modify: `app/api/firewall.py`
- Create: `packaging/systemd/dns-manager-firewall-rollback@.service`
- Test: `tests/unit/test_firewall_helper.py`
- Test: `tests/integration/test_firewall_api.py`
- Test: `tests/integration/test_privileged_helper.py`

**Interfaces:**
- Helper commands: `firewall_apply`, `firewall_confirm`, `firewall_rollback`.
- API endpoints: `POST /api/v1/firewall/apply`, `/confirm`, `/rollback`.
- Apply response exposes `revision`, `pending_confirmation=true`, and `rollback_deadline`.
- Systemd rollback instance is keyed by opaque server-generated snapshot/revision token, never by raw path from the browser.

- [ ] **Step 1: Write failing transaction tests**
  - Successful apply creates snapshot, mutates only managed rules/defaults, verifies UFW status, and arms a 120-second rollback unit.
  - Confirm cancels rollback and advances applied revision.
  - Timeout simulation restores snapshot and leaves desired revision intact but applied revision unchanged/reverted.
  - Explicit rollback restores previous snapshot.
  - FastAPI/helper restart while timer is armed does not cancel systemd rollback.
  - Mid-apply failure restores snapshot and records `FIREWALL_APPLY_FAILED`.

- [ ] **Step 2: Run RED tests**
  - Run: `pytest tests/unit/test_firewall_helper.py tests/integration/test_firewall_api.py tests/integration/test_privileged_helper.py -q`
  - Expected: FAIL for missing transaction lifecycle.

- [ ] **Step 3: Implement apply/confirm/rollback lifecycle**
  - Use fixed `/bin/systemctl` path and root-owned state directory.
  - Write pending metadata atomically before arming rollback.
  - Confirmation must be idempotent for the currently pending revision.

- [ ] **Step 4: Run GREEN tests**
  - Run same command; expected PASS.

- [ ] **Step 5: Commit**
  - `git add privileged app/services app/api/firewall.py packaging/systemd tests`
  - `git commit -m "feat: add firewall emergency rollback transaction"`

---

### Task 7: System/Security firewall UI and global modal flows

**Files:**
- Modify: `app/templates/system.html`
- Modify: `app/static/app.js`
- Modify: `app/static/app.css`
- Modify: `app/web.py`
- Test: `tests/integration/test_web_ui.py`

**Interfaces:**
- Jinja context adds `can_firewall_manage`.
- UI consumes Task 5/6 endpoints only; no raw CLI input field exists.
- All mutation feedback uses existing global `runAction`/modal pattern.

- [ ] **Step 1: Write failing UI tests**
  - Firewall card appears under System/Security.
  - Rule editor exposes purpose/action/protocol/port/range/source/comment/enabled only.
  - Preview, Validate, Apply, Confirm, Rollback, Refresh buttons exist for permitted user.
  - Non-permitted user sees informational status but no mutation controls.
  - Critical DNS and SSH warnings render from API status/risk payloads.
  - No textbox/textarea accepts arbitrary UFW command text.

- [ ] **Step 2: Run RED test**
  - Run: `pytest tests/integration/test_web_ui.py -q`
  - Expected: FAIL because firewall UI is absent.

- [ ] **Step 3: Implement structured UI**
  - Add recommended baseline helper text without auto-applying any rules.
  - Apply modal must show pending-confirmation countdown/deadline and explicit **Keep firewall changes** action.
  - High-risk modal requires explicit confirmation before API apply proceeds.

- [ ] **Step 4: Run GREEN test and JS syntax check**
  - Run: `pytest tests/integration/test_web_ui.py -q && node --check app/static/app.js`
  - Expected: PASS / exit 0.

- [ ] **Step 5: Commit**
  - `git add app/templates/system.html app/static/app.js app/static/app.css app/web.py tests/integration/test_web_ui.py`
  - `git commit -m "feat: add firewall management ui"`

---

### Task 8: Security status findings for DNS, SSH, FastAPI, direct-IP block, and SSL timer

**Files:**
- Modify: `app/services/health_service.py`
- Modify: `app/api/firewall.py`
- Modify: `app/templates/system.html`
- Modify: `app/static/app.js`
- Test: `tests/integration/test_health.py`
- Test: `tests/integration/test_firewall_api.py`
- Test: `tests/integration/test_web_ui.py`

**Interfaces:**
- `GET /api/v1/firewall/status` includes severity-coded findings for UFW inactive, DNS 53 exposure, SSH root/password/public-listener posture, FastAPI bind, direct-IP Nginx block, and SSL renewal timer.
- This task reports SSH posture only; it never edits `sshd_config`.

- [ ] **Step 1: Write failing security-status tests**
  - Current production-shaped state reports UFW inactive + public DNS 53 + public SSH listener/root-password risk.
  - `127.0.0.1:8500` reports safe FastAPI bind.
  - Direct-IP deny vhost and SSL renew timer status remain visible.

- [ ] **Step 2: Run RED tests**
  - Run: `pytest tests/integration/test_health.py tests/integration/test_firewall_api.py tests/integration/test_web_ui.py -q`
  - Expected: FAIL for missing combined findings.

- [ ] **Step 3: Implement findings aggregation and UI badges**
  - Keep findings informational unless a firewall apply validation uses them.

- [ ] **Step 4: Run GREEN tests**
  - Run same command; expected PASS.

- [ ] **Step 5: Commit**
  - `git add app/services/health_service.py app/api/firewall.py app/templates/system.html app/static/app.js tests`
  - `git commit -m "feat: surface firewall security findings"`

---

### Task 9: Packaging, permissions, and upgrade safety

**Files:**
- Modify: `packaging/install.sh`
- Modify: `packaging/tmpfiles.d/dns-manager.conf`
- Modify: `packaging/systemd/dns-manager-helper.service`
- Add: `packaging/systemd/dns-manager-firewall-rollback@.service`
- Modify: `VERSION`
- Test: `tests/integration/test_packaging.py`

**Interfaces:**
- State directory `/var/lib/dns-manager/firewall/` is root-owned and not writable by the FastAPI user except through helper-mediated operations.
- Installer detects `/usr/sbin/ufw`; missing binary leaves feature unavailable but does not silently install/enable UFW.
- Installer copies rollback unit, reloads systemd, and preserves 0.5.7 Nginx/dnsmasq/systemd behavior.

- [ ] **Step 1: Write failing packaging tests**
  - Upgrade from 0.5.7 does not call `ufw enable` or `ufw reset`.
  - Required directories/unit files are installed with restrictive permissions.
  - Missing UFW does not abort unrelated DNS Manager upgrade; UI status becomes unavailable.
  - Existing direct-IP block, vhost dedup, public internal-proxy IP support, and helper socket remain installed.

- [ ] **Step 2: Run RED test**
  - Run: `pytest tests/integration/test_packaging.py -q`
  - Expected: FAIL for missing firewall packaging.

- [ ] **Step 3: Implement packaging and set `VERSION` to `0.5.8`**
  - Do not alter UFW active/inactive state in installer.

- [ ] **Step 4: Run GREEN test and shell syntax**
  - Run: `pytest tests/integration/test_packaging.py -q && bash -n packaging/install.sh`
  - Expected: PASS / exit 0.

- [ ] **Step 5: Commit**
  - `git add packaging VERSION tests/integration/test_packaging.py`
  - `git commit -m "feat: package firewall management safely"`

---

### Task 10: End-to-end acceptance and regression verification

**Files:**
- Modify: `tests/e2e/test_acceptance.py`
- Add: `tests/e2e/test_firewall_acceptance.py`
- Update: `docs/hosted-acme-dns-runbook.md` only if security-status references need cross-linking.

**Interfaces:**
- No new runtime interfaces; this task proves the release contract.

- [ ] **Step 1: Add acceptance tests**
  - Super-admin can create/edit/delete a structured rule.
  - Raw command payloads are impossible/rejected.
  - Unsafe SSH apply is rejected.
  - Public 8500 rule is rejected.
  - World-open DNS requires explicit high-risk confirmation.
  - Apply enters pending state, confirm commits, simulated timeout rolls back.
  - Unmanaged UFW rule survives apply.
  - Installer does not enable UFW automatically.
  - 0.5.7 mapping/SSL/direct-IP/Nginx-dedup regressions stay green.

- [ ] **Step 2: Run focused acceptance suite**
  - Run: `pytest tests/e2e/test_firewall_acceptance.py tests/e2e/test_acceptance.py -q`
  - Expected: PASS.

- [ ] **Step 3: Run full regression suite**
  - Run: `pytest -q`
  - Expected: all tests PASS, zero failures/errors.

- [ ] **Step 4: Run syntax/security gates**
  - `python3 -m compileall -q app privileged migrations`
  - `node --check app/static/app.js`
  - `bash -n packaging/install.sh`
  - `grep -RniE 'shell=True|ufw reset' app privileged packaging` and manually confirm no unsafe production invocation exists.
  - Expected: syntax commands exit 0; unsafe-command review has no prohibited runtime implementation.

- [ ] **Step 5: Verify release archive contract**
  - Build cumulative `dns-manager-security-firewall-0.5.8.zip`.
  - Re-open archive and assert: `VERSION=0.5.8`, migration `0009`, firewall API/service/helper/UI/systemd rollback files present, 0.5.7 direct-IP/default-deny and Nginx dedup files preserved.

- [ ] **Step 6: Commit**
  - `git add tests/e2e docs VERSION`
  - `git commit -m "test: verify firewall management release"`

---

## Self-Review Results

- **Spec coverage:** All functional goals, safety goals, API endpoints, helper commands, ownership model, audit events, rollback lifecycle, security reporting, packaging constraints, and acceptance criteria map to Tasks 1–10.
- **Step scan:** Each task has one RED test step, one RED verification, one focused implementation step, one GREEN verification, and one commit boundary; no task depends on unspecified behavior.
- **Type consistency:** `firewall.manage`, endpoint paths, helper command names, `DNSMGR:` ownership prefix, desired/applied/pending revisions, and 120-second rollback semantics are consistent across tasks.
- **Review Focus:** Proxy trust, dual-protocol expansion, interrupted apply, restart while pending, and IPv6 world-open detection each have a named owning task/test.
- **Proportion:** Plan specifies interfaces and proof points without transcribing implementation bodies.
