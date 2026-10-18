# DNS Manager 0.5.8 Security Firewall Management — Design Specification

**Date:** 2026-10-17  
**Target release:** 0.5.8  
**Status:** Draft for user review  
**Current baseline:** DNS Manager 0.5.7

## 1. Purpose

Add a safe, auditable web-based UFW firewall management subsystem to DNS Manager so an authorized administrator can view, configure, edit, validate, preview, apply, and roll back firewall policy from the existing web UI without giving the FastAPI application root privileges.

The release must specifically address the current production exposure profile:

- DNS service listens on the configured public/internal proxy address on TCP/UDP 53.
- Nginx listens publicly on TCP 80/443.
- SSH listens on TCP 2222.
- FastAPI/Gunicorn listens only on 127.0.0.1:8500.
- UFW is currently inactive and no nftables policy is present.
- SSH currently permits root login and password authentication; this release will report that risk but will not automatically change `sshd_config`.

The system must reduce the risk of creating an open DNS resolver or accidentally locking the administrator out of SSH while preserving the existing reverse-proxy, SSL, DNS Manager UI, and mapping behavior.

## 2. Goals

### 2.1 Functional goals

The web UI must allow an authorized user to:

1. See UFW installed/enabled state and effective default policies.
2. List DNS Manager-managed firewall rules.
3. Add, edit, and delete structured rules.
4. Configure action (`allow`/`deny`), protocol (`tcp`/`udp`/`both`), port or port range, source CIDR, and comment.
5. Preview the proposed firewall policy before applying it.
6. Validate the proposal for syntax and lockout/security risks.
7. Apply the proposed policy through the existing privileged-helper architecture.
8. Restore the last known-good managed firewall snapshot.
9. See warnings for unsafe DNS 53 exposure and risky SSH exposure.
10. See every firewall change in the audit log.

### 2.2 Safety goals

The system must:

- Never execute arbitrary user-supplied shell commands.
- Never run FastAPI as root.
- Prevent enabling a policy that lacks a viable SSH management allow path unless an explicit protected emergency mechanism is active.
- Never create a public rule for FastAPI port 8500.
- Require explicit high-risk confirmation for world-open DNS 53 or SSH 2222 rules.
- Validate all source CIDRs and port/range values server-side.
- Preserve working firewall state if validation or apply fails.
- Maintain a last-known-good snapshot before every successful mutation.
- Fail closed at the helper validation boundary for unknown keys or unsupported operations.

## 3. Non-goals for 0.5.8

The following are intentionally out of scope:

- General raw iptables/nftables editor.
- Arbitrary UFW CLI text box.
- Automatic SSH key provisioning.
- Automatic modification of `sshd_config`.
- Dynamic geo-IP or ASN firewall rules.
- Per-user firewall namespaces.
- IPv6-specific advanced rule editor beyond safe support for CIDRs already accepted by UFW; if IPv6 is disabled by host UFW configuration, the UI reports that state.
- Automatic discovery of every upstream network prefix used by the ISP.

## 4. Selected architecture

### 4.1 Approach

Use a **structured managed-policy model** stored in the DNS Manager database, rendered into deterministic UFW operations, and applied only by the existing root privileged helper.

This is preferred over editing `/etc/ufw/*` directly because it gives the application a stable validation model, makes audit/rollback deterministic, and keeps the root boundary narrow.

### 4.2 Components

New or extended components:

- `app/models/firewall.py` — managed firewall policy/rule persistence.
- `app/schemas/firewall.py` — request/response validation.
- `app/services/firewall_service.py` — rule validation, preview generation, safety analysis, snapshot metadata.
- `app/api/firewall.py` — authenticated firewall API.
- `app/templates/system.html` — new Firewall section under System/Security.
- `app/static/app.js` — structured rule editor and global modal actions.
- `app/services/privileged_helper.py` — typed helper client operations.
- `privileged/helper_server.py` — strict allow-list for firewall operations.
- `privileged/firewall_helper.py` — root-only UFW status/apply/rollback implementation.
- Alembic migration for firewall tables and RBAC permission seed.

No firewall command will be constructed directly in browser JavaScript.

## 5. Data model

### 5.1 Firewall policy

One active managed policy record stores:

- enabled flag (desired UFW enabled state)
- default incoming policy (`deny` or `reject`; initial UI recommendation: `deny`)
- default outgoing policy (`allow` or `deny`; initial recommendation: `allow`)
- current revision number
- last applied timestamp
- last applied actor user ID

### 5.2 Firewall rule

Each managed rule stores:

- stable UUID/integer ID
- display label/comment
- action: `allow` or `deny`
- protocol: `tcp`, `udp`, or `both`
- port start
- optional port end
- source CIDR
- enabled flag
- purpose classification: `web`, `dns`, `ssh`, `custom`
- deterministic sort key

The first release does not expose arbitrary destination addresses/interfaces. Rules apply to the server host.

### 5.3 Snapshot

Before each successful apply, the helper writes a root-owned last-known-good snapshot under a dedicated state directory such as:

`/var/lib/dns-manager/firewall/`

Snapshot contents include:

- `ufw status numbered` output
- relevant UFW defaults
- DNS Manager managed rule manifest
- timestamp/revision

Secrets are not stored in snapshots.

## 6. RBAC

Add permission:

`firewall.manage`

Default permission policy:

- `super_admin`: allowed
- `admin`: not automatically granted unless migration policy explicitly includes it; safest default is super-admin only
- `viewer`: denied
- custom roles: assignable through existing role permission editor

Read-only firewall status may use the same permission in 0.5.8 to keep the initial model simple. A future release may split `firewall.read` and `firewall.manage`.

## 7. Web UI

### 7.1 Location

Add a **Firewall (UFW)** card/section under **System → Security**.

### 7.2 Status summary

Show:

- UFW installed: yes/no
- UFW state: active/inactive
- default incoming/outgoing
- managed rule count
- active SSH port detected from local configuration/listener
- DNS TCP/UDP 53 exposure warning
- FastAPI bind safety status (`127.0.0.1:8500` expected)

### 7.3 Rule table

Columns:

- Status
- Purpose
- Action
- Protocol
- Port
- Source
- Comment
- Actions

Actions:

- Add rule
- Edit rule
- Delete rule
- Preview
- Validate
- Apply
- Rollback
- Refresh

All actions use the existing global modal system.

### 7.4 Structured editor

Fields:

- Purpose
- Action
- Protocol
- Port / start-end range
- Source CIDR
- Comment
- Enabled

The UI never accepts raw UFW command text.

## 8. Safety validation

Validation happens in both the application service and privileged helper.

### 8.1 Mandatory checks

Reject apply when:

- any CIDR is malformed
- port is outside 1-65535
- range is reversed or invalid
- unsupported action/protocol is used
- a rule attempts to expose port 8500 publicly
- UFW executable/state cannot be safely inspected
- generated policy cannot be converted into the constrained helper format

### 8.2 SSH lockout prevention

Before enabling/applying restrictive incoming policy:

1. Detect the active SSH listener port, expected currently to be 2222.
2. Inspect the current request source IP at the FastAPI/Nginx boundary.
3. Require at least one enabled allow rule that covers the detected SSH port and either:
   - the request source IP, or
   - a broader management CIDR that contains it.
4. If source IP is unavailable/untrusted due to proxying, require an explicit management CIDR rule and show a stronger warning.
5. Reject apply if no safe SSH path exists.

The application must not trust arbitrary `X-Forwarded-For` from the public internet. It may only use the remote address established through the known local Nginx proxy path and must document the trust boundary.

### 8.3 Emergency rollback

Apply uses a delayed-confirmation safety model:

1. Helper records last-known-good state.
2. Helper applies proposed UFW policy.
3. Helper schedules an automatic rollback deadline (recommended 120 seconds).
4. Web UI performs post-apply connectivity/health confirmation.
5. User confirms **Keep firewall changes** or successful health confirmation commits the new state.
6. If confirmation is not received before the deadline, helper automatically restores the prior snapshot.

The rollback mechanism must be system-level and must not depend on the FastAPI process remaining reachable after apply. Implementation should use a transient systemd unit/timer or equivalent root-owned mechanism rather than a browser timer.

## 9. DNS open-resolver protection

The system must specifically analyze TCP/UDP port 53 rules.

Warnings:

- `0.0.0.0/0` or `::/0` allow to TCP/UDP 53: **Critical / Internet-open DNS**.
- Broad source CIDRs: warning based on explicit user configuration, not guessed ISP topology.
- No rule while UFW is inactive: informational warning that host firewall is not protecting port 53.

Applying a world-open port 53 allow rule requires a high-risk confirmation modal. The UI recommends trusted customer/ISP prefixes instead.

The release does not silently invent or auto-apply trusted DNS networks.

## 10. SSH security reporting

0.5.8 will display, but not automatically edit, these SSH security findings:

- root password login enabled
- password authentication enabled
- public listener on 0.0.0.0/[::]

Suggested target posture may be displayed:

- `PermitRootLogin prohibit-password`
- `PasswordAuthentication no`
- `PubkeyAuthentication yes`

Changing SSH daemon configuration remains a separate future feature because it has independent lockout risks.

## 11. API design

Proposed endpoints:

- `GET /api/v1/firewall/status`
- `GET /api/v1/firewall/policy`
- `PUT /api/v1/firewall/policy`
- `POST /api/v1/firewall/rules`
- `PUT /api/v1/firewall/rules/{rule_id}`
- `DELETE /api/v1/firewall/rules/{rule_id}`
- `POST /api/v1/firewall/preview`
- `POST /api/v1/firewall/validate`
- `POST /api/v1/firewall/apply`
- `POST /api/v1/firewall/confirm`
- `POST /api/v1/firewall/rollback`

Mutating endpoints require:

- authenticated session
- CSRF validation
- `firewall.manage`

## 12. Privileged-helper contract

Only typed operations are allowed, for example:

- `firewall_status`
- `firewall_apply`
- `firewall_confirm`
- `firewall_rollback`

The helper validates a strict JSON schema/allow-list and rejects unknown keys.

The helper may invoke only fixed executable paths such as `/usr/sbin/ufw` and `/bin/systemctl`. No `shell=True`, no user-controlled executable, and no raw command concatenation.

The apply operation receives normalized structured rules, not arbitrary CLI fragments.

## 13. Apply algorithm

High-level transaction:

1. API authenticates + checks CSRF/RBAC.
2. Service loads desired policy/rules.
3. Service performs application-level safety validation.
4. Service requests helper preview/status.
5. Helper independently validates normalized payload.
6. Helper writes last-known-good snapshot.
7. Helper resets/rebuilds DNS Manager managed UFW policy deterministically.
8. Helper runs `ufw status verbose` and verifies expected state.
9. Helper arms automatic rollback deadline.
10. API returns applied-but-pending-confirmation state.
11. Browser/health check verifies panel remains reachable.
12. Confirm endpoint cancels rollback and marks revision committed.
13. On timeout or explicit rollback, helper restores previous snapshot.

## 14. UFW ownership model

To avoid accidentally destroying unrelated administrator rules, DNS Manager must have an explicit ownership policy.

For 0.5.8, the selected model is:

- DNS Manager manages only rules carrying a deterministic comment prefix such as `DNSMGR:`.
- Existing non-DNS-Manager UFW rules are preserved.
- Default policy changes are managed only when explicitly changed in the web policy editor.
- The helper must never perform an unconditional `ufw reset` on a host with unmanaged rules.

If deterministic safe reconciliation cannot be guaranteed for the installed UFW version, apply must fail rather than delete unknown rules.

## 15. Audit events

At minimum:

- `FIREWALL_RULE_CREATED`
- `FIREWALL_RULE_UPDATED`
- `FIREWALL_RULE_DELETED`
- `FIREWALL_POLICY_UPDATED`
- `FIREWALL_APPLY_STARTED`
- `FIREWALL_APPLIED_PENDING_CONFIRMATION`
- `FIREWALL_APPLY_CONFIRMED`
- `FIREWALL_ROLLED_BACK`
- `FIREWALL_APPLY_FAILED`

Audit payloads include rule IDs/revisions and normalized non-secret configuration only.

## 16. Error handling

- UFW missing: show unavailable state; do not attempt install silently.
- Invalid rule: HTTP 422 with field-level error.
- Unsafe SSH path: HTTP 409 with lockout-specific detail.
- High-risk but permitted action: explicit confirmation token/modal required.
- Helper unavailable: HTTP 503; no partial database commit.
- UFW command failure: restore prior state and return failure detail without leaking sensitive environment data.
- Auto-rollback triggered: UI reports rollback event on next refresh/login.

## 17. Database transaction rules

Draft changes may be stored before apply, but the system distinguishes:

- desired revision
- applied revision
- pending-confirmation revision

A failed apply does not mark the desired revision as active. Confirmed helper state is the source of truth for applied revision metadata.

## 18. Default recommended policy

The UI may offer a **Recommended baseline** preset but must not apply it automatically:

| Service | Protocol | Source | Action |
|---|---|---|---|
| Web | TCP 80 | Anywhere | Allow |
| HTTPS | TCP 443 | Anywhere | Allow |
| DNS | UDP 53 | Trusted DNS CIDRs only | Allow |
| DNS | TCP 53 | Trusted DNS CIDRs only | Allow |
| SSH | TCP 2222 | Management/NOC CIDRs only | Allow |
| Other inbound | — | — | Deny by default |
| Outbound | — | — | Allow by default |

The user must supply trusted DNS and SSH management networks; DNS Manager will not infer them.

## 19. Security-status reporting

The System/Security view should summarize:

- direct-IP HTTP/HTTPS block status
- UFW enabled state
- DNS 53 exposure state
- SSH exposure/password/root-login findings
- FastAPI bind state
- SSL renewal timer state

This section is informational unless the user has `firewall.manage` permission.

## 20. Testing strategy

### 20.1 Unit tests

- rule/CIDR/port validation
- world-open DNS warning detection
- SSH management-rule coverage
- port 8500 public exposure rejection
- managed-rule reconciliation
- snapshot serialization
- rollback deadline state

### 20.2 Integration tests

- RBAC/CSRF on every mutation
- create/edit/delete rules
- preview and validate behavior
- helper strict-schema rejection
- audit event coverage
- desired/applied/pending revision transitions
- rollback after simulated failed confirmation

### 20.3 Privileged helper tests

Run against a fake/stub UFW executor for automated tests; production helper code must still use fixed absolute command paths.

Tests cover:

- preserves unmanaged UFW rules
- creates only `DNSMGR:` managed rules
- helper rejects arbitrary command material
- snapshot before mutation
- restore on failure
- delayed rollback arming/cancellation

### 20.4 Packaging tests

- required UFW binary detection
- helper/service installation
- state-directory ownership/permissions
- migration/RBAC seed
- upgrade from 0.5.7 preserves existing services and Nginx direct-IP block

## 21. Deployment and compatibility

Upgrade must preserve all 0.5.7 functionality:

- mappings and reverse proxy
- SSL/Hosted ACME
- backup upload/restore
- custom role create/delete
- direct-IP HTTP/HTTPS blocking
- Nginx vhost deduplication
- public configured `DNS_MANAGER_INTERNAL_PROXY_IP=157.15.20.132`

UFW must not be enabled automatically during package installation. Installation only adds capability. The administrator explicitly previews and applies the first policy from the web UI.

## 22. Acceptance criteria

0.5.8 is acceptable when all of the following are true:

1. Super Admin can create/edit/delete structured firewall rules from the UI.
2. Raw shell/UFW command input is impossible through the API/UI.
3. The application process remains non-root.
4. Existing unmanaged UFW rules survive DNS Manager apply.
5. Enabling a restrictive policy without a safe SSH rule is rejected.
6. Public port 8500 exposure is rejected.
7. World-open DNS 53 produces a critical warning and explicit confirmation requirement.
8. Apply creates a last-known-good snapshot and arms independent automatic rollback.
9. Confirmation commits changes; timeout restores the old state.
10. Audit log records every mutation/apply/rollback.
11. Existing 0.5.7 mapping/SSL/direct-IP protections pass regression tests.
12. Installer does not enable UFW automatically.

## 23. Implementation sequencing recommendation

The implementation plan should sequence work roughly as:

1. DB/RBAC models and validation service.
2. Read-only status detection.
3. Privileged helper UFW boundary.
4. Managed-rule reconciliation and snapshots.
5. Apply + independent emergency rollback.
6. API endpoints.
7. UI rule editor/status/preview flow.
8. Audit integration.
9. Packaging/migration.
10. Full security and regression verification.

This sequencing is advisory; the implementation plan will define exact TDD task boundaries after this written spec is approved.
