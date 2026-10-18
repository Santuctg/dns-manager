# Web SSL Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add secure browser-based Let's Encrypt certificate issuance, renewal, status, Nginx application, and auto-renewal to DNS Manager using DNS-01 while preserving the current least-privilege systemd socket-helper architecture.

**Architecture:** FastAPI remains unprivileged and stores only SSL metadata plus encrypted provider credentials in SQLite. Certificate/Nginx operations cross the existing root-owned Unix socket using a fixed SSL command protocol; the root helper invokes Certbot, creates short-lived DNS-provider credential files, validates generated Nginx config, and reloads only after successful validation. Cloudflare DNS-01 is fully automated; manual DNS-01 runs as an asynchronous root operation whose challenge state is exposed to the UI until TXT propagation is confirmed.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy/SQLite, Alembic, Jinja2 + vanilla JS, `cryptography`/Fernet, Certbot, Certbot Cloudflare DNS plugin, Nginx, systemd service/socket/timer.

**Spec:** `docs/superpowers/specs/2026-10-15-dns-manager-web-ssl-management.md`

## Global Constraints

- Super Admin is the only role allowed to mutate SSL configuration or certificates.
- Every mutating HTTP endpoint requires the existing CSRF protection.
- Cloudflare API tokens are write-only in the API/UI and encrypted at rest; tokens never appear in audit logs or responses.
- No arbitrary shell commands, arbitrary paths, Nginx snippets, or Certbot arguments may cross the helper socket.
- The app service retains `NoNewPrivileges=yes`, `ProtectSystem=strict`, and no writable `/etc`.
- The root helper remains socket-activated and accepts only fixed commands.
- DNS safety protections from Task 18 remain unchanged.
- Nginx is reloaded only after certificate presence checks and `nginx -t` pass.
- Private keys under `/etc/letsencrypt` are never copied into DNS Manager backup archives.
- Existing backup/restore, apply/rollback, RBAC, audit, and UI behavior must remain green.
- Cloudflare automated renewal must not depend on a plaintext persistent credentials file.
- Manual DNS-01 must not hold an HTTP request open while waiting for operator TXT changes.

## Review Focus

1. **Secret leakage:** API errors, audit events, helper exceptions, subprocess command logging, and UI state must never include the Cloudflare token. Task 1 and Task 6 tests pin this.
2. **Path/domain injection:** IDN/punycode edge cases, slashes, shell metacharacters, wildcard domains, and traversal-like strings must be rejected before Certbot/Nginx. Task 2 and Task 3 tests pin this.
3. **Failed certificate/Nginx transition:** a valid current HTTPS vhost must survive Certbot failure, missing cert files, or `nginx -t` failure. Task 3/4 tests pin rollback.
4. **Concurrent operations:** two issue/renew/apply operations for the same domain must not race. Task 3 adds a per-domain lock test.
5. **Restored metadata without local cert files:** after database restore, UI must show `NOT_ISSUED`/`ERROR` instead of assuming the certificate exists. Task 9 pins reconciliation.

---

## File Structure

### New application files
- `app/models/ssl.py` — SSL certificate/provider/operation persistence models.
- `app/schemas/ssl.py` — SSL request/response schemas with token write-only behavior.
- `app/services/ssl_crypto.py` — encryption-key loading and Fernet encrypt/decrypt helpers.
- `app/services/ssl_service.py` — domain validation, metadata lifecycle, helper orchestration, status reconciliation.
- `app/api/ssl.py` — Super Admin SSL REST API.
- `privileged/ssl_helper.py` — fixed Certbot/Nginx SSL operations executed as root.
- `privileged/manual_dns_hook.py` — Certbot manual auth/cleanup hook state bridge.
- `packaging/systemd/dns-manager-ssl-renew.service` — root renewal one-shot.
- `packaging/systemd/dns-manager-ssl-renew.timer` — periodic renewal timer.
- `packaging/dns-manager-ssl-renew` — fixed renewal entrypoint.
- `tests/integration/test_ssl_models.py`
- `tests/integration/test_ssl_api.py`
- `tests/integration/test_ssl_helper.py`
- `tests/integration/test_ssl_cloudflare.py`
- `tests/integration/test_ssl_manual_dns.py`
- `tests/integration/test_ssl_renewal.py`
- `tests/security/test_ssl_secrets.py`
- `tests/e2e/test_ssl_acceptance.py`

### Modified files
- `app/models/__init__.py`
- `app/main.py`
- `app/api/__init__.py`
- `app/services/privileged_helper.py`
- `app/services/backup_service.py`
- `app/templates/system.html`
- `app/static/app.js`
- `app/static/app.css`
- `privileged/helper_server.py`
- `privileged/helper_lib.py` only if common fixed-path helpers are needed.
- `packaging/systemd/dns-manager-helper.service`
- `packaging/install.sh`
- `packaging/uninstall.sh`
- `packaging/tmpfiles.d/dns-manager.conf`
- `requirements.txt`
- `tests/integration/test_packaging.py`
- Alembic: `migrations/versions/0006_ssl_management.py`

---

### Task 1: SSL Persistence and Encrypted Secret Foundation

**Files:**
- Create: `app/models/ssl.py`
- Create: `app/schemas/ssl.py`
- Create: `app/services/ssl_crypto.py`
- Create: `migrations/versions/0006_ssl_management.py`
- Modify: `app/models/__init__.py`
- Modify: `app/config.py`
- Modify: `requirements.txt`
- Test: `tests/integration/test_ssl_models.py`
- Test: `tests/security/test_ssl_secrets.py`

**Interfaces:**
- Produces `SslCertificate`, `SslProviderCredential`, and `SslOperation`.
- Produces `encrypt_secret(plaintext: str) -> str`, `decrypt_secret(ciphertext: str) -> str`, and `load_ssl_secret_key() -> bytes`.
- Later tasks consume the models and encrypted credential API.

- [ ] **Step 1: Write failing model/migration tests**
  - `SslCertificate.domain` is unique and normalized lowercase.
  - provider is `cloudflare` or `manual`.
  - `SslProviderCredential.token_ciphertext` persists ciphertext only.
  - `SslOperation` persists asynchronous manual-DNS operation state.
  - migration head becomes `0006_ssl_management`.

- [ ] **Step 2: Run the new tests and verify RED**
  - Run: `python3 -m pytest tests/integration/test_ssl_models.py tests/security/test_ssl_secrets.py -v`
  - Expected: import/model/migration failures.

- [ ] **Step 3: Implement models and migration**
  - `SslCertificate`: `id`, `domain`, `provider`, `auto_renew`, `redirect_http`, `status`, `issuer`, `issued_at`, `expires_at`, `last_renewal_at`, `last_renewal_status`, `last_error`, timestamps.
  - `SslProviderCredential`: one row per certificate/provider, encrypted token only, token fingerprint/last-four metadata allowed.
  - `SslOperation`: `domain`, `action`, `status`, `challenge_name`, `challenge_value`, `started_at`, `completed_at`, `error_message`.

- [ ] **Step 4: Implement encrypted secret handling**
  - Add `cryptography` dependency.
  - Load a base64 Fernet key from systemd credential/environment path configured as `DNS_MANAGER_SSL_SECRET_KEY_FILE`.
  - Reject missing/invalid key rather than silently generating a replacement at runtime.
  - API schemas never serialize token ciphertext or plaintext.

- [ ] **Step 5: Add secret-leak regression tests**
  - Assert raw token is absent from model repr, API-shaped response dicts, exception strings used by service tests, and audit-ready metadata.
  - Assert encrypt→decrypt round trip and wrong-key failure.

- [ ] **Step 6: Run tests GREEN**
  - Run: `python3 -m pytest tests/integration/test_ssl_models.py tests/security/test_ssl_secrets.py -v`
  - Expected: all pass.

- [ ] **Step 7: Commit**
  - `git commit -m "feat: add encrypted ssl management persistence"`

---

### Task 2: Domain Validation and Certificate Status Reconciliation

**Files:**
- Create: `app/services/ssl_service.py`
- Test: `tests/integration/test_ssl_status.py`

**Interfaces:**
- Produces `normalize_ssl_domain(value: str) -> str`.
- Produces `read_certificate_status(domain: str) -> CertificateStatus`.
- Produces `reconcile_certificate(db, certificate) -> SslCertificate`.
- Consumes Task 1 models.

- [ ] **Step 1: Write failing validation tests**
  - Accept `dns.connect3.net.bd`.
  - Normalize uppercase/trailing-dot input.
  - Reject URL schemes, ports, paths, whitespace, shell metacharacters, wildcard `*`, traversal-like strings, empty labels, and public-suffix-only values.
  - IDN input is normalized to a stable ASCII/punycode representation before filesystem/helper use.

- [ ] **Step 2: Verify RED**
  - Run: `python3 -m pytest tests/integration/test_ssl_status.py -v`

- [ ] **Step 3: Implement domain normalization**
  - Filesystem paths are always derived internally as `/etc/letsencrypt/live/<normalized-domain>/...`; callers never pass paths.

- [ ] **Step 4: Implement certificate reconciliation**
  - Parse `fullchain.pem` using Python cryptography X.509 APIs.
  - Map to `ISSUED`, `EXPIRING` (<=30 days), `EXPIRED`, `ERROR`, or `NOT_ISSUED`.
  - Read issuer, not-before/not-after, days remaining.
  - Missing files after DB restore result in `NOT_ISSUED`, not stale `ISSUED`.

- [ ] **Step 5: Run tests GREEN**
  - Run: `python3 -m pytest tests/integration/test_ssl_status.py -v`

- [ ] **Step 6: Commit**
  - `git commit -m "feat: add ssl domain validation and status reconciliation"`

---

### Task 3: Privileged SSL Helper Protocol and Safe Nginx Application

**Files:**
- Create: `privileged/ssl_helper.py`
- Modify: `privileged/helper_server.py`
- Modify: `app/services/privileged_helper.py`
- Modify: `packaging/systemd/dns-manager-helper.service`
- Test: `tests/integration/test_ssl_helper.py`
- Test: `tests/integration/test_packaging.py`

**Interfaces:**
- App client methods:
  - `ssl_status(domain: str) -> dict`
  - `ssl_issue(payload: dict) -> dict`
  - `ssl_renew(payload: dict) -> dict`
  - `ssl_test_renewal(payload: dict) -> dict`
  - `ssl_apply(domain: str, redirect_http: bool) -> dict`
  - `ssl_delete(domain: str) -> dict`
  - internal fixed command `ssl_manual_continue(domain: str) -> dict`
- Helper accepts only normalized domain plus fixed booleans/provider enum; no arbitrary path/argv fields.

- [ ] **Step 1: Write failing fixed-command protocol tests**
  - Unknown SSL command rejected.
  - Extra arbitrary `command`, `path`, `argv`, or Nginx text fields rejected.
  - Invalid domain rejected before subprocess call.
  - per-domain operation lock prevents concurrent issue/renew/apply.

- [ ] **Step 2: Verify RED**
  - Run: `python3 -m pytest tests/integration/test_ssl_helper.py -v`

- [ ] **Step 3: Implement Certbot runner abstraction**
  - Use argument arrays, never `shell=True`.
  - Apply explicit timeouts.
  - Redact credential/token values from captured errors.
  - Use fixed Let's Encrypt directories only.

- [ ] **Step 4: Implement managed HTTPS Nginx vhost generation**
  - Fixed backend `127.0.0.1:8500`.
  - Optional port 80 redirect.
  - Port 443 TLS with fullchain/privkey derived from domain.
  - TLS 1.2/1.3.
  - Existing forwarded headers.
  - Write candidate → `nginx -t` → atomic install → reload.
  - Snapshot previous managed SSL vhost and restore it on failure.

- [ ] **Step 5: Add rollback tests**
  - Cert files missing: no live Nginx change.
  - `nginx -t` failure: previous vhost restored.
  - reload failure: previous vhost restored/reloaded.
  - current HTTP management vhost remains available during failed transition.

- [ ] **Step 6: Extend helper sandbox minimally**
  - Add only required writable paths: `/etc/letsencrypt`, `/var/lib/letsencrypt`, `/var/log/letsencrypt`, and managed SSL Nginx config location.
  - Preserve existing app-service hardening unchanged.
  - Keep `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`.

- [ ] **Step 7: Run tests GREEN**
  - Run: `python3 -m pytest tests/integration/test_ssl_helper.py tests/integration/test_packaging.py -v`

- [ ] **Step 8: Commit**
  - `git commit -m "feat: add privileged ssl helper and nginx tls apply"`

---

### Task 4: Automated Cloudflare DNS-01 Issue, Renewal, and Renewal Test

**Files:**
- Modify: `privileged/ssl_helper.py`
- Modify: `app/services/ssl_service.py`
- Test: `tests/integration/test_ssl_cloudflare.py`
- Test: `tests/security/test_ssl_secrets.py`

**Interfaces:**
- `issue_cloudflare_certificate(domain, token_plaintext) -> HelperResult`
- `renew_cloudflare_certificate(domain, token_plaintext, force: bool=False) -> HelperResult`
- `test_cloudflare_renewal(domain, token_plaintext) -> HelperResult`

- [ ] **Step 1: Write failing Cloudflare command tests**
  - Credentials file mode is `0600`.
  - Token is written only to a temporary credentials file.
  - Temporary file is deleted on success and failure.
  - Token never appears in argv, helper JSON response, logs, or raised error.
  - Certbot receives fixed `--dns-cloudflare`, domain, email/configured account options, noninteractive agreement flags.

- [ ] **Step 2: Verify RED**
  - Run: `python3 -m pytest tests/integration/test_ssl_cloudflare.py tests/security/test_ssl_secrets.py -v`

- [ ] **Step 3: Implement Cloudflare issue**
  - Decrypt token in app service immediately before socket request.
  - Send token only over the local root-owned Unix socket.
  - Helper writes a short-lived root-only credential file.
  - Certbot creates/updates the named lineage for the normalized domain.

- [ ] **Step 4: Implement renewal**
  - Recreate temporary credentials for every renewal attempt; never rely on a persistent plaintext provider file.
  - Update DB status/expiry by reconciling certificate files after helper success.

- [ ] **Step 5: Implement renewal test**
  - Use a staging/dry-run path that does not replace the production lineage.
  - Clean any staging artifacts produced by the test.
  - Report success/failure without changing live Nginx configuration.

- [ ] **Step 6: Add Certbot failure tests**
  - DNS API rejection, timeout, rate limit, invalid token, and missing plugin return sanitized operator errors.

- [ ] **Step 7: Run tests GREEN**
  - Run: `python3 -m pytest tests/integration/test_ssl_cloudflare.py tests/security/test_ssl_secrets.py -v`

- [ ] **Step 8: Commit**
  - `git commit -m "feat: add cloudflare dns01 certificate lifecycle"`

---

### Task 5: Asynchronous Manual DNS-01 Workflow

**Files:**
- Create: `privileged/manual_dns_hook.py`
- Modify: `privileged/ssl_helper.py`
- Modify: `app/services/ssl_service.py`
- Test: `tests/integration/test_ssl_manual_dns.py`

**Interfaces:**
- `start_manual_issue(domain: str) -> SslOperation`
- `get_manual_operation(domain: str) -> SslOperation`
- `check_manual_dns(domain: str) -> ManualDnsCheckResult`
- Helper background operation communicates through fixed state files under `/var/lib/dns-manager/acme/<domain>/`.

- [ ] **Step 1: Write failing asynchronous-flow tests**
  - Starting manual issue returns promptly and does not hold the API request open.
  - Certbot auth hook writes challenge name/value into a fixed state file.
  - UI/API can read challenge state without root access.
  - TXT propagation check succeeds only when the expected exact value is observed.
  - Continue signal is accepted only for an active matching operation.
  - Operation timeout/failure cleans state.

- [ ] **Step 2: Verify RED**
  - Run: `python3 -m pytest tests/integration/test_ssl_manual_dns.py -v`

- [ ] **Step 3: Implement fixed manual hook**
  - Root Certbot operation runs in a dedicated transient/systemd-managed process.
  - Hook writes challenge state, then waits with bounded timeout for a fixed continuation marker.
  - No challenge text is interpreted as a shell command/path.

- [ ] **Step 4: Implement DNS propagation checker**
  - Use resolver queries for TXT.
  - Return observed values and readiness state.
  - On exact match, service signals helper continuation.

- [ ] **Step 5: Implement operation lifecycle**
  - States: `PENDING`, `WAITING_DNS`, `RUNNING`, `SUCCEEDED`, `FAILED`, `EXPIRED`.
  - Reconcile finished operation into certificate metadata.

- [ ] **Step 6: Run tests GREEN**
  - Run: `python3 -m pytest tests/integration/test_ssl_manual_dns.py -v`

- [ ] **Step 7: Commit**
  - `git commit -m "feat: add asynchronous manual dns01 flow"`

---

### Task 6: SSL REST API, RBAC, CSRF, and Audit

**Files:**
- Create: `app/api/ssl.py`
- Modify: `app/main.py`
- Modify: `app/api/__init__.py`
- Modify: `app/services/audit_service.py` only if action helpers/enums exist there.
- Test: `tests/integration/test_ssl_api.py`
- Test: `tests/security/test_ssl_secrets.py`

**Interfaces:**
- Implements the spec API under `/api/v1/ssl`.
- Consumes Tasks 1–5 service/helper interfaces.

- [ ] **Step 1: Write failing API authorization tests**
  - Viewer/Admin cannot create/renew/apply/delete/update SSL settings.
  - Super Admin can.
  - All mutations fail without valid CSRF.
  - GET endpoints never expose encrypted/plain tokens.

- [ ] **Step 2: Verify RED**
  - Run: `python3 -m pytest tests/integration/test_ssl_api.py tests/security/test_ssl_secrets.py -v`

- [ ] **Step 3: Implement endpoints**
  - list/get certificate status
  - create/issue
  - renew
  - test renewal
  - apply to Nginx
  - update redirect/auto-renew/provider settings
  - delete managed SSL configuration
  - manual DNS propagation check

- [ ] **Step 4: Implement audit events**
  - `SSL_CERT_ISSUE_STARTED`
  - `SSL_CERT_ISSUED`
  - `SSL_CERT_ISSUE_FAILED`
  - `SSL_CERT_RENEWED`
  - `SSL_CERT_RENEW_FAILED`
  - `SSL_CERT_APPLIED`
  - `SSL_CERT_DELETED`
  - `SSL_SETTINGS_UPDATED`
  - Audit values include domain/provider/result only; never token/ciphertext.

- [ ] **Step 5: Add error-redaction tests**
  - Mock helper/Certbot exceptions containing a fake token and prove API/audit output redacts it.

- [ ] **Step 6: Run tests GREEN**
  - Run: `python3 -m pytest tests/integration/test_ssl_api.py tests/security/test_ssl_secrets.py -v`

- [ ] **Step 7: Commit**
  - `git commit -m "feat: expose secure ssl management api"`

---

### Task 7: System Page SSL / Certificates UI

**Files:**
- Modify: `app/templates/system.html`
- Modify: `app/static/app.js`
- Modify: `app/static/app.css`
- Test: `tests/integration/test_web_ui.py`

**Interfaces:**
- Consumes `/api/v1/ssl/*`.
- Existing System page and Backup/Restore controls remain intact.

- [ ] **Step 1: Write failing UI contract tests**
  - Super Admin sees SSL / Certificates section.
  - Admin/Viewer do not see mutating SSL controls.
  - Token input is password-type/write-only and never prefilled.
  - Certificate rows render status, expiry, provider, auto-renew, and last result.
  - Issue/Renew/Test/Apply/Delete actions require confirmation where destructive.
  - Manual DNS challenge panel renders TXT name/value and Check propagation action.

- [ ] **Step 2: Verify RED**
  - Run: `python3 -m pytest tests/integration/test_web_ui.py -v`

- [ ] **Step 3: Implement UI**
  - Add provider selector, domain field, Cloudflare token field, auto-renew and redirect toggles.
  - Add `ISSUED/EXPIRING/EXPIRED/ERROR/NOT_ISSUED` badges.
  - Poll active manual operation without full-page reload.
  - Reuse corrected modal close pattern (`type="button"` + shared close handler).

- [ ] **Step 4: Implement JS API flows**
  - Use existing CSRF helper.
  - Clear token input immediately after submit.
  - Never persist token in DOM dataset/localStorage/sessionStorage.
  - Refresh certificate status after issue/renew/apply.

- [ ] **Step 5: Verify JS syntax and tests**
  - Run: `node --check app/static/app.js`
  - Run: `python3 -m pytest tests/integration/test_web_ui.py -v`

- [ ] **Step 6: Commit**
  - `git commit -m "feat: add web ssl certificate management"`

---

### Task 8: Automatic Renewal Service, Timer, and Installer

**Files:**
- Create: `packaging/dns-manager-ssl-renew`
- Create: `packaging/systemd/dns-manager-ssl-renew.service`
- Create: `packaging/systemd/dns-manager-ssl-renew.timer`
- Modify: `packaging/install.sh`
- Modify: `packaging/uninstall.sh`
- Modify: `packaging/tmpfiles.d/dns-manager.conf`
- Modify: `packaging/systemd/dns-manager.service`
- Modify: `packaging/systemd/dns-manager-helper.service`
- Test: `tests/integration/test_ssl_renewal.py`
- Test: `tests/integration/test_packaging.py`

**Interfaces:**
- Timer invokes a fixed root renewal entrypoint.
- Renewal entrypoint reads SSL metadata + encrypted credential, decrypts via the configured systemd credential, and invokes the same fixed SSL helper functions as manual API renewal.

- [ ] **Step 1: Write failing timer/packaging tests**
  - timer enabled by installer
  - renewal service is root-owned one-shot
  - app/helper receive the SSL encryption key through systemd credential/file, not a CLI argument
  - installer creates key exactly once with restrictive mode
  - reinstall preserves the existing key
  - uninstall does not remove `/etc/letsencrypt` private keys by default

- [ ] **Step 2: Verify RED**
  - Run: `python3 -m pytest tests/integration/test_ssl_renewal.py tests/integration/test_packaging.py -v`

- [ ] **Step 3: Implement renewal runner**
  - Select `auto_renew=true` certificates expiring within 30 days.
  - Process domains serially or with explicit bounded locking.
  - Record success/failure in DB and audit-compatible operation metadata.
  - Run Nginx validation/reload only after successful renewal.

- [ ] **Step 4: Implement systemd timer**
  - Daily run with `Persistent=true`.
  - Add randomized delay to avoid synchronized ACME traffic.
  - Service gets only the filesystem/network capabilities required for Certbot + Nginx reload.

- [ ] **Step 5: Update installer**
  - Install/check `certbot` and Cloudflare DNS plugin.
  - Generate `/etc/dns-manager/ssl-secret.key` once, root-owned `0600`.
  - Install/enable timer.
  - Preserve existing Task 17/18 hardening and DNS safety validation.

- [ ] **Step 6: Run tests GREEN**
  - Run: `python3 -m pytest tests/integration/test_ssl_renewal.py tests/integration/test_packaging.py -v`
  - Run: `bash -n packaging/install.sh packaging/uninstall.sh`

- [ ] **Step 7: Commit**
  - `git commit -m "feat: add automatic ssl renewal packaging"`

---

### Task 9: Backup/Restore Reconciliation and Certificate Deletion Semantics

**Files:**
- Modify: `app/services/backup_service.py`
- Modify: `app/services/ssl_service.py`
- Test: `tests/integration/test_backup_restore.py`
- Test: `tests/integration/test_ssl_status.py`

**Interfaces:**
- Existing DB backup automatically contains SSL metadata/ciphertext through SQLite.
- No `/etc/letsencrypt` file is added to archive.
- Restore completion invokes SSL reconciliation.

- [ ] **Step 1: Write failing backup/restore tests**
  - archive member list never includes private keys/cert files
  - restored SSL row with missing local lineage becomes `NOT_ISSUED`
  - restored row with valid local lineage reconciles actual expiry/issuer
  - encrypted credential survives DB point-in-time restore
  - encryption key is not present in archive

- [ ] **Step 2: Verify RED**
  - Run: `python3 -m pytest tests/integration/test_backup_restore.py tests/integration/test_ssl_status.py -v`

- [ ] **Step 3: Implement post-restore reconciliation**
  - After database replacement/reconnect, iterate SSL certificate rows and reconcile local certificate state.
  - Do not auto-issue/renew during restore.

- [ ] **Step 4: Implement delete semantics**
  - “Delete managed certificate configuration” removes DNS Manager metadata and managed Nginx SSL vhost.
  - Actual `/etc/letsencrypt` lineage deletion is a separate explicit helper operation/confirmation if exposed; default delete must not silently destroy private key material.

- [ ] **Step 5: Run tests GREEN**
  - Run: `python3 -m pytest tests/integration/test_backup_restore.py tests/integration/test_ssl_status.py -v`

- [ ] **Step 6: Commit**
  - `git commit -m "feat: reconcile ssl state across backup restore"`

---

### Task 10: End-to-End SSL Acceptance, Security Review, and Release Gate

**Files:**
- Create: `tests/e2e/test_ssl_acceptance.py`
- Modify: `tests/e2e/README.md`
- Update: `VERSION` for the chosen feature release after acceptance.

**Interfaces:**
- Exercises Tasks 1–9 as one flow.

- [ ] **Step 1: Write E2E acceptance tests**
  - Super Admin creates Cloudflare SSL config with fake encrypted token.
  - Fake helper issue → reconcile → apply produces `ISSUED`.
  - Admin/Viewer mutation denied.
  - renewal failure preserves current live vhost.
  - manual DNS operation progresses `WAITING_DNS → SUCCEEDED`.
  - backup/restore reconciliation behaves correctly.
  - auto-renew selection only includes due automated certificates.

- [ ] **Step 2: Run E2E RED then GREEN**
  - Run: `python3 -m pytest tests/e2e/test_ssl_acceptance.py -v`

- [ ] **Step 3: Run full regression**
  - Run: `python3 -m pytest -q`
  - Expected: zero failures, including all existing DNS Manager tests.

- [ ] **Step 4: Run static/security checks**
  - `python3 -m compileall -q app privileged`
  - `node --check app/static/app.js`
  - `bash -n packaging/install.sh packaging/uninstall.sh packaging/dns-manager-ssl-renew`
  - grep/package scan proves no token literals, credential files, private keys, or `/etc/letsencrypt/live/*/privkey.pem` contents are packaged.
  - inspect systemd units to prove app service still has `NoNewPrivileges=yes` and no writable `/etc`.

- [ ] **Step 5: Production acceptance on `dns.connect3.net.bd`**
  1. Back up current DNS Manager DB/config.
  2. Detect and display current certificate without changing it.
  3. Configure Cloudflare token or manual DNS-01.
  4. Run renewal/staging test.
  5. Issue/renew real certificate.
  6. Apply managed HTTPS vhost; verify `nginx -t`.
  7. Verify `https://dns.connect3.net.bd/login`.
  8. Verify Secure session cookie login/dashboard.
  9. Verify `systemctl is-active dns-manager-ssl-renew.timer`.
  10. Verify audit entries contain no token.
  11. Verify `/ready`, DNS safety, helper socket, backup list, and existing mappings remain healthy.

- [ ] **Step 6: Final release gate**
  - No unresolved Critical/Important review findings.
  - Full regression green.
  - Production acceptance green.
  - Only then bump `VERSION` and build cumulative release ZIP.

- [ ] **Step 7: Commit**
  - `git commit -m "test: complete ssl management acceptance"`

---

## Execution Order and Dependencies

`Task 1 → Task 2 → Task 3 → Task 4 → Task 5 → Task 6 → Task 7 → Task 8 → Task 9 → Task 10`

Task 4 and Task 5 both depend on the fixed helper protocol in Task 3.  
Task 6 depends on both certificate workflows.  
Task 7 consumes Task 6 API.  
Task 8 reuses Task 4 automated-provider lifecycle.  
Task 9 depends on Task 1/2 reconciliation.  
Task 10 is the release gate.

## Completion Contract

The Web SSL Management feature is complete only when:

- SSL mutations are Super Admin-only and CSRF-protected.
- Cloudflare token is encrypted at rest, write-only in UI/API, absent from logs/audit.
- Cloudflare DNS-01 issue, renew, and renewal test work without a persistent plaintext credentials file.
- Manual DNS-01 works asynchronously without holding an HTTP request open.
- Existing root helper remains fixed-command only.
- Nginx TLS apply is atomic and rollback-safe.
- Auto-renew systemd timer works without an interactive session.
- Backup archives contain metadata/ciphertext but no TLS private keys or encryption key.
- `/ready`, DNS safety, current mappings, Backup/Restore, and existing UI remain healthy.
- Full regression and production acceptance pass.
