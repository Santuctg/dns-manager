# DNS Manager Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a production-ready web-based DNS Manager that lets authenticated users manage HTTP/HTTPS domain-to-IP:port mappings, automatically generates LAN split-DNS entries for dnsmasq, generates Nginx reverse-proxy configuration, validates changes, applies them atomically, and rolls back safely on failure.

**Architecture:** FastAPI serves the web UI and REST API on loopback only. SQLite stores users, roles, permissions, mappings, audit events, revisions, and settings. A narrowly scoped privileged helper validates and installs DNS Manager-owned dnsmasq/Nginx configuration, reloads services, and restores the last known-good revision when needed.

**Tech Stack:** Python 3.12+, FastAPI, SQLAlchemy 2.x, Alembic, SQLite WAL, Pydantic, Argon2id, Jinja2, HTMX, Bootstrap 5, dnsmasq, Nginx, Gunicorn/Uvicorn, systemd, pytest.

**Spec:** `docs/superpowers/specs/2026-10-09-dns-manager-design.md`

## Global Constraints

- Target OS: Ubuntu Server 24.04 LTS.
- FastAPI binds only to `127.0.0.1:8500`.
- Public DNS is manual; only LAN split-DNS is managed automatically.
- LAN DNS engine: dnsmasq.
- Reverse proxy scope: HTTP/HTTPS only.
- Multiple user accounts with RBAC.
- Default roles: `super_admin`, `admin`, `viewer`.
- Password hashes use Argon2id.
- FastAPI process must not run as root.
- Generated dnsmasq file: `/etc/dnsmasq.d/dns-manager.conf`.
- Generated Nginx file: `/etc/nginx/conf.d/dns-manager.conf`.
- Apply flow: generate → validate → revision → atomic install → reload → health check.
- Failed apply must restore the previous known-good configuration.
- Public recursive DNS must not be exposed.
- Managed domain input must never permit arbitrary Nginx/dnsmasq directives.
- SQLite must use WAL, foreign keys, and a 5000 ms busy timeout.

## Review Focus

1. Duplicate or differently cased domains such as `Panel.Example.com` and `panel.example.com` must normalize to one unique key and reject conflicts.
2. A malformed or injection-oriented upstream/domain string must never reach generated Nginx/dnsmasq config.
3. If dnsmasq reload succeeds but Nginx reload fails, the system must restore both prior live configs and reload both services.
4. Two simultaneous Apply requests must not race; one must acquire the apply lock and the other must fail cleanly with `CONFIG_LOCKED`.
5. A disabled, deleted, or permission-reduced user session must not retain access to privileged actions.

---

## File Structure

```text
/opt/dns-manager/
├── app/
│   ├── main.py
│   ├── config.py
│   ├── database.py
│   ├── dependencies.py
│   ├── security.py
│   ├── cli.py
│   ├── api/
│   │   ├── auth.py
│   │   ├── mappings.py
│   │   ├── users.py
│   │   ├── roles.py
│   │   ├── config_ops.py
│   │   ├── audit.py
│   │   ├── system.py
│   │   └── backups.py
│   ├── models/
│   │   ├── auth.py
│   │   ├── mapping.py
│   │   ├── audit.py
│   │   ├── revision.py
│   │   └── setting.py
│   ├── schemas/
│   │   ├── auth.py
│   │   ├── mapping.py
│   │   ├── user.py
│   │   ├── revision.py
│   │   └── system.py
│   ├── services/
│   │   ├── auth_service.py
│   │   ├── mapping_service.py
│   │   ├── dns_service.py
│   │   ├── nginx_service.py
│   │   ├── revision_service.py
│   │   ├── privileged_helper.py
│   │   ├── apply_service.py
│   │   ├── audit_service.py
│   │   ├── health_service.py
│   │   └── backup_service.py
│   ├── templates/
│   └── static/
├── privileged/
│   └── dns-manager-helper
├── migrations/
├── packaging/
│   ├── dns-manager.service
│   ├── dns-manager.sudoers
│   ├── dns-manager.nginx.conf
│   ├── dns-manager.logrotate
│   └── install.sh
├── tests/
│   ├── unit/
│   ├── integration/
│   └── security/
├── requirements.txt
└── alembic.ini
```

---

### Task 1: Project Foundation, Settings, and Database Bootstrap

**Files:**
- Create: `app/config.py`
- Create: `app/database.py`
- Create: `app/main.py`
- Create: `requirements.txt`
- Create: `alembic.ini`
- Create: `tests/unit/test_config.py`
- Create: `tests/integration/test_database.py`

**Interfaces:**
- Produces: `Settings`, `get_settings()`, `SessionLocal`, `get_db()`, `Base`, FastAPI `app`.

- [ ] **Step 1: Write failing settings tests**
  - Assert default bind host is `127.0.0.1`.
  - Assert default bind port is `8500`.
  - Assert DB path is `/var/lib/dns-manager/dns-manager.db`.

- [ ] **Step 2: Run tests**
  - Run: `pytest tests/unit/test_config.py -v`
  - Expected: FAIL because settings module does not exist.

- [ ] **Step 3: Implement settings**
  - Create `Settings` with exact production defaults from the spec.

- [ ] **Step 4: Write failing database bootstrap test**
  - Assert connection enables WAL.
  - Assert foreign keys are ON.
  - Assert busy timeout is 5000 ms.

- [ ] **Step 5: Implement database layer**
  - Expose `SessionLocal`, `Base`, `get_db()`.

- [ ] **Step 6: Create minimal FastAPI app**
  - Add `/health` placeholder with database state only.

- [ ] **Step 7: Run tests**
  - Run: `pytest tests/unit/test_config.py tests/integration/test_database.py -v`
  - Expected: PASS.

- [ ] **Step 8: Commit**
```bash
git add app requirements.txt alembic.ini tests
git commit -m "feat: bootstrap dns manager application"
```

---

### Task 2: Database Models and Alembic Migration

**Files:**
- Create: `app/models/auth.py`
- Create: `app/models/mapping.py`
- Create: `app/models/audit.py`
- Create: `app/models/revision.py`
- Create: `app/models/setting.py`
- Create: `migrations/versions/0001_initial.py`
- Create: `tests/integration/test_models.py`

**Interfaces:**
- Produces SQLAlchemy models: `User`, `Role`, `Permission`, `RolePermission`, `Mapping`, `AuditLog`, `ConfigRevision`, `Setting`.

- [ ] **Step 1: Write failing model tests**
  - Assert username uniqueness.
  - Assert domain uniqueness.
  - Assert mapping has version/update timestamp for optimistic concurrency.
  - Assert audit rows retain username/action/source IP.

- [ ] **Step 2: Run tests**
  - Expected: FAIL.

- [ ] **Step 3: Implement models**
  - Store mapping domains lowercase.
  - Do not hard-delete users referenced by audit history.

- [ ] **Step 4: Create initial migration**
  - Include all tables, indexes, and foreign keys.

- [ ] **Step 5: Verify migration**
```bash
alembic upgrade head
alembic downgrade base
alembic upgrade head
```
  - Expected: all commands succeed.

- [ ] **Step 6: Run tests and commit**
```bash
pytest tests/integration/test_models.py -v
git add app/models migrations tests/integration/test_models.py
git commit -m "feat: add core database schema"
```

---

### Task 3: RBAC Seed Data and Permission Engine

**Files:**
- Create: `app/services/auth_service.py`
- Create: `app/dependencies.py`
- Create: `tests/unit/test_rbac.py`
- Modify: initial migration or add seed migration.

**Interfaces:**
- Produces: `has_permission(user, permission_name) -> bool`
- Produces: `require_permission(permission_name)` FastAPI dependency.

- [ ] **Step 1: Write failing RBAC tests**
  - Super Admin has all permissions.
  - Admin can manage mappings/apply config but cannot manage roles or restore backups.
  - Viewer cannot perform writes.

- [ ] **Step 2: Add review-focus session test**
  - Disable a user after session creation and assert next privileged request is denied.

- [ ] **Step 3: Implement default roles and permissions**
  - Use permission names from the approved spec.

- [ ] **Step 4: Implement authorization dependencies**
  - Resolve the current user from session for every protected request.

- [ ] **Step 5: Run tests**
```bash
pytest tests/unit/test_rbac.py -v
```

- [ ] **Step 6: Commit**
```bash
git add app tests
git commit -m "feat: add role based access control"
```

---

### Task 4: Password Hashing, Sessions, Login Protection, and CSRF

**Files:**
- Create: `app/security.py`
- Create: `app/api/auth.py`
- Create: `app/schemas/auth.py`
- Create: `tests/security/test_auth.py`
- Create: `tests/security/test_csrf.py`

**Interfaces:**
- Produces: `hash_password()`, `verify_password()`, `create_session()`, `destroy_session()`, `validate_csrf()`.

- [ ] **Step 1: Write failing password tests**
  - Assert Argon2id hashing.
  - Assert plaintext is never stored.

- [ ] **Step 2: Write failing login throttling tests**
  - 5 failed attempts from one IP in 10 minutes trigger throttling.
  - 10 failed account attempts trigger 15-minute lock.

- [ ] **Step 3: Write failing cookie tests**
  - Assert `Secure`, `HttpOnly`, `SameSite=Lax`.

- [ ] **Step 4: Write failing CSRF tests**
  - POST/PUT/PATCH/DELETE without valid token returns 403.

- [ ] **Step 5: Implement auth flow**
  - Session lifetime: 8 hours.
  - Idle timeout: configurable, default 30 minutes.

- [ ] **Step 6: Run tests and commit**
```bash
pytest tests/security/test_auth.py tests/security/test_csrf.py -v
git add app tests
git commit -m "feat: add secure authentication and csrf protection"
```

---

### Task 5: CLI Bootstrap and Local Password Recovery

**Files:**
- Create: `app/cli.py`
- Create: `tests/integration/test_cli.py`

**Interfaces:**
- Produces CLI commands: `create-superadmin`, `reset-password`.

- [ ] **Step 1: Write failing CLI tests**
  - `create-superadmin` creates an active Super Admin.
  - `reset-password` replaces the hash without echoing the password.

- [ ] **Step 2: Implement CLI commands**

- [ ] **Step 3: Run tests**
```bash
pytest tests/integration/test_cli.py -v
```

- [ ] **Step 4: Commit**
```bash
git add app/cli.py tests/integration/test_cli.py
git commit -m "feat: add administrator bootstrap cli"
```

---

### Task 6: Mapping Validation and CRUD Service

**Files:**
- Create: `app/schemas/mapping.py`
- Create: `app/services/mapping_service.py`
- Create: `app/api/mappings.py`
- Create: `tests/unit/test_mapping_validation.py`
- Create: `tests/integration/test_mapping_api.py`

**Interfaces:**
- Produces: `normalize_domain()`, `validate_upstream_host()`, `create_mapping()`, `update_mapping()`, `delete_mapping()`.

- [ ] **Step 1: Write failing validation tests**
  - Valid domains pass.
  - Scheme/path/port/wildcard in domain fail.
  - Ports outside `1..65535` fail.
  - Only `http`/`https` schemes pass.

- [ ] **Step 2: Add review-focus tests**
  - `Panel.Example.com` and `panel.example.com` conflict.
  - Strings containing semicolons, braces, CR/LF, quotes, or Nginx directives are rejected where unsafe.

- [ ] **Step 3: Write CRUD/API permission tests**
  - Admin can create/edit/delete.
  - Viewer receives 403.

- [ ] **Step 4: Implement mapping service and API**

- [ ] **Step 5: Implement optimistic concurrency**
  - Stale update returns conflict.

- [ ] **Step 6: Run tests**
```bash
pytest tests/unit/test_mapping_validation.py tests/integration/test_mapping_api.py -v
```

- [ ] **Step 7: Commit**
```bash
git add app tests
git commit -m "feat: add domain mapping management"
```

---

### Task 7: Audit Logging

**Files:**
- Create: `app/services/audit_service.py`
- Create: `app/api/audit.py`
- Create: `tests/integration/test_audit.py`

**Interfaces:**
- Produces: `record_audit_event(...)`.
- Consumes: authenticated user, request IP, user agent.

- [ ] **Step 1: Write failing tests**
  - Create/update/delete mapping events record old/new values.
  - Login failures are recorded.
  - Secrets/passwords/session tokens are excluded.

- [ ] **Step 2: Implement immutable audit writes**

- [ ] **Step 3: Implement filters**
  - user, action, object, date range, status, source IP.

- [ ] **Step 4: Run tests and commit**
```bash
pytest tests/integration/test_audit.py -v
git add app tests
git commit -m "feat: add immutable audit logging"
```

---

### Task 8: dnsmasq Configuration Generator

**Files:**
- Create: `app/services/dns_service.py`
- Create: `tests/unit/test_dns_generator.py`

**Interfaces:**
- Produces: `render_dnsmasq_config(mappings, internal_proxy_ip) -> str`.

- [ ] **Step 1: Write failing generator tests**
  - Enabled mappings render `address=/domain/internal_ip`.
  - Disabled mappings do not render.
  - Output has generated-file warning header.
  - Unmanaged DNS settings are not touched.

- [ ] **Step 2: Implement deterministic generation**
  - Sort domains lexicographically.

- [ ] **Step 3: Add injection regression tests**
  - Invalid newline/directive-bearing input cannot render.

- [ ] **Step 4: Run tests and commit**
```bash
pytest tests/unit/test_dns_generator.py -v
git add app/services/dns_service.py tests/unit/test_dns_generator.py
git commit -m "feat: generate managed dnsmasq configuration"
```

---

### Task 9: Nginx Configuration Generator

**Files:**
- Create: `app/services/nginx_service.py`
- Create: `tests/unit/test_nginx_generator.py`

**Interfaces:**
- Produces: `render_nginx_config(mappings, defaults) -> str`.

- [ ] **Step 1: Write failing tests**
  - HTTP upstream renders correct `proxy_pass`.
  - HTTPS upstream renders correct `proxy_pass`.
  - WebSocket option renders Upgrade/Connection headers.
  - Preserve Host option renders `$host`.
  - Disabled mapping is omitted.

- [ ] **Step 2: Add security tests**
  - No user input can escape a `server_name` or `proxy_pass` directive.

- [ ] **Step 3: Implement deterministic generation**

- [ ] **Step 4: Run tests and commit**
```bash
pytest tests/unit/test_nginx_generator.py -v
git add app/services/nginx_service.py tests/unit/test_nginx_generator.py
git commit -m "feat: generate managed nginx configuration"
```

---

### Task 10: Configuration Revision Store and Dirty State

**Files:**
- Create: `app/services/revision_service.py`
- Create: `app/schemas/revision.py`
- Create: `tests/integration/test_revisions.py`

**Interfaces:**
- Produces: `create_revision()`, `mark_revision_status()`, `get_active_revision()`, `get_pending_change_count()`.

- [ ] **Step 1: Write failing revision tests**
  - Generate `REV-YYYYMMDD-NNNNNN`.
  - Retain generated DNS and Nginx text.
  - Track statuses: generated, validated, active, failed, rolled_back.

- [ ] **Step 2: Implement dirty-state calculation**
  - Compare database mapping state with active revision metadata.

- [ ] **Step 3: Run tests and commit**
```bash
pytest tests/integration/test_revisions.py -v
git add app tests
git commit -m "feat: add configuration revision tracking"
```

---

### Task 11: Privileged Helper Contract

**Files:**
- Create: `privileged/dns-manager-helper`
- Create: `app/services/privileged_helper.py`
- Create: `tests/integration/test_privileged_helper.py`

**Interfaces:**
- Helper commands: `validate`, `apply`, `rollback`, `status`.
- Python wrapper: `PrivilegedHelper.validate()`, `.apply()`, `.rollback()`, `.status()`.

- [ ] **Step 1: Write contract tests**
  - Unknown command exits non-zero.
  - Helper does not accept arbitrary path or shell arguments.
  - Candidate files come only from fixed DNS Manager runtime paths.

- [ ] **Step 2: Implement `validate`**
  - Run dnsmasq validation and `nginx -t` against staged configuration.

- [ ] **Step 3: Implement `apply`**
  - Fixed paths only.
  - Atomic file replacement.
  - Reload dnsmasq, then Nginx.

- [ ] **Step 4: Implement `rollback`**
  - Restore previous fixed known-good files and reload both services.

- [ ] **Step 5: Implement `status`**
  - Report service states and validation state in machine-readable JSON.

- [ ] **Step 6: Run tests and commit**
```bash
pytest tests/integration/test_privileged_helper.py -v
git add privileged app/services/privileged_helper.py tests
git commit -m "feat: add restricted privileged configuration helper"
```

---

### Task 12: Safe Apply Pipeline and Rollback

**Files:**
- Create: `app/services/apply_service.py`
- Create: `app/api/config_ops.py`
- Create: `tests/integration/test_apply_pipeline.py`

**Interfaces:**
- Produces: `preview_config()`, `validate_pending_config()`, `apply_pending_config()`, `rollback_revision()`.

- [ ] **Step 1: Write happy-path test**
  - Generate configs.
  - Create revision.
  - Validate.
  - Apply.
  - Health check.
  - Mark active.

- [ ] **Step 2: Add partial-failure rollback test**
  - dnsmasq reload succeeds.
  - Nginx reload fails.
  - Both prior configs are restored.
  - Both services are reloaded.
  - New revision becomes failed.

- [ ] **Step 3: Add concurrency test**
  - First request holds `/run/dns-manager/apply.lock`.
  - Second Apply returns `CONFIG_LOCKED`.

- [ ] **Step 4: Implement flock-based apply lock**

- [ ] **Step 5: Implement apply/rollback orchestration**

- [ ] **Step 6: Run tests and commit**
```bash
pytest tests/integration/test_apply_pipeline.py -v
git add app tests
git commit -m "feat: add atomic apply and rollback pipeline"
```

---

### Task 13: Health and Backend Reachability

**Files:**
- Create: `app/services/health_service.py`
- Create: `app/api/system.py`
- Create: `tests/integration/test_health.py`

**Interfaces:**
- Produces `/health`, `/ready`, `/api/v1/system/status`, backend reachability status.

- [ ] **Step 1: Write service health tests**
  - Database, dnsmasq, Nginx, port 53, port 80/443 state.

- [ ] **Step 2: Write backend reachability tests**
  - UP, DOWN, TIMEOUT, TLS ERROR, UNKNOWN.

- [ ] **Step 3: Implement health service**

- [ ] **Step 4: Run tests and commit**
```bash
pytest tests/integration/test_health.py -v
git add app tests
git commit -m "feat: add system and backend health checks"
```

---

### Task 14: User and Role Administration APIs

**Files:**
- Create: `app/schemas/user.py`
- Create: `app/api/users.py`
- Create: `app/api/roles.py`
- Create: `tests/integration/test_user_admin.py`

**Interfaces:**
- User CRUD with deactivation.
- Role permission editing.

- [ ] **Step 1: Write permission tests**
  - Super Admin can manage users/roles.
  - Admin cannot manage roles or Super Admin.
  - Viewer cannot modify users.

- [ ] **Step 2: Write deactivation test**
  - Deactivation invalidates future privileged requests.

- [ ] **Step 3: Implement APIs**

- [ ] **Step 4: Run tests and commit**
```bash
pytest tests/integration/test_user_admin.py -v
git add app tests
git commit -m "feat: add user and role administration"
```

---

### Task 15: Management Web UI

**Files:**
- Create: `app/templates/base.html`
- Create: `app/templates/login.html`
- Create: `app/templates/dashboard.html`
- Create: `app/templates/mappings/*.html`
- Create: `app/templates/users/*.html`
- Create: `app/templates/audit.html`
- Create: `app/templates/system.html`
- Create: `app/static/app.js`
- Create: `app/static/app.css`
- Create: `tests/integration/test_web_ui.py`

**Interfaces:**
- Consumes all existing REST/service interfaces.

- [ ] **Step 1: Write page-access tests**
  - Unauthenticated users redirect to login.
  - Viewer sees read-only controls.
  - Admin sees mapping/apply controls.
  - Super Admin sees user/role/settings controls.

- [ ] **Step 2: Implement shared layout/navigation**

- [ ] **Step 3: Implement Dashboard**
  - DNS status, Nginx status, mapping counts, unreachable backends, current revision, pending count, recent audit.

- [ ] **Step 4: Implement mapping screens**
  - Search, filters, add/edit/delete, pending-change preview.

- [ ] **Step 5: Implement user/role screens**

- [ ] **Step 6: Implement audit/system screens**

- [ ] **Step 7: Run tests and commit**
```bash
pytest tests/integration/test_web_ui.py -v
git add app/templates app/static tests
git commit -m "feat: add dns manager web interface"
```

---

### Task 16: Backup and Restore

**Files:**
- Create: `app/services/backup_service.py`
- Create: `app/api/backups.py`
- Create: `tests/integration/test_backup_restore.py`

**Interfaces:**
- Produces: `create_backup()`, `validate_backup()`, `restore_backup()`.

- [ ] **Step 1: Write backup-content test**
  - Include DB, settings, generated configs, revisions.
  - Exclude certificate private keys.

- [ ] **Step 2: Write restore authorization test**
  - Only Super Admin with recent password confirmation may restore.

- [ ] **Step 3: Write restore-failure safety test**
  - Current state is backed up before restore.
  - Invalid archive leaves current state untouched.

- [ ] **Step 4: Implement backup/restore**

- [ ] **Step 5: Run tests and commit**
```bash
pytest tests/integration/test_backup_restore.py -v
git add app tests
git commit -m "feat: add backup and restore"
```

---

### Task 17: Production Packaging and systemd

**Files:**
- Create: `packaging/dns-manager.service`
- Create: `packaging/dns-manager.sudoers`
- Create: `packaging/dns-manager.nginx.conf`
- Create: `packaging/dns-manager.logrotate`
- Create: `packaging/install.sh`
- Create: `tests/integration/test_packaging.py`

**Interfaces:**
- Produces complete Ubuntu 24.04 installation assets.

- [ ] **Step 1: Write packaging assertions**
  - Service runs as `dnsmanager`, not root.
  - Bind is `127.0.0.1:8500`.
  - sudoers permits only four fixed helper subcommands.
  - FastAPI runtime gets write access only to required state/log directories.

- [ ] **Step 2: Implement systemd hardening**
  - `NoNewPrivileges=true`
  - `ProtectSystem=strict`
  - `ProtectHome=true`
  - explicit `ReadWritePaths`.

- [ ] **Step 3: Implement Nginx admin-site template**
  - HTTPS termination.
  - HTTP→HTTPS redirect.
  - security headers.
  - optional IP allowlist hook.

- [ ] **Step 4: Implement logrotate**

- [ ] **Step 5: Implement idempotent installer**

- [ ] **Step 6: Run packaging tests and commit**
```bash
pytest tests/integration/test_packaging.py -v
git add packaging tests
git commit -m "feat: add ubuntu production packaging"
```

---

### Task 18: dnsmasq Network Safety

**Files:**
- Modify: `packaging/install.sh`
- Create: `packaging/dnsmasq-dns-manager-base.conf`
- Create: `tests/security/test_dns_exposure.py`

**Interfaces:**
- Ensures DNS listens only on trusted LAN/loopback interfaces and forwards unmanaged queries upstream.

- [ ] **Step 1: Write failing safety tests**
  - No wildcard public bind.
  - LAN and loopback only.
  - Managed domains override upstream.
  - Unmanaged domains forward normally.

- [ ] **Step 2: Implement safe dnsmasq base config**
  - `bind-interfaces`.
  - configurable LAN interface/IP.
  - `cache-size=10000`.

- [ ] **Step 3: Run tests and commit**
```bash
pytest tests/security/test_dns_exposure.py -v
git add packaging tests
git commit -m "security: restrict dns service to trusted networks"
```

---

### Task 19: End-to-End Acceptance Test

**Files:**
- Create: `tests/e2e/test_acceptance.py`
- Create: `tests/e2e/README.md`

**Interfaces:**
- Verifies full system against the 25 acceptance criteria.

- [ ] **Step 1: Create fixture environment**
  - Temporary SQLite DB.
  - fake/stub privileged helper for CI.
  - optional real-service mode for Ubuntu VM testing.

- [ ] **Step 2: Test complete mapping lifecycle**
  - Login → create mapping → preview → apply → resolve LAN domain → proxy request → edit → reapply → delete → reapply.

- [ ] **Step 3: Test RBAC lifecycle**
  - Super Admin, Admin, Viewer.

- [ ] **Step 4: Test failed config apply**
  - Live config remains/returns known-good.

- [ ] **Step 5: Test reboot persistence in VM mode**
  - systemd service restarts.
  - active generated configuration remains functional.

- [ ] **Step 6: Run full suite**
```bash
pytest -v
```
  - Expected: all tests PASS.

- [ ] **Step 7: Commit**
```bash
git add tests/e2e
git commit -m "test: add end to end dns manager acceptance coverage"
```

---

### Task 20: Final Security Review and Release Readiness

**Files:**
- Create: `SECURITY.md`
- Create: `README.md`
- Create: `docs/operations.md`
- Create: `docs/recovery.md`

**Interfaces:**
- Produces operator-facing install, upgrade, backup, rollback, and recovery documentation.

- [ ] **Step 1: Run security-focused test suite**
```bash
pytest tests/security -v
```

- [ ] **Step 2: Run dependency audit**
  - Record and fix high/critical dependency findings before release.

- [ ] **Step 3: Verify generated config ownership and permissions**
  - Root-owned live config.
  - App user cannot arbitrarily edit `/etc/nginx` or `/etc/dnsmasq.d`.

- [ ] **Step 4: Verify sudoers with `visudo -cf`**

- [ ] **Step 5: Verify Nginx and dnsmasq validation commands on Ubuntu 24.04 VM**

- [ ] **Step 6: Write operations and recovery docs**

- [ ] **Step 7: Tag first release after all acceptance criteria pass**
```bash
git tag -a v1.0.0 -m "DNS Manager v1.0.0"
```

---

## Recommended Execution Order

```text
Foundation
  ↓
Database schema
  ↓
RBAC + Authentication
  ↓
Mapping CRUD + Audit
  ↓
dnsmasq generator
  ↓
Nginx generator
  ↓
Revision tracking
  ↓
Privileged helper
  ↓
Apply/Rollback pipeline
  ↓
Health/status
  ↓
User/role administration
  ↓
Web UI
  ↓
Backup/restore
  ↓
Production packaging
  ↓
DNS network hardening
  ↓
E2E acceptance
  ↓
Security/release review
```

## Definition of Done

The implementation is complete only when:

- all 25 spec acceptance criteria pass;
- all unit/integration/security/E2E tests pass;
- `nginx -t` succeeds with generated config;
- dnsmasq validation succeeds with generated config;
- a deliberate Nginx apply failure proves automatic rollback works;
- concurrent apply locking is verified;
- FastAPI remains loopback-only;
- DNS port 53 is not exposed as a public recursive resolver;
- non-root operation and restricted sudo helper are verified;
- Ubuntu 24.04 reboot persistence is verified.
