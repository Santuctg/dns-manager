# Management Web UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a secure, dependency-light browser management console for DNS Manager.

**Architecture:** FastAPI will serve Jinja2 templates and local static assets. HTML routes authenticate using the existing persistent session; page JavaScript consumes the existing REST APIs and existing CSRF mechanism for mutations.

**Tech Stack:** FastAPI, Starlette/Jinja2Templates, Jinja2, vanilla JavaScript, CSS, pytest/TestClient.

**Spec:** `docs/superpowers/specs/2026-10-10-management-web-ui.md`

## Global Constraints
- No external CDN dependencies.
- No React/Vite/npm build toolchain.
- Existing REST APIs remain the source of truth.
- Existing RBAC and CSRF APIs remain authoritative.
- Viewer is read-only; Admin cannot manage Super Admin or role permissions; Super Admin has full controls.

## Review Focus
- Expired/revoked session redirects HTML pages to `/login` rather than returning JSON.
- Viewer pages do not render write controls even though APIs remain the final authorization layer.
- Static assets contain no external CDN/resource URLs.
- Browser API wrapper sends CSRF for mutations and handles 401 by redirecting to login.
- Pages render safely with empty datasets and API errors.

---

### Task 1: Web routing and authenticated shell
**Files:** Create `app/web.py`, `app/templates/base.html`, `app/templates/login.html`; modify `app/main.py`, `requirements.txt`; test `tests/integration/test_web_ui.py`.
**Interfaces:** Produces `/login`, `/`, `/app/{page}` HTML routes and role/permission template context.
- [ ] Write failing access/RBAC/static mount tests.
- [ ] Run targeted tests and confirm failure.
- [ ] Add Jinja2 dependency, templates/static mount, session-aware HTML routing, shared navigation.
- [ ] Run targeted tests and confirm pass.

### Task 2: Dashboard and Mappings UI
**Files:** Create `app/templates/dashboard.html`, `app/templates/mappings.html`; create/modify `app/static/app.js`, `app/static/app.css`; test `tests/integration/test_web_ui.py`.
**Interfaces:** Consumes `/ready`, `/api/v1/system/*`, `/api/v1/mappings`, `/api/v1/config/*`.
- [ ] Write failing page-contract tests for dashboard status and mapping controls.
- [ ] Run and confirm failure.
- [ ] Implement server-rendered page structure plus JS data loading, CRUD modal, preview/validate/apply.
- [ ] Run targeted tests.

### Task 3: Users and Roles UI
**Files:** Create `app/templates/users.html`, `app/templates/roles.html`; modify `app/static/app.js`; test `tests/integration/test_web_ui.py`.
**Interfaces:** Consumes `/api/v1/users` and `/api/v1/roles`.
- [ ] Write failing role-aware control tests.
- [ ] Run and confirm failure.
- [ ] Implement user create/edit/deactivate/reset-password and role view/permission editing controls.
- [ ] Run targeted tests.

### Task 4: Audit and System UI
**Files:** Create `app/templates/audit.html`, `app/templates/system.html`; modify `app/static/app.js`; test `tests/integration/test_web_ui.py`.
**Interfaces:** Consumes `/api/v1/audit`, `/api/v1/system/status`, `/api/v1/config/preview|validate|apply|rollback`.
- [ ] Write failing page-contract tests.
- [ ] Run and confirm failure.
- [ ] Implement audit filters/table and system/config operations UI.
- [ ] Run targeted tests.

### Task 5: Full verification and package
**Files:** All Task 15 files.
- [ ] Run `python3 -m pytest -q` and require green suite.
- [ ] Scan templates/static assets for `http://`, `https://`, CDN references, inline secrets.
- [ ] Verify root/login/app redirects and static assets with TestClient.
- [ ] Build cumulative `dns-manager-task15.zip`.
