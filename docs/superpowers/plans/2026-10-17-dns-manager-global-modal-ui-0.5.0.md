# DNS Manager 0.5.0 — Global Modal UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Standardize all DNS Manager user-triggered actions on one reusable, accessible modal system with consistent confirmation, loading, input, success, error, and info behavior.

**Architecture:** Keep all backend/API contracts unchanged. Harden the existing 0.4.x action modal into a global UI service in `app/static/app.js`, then migrate each page to thin page adapters that call the shared modal/action runner. Preserve inline forms where replacing them would add risk, but route confirmation/loading/result feedback through the global modal.

**Tech Stack:** FastAPI/Jinja2, vanilla JavaScript, HTML `<dialog>`, CSS, pytest, existing fetch/CSRF helpers.

**Spec:** `/mnt/data/2026-10-17-dns-manager-global-modal-ui-0.5.0-spec.md`

## Global Constraints

- Base version is `0.4.4`; target version is `0.5.0`.
- No database migration.
- Backend API authorization, CSRF, request/response semantics, and endpoint paths remain unchanged.
- One reusable `ActionModal` implementation must serve all normal user-triggered actions.
- Supported modes: `loading`, `success`, `error`, `warning`, `confirm`, `input`, `info`.
- Every modal mode transition must fully clear stale mode-specific UI state.
- Normal CRUD/action feedback must not use the global top banner.
- Top banner remains only for session-expired, app-wide degraded-state, and redirect-level messages.
- Destructive actions require confirmation.
- Long-running actions show loading state immediately.
- Duplicate requests are blocked while an action is in flight.
- Modal content uses text-safe rendering; no raw server HTML injection.
- Secrets/tokens/passwords must never be copied into generic result detail or browser storage.
- Focus moves into the modal on open and returns to the triggering control on close.
- Keyboard navigation must remain usable; Escape/backdrop closing follows the spec.
- Existing SSL modal behavior remains functional after reconciliation with shared helpers.
- Full release requires `VERSION=0.5.0`.

## Review Focus

1. **Stale modal state between modes:** loading/input/confirm regions must never remain visible after switching to success/error/info. Covered in Task 1.
2. **Focus loss / keyboard traps:** opening and closing a modal must preserve focus order, trap Tab inside the open dialog, and restore focus. Covered in Task 1.
3. **Secret leakage:** password/token input and backend error text must never appear in generic result detail, storage, or DOM data attributes. Covered in Tasks 2, 4, 9.
4. **Duplicate requests:** double-clicking a destructive or long-running action must create at most one network request. Covered in Tasks 2, 3, 6, 7.
5. **Silent fallback to old banners/native dialogs:** no normal action path may still use `alert()`, `confirm()`, `prompt()`, or page-level success/error banners after migration. Covered in Task 9.

---

## File Structure

### Shared global UI
- Modify: `app/templates/base.html` — single reusable dialog shell and global app notice area.
- Modify: `app/static/app.css` — modal modes, focus states, mobile layout, copyable values, busy states.
- Modify: `app/static/app.js` — modal state machine, confirmation/input promises, action runner, response normalization, focus trap/restore, copy helper.

### Page templates/adapters
- Modify: `app/templates/mappings.html`
- Modify: `app/templates/users.html`
- Modify: `app/templates/roles.html`
- Modify: `app/templates/audit.html`
- Modify: `app/templates/system.html`
- Modify: `app/templates/dashboard.html` when actions exist.

### Tests
- Modify: `tests/integration/test_web_ui.py`
- Modify: `tests/e2e/test_acceptance.py`
- Modify: `tests/e2e/test_ssl_acceptance.py`
- Modify: `tests/security/test_ssl_secrets.py`
- Modify: `tests/integration/test_packaging.py`

---

### Task 1: Harden the global modal core

**Files:**
- Modify: `app/templates/base.html`
- Modify: `app/static/app.css`
- Modify: `app/static/app.js`
- Test: `tests/integration/test_web_ui.py`

**Interfaces:**
- Produces:
  - `showLoading(options)`
  - `showSuccess(options)`
  - `showError(options)`
  - `showWarning(options)`
  - `showInfo(options)`
  - `confirmAction(options) -> Promise<boolean>`
  - `promptAction(options) -> Promise<string|null>`
  - `closeActionModal()`
- Consumes the existing `<dialog data-action-modal>` shell.

- [ ] **Step 1: Write failing modal-state tests** asserting each mode hides every unrelated region, including stale input/progress/copy/confirmation content.

- [ ] **Step 2: Write failing accessibility tests** for `aria-labelledby`, `aria-describedby`, focus on open, focus return on close, Tab focus trap, and Escape rules.

- [ ] **Step 3: Run RED tests**

  Run:
  `pytest tests/integration/test_web_ui.py -k "action_modal or modal_focus or modal_state" -v`

  Expected: FAIL on the new global modal contract.

- [ ] **Step 4: Implement the modal state machine** in `app/static/app.js`. Each public modal function must begin from one reset routine that clears content, mode classes, hidden regions, button state, and stale input values.

- [ ] **Step 5: Implement focus/keyboard behavior**. Track the trigger element, focus the first meaningful modal control, trap Tab/Shift+Tab, restore focus on close, and apply Escape/backdrop rules from the spec.

- [ ] **Step 6: Implement CSS mode/mobile/focus rules** in `app/static/app.css`, including authoritative `.action-modal [hidden]{display:none!important}`.

- [ ] **Step 7: Run GREEN tests**

  Run:
  `node --check app/static/app.js && pytest tests/integration/test_web_ui.py -k "action_modal or modal_focus or modal_state" -v`

  Expected: PASS.

- [ ] **Step 8: Commit**

  ```bash
  git add app/templates/base.html app/static/app.css app/static/app.js tests/integration/test_web_ui.py
  git commit -m "feat: harden global action modal"
  ```

---

### Task 2: Add shared action runner and response normalization

**Files:**
- Modify: `app/static/app.js`
- Test: `tests/integration/test_web_ui.py`
- Test: `tests/security/test_ssl_secrets.py`

**Interfaces:**
- Produces:
  - `normalizeActionResponse(response) -> Promise<{ok,title,message,detail,code}>`
  - `runAction(options) -> Promise<object|null>`
  - `withBusyControls(trigger, controls, fn) -> Promise<any>`
- Consumes Task 1 modal API.

- [ ] **Step 1: Write failing response-normalization tests** for JSON success, JSON error, empty success, non-JSON error, and sanitized HTTP failure.

- [ ] **Step 2: Write failing security tests** proving HTML-like server strings render as text and token/password-like values are not copied into generic detail output.

- [ ] **Step 3: Write failing busy-state tests** proving double invocation while active results in one request and all disabled controls are restored in `finally`.

- [ ] **Step 4: Run RED tests**

  Run:
  `pytest tests/integration/test_web_ui.py tests/security/test_ssl_secrets.py -k "normalize or busy or modal_secret" -v`

  Expected: FAIL.

- [ ] **Step 5: Implement `normalizeActionResponse()`** using safe text fields only, preserving user-safe backend messages without raw HTML.

- [ ] **Step 6: Implement `runAction()`** with optional confirm/input, loading modal, fetch callback, normalized success/error result, and `finally` cleanup.

- [ ] **Step 7: Implement busy-control coordination** so related row buttons can be disabled and restored consistently.

- [ ] **Step 8: Run GREEN tests**

  Run:
  `node --check app/static/app.js && pytest tests/integration/test_web_ui.py tests/security/test_ssl_secrets.py -k "normalize or busy or modal_secret" -v`

  Expected: PASS.

- [ ] **Step 9: Commit**

  ```bash
  git add app/static/app.js tests/integration/test_web_ui.py tests/security/test_ssl_secrets.py
  git commit -m "feat: add shared modal action runner"
  ```

---

### Task 3: Migrate Mappings actions

**Files:**
- Modify: `app/templates/mappings.html`
- Modify: `app/static/app.js`
- Test: `tests/integration/test_web_ui.py`
- Test: `tests/e2e/test_acceptance.py`

**Interfaces:**
- Produces page adapter: `mappingActions`
- Consumes `runAction()`, `confirmAction()`, `promptAction()`.

- [ ] **Step 1: Write failing UI tests** for mapping create/edit submit result, delete confirmation, Validate loading/result, Apply confirmation/loading/result, and no normal mapping banner.

- [ ] **Step 2: Write failing E2E test** proving double-click on Apply/Delete cannot submit twice.

- [ ] **Step 3: Run RED tests**

  Run:
  `pytest tests/integration/test_web_ui.py tests/e2e/test_acceptance.py -k "mapping and modal" -v`

  Expected: FAIL.

- [ ] **Step 4: Implement `mappingActions`** and route mapping CRUD/validate/apply result handling through the global runner. Keep complex existing inline forms if already present.

- [ ] **Step 5: Remove mapping-specific native/browser confirmation and action-result banners** while preserving non-action page notices.

- [ ] **Step 6: Run GREEN tests**

  Run:
  `node --check app/static/app.js && pytest tests/integration/test_web_ui.py tests/e2e/test_acceptance.py -k "mapping and modal" -v`

  Expected: PASS.

- [ ] **Step 7: Commit**

  ```bash
  git add app/templates/mappings.html app/static/app.js tests/integration/test_web_ui.py tests/e2e/test_acceptance.py
  git commit -m "feat: migrate mapping actions to global modal"
  ```

---

### Task 4: Migrate Users actions

**Files:**
- Modify: `app/templates/users.html`
- Modify: `app/static/app.js`
- Test: `tests/integration/test_web_ui.py`
- Test: `tests/e2e/test_acceptance.py`
- Test: `tests/security/test_ssl_secrets.py`

**Interfaces:**
- Produces page adapter: `userActions`
- Consumes shared modal/action runner.

- [ ] **Step 1: Write failing UI tests** for create/edit result modal, password/reset input modal, enable/disable confirmation where applicable, delete confirmation naming the user, and no user-action banner.

- [ ] **Step 2: Write failing secret tests** proving password input is cleared on close and never copied into result text, dataset, localStorage, or sessionStorage.

- [ ] **Step 3: Write failing E2E tests** for Create User success and Delete User confirmation.

- [ ] **Step 4: Run RED tests**

  Run:
  `pytest tests/integration/test_web_ui.py tests/e2e/test_acceptance.py tests/security/test_ssl_secrets.py -k "user and modal" -v`

  Expected: FAIL.

- [ ] **Step 5: Implement `userActions`** using password-mode input where needed and text-only result rendering.

- [ ] **Step 6: Remove browser-native/user-page confirmation paths** while keeping backend super-admin restrictions unchanged.

- [ ] **Step 7: Run GREEN tests**

  Run:
  `node --check app/static/app.js && pytest tests/integration/test_web_ui.py tests/e2e/test_acceptance.py tests/security/test_ssl_secrets.py -k "user and modal" -v`

  Expected: PASS.

- [ ] **Step 8: Commit**

  ```bash
  git add app/templates/users.html app/static/app.js tests/integration/test_web_ui.py tests/e2e/test_acceptance.py tests/security/test_ssl_secrets.py
  git commit -m "feat: migrate user actions to global modal"
  ```

---

### Task 5: Migrate Roles actions

**Files:**
- Modify: `app/templates/roles.html`
- Modify: `app/static/app.js`
- Test: `tests/integration/test_web_ui.py`
- Test: `tests/e2e/test_acceptance.py`

**Interfaces:**
- Produces page adapter: `roleActions`
- Consumes shared modal/action runner.

- [ ] **Step 1: Write failing tests** for create/edit result modal, permission-save loading/result, delete confirmation, and protected-role backend error shown in error modal.

- [ ] **Step 2: Run RED tests**

  Run:
  `pytest tests/integration/test_web_ui.py tests/e2e/test_acceptance.py -k "role and modal" -v`

  Expected: FAIL.

- [ ] **Step 3: Implement `roleActions`** and route save/delete results through the modal.

- [ ] **Step 4: Run GREEN tests**

  Run:
  `node --check app/static/app.js && pytest tests/integration/test_web_ui.py tests/e2e/test_acceptance.py -k "role and modal" -v`

  Expected: PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add app/templates/roles.html app/static/app.js tests/integration/test_web_ui.py tests/e2e/test_acceptance.py
  git commit -m "feat: migrate role actions to global modal"
  ```

---

### Task 6: Migrate System actions

**Files:**
- Modify: `app/templates/system.html`
- Modify: `app/static/app.js`
- Test: `tests/integration/test_web_ui.py`
- Test: `tests/e2e/test_acceptance.py`

**Interfaces:**
- Produces page adapter: `systemActions`
- Consumes shared modal/action runner.

- [ ] **Step 1: Write failing tests** for Validate loading/result, Apply pending-change confirmation/loading/result, Rollback revision confirmation/loading/result, and duplicate request blocking.

- [ ] **Step 2: Run RED tests**

  Run:
  `pytest tests/integration/test_web_ui.py tests/e2e/test_acceptance.py -k "system and modal" -v`

  Expected: FAIL.

- [ ] **Step 3: Implement `systemActions`**. Rollback confirmation must include the revision database ID and destructive styling.

- [ ] **Step 4: Remove system-action top-banner feedback**, retaining only global/app notices.

- [ ] **Step 5: Run GREEN tests**

  Run:
  `node --check app/static/app.js && pytest tests/integration/test_web_ui.py tests/e2e/test_acceptance.py -k "system and modal" -v`

  Expected: PASS.

- [ ] **Step 6: Commit**

  ```bash
  git add app/templates/system.html app/static/app.js tests/integration/test_web_ui.py tests/e2e/test_acceptance.py
  git commit -m "feat: migrate system actions to global modal"
  ```

---

### Task 7: Migrate Backup and Restore actions

**Files:**
- Modify: `app/templates/system.html`
- Modify: `app/static/app.js`
- Test: `tests/integration/test_web_ui.py`
- Test: `tests/e2e/test_acceptance.py`

**Interfaces:**
- Produces page adapter: `backupActions`
- Consumes shared modal/action runner.

- [ ] **Step 1: Write failing tests** for Create Backup loading/success with backup ID, Restore destructive confirmation/loading/result, Delete confirmation, and Download failure modal.

- [ ] **Step 2: Write failing duplicate-request tests** for Create/Restore/Delete.

- [ ] **Step 3: Run RED tests**

  Run:
  `pytest tests/integration/test_web_ui.py tests/e2e/test_acceptance.py -k "backup and modal" -v`

  Expected: FAIL.

- [ ] **Step 4: Implement `backupActions`**. Restore success may include the existing session-state warning, but no secret material.

- [ ] **Step 5: Run GREEN tests**

  Run:
  `node --check app/static/app.js && pytest tests/integration/test_web_ui.py tests/e2e/test_acceptance.py -k "backup and modal" -v`

  Expected: PASS.

- [ ] **Step 6: Commit**

  ```bash
  git add app/templates/system.html app/static/app.js tests/integration/test_web_ui.py tests/e2e/test_acceptance.py
  git commit -m "feat: migrate backup actions to global modal"
  ```

---

### Task 8: Migrate Audit and Dashboard actions

**Files:**
- Modify: `app/templates/audit.html`
- Modify: `app/templates/dashboard.html`
- Modify: `app/static/app.js`
- Test: `tests/integration/test_web_ui.py`
- Test: `tests/e2e/test_acceptance.py`

**Interfaces:**
- Produces page adapters: `auditActions`, `dashboardActions` only for actual interactive controls.
- Consumes shared modal/action runner.

- [ ] **Step 1: Inventory actual interactive controls in Audit and Dashboard** and write failing tests only for those that perform user-triggered actions.

- [ ] **Step 2: Pin silent-refresh policy**: refresh/filter actions remain quiet on success but use error modal on failure; destructive/export actions use modal feedback.

- [ ] **Step 3: Run RED tests**

  Run:
  `pytest tests/integration/test_web_ui.py tests/e2e/test_acceptance.py -k "audit or dashboard" -v`

  Expected: FAIL only for currently actionable controls being migrated.

- [ ] **Step 4: Implement `auditActions`/`dashboardActions`** without inventing actions that do not exist.

- [ ] **Step 5: Run GREEN tests**

  Run:
  `node --check app/static/app.js && pytest tests/integration/test_web_ui.py tests/e2e/test_acceptance.py -k "audit or dashboard" -v`

  Expected: PASS.

- [ ] **Step 6: Commit**

  ```bash
  git add app/templates/audit.html app/templates/dashboard.html app/static/app.js tests/integration/test_web_ui.py tests/e2e/test_acceptance.py
  git commit -m "feat: standardize audit and dashboard action feedback"
  ```

---

### Task 9: Reconcile SSL with the global modal helpers

**Files:**
- Modify: `app/templates/system.html`
- Modify: `app/static/app.js`
- Test: `tests/integration/test_web_ui.py`
- Test: `tests/e2e/test_ssl_acceptance.py`
- Test: `tests/security/test_ssl_secrets.py`

**Interfaces:**
- Produces page adapter: `sslActions`
- Consumes shared `runAction()`, `confirmAction()`, `promptAction()`.
- Preserves Hosted CNAME copy/info modal behavior from 0.4.4.

- [ ] **Step 1: Write failing regression tests** proving SSL no longer has duplicate/private modal state code paths and uses shared global helpers.

- [ ] **Step 2: Pin all SSL behaviors**: Show CNAME info/copy, Verify, Re-register confirm, Issue, Renew, Test renewal, Enable/Disable auto-renew, Apply, Delete, Cloudflare token input.

- [ ] **Step 3: Write secret regression tests** ensuring Cloudflare token/password-like inputs are cleared and never shown in result modal/storage.

- [ ] **Step 4: Run RED tests**

  Run:
  `pytest tests/integration/test_web_ui.py tests/e2e/test_ssl_acceptance.py tests/security/test_ssl_secrets.py -k "ssl and modal" -v`

  Expected: FAIL until private SSL modal helpers are reconciled.

- [ ] **Step 5: Refactor SSL actions onto shared helpers** while keeping endpoint behavior unchanged.

- [ ] **Step 6: Run GREEN tests**

  Run:
  `node --check app/static/app.js && pytest tests/integration/test_web_ui.py tests/e2e/test_ssl_acceptance.py tests/security/test_ssl_secrets.py -k "ssl and modal" -v`

  Expected: PASS.

- [ ] **Step 7: Commit**

  ```bash
  git add app/templates/system.html app/static/app.js tests/integration/test_web_ui.py tests/e2e/test_ssl_acceptance.py tests/security/test_ssl_secrets.py
  git commit -m "refactor: unify SSL actions on global modal"
  ```

---

### Task 10: Remove legacy banners/native dialogs and release 0.5.0

**Files:**
- Modify: `app/templates/base.html`
- Modify: `app/static/app.js`
- Modify: `app/static/app.css`
- Modify: affected page templates
- Modify: `tests/integration/test_web_ui.py`
- Modify: `tests/e2e/test_acceptance.py`
- Modify: `tests/integration/test_packaging.py`
- Modify: `VERSION`

**Interfaces:**
- Consumes all page adapters and the global modal API.
- Produces final 0.5.0 app-wide modal contract.

- [ ] **Step 1: Write failing scan tests** asserting no normal action path uses `window.alert`, `window.confirm`, `window.prompt`, browser-native `confirm(` / `prompt(`, or page-level action banners.

- [ ] **Step 2: Write top-banner policy tests** proving only session/app-wide notice classes remain eligible for the global banner.

- [ ] **Step 3: Update packaging/version tests** for `VERSION=0.5.0`.

- [ ] **Step 4: Run RED tests**

  Run:
  `pytest tests/integration/test_web_ui.py tests/integration/test_packaging.py tests/e2e/test_acceptance.py -k "legacy_dialog or top_banner or version" -v`

  Expected: FAIL until legacy paths/version pins are removed.

- [ ] **Step 5: Remove remaining legacy action-dialog/banner paths** and bump `VERSION` to `0.5.0`.

- [ ] **Step 6: Run targeted GREEN tests**

  Run:
  `node --check app/static/app.js && pytest tests/integration/test_web_ui.py tests/integration/test_packaging.py tests/e2e/test_acceptance.py -v`

  Expected: PASS.

- [ ] **Step 7: Run full regression**

  Run:
  `pytest -q`

  Expected: all tests PASS.

- [ ] **Step 8: Run syntax gates**

  ```bash
  python3 -m compileall -q app privileged
  node --check app/static/app.js
  bash -n packaging/install.sh packaging/uninstall.sh packaging/dns-manager-ssl-renew
  ```

  Expected: all exit 0.

- [ ] **Step 9: Commit**

  ```bash
  git add app/templates app/static tests VERSION
  git commit -m "release: global modal UI 0.5.0"
  ```

---

## Final Release Gate

Before creating `dns-manager-global-modal-ui-0.5.0.zip`:

- [ ] `VERSION=0.5.0`
- [ ] one reusable modal shell
- [ ] loading/success/error/warning/confirm/input/info supported
- [ ] stale modal state reset between every mode
- [ ] focus trap works
- [ ] focus returns to trigger
- [ ] Escape/backdrop rules match spec
- [ ] duplicate action clicks blocked
- [ ] response normalization handles JSON/non-JSON/empty responses
- [ ] raw HTML from backend is not injected
- [ ] secrets/tokens/passwords never rendered in results or browser storage
- [ ] Mappings migrated
- [ ] Users migrated
- [ ] Roles migrated
- [ ] System migrated
- [ ] Backup/Restore migrated
- [ ] Audit/Dashboard migrated where actions exist
- [ ] SSL reconciled with shared helpers
- [ ] no browser-native confirm/prompt/alert for normal actions
- [ ] normal CRUD/action banners removed
- [ ] global banner limited to session/app-wide notices
- [ ] full regression passes
- [ ] Python/JS/shell syntax gates pass
