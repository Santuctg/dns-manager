# DNS Manager 0.5.0 — Global Modal UI Specification

**Status:** Draft for review  
**Target version:** 0.5.0  
**Base version:** 0.4.4  
**Primary feature:** Standardize all user-triggered actions across DNS Manager on one reusable modal interaction system.

## 1. Objective

Replace page-specific banners, inline confirmations, browser-native prompts, and inconsistent action feedback with one reusable modal framework shared across the entire application.

The backend/API contracts remain unchanged unless a minimal response-shape adjustment is required to surface already-existing result text safely.

## 2. Scope

Applies to all pages and action classes:

- Dashboard
- Mappings
- Users
- Roles
- Audit
- System
- Backup & restore
- SSL / Certificates
- Any future action using the shared action helper

## 3. Modal Modes

Single reusable modal supports:

```text
loading
success
error
warning
confirm
input
info
```

Every mode must clear the previous mode's state completely before rendering.

## 4. Global UX Rules

- All user-triggered API actions show feedback in the modal.
- Destructive actions require confirmation.
- Long-running actions show loading state immediately.
- Duplicate action clicks are disabled while request is in flight.
- Error details are sanitized before display.
- Success/error results stay visible until the user closes them unless explicitly safe to auto-close.
- Escape closes only non-blocking/non-destructive-result modals.
- Clicking the backdrop closes only safe informational/result modals.
- Confirmation and input modals do not close from accidental backdrop clicks.
- Focus moves into the modal when opened and returns to the triggering control when closed.
- Keyboard tab order is trapped inside an open modal.
- Enter activates the primary action when appropriate.
- All iconography must have text equivalents.

## 5. Shared Component

The application exposes one global component:

```text
ActionModal
```

Core JS API:

```text
showLoading(options)
showSuccess(options)
showError(options)
showWarning(options)
showInfo(options)
confirmAction(options) -> Promise<boolean>
promptAction(options) -> Promise<string | null>
closeActionModal()
```

Optional helper:

```text
runAction(options)
```

`runAction()` may wrap:

```text
confirm -> loading -> request -> success/error
```

without page code reimplementing modal state transitions.

## 6. Modal Data Contract

Supported options:

```text
title
message
detail
entity
primaryLabel
secondaryLabel
danger
inputLabel
inputType
inputPlaceholder
inputValue
inputRequired
copyFields
autoCloseMs
```

Secrets are never injected into generic detail fields.

## 7. Accessibility

Modal implementation must:

- use `<dialog>` where supported;
- have `aria-labelledby`;
- have `aria-describedby` where message text exists;
- preserve visible focus indication;
- trap focus;
- restore focus to trigger;
- support Escape rules;
- be usable by keyboard only;
- not rely on color alone for status.

## 8. Styling

One visual system for:

- success
- error
- warning
- info
- destructive confirmation
- loading

The modal must remain readable on desktop and mobile.

Maximum content width should be bounded; long values wrap safely.

Copyable technical values use a monospace block with copy button.

## 9. Top Banner Policy

Normal CRUD/action feedback no longer uses the global top banner.

Top banners remain only for:

- session-expired notices;
- application-wide degraded-state notices;
- redirect-level messages where no initiating action context remains.

## 10. Dashboard

Any actionable control on Dashboard must use the shared modal.

Read-only status cards remain inline.

## 11. Mappings

Actions:

```text
Create mapping
Edit mapping
Delete mapping
Validate
Apply
Rollback/revision action if exposed here
```

Behavior:

- Create/Edit uses modal form if the current page action is compact enough; otherwise existing form can remain inline, but submit/result uses modal.
- Delete requires destructive confirmation.
- Validate shows loading -> success/error.
- Apply shows confirmation when deployment impact exists, then loading -> success/error.

## 12. Users

Actions:

```text
Create user
Edit user
Reset/change password
Enable/disable user
Delete user
```

Rules:

- Password input uses password field.
- Password values never appear in result modal.
- Delete requires confirmation naming the user.
- Super-admin safety rules remain backend-enforced.

## 13. Roles

Actions:

```text
Create role
Edit role
Save permissions
Delete role
```

Rules:

- Permission save result uses modal.
- Delete requires confirmation.
- Built-in/protected role restrictions remain backend-enforced.

## 14. Audit

Actions, when present:

```text
Refresh
Filter apply
Export
Clear/delete operations
```

Rules:

- Refresh/filter may remain silent unless there is an error.
- Export success may use info/success modal when a generated artifact is ready.
- Destructive audit actions require confirmation.

## 15. System

Actions:

```text
Validate
Apply
Rollback
```

Rules:

- Validate: loading -> success/error.
- Apply: confirmation if config changes are pending -> loading -> success/error.
- Rollback: destructive warning confirmation including revision ID -> loading -> success/error.

## 16. Backup & Restore

Actions:

```text
Create backup
Restore
Delete
Download
Refresh
```

Rules:

- Create: loading -> success with backup ID.
- Restore: destructive confirmation -> loading -> success/error.
- Delete: destructive confirmation.
- Download: no blocking modal unless generation/preparation occurs; failures use error modal.
- Restore success may warn that session state could change.

## 17. SSL / Certificates

Existing 0.4.4 modal behavior becomes the reference pattern.

Actions:

```text
Show CNAME
Verify CNAME
Re-register
Issue
Renew
Test renewal
Enable auto renew
Disable auto renew
Apply
Delete
Cloudflare token conversion/input
```

Rules:

- Show CNAME uses info modal with copy buttons.
- Verify/Test/Renew/Issue/Apply use loading -> result.
- Re-register/Disable/Delete require confirmation.
- Token/password values never appear in result detail.

## 18. Page Action Adapter

Each page should use a thin adapter rather than directly manipulating modal DOM.

Example:

```text
mappingActions.create(...)
userActions.delete(...)
systemActions.apply(...)
backupActions.restore(...)
sslActions.testRenewal(...)
```

Adapters call the global modal API and the existing fetch/API utilities.

## 19. Fetch/Error Normalization

Add shared response normalization:

```text
normalizeActionResponse(response) -> {
  ok,
  title,
  message,
  detail?,
  code?
}
```

Requirements:

- JSON and non-JSON error bodies handled;
- empty success responses handled;
- HTTP status included only when useful;
- raw stack traces never shown;
- secrets/tokens redacted;
- user-safe backend detail preserved.

## 20. Busy State

While an action is running:

- triggering button disabled;
- related action row controls disabled when appropriate;
- modal primary/secondary controls reflect busy state;
- duplicate requests blocked client-side.

Busy state must always clear in `finally`.

## 21. Confirmation Semantics

Destructive confirmation modal contains:

```text
action title
entity name/id
impact text
Cancel
destructive primary action
```

Do not use browser `confirm()`.

## 22. Input Semantics

Input modal supports:

```text
text
password
number
```

Requirements:

- validation message in modal;
- required inputs enforced before submit;
- password values cleared on close;
- secrets never persisted to DOM data attributes/localStorage/sessionStorage.

## 23. Copyable Values

For CNAME, IDs, revision IDs, generated values, etc.:

```text
label
monospace value
Copy button
```

Copy result can use a small transient inline status inside the modal instead of opening a second modal.

## 24. Mobile Behavior

On narrow screens:

- modal width uses viewport-safe padding;
- action buttons stack when needed;
- long technical values wrap;
- body background does not scroll behind an active modal.

## 25. Security

The modal layer must not weaken backend controls.

Security requirements:

- no HTML injection from server messages;
- content inserted via text nodes/textContent;
- secrets redacted before render;
- no token/password caching;
- CSRF behavior unchanged;
- authorization unchanged.

## 26. Backward Compatibility

Backend API endpoints remain unchanged.

Existing forms may stay structurally intact where replacing them would add unnecessary risk; only their submit/confirmation/result interaction is standardized.

No database migration is required.

## 27. Files Likely Modified

```text
app/templates/base.html
app/static/app.css
app/static/app.js
app/templates/dashboard.html
app/templates/mappings.html
app/templates/users.html
app/templates/roles.html
app/templates/audit.html
app/templates/system.html
tests/integration/test_web_ui.py
tests/e2e/test_acceptance.py
VERSION
```

Additional page-specific JS helpers may be split from `app.js` if needed to keep files focused.

## 28. Test Requirements

### Unit/UI contract
- state reset between every modal mode;
- hidden sections stay hidden;
- focus restore;
- Escape rules;
- confirmation result;
- prompt result;
- busy-state cleanup;
- response normalization;
- secret redaction.

### Integration
- Mappings actions use modal;
- Users actions use modal;
- Roles actions use modal;
- System actions use modal;
- Backup actions use modal;
- SSL actions remain functional;
- top banner not used for normal action feedback.

### Security
- server message HTML is escaped;
- tokens/passwords absent from modal result markup;
- no secrets in browser storage;
- destructive actions cannot bypass confirmation client flow.

### E2E
At least one representative action per page:

```text
Mappings: Validate/Apply/Delete
Users: Create/Delete
Roles: Save/Delete
System: Validate/Apply/Rollback
Backup: Create/Restore/Delete
SSL: Verify/Test renewal/Delete
```

## 29. Release Acceptance Criteria

0.5.0 ships only when:

```text
single reusable modal is used app-wide
no browser-native confirm/prompt remains
normal CRUD/action result banners removed
all destructive actions confirm
all long-running actions show loading
all modal mode transitions reset stale state
focus/keyboard behavior works
duplicate clicks are blocked
secrets never render in result modals
Mappings covered
Users covered
Roles covered
System covered
Backup covered
SSL covered
Dashboard/Audit covered where actions exist
full regression passes
Python/JS/shell syntax gates pass
VERSION=0.5.0
```

## 30. Implementation Phases

1. Harden global modal core API + accessibility.
2. Add shared action runner and response normalization.
3. Migrate Mappings.
4. Migrate Users.
5. Migrate Roles.
6. Migrate System.
7. Migrate Backup/Restore.
8. Migrate Audit/Dashboard actions.
9. Reconcile SSL with global helpers.
10. Remove old banner/native confirm/prompt action paths.
11. E2E/accessibility/security regression.
12. Package/version/release gate.

## 31. Result

After 0.5.0, user interaction is consistent everywhere:

```text
click action
  -> optional confirm/input modal
  -> loading modal
  -> API request
  -> success/error modal
  -> close
  -> focus returns to original control
```

No page-specific popup behavior should be necessary for standard actions.
