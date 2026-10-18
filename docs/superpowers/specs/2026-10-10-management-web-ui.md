# DNS Manager Management Web UI Specification

## Goal
Provide a browser management console for the existing DNS Manager REST API without adding a frontend build toolchain or external CDN dependencies.

## Architecture
FastAPI serves Jinja2-rendered HTML pages and local static CSS/JavaScript. Existing REST APIs remain the source of truth for data and mutations. Authenticated HTML routes resolve the existing persistent session server-side; browser mutations continue to use the existing CSRF-protected APIs.

## Pages
- `/login`: public login page.
- `/app/dashboard`: service readiness, backend health, mapping summary, pending changes, recent audit.
- `/app/mappings`: search/filter, add/edit/delete, backend status, preview/apply controls.
- `/app/users`: user administration according to RBAC.
- `/app/roles`: role/permission view and Super Admin permission editing.
- `/app/audit`: read-only audit table with filters.
- `/app/system`: readiness/system status, generated config preview, apply/validate/rollback controls.

## RBAC UI
Viewer sees read-only mappings/audit/system controls. Admin sees mapping/apply controls and non-Super-Admin user administration, but not role permission editing or rollback. Super Admin sees all management controls. Server-side rendering hides actions the current role cannot perform; APIs still enforce authorization independently.

## UX / Security
Responsive desktop-first admin console with sidebar and top status bar. Use local assets only, system fonts, semantic status badges, modal forms, confirmation for destructive/apply operations, and accessible labels. No credentials or secrets are embedded in HTML. JavaScript obtains/uses the existing CSRF cookie/token for mutating API requests and redirects to login on 401.
