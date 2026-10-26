# DNS Manager v0.7.0 — release notes

**Release:** v0.7.0 · **Date:** 2026-10-27

## Highlights

- **New console shell** — grouped sidebar with an optional icon rail, top bar with pending-change banner, and a mobile bottom tab bar with a **More** sheet.
- **Dark and light themes** — dark by default, remembered in the `dns_manager_theme` cookie and rendered server-side so there is no flash of the wrong theme.
- **English and Bengali** — every label, help text, empty state and confirmation is translated; technical terms stay in English. The choice is stored in `dns_manager_lang`, and without a cookie the language follows `Accept-Language` (`bn` preferred → Bengali, otherwise English).
- **Offline assets** — fonts, icons, CSS and JavaScript are served locally; there is no CDN, framework or build step.
- **Nine console pages** — Dashboard, Mappings, Firewall, SSL, System, Backups, Users, Roles and Audit, plus a redesigned sign-in page.

## Page changes

- **Mappings** — filters and search, backend health, per-domain SSL status, a detail panel with the generated Nginx and dnsmasq snippets, and create defaults of WebSocket + host preservation + TLS + enabled.
- **Dashboard** — summary strip, attention list for down backends and pending changes, recent audit events, and CPU/RAM/network sparklines with a clear unavailable state when metrics cannot be read.
- **System** — DNS safety card, service state, configuration preview and line diff, validate/apply, and a paged revision history (50 per page) showing who created each revision, with rollback.
- **Firewall** — multi-source rules with a live confirmation countdown and automatic rollback when the deadline passes.
- **SSL** — certificate table with status, expiry and provider; actions live behind a row overflow menu; the token field only appears for Cloudflare.
- **Backups** — upload, download, delete, and restore that stays disabled until the exact backup identifier is typed.
- **Users, Roles and Audit** — rebuilt on the shared console components.

## Backend additions

- `GET /api/v1/mappings` and `/api/v1/mappings/{id}` gain `ssl_status` (stored certificate status for the mapping's domain, or `null`).
- `GET /api/v1/config/pending` returns `{"count": n, "domains": [...]}` and requires `mapping.view`.
- `GET /api/v1/config/revisions` adds paging and `created_by_username` and requires `config.rollback`.
- Apply now rewrites the HTTPS vhost for every enabled mapping whose certificate is `ISSUED` or `EXPIRING`, and returns `ssl_sync: {"updated": [...], "failed": [...]}`. Sync failures are audited as `SSL_SYNC_FAILED` and never roll back the configuration apply.
- The plain-HTTP server block is suppressed for `EXPIRING` certificates as well, matching the HTTPS vhost sync rule.
- SSL certificate reconciliation keeps listing certificates when one row cannot be read, marking it `ERROR` instead of failing the whole page.

All existing API routes and fields are unchanged; the release is purely additive. There is no database migration.

## Removed

- The legacy `app/static/app.js` and `app/static/app.css` bundles. Each page now has its own module, and the shell is shared through `core.js`.

## Upgrade notes

1. Install the 0.7.0 package using the normal installer; no manual migration is required.
2. Restart `dns-manager.service` (the installer does this and waits for `/health`).
3. Static assets are served with revalidation, so browsers pick up the new modules after a reload.
4. The SSL page requires the Super Admin role.
5. Clear the `dns_manager_lang` / `dns_manager_theme` cookies only if you want to return to the browser-derived defaults.

## Testing

- Full pytest suite, including new coverage for `ssl_status`, `/config/pending`, `/config/revisions`, the SSL vhost sync, page permissions, language and theme cookies, i18n key parity, and WCAG contrast for both themes.
- Console behaviour was checked in both languages and both themes at desktop and phone widths: no horizontal overflow, no raw translation keys, no console errors apart from the expected metrics `503` on hosts without `/proc`.
- Manual check on a release host: create, apply and open an ESXi console mapping through HTTPS.
