# DNS Manager 0.7.0 Console UI Redesign — Design Specification

**Date:** 2026-10-25  
**Target release:** 0.7.0  
**Baseline:** DNS Manager 0.6.11 with the security fixes merged on 2026-10-23 (`main` at `7659776`)  
**Status:** Draft for user review

## 1. Purpose

Give DNS Manager a new visual identity and a page structure that makes the state of every route and every pending action obvious.

The direct trigger was an ESXi VM console that failed behind DNS Manager. The mapping had been created with WebSocket and Preserve Host off, because the "Add mapping" form leaves both unchecked. And after the mapping was fixed, the HTTPS vhost kept the old settings until someone found the separate SSL **Apply** button near the bottom of the System page. The UI hid both facts. 0.7.0 must make that class of mistake hard to make and easy to see.

## 2. Audience and context

- **Users:** one administrator plus a team of NOC/support staff. Some team members have viewer roles. Some sign in from phones.
- **Usage:** frequent short check-ins ("is everything up?", "did my change go live?") and occasional deliberate changes (mappings, firewall, certificates, restores).
- **Deployment:** self-hosted Linux servers that may have no internet access. The UI must work fully offline.

## 3. Decisions taken during brainstorming

| Topic | Decision |
|---|---|
| Scope | Usability restructure (B) plus a new visual design (C) |
| Visual direction | **A — Console**: dense graphite surfaces, monospace for machine values (IPs, ports, CIDRs, revisions), teal signal accent. Mockup: https://claude.ai/artifact/ENstB3fLWvTn2HahEvsm3J |
| Themes | Dark by default, plus a matching Console light theme, switchable from the top bar and remembered per user |
| Language | Bengali and English, switchable from the top bar and remembered per user. Technical terms (DNS, SSL, Nginx, WebSocket, UFW, CIDR) stay in English in both |
| Default language | Bengali when the browser's preferred language is Bengali, otherwise English |
| Implementation approach | Rebuild inside the current stack (FastAPI + Jinja + plain JavaScript). No frontend framework, no build step, no CDN |
| SSL vhost sync | **Apply Changes** also rewrites the HTTPS vhost of every mapping that has an issued certificate |

## 4. Goals

0.7.0 will:

- split the System page into System, Firewall, SSL and Backups pages with grouped, icon-labelled navigation;
- show HTTPS, WebSocket, Preserve Host and health for every mapping without opening it;
- show, on every page, which saved changes are not live yet, with a one-click Apply for users allowed to apply;
- default new mappings to WebSocket on and Preserve Host on, with a one-line explanation under each option;
- keep the HTTPS vhost in step with its mapping on every Apply;
- replace the free-text "revision database ID" rollback field with a revision list;
- make the firewall's 120-second confirmation window impossible to miss;
- provide the Console look in dark and light, in Bengali and English, on desktop and phone;
- replace the single 437-line `app.js` with small per-page modules.

## 5. Non-goals

0.7.0 will not:

- introduce React, Vue, Preact, htmx, Alpine or any build tooling;
- load fonts, scripts or styles from a CDN;
- change authentication, sessions, CSRF, or RBAC semantics, except the new page routes in §8;
- add a database migration (the new UI state lives in two non-sensitive cookies);
- change firewall rule semantics, SSL issuance providers, backup format, or privileged helper protocols;
- translate audit-log action codes, API error codes or generated configuration files;
- add new monitoring data sources (sparklines reuse the metrics the dashboard already polls every second).

## 6. Information architecture

### 6.1 Navigation

The sidebar groups pages. A page the user lacks permission for is not rendered in the navigation (server-side, as today).

| Group | Page | Route | Required permission |
|---|---|---|---|
| Overview | Dashboard | `/app/dashboard` | `system.view` |
| Routing | Mappings | `/app/mappings` | `mapping.view` |
| Security | Firewall | `/app/firewall` (new) | `firewall.manage` |
| Security | SSL | `/app/ssl` (new) | Super Admin role (matches the SSL API's `_super` check) |
| Operations | System | `/app/system` | `system.view` |
| Operations | Backups | `/app/backups` (new) | `backup.create` |
| Admin | Users | `/app/users` | `user.view` |
| Admin | Roles | `/app/roles` | `role.view` |
| Admin | Audit | `/app/audit` | `audit.view` |

`/app/system` keeps working for old bookmarks. It no longer contains the firewall, SSL and backup sections.

### 6.2 Shell layout

**Desktop (≥ 768px)**

- Left sidebar, about 220px, with icon plus label. It can collapse to a 64px icon rail; the choice is remembered in `localStorage` (convenience only, with a safe default if storage is unavailable).
- Top bar, left to right: page title; service status pill ("All services running" or "Needs attention", linking to System); language switch (বাংলা / EN); theme switch; user menu with role and Sign out.
- **Pending-apply banner**, under the top bar on every page, shown when §7.3 reports pending domains and the user has `config.apply`. It names up to three pending domains ("+N more" beyond that) and carries an **Apply changes** button that runs the existing validate → apply flow through the action modal. Users without `config.apply` see a quieter notice without the button.

**Phone (< 768px)**

- Bottom tab bar: Dashboard, Mappings, System, More. **More** opens a sheet listing the remaining permitted pages, language, theme and Sign out. The tab bar respects safe-area insets.
- Tables render each row as a compact card (label/value pairs), so the page never scrolls horizontally.
- Side panels (§7.2) open full-screen.

## 7. Mappings

### 7.1 Table

| Column | Content |
|---|---|
| Domain | Health dot, domain, description underneath, "pending" chip when the domain is in §7.3's list |
| Upstream | `scheme://host:port` in monospace |
| Flags | `HTTPS`, `WS`, `HOST` chips; a disabled flag is struck through and muted. `HTTPS` is lit when the domain has a valid certificate (status `ISSUED` or `EXPIRING`) |
| Health | The health service's status (`UP`, `HTTP_ERROR`, `TLS_ERROR`, `TIMEOUT`, `DOWN`, `UNKNOWN`) as a labelled chip, with latency in ms |
| Actions | Edit and Delete, each shown only with `mapping.update` / `mapping.delete` |

Above the table: search (domain or upstream) and filter chips: All, Up, Down, Disabled, Pending. A disabled mapping's row is muted.

### 7.2 Add / edit panel

- Opens as a right-hand side panel (full-screen on phones) instead of the current modal.
- **New mappings default to WebSocket on and Preserve Host on.** Under each checkbox, one line explains when it matters, e.g. WebSocket: "Needed for VM consoles, chat and other live connections."
- "Verify TLS" is renamed to make clear that it only affects the health check ("Verify upstream certificate during health checks"); its behaviour is unchanged.
- Saving shows a toast, "Saved, not live yet", and the domain joins the pending banner.

Clicking a domain opens a read-only detail panel:

- **Route line:** `domain → nginx :80/:443 → upstream`, with the failing hop drawn in the critical colour when health reports a failure;
- **Generated config:** this domain's port-80 server block and, if it has a certificate, the HTTPS vhost that will be written;
- **Last health check:** result, latency and time.

### 7.3 Backend additions for Mappings

1. **`ssl_status` on mapping responses.** `GET /api/v1/mappings` and `GET /api/v1/mappings/{id}` gain an `ssl_status` field: the stored status of the certificate whose domain equals the mapping's domain (for example `ISSUED`, `EXPIRING`, `EXPIRED`, `ERROR`), or `null` when there is none. This only adds a field; existing fields are unchanged.
2. **`GET /api/v1/config/pending`** (requires `mapping.view`) returns `{"count": n, "domains": [...]}`. It is computed the same way as the existing `get_pending_change_count`: domains whose current mapping state differs from the active revision's snapshot, including added and deleted mappings.
3. **SSL vhost sync on apply.** After `apply_pending_config` succeeds, and still holding the apply lock, it rewrites the HTTPS vhost (`PrivilegedHelper.ssl_apply`) for each enabled mapping whose certificate is still valid (`ISSUED` or `EXPIRING`), using the same upstream payload the SSL page's Apply builds today. The upstream data comes only from the database mapping, so no new privilege is granted to `config.apply` holders.
   - A sync failure never undoes the config apply. The apply response gains `"ssl_sync": {"updated": [...], "failed": [{"domain": ..., "error": ...}]}`, the UI shows failures as a warning, and each failure is audited as `SSL_SYNC_FAILED`.
   - The SSL page's own Apply button stays for manual use.

## 8. Other pages

### 8.1 Dashboard

- **Summary strip:** services running (n/4), mappings (total · up · down), pending changes, certificates expiring within 30 days.
- **Sparklines** for CPU, RAM and network RX/TX over the last two minutes, drawn from the existing 1-second metrics polling (a client-side ring buffer; polling still pauses in hidden tabs).
- **"Needs attention" list:** down backends, certificates expiring or expired, UFW inactive, pending changes. Each item links to the page that fixes it.
- **Recent audit events:** the last ten, compact.

### 8.2 System

- **Services:** dns-manager, dns-manager-helper, nginx and dnsmasq, each with its state.
- **Configuration:** a line diff between the active revision's stored configuration and the current preview, for dnsmasq and nginx (additions and removals coloured). Validate and Apply buttons sit beside it. When there is no active revision yet, the full preview is shown.
- **Revisions:** a table (revision, created, created by, status) from the new `GET /api/v1/config/revisions` (requires `config.rollback`; newest first, 50 per page). The active revision offers **Roll back**. It calls the existing `POST /api/v1/config/rollback/{id}` and says which revision it will restore.
- **Interfaces and filesystems:** as today.

### 8.3 Firewall

- **Summary cards:** UFW state, default incoming/outgoing, managed rule count, detected SSH port.
- **Findings:** each with a severity stripe (critical / warning / info).
- **Rules table:** purpose, action, protocol, port or range, source CIDRs as chips, comment, actions. Editing uses the side panel.
- **After Apply:** a sticky confirmation bar shows the 120-second countdown with **Confirm** and **Roll back now**. When the deadline passes, the bar says the change was rolled back. It relies on the 409 that confirm already returns.

### 8.4 SSL

- **Certificate table:** domain, provider, status, expiry with days remaining (warning under 30 days, critical under 7), auto-renew.
- Each row shows only its primary action (Issue, or Renew once issued). Every other action (test renewal, apply vhost, delegation/CNAME show and verify, re-register, convert, enable/disable auto-renew, delete) moves into a "⋯" menu. Each action keeps its current API call.
- "Add certificate" opens the side panel.

### 8.5 Backups

- **List:** created, backup ID (monospace), label, schema version, size.
- **Toolbar:** Create backup and Upload.
- **Restore:** a confirmation step that explains what happens (a pre-restore backup is created first; the session may end; configuration is regenerated from the backup's mappings). Restore is enabled only after the user types the backup ID.

### 8.6 Users, Roles, Audit, Login

Restyled in the Console system with the same behaviour. Audit gets sticky filters and the mobile card layout. Login gets the language and theme switches.

## 9. Visual system

### 9.1 Tokens

`app/static/css/tokens.css` defines every colour as a custom property on `:root`.

- **Dark (default):** graphite surfaces, roughly `#0b0e13` sidebar, `#11151b` page, `#18202a` raised; text `#d6dde7`, muted `#8f9bab`; accent teal `#2fc1a8`.
- **Light:** the same hues lifted (cool grey surfaces, ink text) with the teal darkened enough for 4.5:1 contrast on white.
- **Semantic colours,** separate from the accent: good, warning, critical, info, each with a dark and a light value.
- **Other tokens:** spacing, radius and shadow; the scale comes from the existing 0.6.0 tokens.

All component CSS uses tokens only. A contrast test (§11) checks text and chip colours in both themes.

### 9.2 Typography

- **UI text:** IBM Plex Sans (400/600).
- **Machine values:** IBM Plex Mono, used for IPs, ports, CIDRs, revisions, backup IDs and config.
- **Bengali text:** Noto Sans Bengali, because Plex has no Bengali glyphs.
- All fonts are vendored as WOFF2 under `app/static/fonts/` with their OFL licence files. The font stack falls back to system fonts.
- Numbers in tables use tabular figures.

### 9.3 Components

`components.css` provides:

- buttons (primary, secondary, ghost, danger), chips, status dots and badges;
- tables with a mobile card mode;
- the side panel, the existing action modal restyled, toasts, the pending banner, the sticky confirmation bar;
- the sparkline and the diff view.

Icons are inline SVG from one sprite file (`app/static/icons.svg`), drawn on a 24px grid with a 1.8px stroke.

### 9.4 Accessibility

- Every interactive element has a visible focus ring.
- Colour is never the only signal: chips carry text, dots carry a label.
- Panels and modals trap focus and close on Escape.
- `prefers-reduced-motion` disables transitions.

## 10. Technical design

### 10.1 File layout

```
app/static/
  css/tokens.css  base.css  components.css  pages.css
  fonts/          IBMPlexSans-*.woff2  IBMPlexMono-*.woff2  NotoSansBengali-*.woff2  LICENSE-*.txt
  icons.svg
  js/core.js      api() with CSRF, toast, modal, side panel, t(), theme and language switches, poller
  js/pages/       dashboard.js mappings.js system.js firewall.js ssl.js backups.js users.js roles.js audit.js login.js
  i18n/en.json  bn.json
app/templates/
  base.html       shell: sidebar, top bar, pending banner, mobile tab bar, action modal
  _macros.html    chip, badge, card, empty state
  dashboard.html mappings.html system.html firewall.html ssl.html backups.html users.html roles.html audit.html login.html
```

- `base.html` loads `core.js` and then the page module (`js/pages/<page>.js`) with `<script type="module">`. Each module exports `init()`.
- `app.js` and `app.css` are removed at the end of the rollout (§12).
- Until then, each page's template uses either the old or the new assets, never both.

### 10.2 Language

- **Storage:** the choice is stored in a `dns_manager_lang` cookie (`bn` or `en`; `SameSite=Lax`, `Path=/`, one year, not HttpOnly so the switch can set it).
- **Server side:** a Jinja global `t(key)` reads the dictionaries, which are loaded once at startup.
- **Client side:** the server embeds only the active dictionary in the page as a JSON `<script type="application/json">` block, and `core.js` exposes `t(key, params)` over it.
- **Missing keys:** fall back to English, then to the key itself. A test (§11) keeps both files complete.
- **Default:** without a cookie, Bengali if `Accept-Language` prefers `bn`, otherwise English.
- **What is translated:** all labels, help text, empty states, confirmations and client-side error messages. Server API error `detail` strings stay as they are (English).

### 10.3 Theme

- The choice is stored in a `dns_manager_theme` cookie (`dark` or `light`, same attributes as the language cookie).
- The server renders `<html data-theme="…">`, so there is no flash of the wrong theme. The default is `dark`.
- Neither cookie carries anything sensitive. The session and CSRF cookies are unchanged.

### 10.4 Backend changes

1. `app/web.py`: add the `firewall`, `ssl` and `backups` pages to `PAGE_TITLES` and the permission map (SSL checks the Super Admin role). Pass `lang`, `theme` and the active dictionary into the template context.
2. `app/api/mappings.py`: add `ssl_status` (§7.3).
3. `app/api/config_ops.py`: add `GET /config/pending` and `GET /config/revisions`, and return `ssl_sync` from apply.
4. `app/services/apply_service.py`: run the SSL vhost sync after a successful apply, inside the apply lock (§7.3).
5. No schema migration.

### 10.5 Compatibility

- **API:** every existing route and field is unchanged; there are only additions.
- **Tests:** existing UI tests that assert on `/static/app.js` or the 0.6.0 markup are updated to the new assets as each page moves over.

## 11. Testing

- The full existing suite stays green.
- **New pytest coverage:**
  - `ssl_status` on mappings;
  - `/config/pending` (added, changed and deleted mappings) and its permission;
  - `/config/revisions`, its ordering, paging and permission;
  - SSL sync: it updates domains with valid certificates (`ISSUED`, `EXPIRING`) only, it skips disabled mappings and expired or failed certificates, a failure leaves the apply in place and is audited, and it runs inside the lock;
  - new page routes and their permissions;
  - the language cookie, the `Accept-Language` default and the theme cookie in rendered HTML.
- **i18n completeness:** `en.json` and `bn.json` have identical keys, and every `t('…')` key used in templates and JS modules exists in both.
- **Contrast:** a unit test computes WCAG contrast for the text/background and chip pairs in `tokens.css`, for both themes (≥ 4.5:1 for text, ≥ 3:1 for large text and icons).
- **Browser smoke test (Playwright, `@pytest.mark.browser`, skipped when Chromium is unavailable):** every page at 1440px and 390px, dark and light, `en` and `bn`. Each run fails on horizontal overflow of the page body, console errors, or missing fonts (checked with `document.fonts.check`).
- **Manual check before release:** an ESXi console mapping end to end (create, apply, open console through HTTPS) on a test host.

## 12. Rollout

Each step is one pull request and leaves the app fully usable.

1. **Foundation:** tokens, fonts, icons, `core.js`, the i18n and theme plumbing, the new shell (sidebar, top bar, pending banner, mobile tab bar), the login page. The existing pages render inside the new shell with their current content.
2. **Mappings:** the new page, `ssl_status`, `/config/pending`, new-mapping defaults, the detail panel, the SSL vhost sync.
3. **Dashboard and System:** the summary strip, sparklines, attention list, config diff, `/config/revisions` and the revision list.
4. **Firewall, SSL and Backups pages:** move each section out of System into its own page.
5. **Users, Roles and Audit; complete the Bengali dictionary; remove `app.js` and `app.css`;** bump `VERSION` to 0.7.0 and update `docs/ADMINISTRATION.md`.

## 13. Risks

| Risk | Mitigation |
|---|---|
| Bengali strings run longer than English and break dense layouts | The browser smoke test runs every page in `bn` at phone width |
| SSL sync turns one Apply into many nginx reloads | One `ssl_apply` per issued domain on each apply. Acceptable at the current scale (tens of domains); revisit if a host has hundreds |
| Shipping fonts grows the package | Only the weights used are shipped (about 400 KB of WOFF2 in total) |
| Two asset systems during the rollout | Each template uses exactly one; step 5 removes the old one |

## 14. Related issue found while writing this spec

`apply_service._ssl_redirect_domains` drops a domain's plain port-80 server block only while its certificate is `ISSUED`. Once a certificate turns `EXPIRING`, the generated nginx config adds the port-80 block back, alongside the HTTPS file's own port-80 redirect. Step 2 aligns that check with the sync rule above (`ISSUED` or `EXPIRING`) and adds a test.
