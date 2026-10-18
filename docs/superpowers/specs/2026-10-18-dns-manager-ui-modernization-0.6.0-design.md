# DNS Manager 0.6.0 UI Modernization — Design Specification

**Date:** 2026-10-18  
**Target release:** 0.6.0  
**Baseline:** DNS Manager 0.5.9  
**Status:** Draft for user review

## 1. Purpose

Modernize the DNS Manager web interface while preserving all current behavior.

The release must fix UI defects across the software, especially broken or clipped text, inconsistent box sizing, spacing and alignment problems, horizontal overflow, dense layouts, modal sizing, form wrapping, table usability, and responsive behavior on desktop, tablet, and mobile.

This is a presentation-layer release. Existing API routes, database schema, permissions, firewall logic, SSL workflows, backup/restore, mappings, audit behavior, and current server-side functionality must remain compatible with 0.5.9.

## 2. Goals

0.6.0 will:

- modernize the visual hierarchy without changing core workflows;
- establish a consistent design system for spacing, typography, surfaces, controls, status states, and responsive layout;
- prevent long domains, IPs, IPv6 values, CIDRs, comments, permissions, revision IDs, certificate data, audit fields, and generated config text from breaking containers;
- improve mobile and tablet usability across all pages;
- make dense System-page controls easier to scan and operate;
- keep table data usable without destructive squeezing;
- standardize modals and action dialogs;
- improve keyboard focus and general accessibility;
- preserve the 0.5.9 JavaScript action hooks and backend contracts.

## 3. Non-goals

0.6.0 will not:

- replace FastAPI/Jinja with a client-side framework;
- change API endpoint paths or payload formats;
- change authentication, CSRF, RBAC, or session behavior;
- add database migrations solely for UI;
- change firewall rule semantics or UFW reconciliation;
- change SSL issuance/provider behavior;
- change mapping generation or Nginx routing behavior;
- change backup/restore semantics;
- redesign business logic inside `app.js`;
- add unrelated new product features.

## 4. Current UI Constraints

The 0.5.9 interface is server-rendered with Jinja templates and a shared CSS/JavaScript layer.

Key constraints:

- `app/templates/base.html` owns the global sidebar, topbar, flash region, and global action modal.
- Page templates include:
  - `dashboard.html`
  - `mappings.html`
  - `users.html`
  - `roles.html`
  - `audit.html`
  - `system.html`
  - `login.html`
- `app/static/app.js` binds behavior through existing `data-*` hooks and must remain compatible.
- `app/static/app.css` is currently highly compressed and mixes global layout, page-specific rules, modal rules, and firewall rules.
- The current mobile layout converts navigation into a 3-column grid and hides the sidebar footer, which can create awkward wrapping and weak navigation hierarchy.
- Tables currently rely primarily on `overflow:auto`.
- Long content protection is inconsistent outside the action modal.
- Several dense inline forms depend on flex wrapping without a coherent responsive form model.

## 5. Design Direction

The UI will become a clean network-administration console with:

- neutral modern surfaces;
- stronger spacing hierarchy;
- clearer section grouping;
- consistent control sizes;
- restrained use of elevation;
- clearer success/warning/error states;
- better distinction between primary, secondary, destructive, and passive actions;
- light and dark support through the existing system color preference.

The redesign will prioritize readability and operational clarity over decorative effects.

## 6. Design System

### 6.1 Tokens

Introduce semantic CSS variables for:

- background layers;
- panel/surface layers;
- text and muted text;
- borders/dividers;
- primary/accent;
- success/warning/danger;
- focus ring;
- border radius;
- spacing scale;
- shadow scale;
- control height;
- content max-width;
- sidebar width.

Representative spacing scale:

- 4px
- 8px
- 12px
- 16px
- 20px
- 24px
- 32px

Spacing must be applied consistently instead of page-specific arbitrary gaps.

### 6.2 Typography

Use the existing system/Inter-style font stack.

Required behavior:

- headings have consistent line-height and responsive sizing;
- labels remain readable without becoming oversized;
- monospace data uses a dedicated utility class;
- long machine-readable values use safe wrapping;
- buttons may wrap only where explicitly allowed;
- important state text must never be clipped.

Global long-text handling will include appropriate use of:

- `min-width: 0`
- `overflow-wrap: anywhere`
- `word-break` only where required for machine values
- `white-space` rules appropriate to each component

## 7. Global Application Shell

### 7.1 Desktop

Desktop layout will use:

- a stable sidebar approximately 248–260px wide;
- a flexible main content column with `min-width:0`;
- bounded readable content width where appropriate;
- a topbar with title/context on the left and health state/actions on the right.

### 7.2 Tablet

At tablet widths:

- metric grids collapse from 4/3 columns to 2 columns;
- toolbars wrap predictably;
- inline forms become grid-based or stacked where needed;
- two-column content becomes one column when content no longer fits cleanly.

### 7.3 Mobile

Mobile layout must not rely on a fragile 3-column navigation grid.

The mobile navigation will use a deliberate compact navigation treatment that:

- keeps every accessible page reachable;
- avoids clipped navigation labels;
- keeps sign-out and identity accessible;
- prevents horizontal page overflow.

No page should require viewport-level horizontal scrolling.

## 8. Cards, Sections, and Page Hierarchy

Cards will be standardized with:

- consistent radius;
- border;
- padding;
- heading gap;
- optional header toolbar;
- predictable vertical rhythm.

`card-head` behavior will be updated so heading content and actions can stack gracefully on narrow screens.

Dense pages, especially System, will group related controls into visually distinct sections without altering underlying behavior.

Nested blocks will use lower-emphasis surfaces to avoid excessive card-on-card visual noise.

## 9. Buttons and Toolbars

Buttons will use a shared sizing system with consistent:

- height;
- padding;
- border radius;
- font weight;
- focus state;
- disabled state.

Variants remain:

- primary;
- secondary;
- ghost;
- danger.

Toolbar behavior:

- actions align consistently on desktop;
- actions wrap without overlap;
- mobile actions can expand to full-width where that improves usability;
- destructive actions remain visually distinct;
- row-action groups never overflow their table cell.

Existing `data-action` attributes must not be renamed.

## 10. Forms

All standard form controls will share:

- consistent minimum height;
- width behavior;
- padding;
- border and focus treatment;
- disabled/read-only appearance;
- validation/error state support.

Labels will be consistently spaced from controls.

Form layout rules:

- wide forms can use 2-column grids;
- long or critical fields may span full width;
- mobile forms collapse to one column;
- checkbox/radio controls use an inline alignment pattern rather than inheriting the standard stacked label layout;
- `inline-form` will become responsive and must not depend on uncontrolled flex shrink.

Specific high-risk layouts include:

- firewall policy controls;
- firewall rule modal;
- SSL issue form;
- rollback controls;
- mapping edit forms;
- user/role forms.

## 11. Tables

Desktop tables remain semantic HTML tables.

Required improvements:

- predictable cell padding;
- clear headers;
- safe wrapping for long data;
- machine values can use monospace styling;
- action cells have stable alignment;
- empty/loading rows remain readable;
- rows must not expand uncontrollably because of one long token.

Responsive behavior:

- use a local `.table-wrap` scroller when table width genuinely exceeds available space;
- page itself must remain fixed to viewport width;
- define sensible table `min-width` values per data density;
- compact action buttons without making them too small to operate;
- preserve headers and data relationships;
- avoid forcing every column into unreadably narrow widths.

Tables to validate include mappings, users, audit, firewall rules, SSL/certificates/backups where applicable.

## 12. Modal and Dialog System

Global action modal and page-specific dialogs will share a consistent responsive model.

Requirements:

- width constrained by viewport;
- maximum height constrained by viewport;
- body can scroll internally;
- header and footer remain usable;
- long error/detail content wraps safely;
- mobile footer actions stack when necessary;
- focus-visible state is strong;
- close controls have adequate target size;
- modal opening must not cause background layout shift or horizontal overflow.

Existing modal confirmation behavior from 0.5.9 must remain unchanged, including the sequential-confirmation race fix.

## 13. Dashboard

Dashboard modernization will:

- improve metric-card visual hierarchy;
- align health/status components;
- standardize loading and empty states;
- balance multi-column layouts;
- improve readability at tablet/mobile sizes.

No dashboard data contract changes are permitted.

## 14. Mappings

Mappings UI will:

- improve search/toolbar wrapping;
- protect long domain/upstream values;
- keep action controls aligned;
- make modal/form fields responsive;
- preserve all existing mapping CRUD behavior.

## 15. Users and Roles

Users/roles UI will:

- improve table/card spacing;
- prevent long usernames/role/permission labels from breaking layouts;
- make permission lists easier to scan;
- ensure role cards and permission grids collapse cleanly;
- preserve existing RBAC behavior.

## 16. Audit

Audit UI will:

- protect long event/resource/detail fields;
- make timestamps and actors visually distinct;
- improve table readability on smaller screens;
- preserve existing filtering/loading behavior.

## 17. System Page

The System page is the highest-density screen and receives special treatment.

### 17.1 Service status

Metric cards will use a consistent responsive grid and clear state styling.

### 17.2 Generated configuration

dnsmasq and Nginx previews will:

- stack on narrower screens;
- retain internal scrolling;
- preserve monospace formatting;
- never force page-level horizontal overflow.

### 17.3 Rollback

Revision input and action will use a bounded responsive form row, stacking on small screens.

### 17.4 Firewall

Firewall UI will improve:

- metric spacing;
- finding/warning presentation;
- policy form layout;
- rule table width handling;
- preview/validate/apply/rollback toolbar grouping;
- firewall rule dialog responsiveness.

No firewall API or safety behavior changes are allowed.

### 17.5 SSL / Certificates

SSL issue/provider controls will use a responsive grid rather than an over-dense inline row.

Sensitive fields and long certificate/domain data must not break layout.

### 17.6 Backups and other operational sections

Actions, metadata, and tables will follow the same component system.

## 18. Login

Login will retain the same authentication POST/session behavior.

Visual changes:

- improved card spacing;
- clearer brand treatment;
- improved input/button sizing;
- stronger focus state;
- better mobile safe-area handling;
- no viewport overflow.

## 19. Accessibility

The release will improve:

- keyboard focus visibility;
- accessible control sizes;
- dialog focus treatment;
- readable contrast in light/dark modes;
- consistent disabled state;
- semantic headings;
- form label relationships;
- button/action distinction.

No information should be conveyed exclusively by color.

## 20. CSS Architecture

`app/static/app.css` will be expanded from the current compressed form into maintainable sections:

1. tokens/reset;
2. typography/utilities;
3. application shell/navigation;
4. cards/status components;
5. buttons/toolbars;
6. forms;
7. tables;
8. dialogs/modals;
9. page-specific components;
10. responsive breakpoints;
11. dark-mode overrides where necessary.

Avoid introducing a CSS framework or build pipeline.

## 21. JavaScript Compatibility

`app.js` should remain functionally unchanged unless a small UI-only behavior is required for responsive navigation or dialog ergonomics.

Rules:

- preserve all existing `data-action` hooks;
- preserve data attributes consumed by page loaders;
- preserve modal resolver behavior fixed in 0.5.9;
- do not move business logic into CSS-dependent selectors when avoidable;
- any JavaScript change requires a regression test.

## 22. Template Compatibility

Template edits may add wrapper elements or CSS classes but must not:

- rename existing form field names used by JavaScript;
- rename `data-*` hooks used by JavaScript;
- change permission conditionals;
- remove accessible labels;
- change server-side data requirements.

## 23. Responsive Breakpoints

Use a small, consistent breakpoint set.

Proposed breakpoints:

- desktop: above 1024px;
- tablet: 721px–1024px;
- mobile: 720px and below;
- narrow mobile refinements around 520–560px where dialog/toolbars require it.

Breakpoints should be driven by layout failure rather than device brand assumptions.

## 24. Regression and Acceptance Testing

Existing regression suite must remain green.

Baseline before UI work:

- 370 tests passing on 0.5.9;
- Python syntax passing;
- shell syntax passing;
- application health passing;
- all production services active.

New UI regression tests should verify structural contracts such as:

- responsive navigation wrapper/classes exist;
- key templates preserve required `data-*` hooks;
- modal structure supports internal scrolling;
- long-text utility/classes exist;
- firewall modal/action hooks remain present;
- critical forms use responsive layout classes;
- `VERSION` is updated for the final release.

Where practical, add browser/e2e viewport checks for representative desktop and mobile widths.

## 25. Manual Acceptance Matrix

Validate at minimum:

### Desktop
- 1440×900
- 1280×800

### Tablet
- 1024×768
- 768×1024

### Mobile
- 390×844
- 360×800

For each viewport verify:

- no page-level horizontal scrollbar;
- navigation remains usable;
- headings and status text do not clip;
- cards remain inside viewport;
- buttons do not overlap;
- inputs/selects stay inside containers;
- tables are locally scrollable when required;
- modals fit viewport and can scroll internally;
- long domains/IPs/CIDRs/comments wrap safely.

## 26. Release Strategy

Target release is **0.6.0** because the visual system changes across the full application, while backend behavior remains compatible with 0.5.9.

Release will be cumulative and must include all 0.5.9 fixes.

Before packaging:

- run focused UI tests;
- run full `pytest -q`;
- run JavaScript syntax validation;
- run Python syntax validation;
- run shell syntax validation;
- verify package contents;
- confirm `VERSION=0.6.0`;
- generate SHA256;
- install on the current production host through the existing installer;
- verify services, health endpoint, UFW state, and key UI workflows.

## 27. Acceptance Criteria

0.6.0 is acceptable when:

1. all existing 0.5.9 functional tests remain green;
2. new UI regression tests pass;
3. no supported page has viewport-level horizontal overflow at the acceptance widths;
4. long machine-readable text cannot visibly break its containing card, table, modal, or form;
5. desktop/tablet/mobile navigation remains usable;
6. all major forms fit and align correctly;
7. tables retain readable data and usable row actions;
8. dialogs remain inside the viewport and scroll internally where needed;
9. light and dark themes remain readable;
10. firewall, SSL, mappings, users, roles, audit, backup, config apply/rollback, and authentication behavior remain unchanged;
11. the cumulative release package includes all prior 0.5.9 fixes;
12. production verification passes after installation.
