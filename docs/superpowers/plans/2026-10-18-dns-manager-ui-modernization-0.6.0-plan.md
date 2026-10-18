# DNS Manager 0.6.0 UI Modernization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Modernize the full DNS Manager web interface while preserving all 0.5.9 functionality and fixing broken text, box sizing, spacing, alignment, overflow, modal sizing, table usability, and responsive behavior.

**Architecture:** Keep FastAPI/Jinja and the existing JavaScript action layer. Rebuild the presentation layer around a maintainable CSS design system, make minimal class/wrapper changes to templates, and preserve every existing backend contract and `data-*` action hook. Use structural regression tests plus the existing functional suite to prevent UI modernization from changing behavior.

**Tech Stack:** FastAPI, Jinja2, vanilla JavaScript, CSS, HTML `<dialog>`, pytest.

**Spec:** `docs/superpowers/specs/2026-10-18-dns-manager-ui-modernization-0.6.0-design.md`

## Global Constraints

- Baseline is DNS Manager `0.5.9`; target release is `0.6.0`.
- Preserve API routes, database schema, authentication, CSRF, RBAC, firewall semantics, SSL behavior, mappings, backup/restore, audit behavior, and server-side data contracts.
- Preserve all existing `data-*` hooks used by `app/static/app.js`.
- Preserve the 0.5.9 sequential-confirmation modal race fix.
- Preserve the 0.5.9 inactive-UFW stale managed-rule reconciliation fix.
- Do not introduce a CSS framework, JavaScript framework, bundler, or frontend build pipeline.
- No database migration is required solely for this UI release.
- No supported page may require viewport-level horizontal scrolling.
- Long domains, IPs, IPv6 values, CIDRs, comments, permissions, IDs, certificate details, and generated configuration must not break their containing UI.
- Responsive acceptance widths: `1440x900`, `1280x800`, `1024x768`, `768x1024`, `390x844`, `360x800`.
- Existing light/dark system preference support must remain.
- The supplied source archive has no `.git` repository. During archive-based execution, replace commit steps with named checkpoint copies unless a real Git worktree is provided.

## Review Focus

1. **Unbroken machine strings:** domains, IPv6/CIDRs, revision IDs, certificate text, and long audit values must wrap or locally scroll without causing page-level overflow. Pin in Tasks 2, 4, 6, and 8.
2. **Dense action rows on narrow screens:** toolbars, inline forms, firewall controls, and modal footers must stack or wrap without overlap at `360px`. Pin in Tasks 2, 5, 7, and 8.
3. **Navigation with conditional RBAC items:** viewer/admin/super-admin navigation must remain complete and usable when links appear/disappear. Pin in Tasks 3 and 10.
4. **Table overflow isolation:** data tables may scroll inside `.table-wrap`, but the page/root shell must remain within viewport width. Pin in Tasks 4, 6, and 7.
5. **Modal regression risk:** global and firewall dialogs must preserve existing action hooks, sequential confirmations, form semantics, focus visibility, and internal scrolling. Pin in Tasks 5 and 10.

---

## File Structure

### Main files modified

- `app/static/app.css` — expanded maintainable design system and responsive component rules.
- `app/templates/base.html` — application shell, navigation wrappers, main content wrapper, global modal structure/classes.
- `app/templates/dashboard.html` — dashboard layout classes only.
- `app/templates/mappings.html` — responsive toolbar/table/form classes only.
- `app/templates/users.html` — responsive table/form classes only.
- `app/templates/roles.html` — role grid/permission presentation classes only.
- `app/templates/audit.html` — responsive filter/table classes only.
- `app/templates/system.html` — responsive System/Firewall/SSL/Backup section classes only.
- `app/templates/login.html` — modern login presentation classes only.
- `tests/integration/test_web_ui.py` — structural and regression contracts for all modified UI.
- `tests/integration/test_packaging.py` — final release version assertion update.
- `VERSION` — `0.6.0`.
- `docs/superpowers/specs/2026-10-18-dns-manager-ui-modernization-0.6.0-design.md` — approved design.
- `docs/superpowers/plans/2026-10-18-dns-manager-ui-modernization-0.6.0.md` — this implementation plan.

### JavaScript policy

`app/static/app.js` is **not** a planned modification. If implementation discovers a responsive behavior that cannot be solved with HTML/CSS alone, stop and upgrade the plan before editing JavaScript.

---

### Task 1: Add approved design artifacts and establish the 0.5.9 UI baseline

**Files:**
- Create: `docs/superpowers/specs/2026-10-18-dns-manager-ui-modernization-0.6.0-design.md`
- Create: `docs/superpowers/plans/2026-10-18-dns-manager-ui-modernization-0.6.0.md`
- Test: `tests/integration/test_web_ui.py`

**Interfaces:**
- Consumes: existing 0.5.9 templates, CSS, JavaScript hooks, and 370-test baseline.
- Produces: immutable design/plan references and a named baseline test set for later tasks.

- [ ] **Step 1: Add the approved spec and this plan to the project tree**

Copy the approved artifacts to the exact `docs/superpowers/...` paths above.

- [ ] **Step 2: Run the pre-change UI regression baseline**

Run:

```bash
pytest -q tests/integration/test_web_ui.py
```

Expected: all current UI tests PASS.

- [ ] **Step 3: Run the complete 0.5.9 baseline**

Run:

```bash
pytest -q
```

Expected: `370 passed` with only the existing Starlette/httpx deprecation warning.

- [ ] **Step 4: Create a baseline checkpoint**

If Git exists:

```bash
git add docs/superpowers
git commit -m "docs: add 0.6.0 UI modernization design and plan"
```

If Git does not exist, save a source checkpoint named `dns-manager-0.5.9-ui-baseline`.

---

### Task 2: Rebuild the shared CSS foundation and overflow safety model

**Files:**
- Modify: `app/static/app.css`
- Modify: `tests/integration/test_web_ui.py`

**Interfaces:**
- Consumes: current semantic classes (`.app-shell`, `.sidebar`, `.main-panel`, `.card`, `.btn`, `.table-wrap`, `.modal`, `.inline-form`, `.form-grid`, `.toolbar-group`).
- Produces: design tokens, typography utilities, spacing system, box-sizing reset, long-text safety utilities, reusable responsive primitives.

- [ ] **Step 1: Write failing CSS-structure tests**

Add tests with assertions that `app.css` contains all of:

```python
assert "box-sizing:border-box" in css.replace(" ", "")
assert "min-width:0" in css.replace(" ", "")
assert "overflow-wrap:anywhere" in css.replace(" ", "")
assert "--sidebar-width:" in css
assert "--control-height:" in css
assert ".machine-value" in css
assert ".content-stack" in css
```

Also assert that the stylesheet contains a global child box-sizing rule and no global `body` horizontal scrolling workaround such as `overflow-x:hidden` used to mask layout bugs.

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```bash
pytest -q tests/integration/test_web_ui.py -k "design_system or overflow"
```

Expected: FAIL because the new design-system contracts do not yet exist.

- [ ] **Step 3: Expand `app/static/app.css` into maintainable sections**

Implement these sections in order:

1. tokens/reset;
2. typography/utilities;
3. application shell/navigation;
4. cards/status;
5. buttons/toolbars;
6. forms;
7. tables;
8. dialogs;
9. page-specific components;
10. responsive breakpoints;
11. dark-mode overrides.

Required fixed values from the spec:

- desktop sidebar variable in the `248px–260px` range;
- spacing scale includes `4, 8, 12, 16, 20, 24, 32px`;
- breakpoints at `1024px`, `720px`, and narrow-mobile refinement near `560px`;
- controls use a shared minimum/control height;
- root/layout containers use `min-width:0`;
- machine values use safe wrapping.

- [ ] **Step 4: Run CSS-structure tests and verify GREEN**

Run the same focused command.

Expected: PASS.

- [ ] **Step 5: Checkpoint**

Commit or archive checkpoint `ui-foundation`.

---

### Task 3: Modernize application shell, navigation, topbar, and login

**Files:**
- Modify: `app/templates/base.html`
- Modify: `app/templates/login.html`
- Modify: `app/static/app.css`
- Modify: `tests/integration/test_web_ui.py`

**Interfaces:**
- Consumes: RBAC template variables and existing navigation URLs.
- Produces: `.app-frame`, `.sidebar`, `.nav-list`, `.main-panel`, `.page-content`, responsive navigation and modern login shell without JavaScript dependencies.

- [ ] **Step 1: Write failing shell/navigation tests**

Add tests that assert:

```python
assert 'class="page-content"' in base_html
assert 'aria-label="Primary navigation"' in base_html
assert 'data-action="logout"' in base_html
assert 'data-global-status' in base_html
assert 'class="login-shell"' in login_html
```

Add role-rendering assertions proving viewer/admin/super-admin still receive exactly the navigation permitted by current RBAC conditions.

Add CSS assertions that mobile navigation is no longer implemented as:

```css
.nav-list{display:grid;grid-template-columns:repeat(3,1fr)}
```

and that mobile navigation labels can wrap without clipping.

- [ ] **Step 2: Run shell tests and verify RED**

Run:

```bash
pytest -q tests/integration/test_web_ui.py -k "navigation or login or shell"
```

Expected: at least the new layout contract FAILS.

- [ ] **Step 3: Implement the modern shell**

Update `base.html` only with structural wrappers/classes; preserve:

- all navigation URLs;
- all RBAC `{% if %}` conditions;
- `data-action="logout"`;
- global service status hooks;
- global action modal;
- page/body data attributes.

Implement responsive shell CSS without viewport-level horizontal overflow.

- [ ] **Step 4: Modernize login presentation**

Retain the current form action, field names, CSRF/session behavior, and error rendering; change presentation classes only.

- [ ] **Step 5: Run shell/navigation tests**

Expected: PASS.

- [ ] **Step 6: Checkpoint**

Commit or archive checkpoint `modern-shell-login`.

---

### Task 4: Modernize shared tables, forms, cards, long-text handling, and action rows

**Files:**
- Modify: `app/static/app.css`
- Modify: `app/templates/mappings.html`
- Modify: `app/templates/users.html`
- Modify: `app/templates/roles.html`
- Modify: `app/templates/audit.html`
- Modify: `tests/integration/test_web_ui.py`

**Interfaces:**
- Consumes: CSS primitives from Task 2.
- Produces: reusable `.data-table`, `.table-wrap`, `.form-row`, `.responsive-form`, `.machine-value`, `.row-actions`, `.toolbar-group` behavior used by all data pages.

- [ ] **Step 1: Write failing structural tests for long-data and responsive rows**

Tests must assert:

- every data table remains inside `.table-wrap`;
- relevant domain/upstream/IP/permission/audit fields receive a long-value/machine-value class or are covered by a table-cell rule;
- row-action hooks from 0.5.9 remain unchanged;
- mappings/users/roles/audit templates retain their existing `data-*` loader/action hooks;
- CSS localizes table horizontal scrolling to `.table-wrap`.

- [ ] **Step 2: Run focused tests and verify RED**

Run:

```bash
pytest -q tests/integration/test_web_ui.py -k "mapping or user or role or audit or table or overflow"
```

Expected: new presentation-contract tests FAIL.

- [ ] **Step 3: Update mappings and users templates**

Add presentation classes/wrappers only. Preserve all CRUD hooks and form field names.

- [ ] **Step 4: Update roles and audit templates**

Improve permission wrapping, card grids, audit long-value presentation, filter/toolbars, and local table overflow while preserving RBAC/action hooks.

- [ ] **Step 5: Implement shared table/form CSS**

Required behavior:

- no uncontrolled flex shrink;
- inputs/selects have `max-width:100%`;
- tables use sensible density-specific `min-width`;
- `.table-wrap` owns overflow;
- `.row-actions` may wrap;
- mobile action controls remain operable;
- long unbroken strings cannot widen the page shell.

- [ ] **Step 6: Run focused tests and verify GREEN**

Expected: PASS.

- [ ] **Step 7: Checkpoint**

Commit or archive checkpoint `responsive-data-pages`.

---

### Task 5: Modernize global modal and page dialog ergonomics without changing behavior

**Files:**
- Modify: `app/templates/base.html`
- Modify: `app/templates/system.html`
- Modify: `app/static/app.css`
- Modify: `tests/integration/test_web_ui.py`

**Interfaces:**
- Consumes: existing global modal and firewall dialog DOM hooks.
- Produces: viewport-constrained modal layout with internal scrolling, stable header/body/footer structure, mobile-stacked actions, preserved resolver behavior.

- [ ] **Step 1: Write failing modal layout tests**

Assert:

```python
assert "max-height:" in css
assert "overflow:auto" in css or "overflow-y:auto" in css
assert "[data-action-modal-confirm]" in app_js
assert "actionModal()?.addEventListener('close'" in app_js
```

Test that:

- `[data-action-modal-*]` attributes are unchanged;
- firewall dialog `data-firewall-dialog`, `data-firewall-form`, and `data-dialog-close` remain;
- no close/cancel button becomes a form submit control;
- mobile modal actions stack below the narrow breakpoint;
- modal long detail/code content uses safe wrapping.

- [ ] **Step 2: Run modal tests and verify RED for new layout contract**

Run:

```bash
pytest -q tests/integration/test_web_ui.py -k "modal or dialog"
```

Expected: existing modal behavior tests pass; new viewport/scroll contract initially FAILS.

- [ ] **Step 3: Implement modal CSS and minimal template wrappers**

Do not change `app.js`.

Global and firewall dialogs must:

- stay within viewport width;
- stay within viewport height;
- scroll internally;
- preserve usable action footer;
- wrap long detail text;
- preserve form semantics.

- [ ] **Step 4: Run modal tests and verify GREEN**

Expected: PASS, including `test_action_modal_native_close_event_does_not_resolve_confirmation_promise`.

- [ ] **Step 5: Checkpoint**

Commit or archive checkpoint `responsive-modals`.

---

### Task 6: Modernize Dashboard and generated configuration panels

**Files:**
- Modify: `app/templates/dashboard.html`
- Modify: `app/templates/system.html`
- Modify: `app/static/app.css`
- Modify: `tests/integration/test_web_ui.py`

**Interfaces:**
- Consumes: metric-card and responsive grid primitives.
- Produces: balanced dashboard grid and generated-config preview panels with local scrolling/wrapping.

- [ ] **Step 1: Write failing dashboard/config presentation tests**

Assert:

- dashboard retains all existing data hooks;
- System generated config retains `data-preview-dns`, `data-preview-nginx`, `data-pending-count`;
- preview `<pre>` elements are contained by responsive preview panel classes;
- CSS prevents preview blocks from widening the page.

- [ ] **Step 2: Run focused tests and verify RED**

Run:

```bash
pytest -q tests/integration/test_web_ui.py -k "dashboard or preview or config"
```

- [ ] **Step 3: Implement dashboard and preview layout changes**

Use 4/3-column desktop grids where appropriate, 2-column tablet, and 1-column mobile. Preserve every data hook.

- [ ] **Step 4: Run focused tests and verify GREEN**

Expected: PASS.

- [ ] **Step 5: Checkpoint**

Commit or archive checkpoint `dashboard-config-ui`.

---

### Task 7: Modernize System, Firewall, SSL, Backup, and recovery layouts

**Files:**
- Modify: `app/templates/system.html`
- Modify: `app/static/app.css`
- Modify: `tests/integration/test_web_ui.py`

**Interfaces:**
- Consumes: Task 2–6 shared UI primitives.
- Produces: responsive operational sections for System status, rollback, firewall, SSL/certificates, backups, and related controls.

- [ ] **Step 1: Write failing System-page responsive contract tests**

Assert preservation of all critical hooks:

```python
required_hooks = [
    'data-system-status',
    'data-action="config-validate"',
    'data-action="config-apply"',
    'data-firewall-section',
    'data-firewall-rules',
    'data-action="firewall-preview"',
    'data-action="firewall-validate"',
    'data-action="firewall-apply"',
    'data-action="firewall-rollback"',
    'data-firewall-dialog',
    'data-ssl-section',
]
```

Also assert:

- firewall policy uses a dedicated responsive form/grid class;
- rollback row uses a dedicated responsive layout class;
- SSL issue form uses a responsive layout class;
- long firewall source/comment and SSL/certificate values receive safe wrapping;
- table wrappers remain local scrollers.

- [ ] **Step 2: Run focused tests and verify RED**

Run:

```bash
pytest -q tests/integration/test_web_ui.py -k "system or firewall or ssl or backup"
```

Expected: new layout assertions FAIL.

- [ ] **Step 3: Refactor System template presentation**

Change classes/wrappers only. Preserve conditional RBAC blocks, form names, action hooks, and endpoint behavior.

- [ ] **Step 4: Implement System-specific CSS**

Required behavior:

- service metrics responsive;
- rollback input/action stack cleanly on small screens;
- firewall policy stops relying on uncontrolled flex widths;
- firewall rule action toolbar wraps;
- SSL provider/token/checkbox controls align and stack predictably;
- backup/certificate/action tables localize overflow;
- warning/findings blocks wrap long text.

- [ ] **Step 5: Run focused tests and verify GREEN**

Expected: PASS.

- [ ] **Step 6: Checkpoint**

Commit or archive checkpoint `system-security-ui`.

---

### Task 8: Add explicit responsive/overflow regression contracts for all pages

**Files:**
- Modify: `tests/integration/test_web_ui.py`
- Modify: `app/static/app.css` only if tests expose missing rules.

**Interfaces:**
- Consumes: completed templates/CSS.
- Produces: a permanent automated guard against the UI breakage class that motivated 0.6.0.

- [ ] **Step 1: Add a cross-page responsive contract test**

The test reads all templates and `app.css` and asserts:

- all primary page content is inside the common content wrapper;
- no obsolete mobile 3-column nav rule remains;
- `.main-panel`, cards, grid children, and form/grid children can shrink (`min-width:0` coverage);
- inputs/selects/textareas do not exceed parent width;
- tables are wrapped;
- modal viewport constraints exist;
- `overflow-wrap:anywhere` is applied to machine/long-value paths.

- [ ] **Step 2: Add regression test for review-focus input classes**

Use representative strings:

- long domain;
- IPv6 `/64`;
- long CIDR/comment;
- long permission name;
- long audit/resource identifier.

This is a structural CSS/template test: each representative value class must map to safe wrap/local-scroll behavior.

- [ ] **Step 3: Run responsive-contract tests**

Run:

```bash
pytest -q tests/integration/test_web_ui.py -k "responsive or overflow or long_text"
```

Expected: PASS.

- [ ] **Step 4: Run the entire UI integration test file**

Run:

```bash
pytest -q tests/integration/test_web_ui.py
```

Expected: PASS.

- [ ] **Step 5: Checkpoint**

Commit or archive checkpoint `responsive-regression-guards`.

---

### Task 9: Bump release metadata to 0.6.0 using TDD

**Files:**
- Modify: `tests/integration/test_packaging.py`
- Modify: `VERSION`

**Interfaces:**
- Consumes: existing packaging/version contract.
- Produces: `VERSION=0.6.0` and packaging tests expecting the same.

- [ ] **Step 1: Change packaging tests to expect `0.6.0`**

Update only the existing hard-coded release-version assertions.

- [ ] **Step 2: Run packaging tests and verify RED**

Run:

```bash
pytest -q tests/integration/test_packaging.py
```

Expected: version assertions FAIL while `VERSION` still reads `0.5.9`.

- [ ] **Step 3: Set `VERSION` to `0.6.0`**

Exact file content:

```text
0.6.0
```

- [ ] **Step 4: Run packaging tests and verify GREEN**

Run:

```bash
pytest -q tests/integration/test_packaging.py
```

Expected: PASS.

- [ ] **Step 5: Checkpoint**

Commit or archive checkpoint `release-0.6.0-metadata`.

---

### Task 10: Full regression, syntax, compatibility, and production-behavior verification

**Files:**
- Test only unless a regression is discovered.

**Interfaces:**
- Consumes: complete 0.6.0 candidate.
- Produces: release-quality evidence that UI changes did not alter behavior.

- [ ] **Step 1: Run the entire test suite**

Run:

```bash
pytest -q
```

Expected: all tests PASS; total should be greater than the 0.5.9 baseline because new UI tests were added.

- [ ] **Step 2: Verify JavaScript syntax**

Run:

```bash
node --check app/static/app.js
```

Expected: exit code `0`.

If Node is not installed, use the established project JavaScript syntax check used by the release environment; do not modify JavaScript to bypass the check.

- [ ] **Step 3: Verify Python syntax**

Run:

```bash
python3 -m py_compile app/web.py privileged/firewall_helper.py privileged/helper_server.py
```

Expected: exit code `0`.

- [ ] **Step 4: Verify shell syntax**

Run:

```bash
bash -n packaging/install.sh
bash -n packaging/uninstall.sh
```

Expected: exit code `0`.

- [ ] **Step 5: Re-run critical 0.5.9 regressions explicitly**

Run:

```bash
pytest -q \
  tests/integration/test_web_ui.py::test_action_modal_native_close_event_does_not_resolve_confirmation_promise \
  tests/unit/test_firewall_helper.py::test_delete_managed_uses_show_added_when_numbered_status_has_no_rules
```

Expected: `2 passed`.

- [ ] **Step 6: Verify that `app.js` behavior was not changed**

Compare its SHA256 with the 0.5.9 baseline unless the plan was explicitly upgraded to allow a JavaScript change.

Expected: identical hash when no JS change was approved.

- [ ] **Step 7: Checkpoint**

Commit or archive checkpoint `0.6.0-release-candidate`.

---

### Task 11: Manual viewport acceptance

**Files:**
- No source changes unless a verified layout defect is found.

**Interfaces:**
- Consumes: release candidate running in a browser.
- Produces: viewport-level acceptance evidence.

- [ ] **Step 1: Validate desktop widths**

Check:

- `1440x900`
- `1280x800`

On Dashboard, Mappings, Users, Roles, Audit, System, Login verify:

- no page-level horizontal scrollbar;
- navigation and topbar align;
- long values stay inside components;
- row actions remain visible;
- modal content fits viewport.

- [ ] **Step 2: Validate tablet widths**

Check:

- `1024x768`
- `768x1024`

Verify grid collapse, toolbar wrapping, local table scrolling, and System-page form stacking.

- [ ] **Step 3: Validate mobile widths**

Check:

- `390x844`
- `360x800`

Verify:

- navigation remains complete for each RBAC role;
- no clipped nav text;
- no viewport-level horizontal scroll;
- controls stay inside cards;
- form fields are full-width where required;
- modal actions stack;
- modal body scrolls internally;
- tables use local scroll only.

- [ ] **Step 4: Exercise representative workflows**

Without changing backend semantics, verify:

- mapping add/edit/delete modal flow;
- user/role action modal flow;
- config validate/apply confirmation flow;
- firewall preview → validate → apply → confirmation flow;
- SSL modal feedback;
- backup action feedback;
- sign out/login.

- [ ] **Step 5: Fix only reproducible UI defects with a regression test first**

Any defect found here requires:

1. failing structural/UI test;
2. minimal template/CSS fix;
3. focused test pass;
4. full UI test pass.

- [ ] **Step 6: Final acceptance checkpoint**

Commit or archive checkpoint `0.6.0-ui-accepted`.

---

### Task 12: Build and verify the cumulative 0.6.0 release ZIP

**Files:**
- Package all application source and tests.
- Create artifact: `dns-manager-ui-modernization-0.6.0.zip`

**Interfaces:**
- Consumes: accepted 0.6.0 tree.
- Produces: cumulative installable release containing every 0.5.9 fix plus the 0.6.0 UI modernization.

- [ ] **Step 1: Build a clean ZIP**

Exclude runtime/cache artifacts:

- `__pycache__`
- `.pytest_cache`
- `*.pyc`
- temporary files

Archive root must be exactly:

```text
dns-manager/
```

- [ ] **Step 2: Verify required archive contents**

Assert the ZIP contains at minimum:

```text
dns-manager/VERSION
dns-manager/app/static/app.css
dns-manager/app/static/app.js
dns-manager/app/templates/base.html
dns-manager/app/templates/dashboard.html
dns-manager/app/templates/mappings.html
dns-manager/app/templates/users.html
dns-manager/app/templates/roles.html
dns-manager/app/templates/audit.html
dns-manager/app/templates/system.html
dns-manager/app/templates/login.html
dns-manager/privileged/firewall_helper.py
dns-manager/tests/integration/test_web_ui.py
dns-manager/tests/unit/test_firewall_helper.py
dns-manager/packaging/install.sh
dns-manager/docs/superpowers/specs/2026-10-18-dns-manager-ui-modernization-0.6.0-design.md
dns-manager/docs/superpowers/plans/2026-10-18-dns-manager-ui-modernization-0.6.0.md
```

- [ ] **Step 3: Verify release identity and preserved hotfixes from inside the archive**

Assert:

- `VERSION` is `0.6.0`;
- global modal stale-close resolver bug remains absent;
- inactive-UFW `ufw show added` fallback remains present;
- installer still restarts `dns-manager-helper.service`;
- new responsive CSS contracts are present.

- [ ] **Step 4: Generate SHA256**

Run:

```bash
sha256sum dns-manager-ui-modernization-0.6.0.zip
```

Record the digest with the release artifact.

- [ ] **Step 5: Install through the existing production installer**

Use the existing production-safe update flow with:

```bash
DNS_MANAGER_INTERNAL_PROXY_IP=157.15.20.132 \
bash /tmp/dns-manager-0.6.0/dns-manager/packaging/install.sh
```

- [ ] **Step 6: Verify production state**

Run:

```bash
cat /opt/dns-manager/dns-manager/VERSION

systemctl is-active \
  dnsmasq \
  dns-manager \
  dns-manager-helper.socket \
  dns-manager-helper.service \
  dns-manager-ssl-renew.timer \
  nginx

curl -sS http://127.0.0.1:8500/health
ufw status verbose
```

Expected:

- version `0.6.0`;
- all listed services active;
- health `{"status":"ok","database":"ok"}`;
- UFW remains active with the user's intended managed rules and no stale managed rule regression.

- [ ] **Step 7: Release completion**

Only after Tasks 10–12 all pass, mark `0.6.0` ready.
