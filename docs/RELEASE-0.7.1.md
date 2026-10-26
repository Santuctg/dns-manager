# DNS Manager v0.7.1 — release notes

**Release:** v0.7.1 · **Date:** 2026-10-27

Patch release for the 0.7.0 console. No API, schema or configuration changes; existing
installations can upgrade in place.

## Fixes

- **Closed drawers no longer cover the console.** Author `display` rules on
  `.side-panel` and `.action-modal` overrode the browser's rule for
  `dialog:not([open])`, so every page rendered a stray right-hand drawer
  (Add user, Add rule, Manual DNS challenge, Restore backup?, Mapping detail, …)
  or an empty "Information" dialog at the bottom of the document. A
  `dialog:not([open]) { display: none }` reset restores correct behaviour.
  This is the main cause of the reported broken layout: the stray drawer hid
  the right-hand half of tables and action buttons.
- **SSL actions stay on screen at phone widths.** The desktop-only
  `.ssl-table td:last-child { width: 1% }` rule collapsed the action cell to
  3 px at 390 px, pushing the buttons off the left edge. It is now scoped to
  `min-width: 768px`.
- **Audit values wrap in the mobile card layout.** The `nowrap` rules are now
  desktop-only.

## Documentation

- Installation examples now name the listen address `HOST_LAN_IP` and explain
  that it must be the host's own LAN address, that an upgrade must reuse the
  existing value, and that the installer aborts before restarting services
  when dnsmasq validation fails.
- Added the direct `git clone --branch v0.7.1` installation option next to the
  release ZIP.
- `docs/API_AND_TESTING.md` describes the browser smoke test additions.

## Testing

`pytest -m browser` now fails when a closed dialog is still rendered, as well
as when a visible element escapes the viewport outside a scroll container.
The suite covers the sign-in page and all nine console pages at 1440 px and
390 px, in both themes and both languages.

## Upgrade notes

1. Download the 0.7.1 ZIP (or clone the `v0.7.1` tag) and run the normal installer.
2. No database migration is required.
3. The installer restarts the service and waits for `/health`.
4. Static assets are served with `cache-control: no-cache`, so a normal reload
   picks up the CSS fix. Use a hard reload (`Ctrl+Shift+R`) if the old page is
   still open.
