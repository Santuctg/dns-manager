# DNS Manager v0.7.3 — release notes

**Release:** v0.7.3 · **Date:** 2026-10-27 · **Upgrade from 0.7.0–0.7.2:** no database migration

Fixes two full-screen layout defects that made the console look cut off.

## Fixes

- **Side panels fill the screen again.** Browsers cap a modal `<dialog>` at
  `calc(100% - 34px)`, so every drawer (mappings, firewall, SSL, users, roles,
  backups restore) stopped 34px above the bottom edge and the page showed
  through underneath. The panel now uses `height: 100%` with
  `max-height: 100%`, `margin: 0` and `overflow: hidden`; the body scrolls, the
  footer stays on screen.
- **The phone "More pages" sheet scrolls instead of clipping.** On a short
  landscape screen the sheet was taller than the browser cap and its last rows
  (theme, sign out) were cut off with no way to reach them. The sheet is now
  bottom-anchored, capped at the viewport and its inner list scrolls.

Everything from v0.7.2 is included: drawer forms inside `<form>` keep their
footer visible, dashboard cards render independently, backend probes run in
parallel, metrics failures back off, and duplicate GETs are shared.

## Upgrade

1. Download `dns-manager-0.7.3-documented.zip` or clone tag `v0.7.3`.
2. Run `packaging/install.sh` with the same `DNS_MANAGER_INTERNAL_PROXY_IP` the
   installation already uses.
3. Hard-reload the console (`Ctrl+Shift+R`).
4. Confirm `cat /opt/dns-manager/dns-manager/VERSION` prints `0.7.3`.

No Alembic revision is added; the existing database is used as-is.

## Verification performed

- `pytest -m browser -q` → 14 passed, including new assertions that every
  drawer spans the full viewport height and that the mobile sheet reaches the
  bottom and scrolls.
- `pytest -q -m "not browser"` → 467 passed; the helper socket tests fail only
  on macOS because of the `AF_UNIX` path-length limit.
