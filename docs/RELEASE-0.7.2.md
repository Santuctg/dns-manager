# DNS Manager v0.7.2 — release notes

**Release:** v0.7.2 · **Date:** 2026-10-27 · **Upgrade from 0.7.0/0.7.1:** no database migration

This patch finishes the console fixes reported against 0.7.1: drawer forms on
short screens, dashboard paint time and metrics polling under failure.

## Fixes

- **Drawer forms no longer push their action button off screen.** Panels whose
  head, body and footer live inside a `<form>` (mappings, firewall rules, SSL,
  users and roles) now inherit the panel's column layout. The body scrolls and
  the Save/Cancel footer stays inside the viewport on 1366×768 laptops, small
  windows and landscape phones.
- **Dashboard cards paint independently.** Every summary card, the attention
  list and the audit list update as soon as their own request completes. A slow
  upstream probe no longer leaves the whole page showing "Loading…" for three
  seconds.
- **Backend probes run concurrently.** `/api/v1/system/backends` checks all
  mappings in parallel instead of waiting for each timeout in sequence. The
  response order is unchanged.
- **Metrics failures back off.** The dashboard poller now sees the 503 and
  retries after 2 s, 4 s, 8 s … up to 30 s instead of every second. The
  unavailable state is still rendered immediately.
- **Duplicate shell/page requests are shared.** In-flight `GET` requests for the
  same URL are coalesced, so the shell and a page no longer fetch status and
  pending changes twice.
- **Loading placeholders are skeletons** instead of layout-shifting text, with
  a reduced-motion fallback.
- **Section labels have stronger contrast** in both themes (eyebrow and sidebar
  group labels).

## Upgrade

1. Download `dns-manager-0.7.2-documented.zip` or clone tag `v0.7.2`.
2. Run `packaging/install.sh` with the same `DNS_MANAGER_INTERNAL_PROXY_IP` the
   installation already uses.
3. Hard-reload the console (`Ctrl+Shift+R`) so the browser drops the old CSS and
   JavaScript.
4. Confirm `cat /opt/dns-manager/dns-manager/VERSION` prints `0.7.2`.

No Alembic revision is added; the existing database is used as-is.

## Verification performed

- `pytest -m browser -q` → 13 passed (adds drawer-height, dashboard progressive
  render and metrics back-off checks).
- `pytest -q -m "not browser"` → 467 passed; the helper socket tests fail only
  on macOS because of the `AF_UNIX` path-length limit.
