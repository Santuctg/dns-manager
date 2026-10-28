# DNS Manager v0.7.10 — release notes

Polishes the v0.7.9 dashboard monitoring charts: network values are now
properly rounded, and chart history survives a page reload or browser restart.

## What changed

### 1. Network values rounded to two decimals

The v0.7.9 network chart could print raw floating-point values in its legend
and y-axis (e.g. `100.212616512666 KB/s` or `874.686716791978 B/s`). Byte
formatting now always rounds to two decimals, so you see clean values like:

- `100.21 KB/s`
- `2.35 MB/s`
- `874.69 B/s`

This applies to the legend (Input / Output), the y-axis labels, and anywhere
else the shared byte formatter is used.

### 2. Chart history is kept across reloads

Previously the charts started empty on every page load, so after a reload you
had to wait again for the lines to build up. Chart history is now mirrored to
the browser's local storage (per chart, namespaced `dns-manager:chart:*`,
timestamps included) and restored on load, pruned to the same ~1 hour window
the charts display. After a reload — or even reopening the browser — the
recorded history is there immediately.

Notes:

- Only numeric metric samples are stored, never credentials or any prompt
  input (a security test guards this).
- If local storage is unavailable (private mode, quota), the live charts keep
  working exactly as before; they just won't survive a reload.
- This is browser-side only: no new backend endpoint, database table, or
  migration.

## Verification

- Linux container suite: 479 passed, 1 skipped. Browser suite: 21 passed,
  including two new regression tests:
  - `test_dashboard_network_values_are_rounded_to_two_decimals` — legend and
    axis values match `<number with exactly 2 decimals> <unit>/s`;
  - `test_dashboard_chart_history_survives_reload` — recorded chart points are
    restored immediately after a page reload.
- The SSL-secrets storage guard test was updated for the new (non-sensitive)
  chart-history storage use; it still forbids any storage of prompt values.
- No database migration. Firewall, SSL, mapping, and backup behavior are
  unchanged.

Upgrade with the existing `DNS_MANAGER_INTERNAL_PROXY_IP` and hard-reload the
browser (Ctrl/Cmd+Shift+R).
