# DNS Manager v0.7.9 — release notes

Upgrades the dashboard's system monitoring from four tiny sparklines to two
larger, richer charts, matching the operator's reference layout.

## What changed

The dashboard "System monitoring" card previously showed four small sparklines
(CPU, Memory, and Network RX/TX) with a single line each and no axes. It now
shows two combined charts:

- **CPU & Memory** — CPU and memory usage plotted together as two filled lines
  on a shared percentage axis (0–100%).
- **Network Traffic** — input and output throughput plotted together, with the
  rate auto-formatted into human units (B / kB / MB / GB per second).

Each chart has a labelled y-axis with gridlines, a time-labelled x-axis, a
filled area under each line, and a bottom legend showing the live current value
per series (e.g. "CPU 14.3%", "Input 250.0 kB/s").

## Details

- Presentation only: no new backend endpoint, database table, or migration.
  The existing `/api/v1/system/metrics` data flow is reused unchanged.
- Charts render as hand-rolled SVG (no charting library, no CDN, no build
  step), consistent with the rest of the offline console.
- Roughly the last hour of history is kept, downsampled to about one point per
  5 seconds (~720 points) so rendering stays cheap while the time axis stays
  meaningful.
- Dark and light themes and Bengali/English labels both work; technical terms
  stay in English.
- The old sparkline code and styles were removed as dead code.

## Also in this release

- Updates the release-version test metadata to 0.7.9 (these checks hardcode the
  expected version and gate each release).

## Verification

- Linux container suite: 479 passed, 1 skipped. Browser suite: 19 passed,
  including a new regression test that asserts both charts render gridlines,
  axis labels, both data lines, and a populated live legend.
- No database migration. Firewall, SSL, mapping, and backup behavior are
  unchanged.

Upgrade with the existing `DNS_MANAGER_INTERNAL_PROXY_IP` and hard-reload the
browser.
