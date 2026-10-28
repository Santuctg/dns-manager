# DNS Manager v0.7.11 — release notes

Polishes the dashboard chart layout after operator feedback on v0.7.10: the two
charts now read as clearly separate panels, their bottom labels are centered,
and the chart text is no longer distorted.

## What changed

### 1. The two charts are visually separated

Previously the CPU & Memory and Network Traffic charts sat side by side with no
divider, so they read as one big graph. Each chart now lives in its own bordered,
backgrounded card, making it obvious which graph is which.

### 2. Bottom legend text is centered

The legend line under each chart (e.g. "CPU 14.3% · RAM 19.7%", "Input 1.13
KB/s · Output 825.76 B/s") is now centered under its chart instead of left
aligned.

### 3. Chart text is no longer stretched/distorted

The chart SVGs used `preserveAspectRatio="none"`, which horizontally stretched
every axis label. The renderer now measures the real rendered size and matches
the viewBox 1:1, re-syncing on resize (window resize, sidebar toggle,
orientation). Additionally, the left y-axis gutter now grows automatically to
fit the longest label (e.g. "8.52 MB/s"), so axis labels are never clipped.

## Verification

- Browser suite: 22 passed, including a new regression test
  (`test_dashboard_charts_are_separated_centered_and_undistorted`) asserting
  per-chart card border/background, centered legend, and a viewBox that matches
  the rendered size with no `preserveAspectRatio="none"`.
- Linux container suite: 479 passed, 1 skipped.
- No database migration. Firewall, SSL, mapping, and backup behavior are
  unchanged.

Upgrade with the existing `DNS_MANAGER_INTERNAL_PROXY_IP` and hard-reload the
browser (Ctrl/Cmd+Shift+R).
