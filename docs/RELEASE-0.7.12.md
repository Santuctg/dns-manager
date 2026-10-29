# DNS Manager v0.7.12 — release notes

Adds server-side metrics history and a chart hover tooltip. The dashboard
charts are now seeded from a ~1 hour history recorded on the server, so any
device (or a fresh browser) opens the console with the graphs already filled
instead of starting empty.

## What changed

### 1. The server records ~1 hour of metrics history

A best-effort background collector samples CPU, memory, and network counters
every 5 seconds and appends them to a JSONL file
(`/var/lib/dns-manager/metrics-history.jsonl`, overridable via
`DNS_MANAGER_METRICS_HISTORY_PATH`). The file is pruned to a 1-hour window
atomically; readers additionally drop stale samples and de-duplicate 5-second
buckets, so the two gunicorn workers writing concurrently collapse into one
clean timeline. History is best-effort: if the path is unwritable the recorder
stays inert and nothing else is affected.

### 2. New read-only endpoint: `GET /api/v1/system/metrics/history`

Requires the `system.view` permission, returns `Cache-Control: no-store`, and
answers with computed B/s input/output rates (a counter reset yields `null`
rather than a negative rate). On an unexpected error it answers 503 without
leaking internals, mirroring the existing `/api/v1/system/metrics` route. No
existing route or field changed; this is an addition.

### 3. Dashboard charts are seeded from that history

On load the dashboard fetches the recorded history and replays it into both
charts (with real timestamps), so the graphs are populated on first paint.
The server timeline is authoritative: it replaces whatever localStorage had.
If the history fetch fails, the charts fall back to the previous localStorage
restore, and if that is empty they start from live sampling as before — a
failed history fetch never breaks the dashboard.

### 4. Chart hover tooltip

Hovering a chart now shows a tooltip with the timestamp and the per-series
values (e.g. "3:42:10 PM / CPU 30.0% / RAM 60.0%") of the nearest recorded
point. Moving the pointer outside the chart hides it; charts with no recorded
points show nothing.

## Verification

- Browser suite: 25 passed, including three new tests:
  `test_dashboard_seeds_charts_from_server_history` (charts render the mocked
  server history immediately), `test_dashboard_history_failure_still_renders_charts`
  (aborted history fetch falls back without page errors), and
  `test_chart_tooltip_shows_point_values` (tooltip shows/hides with hover).
- Linux container suite: 494 passed, 1 skipped (unit tests for the
  JSONL recorder/reader and integration tests for the new endpoint and the
  app-lifespan recorder lifecycle included).
- No database migration. Firewall, SSL, mapping, and backup behavior are
  unchanged.

Note: history starts recording from the moment this version is installed;
older samples do not exist retroactively.

Upgrade with the existing `DNS_MANAGER_INTERNAL_PROXY_IP` and hard-reload the
browser (Ctrl/Cmd+Shift+R). No `daemon-reload` is needed.
