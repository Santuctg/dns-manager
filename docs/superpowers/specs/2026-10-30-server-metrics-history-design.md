# Server-side metrics history + chart hover tooltip — design (2026-10-30)

## Intent

Chart history currently lives only in the operator's browser (localStorage),
so a different device or a cleared browser starts empty. The operator wants
the recording on the server, plus a hover tooltip on the charts showing the
values of the point under the mouse.

## Goals

- Server records CPU / memory / network samples every ~5 s, keeps ~1 hour,
  survives reboot, and serves them to any authenticated console session.
- Charts load server history on page load, then keep streaming live.
- Hovering a chart shows a tooltip: sample time + each series' value.
- Additive only: no DB migration, no changes to firewall/SSL/mapping behavior.

## Non-goals / anti-goals

- No longer retention than ~1 hour (matches the visible window; longer
  retention would need a real DB table → separate request).
- No new dependencies, no CDN, no build step (project constraint).
- Never break live charts if history file/endpoint fails.

## Constraints & facts found

- `Settings` (app/config.py) uses env prefix `DNS_MANAGER_`; data dir is
  `/var/lib/dns-manager/` (db + backups already live there).
- gunicorn runs **2 workers** (packaging/systemd/dns-manager.service), so two
  recorder threads may write concurrently → reader must de-duplicate by
  5-second time bucket.
- `collect_metrics()` (app/services/system_metrics.py) already returns
  cpu %, memory %, cumulative rx/tx byte counters, and `sampled_at_ms`.
- `createChart().push(key, value, timestamp)` already accepts explicit
  timestamps → history points can be replayed exactly.

## Approaches considered

1. **File-based JSONL recorder (chosen)** — background thread appends one JSON
   line per sample to `/var/lib/dns-manager/metrics-history.jsonl`, prunes to
   the 1-hour window; new read-only endpoint serves it. ~90 KB file, no
   migration, works with 2 workers via bucket de-dup on read.
2. SQLite metrics table — more powerful queries but needs an alembic
   migration; operator earlier ruled migrations out. Revisit if retention
   > 1 h is wanted.
3. Keep browser-only recording — rejected: per-device, lost on clear.

## Design

### Backend

- `Settings.metrics_history_path: str = "/var/lib/dns-manager/metrics-history.jsonl"`
  (env `DNS_MANAGER_METRICS_HISTORY_PATH`; tests point it at tmp dirs).
- New `app/services/metrics_history.py`:
  - `start_recorder()` / `stop_recorder()` — daemon thread, loop:
    `collect_metrics()` → append JSON line
    `{"t": ms, "cpu": %, "mem": %, "rx": bytes, "tx": bytes}` → every ~60 s
    rewrite file keeping only samples with `t >= now - 1h`. Thread swallows
    and logs all errors; never raises into the app.
  - `read_history(now_ms=None)` — parse file, drop malformed lines and
    samples older than 1 h, de-duplicate 5 s buckets (keep first per bucket),
    then compute `input`/`output` rates (B/s) from consecutive cumulative
    counters (negative deltas → counter reset → rate omitted for that gap).
  - Returns `[{"t": ms, "cpu": float|null, "mem": float|null,
    "input": float|null, "output": float|null}, ...]` sorted by t.
- `app/main.py`: FastAPI lifespan starts/stops the recorder (idempotent; a
  recorder that cannot write, e.g. read-only fs, is simply inert).
- New endpoint `GET /api/v1/system/metrics/history` in `app/api/system.py`,
  permission `system.view` (same as live metrics), `Cache-Control: no-store`.

### Frontend

- `dashboard.js` init: fetch `/api/v1/system/metrics/history`; on success
  replay points into the charts with their real timestamps (and update
  legends). On failure fall back to the existing localStorage restore, so an
  older server or a file hiccup never blanks the charts.
- `createChart` gains tooltip support: pointermove over the plot finds the
  nearest recorded sample and shows an absolutely-positioned tooltip div
  inside the (position:relative) `.chart-card` — sample time (HH:MM:SS) plus
  every series value at that point, formatted with the same `formatValue`.
  Pointer leaves → tooltip hides. Touch devices: tapping pins/unpins briefly.
- CSS: `.chart-tooltip` styled from theme tokens (dark + light).
- i18n: none needed beyond reusing existing series labels (technical terms
  stay English; time uses `toLocaleTimeString`).

### Tests

- Unit/integration: recorder writes → `read_history()` returns computed
  rates; malformed/old lines skipped; 5 s bucket de-dup; endpoint requires
  auth and returns the shape above.
- Browser: dashboard renders points from a mocked `/history` response on
  first load (no waiting); hovering a chart shows a tooltip with the point's
  time and values.

### Release

- Patch release (v0.7.12): tests green in both suites, ZIP asset, sha256
  re-download verify, Bengali upgrade commands. No systemd unit change
  needed (no new ports/permissions); `/var/lib/dns-manager/` already owned
  by the service user.
