# Server-side Metrics History + Chart Tooltip Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The server records ~1 hour of CPU/memory/network samples in a JSONL file, serves them to any authenticated console session, and the dashboard charts show a hover tooltip with the values of the point under the mouse.

**Architecture:** A daemon thread inside each gunicorn worker appends one JSON line per 5 s sample to `/var/lib/dns-manager/metrics-history.jsonl` (pruned to 1 h; ~90 KB). A new read-only endpoint `GET /api/v1/system/metrics/history` returns time-bucketed samples with computed B/s rates. The dashboard replays that history into the existing `createChart` charts on load (fall back to the v0.7.10 localStorage restore when the endpoint fails), and `createChart` gains an in-card tooltip on pointermove.

**Tech Stack:** FastAPI + SQLAlchemy (existing), plain JS + hand-rolled SVG (no framework/CDN/build step), pytest + Playwright browser tests.

**Spec:** `docs/superpowers/specs/2026-10-30-server-metrics-history-design.md`

## Global Constraints

- No DB migration, no new Python/JS dependencies, no CDN, no build step.
- Keep existing API routes/fields; additions only. Firewall/SSL/mapping behavior untouched.
- Data file path comes from `Settings` (env prefix `DNS_MANAGER_`); default `/var/lib/dns-manager/metrics-history.jsonl`.
- Window = 1 hour (`WINDOW_MS = 3_600_000`), sample bucket = 5 s (`BUCKET_MS = 5_000`).
- Recorder must never raise into the app: all errors swallowed+logged; unwritable path → inert.
- 2 gunicorn workers may write concurrently → `read_history` de-duplicates identical/close samples by 5 s bucket (keep first per bucket after sort by t).
- Frontend fallback chain: server history → localStorage → empty. Charts must never go blank because history failed.
- Technical terms stay English; Bengali + English i18n for any new visible strings (tooltip reuses existing series labels, time via `toLocaleTimeString` — no new i18n keys expected).
- Release = v0.7.12 patch with both suites green, ZIP asset, re-downloaded sha256 verify, Bengali upgrade commands.

## Review Focus

- **Concurrent writers (2 workers) double-append or tear the file while pruning** → `read_history` must return one sample per 5 s bucket even with duplicate t values; prune must be atomic replace (temp file + `os.replace`) so a reader never sees a half-written file. Pinned in Task 1 tests `test_read_history_deduplicates_identical_samples`, `test_prune_keeps_window_and_replaces_atomically`.
- **Counter reset (interface re-created / reboot → negative delta)** → rates for that gap must be `null`, not negative; chart must skip the point. Pinned in Task 1 `test_negative_delta_yields_null_rate`.
- **Malformed or truncated JSONL lines (partial write crash)** → skipped silently; remaining lines still served. Pinned in Task 1 `test_malformed_lines_are_skipped`.
- **Recorder cannot write (read-only fs, missing parent dir)** → `start_recorder()` returns without raising; `/history` still answers 200 with whatever exists (empty list if file missing). Pinned in Task 1 `test_record_sample_creates_parent_dirs`, Task 2 `test_history_endpoint_empty_when_file_missing`.
- **Stale samples still in an unpruned file** → `read_history(now_ms=...)` drops samples older than the window even if prune hasn't run. Pinned in Task 1 `test_read_history_drops_stale_samples`.
- **Replay + live merge** → after replaying server history, live network rate calculation and the 5 s downsample must not double-record or jump; last recorded timestamp comes from history. Pinned in Task 3 browser test asserting exactly 2 polylines with >= N points and no time-axis break; simplest observable contract: lines render immediately (<3 s) from mocked `/history` alone (live mock delivers no deltas).
- **Tooltip over sparse charts** → with <2 points or pointer outside plot area, tooltip hides and nothing throws. Pinned in Task 4 browser test `test_chart_tooltip_shows_point_values`.

---

### Task 1: `metrics_history` service (recorder + reader)

**Files:**
- Create: `app/services/metrics_history.py`
- Test: `tests/unit/test_metrics_history.py`

**Interfaces:**
- Consumes: `app.services.system_metrics.collect_metrics()` (returns dict with `cpu.usage_percent`, `memory.usage_percent`, `network.interfaces[].rx_bytes/tx_bytes`, `sampled_at_ms`); `app.config.get_settings().metrics_history_path` (added this task).
- Produces (Task 2 uses exactly these):
  - `record_sample(metrics: dict, *, path: Path, now_ms: int | None = None) -> None` — appends one JSON line `{"t": int_ms, "cpu": float|None, "mem": float|None, "rx": int, "tx": int}` (rx/tx = sums over interfaces) to `path` (creating parents), then prunes to the 1 h window at most once per 60 s.
  - `read_history(*, path: Path | None = None, now_ms: int | None = None) -> list[dict]` — returns `[{"t": int_ms, "cpu": float|None, "mem": float|None, "input": float|None, "output": float|None}, ...]` ascending by t; rates in B/s from consecutive rx/tx (both members finite; negative delta → that field null).
  - `start_recorder() -> None` / `stop_recorder() -> None` — idempotent daemon-thread lifecycle around a loop that calls `collect_metrics()` then `record_sample(...)` every ~5 s; every exception caught, logged via `logging.getLogger(__name__).warning`, loop continues.
- Also in this task: add `metrics_history_path: str = "/var/lib/dns-manager/metrics-history.jsonl"` to `Settings` in `app/config.py` (env `DNS_MANAGER_METRICS_HISTORY_PATH`).

- [ ] **Step 1: Write failing unit tests** in `tests/unit/test_metrics_history.py` covering: `test_record_sample_appends_json_line` (tmp_path; dict with rx=1000,tx=2000 → one parseable line with exact keys/values), `test_record_sample_creates_parent_dirs`, `test_read_history_computes_rates` (two samples 5 s apart, rx +5000 → input 1000.0), `test_read_history_deduplicates_identical_samples`, `test_read_history_drops_stale_samples` (injected `now_ms`), `test_malformed_lines_are_skipped`, `test_negative_delta_yields_null_rate`, `test_prune_keeps_window_and_replaces_atomically` (old sample gone after record; no `.*\.tmp` leftovers), `test_read_history_missing_file_returns_empty`, `test_start_stop_recorder_is_idempotent` (monkeypatched `collect_metrics` + tmp path; start twice, stop twice, file gains ≥1 line within 3 s).
- [ ] **Step 2: Run and watch them fail** — `docker run --rm -v "$PWD:/work:ro" -w /work python:3.12-slim sh -c 'ln -s /usr/local/bin/python3 /usr/bin/python3 && pip install -q -r requirements.txt && PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider tests/unit/test_metrics_history.py'` → import errors/FAILs.
- [ ] **Step 3: Implement** `app/services/metrics_history.py` + the `Settings` field per the Interfaces block (atomic prune: write `path.with_suffix('.tmp')` then `os.replace`).
- [ ] **Step 4: Run tests to green** (same command) and re-run the whole non-browser suite in Docker to catch regressions.
- [ ] **Step 5: Commit** — `git add app/services/metrics_history.py app/config.py tests/unit/test_metrics_history.py docs/superpowers/specs/2026-10-30-server-metrics-history-design.md docs/superpowers/plans/2026-10-30-server-metrics-history.md && git commit -m "Add file-based metrics history recorder and reader"`.

### Task 2: `/api/v1/system/metrics/history` endpoint + lifespan wiring

**Files:**
- Modify: `app/api/system.py` (add route), `app/main.py` (lifespan)
- Test: `tests/integration/test_system_metrics_api.py` (extend)

**Interfaces:**
- Consumes: Task 1 `read_history()`, `start_recorder()`, `stop_recorder()`.
- Produces: `GET /api/v1/system/metrics/history` → JSON list of the exact `read_history` dicts, permission `system.view`, `Cache-Control: no-store`, never 500 (collector-style: on unexpected exception → 503 without leaking details, mirroring the existing `/metrics` route). Task 3 consumes the URL and the list shape.

- [ ] **Step 1: Write failing integration tests** (extend `tests/integration/test_system_metrics_api.py`, same auth-override style as the existing metrics tests): unauthenticated → 401/redirect; monkeypatched `system.read_history` returning fixed rows → 200 with that exact body and `cache-control: no-store`; monkeypatched `read_history` raising → 503 and no exception text in body; real missing file (monkeypatched settings path to tmp) → 200 `[]`. Also a lifespan test: `with TestClient(app)` with monkeypatched `collect_metrics`+settings path → history file appears (use a generous 5 s wait).
- [ ] **Step 2: Run and watch them fail.**
- [ ] **Step 3: Implement** the route (import `read_history` from `app.services.metrics_history` into `app.api.system`) and add `lifespan` in `app/main.py` (`@asynccontextmanager`; `start_recorder()` before `yield`, `stop_recorder()` after; pass `lifespan=lifespan` to `FastAPI(...)`).
- [ ] **Step 4: Run integration tests to green**, then the full Docker non-browser suite (existing `TestClient(app)` calls do not run lifespan → no recorder side effects in old tests; confirm suite still green).
- [ ] **Step 5: Commit** — `git add app/api/system.py app/main.py tests/integration/test_system_metrics_api.py && git commit -m "Serve metrics history endpoint and start recorder with app lifespan"`.

### Task 3: Dashboard loads server history into charts

**Files:**
- Modify: `app/static/js/core.js` (`createChart` → add `replay(rows)`), `app/static/js/pages/dashboard.js`
- Test: `tests/browser/test_console_browser.py` (extend)

**Interfaces:**
- Consumes: Task 2 endpoint shape; existing `createChart(...).push(key, value, timestamp)`, `reset()`.
- Produces: `createChart(...).replay(points)` where `points = [{ t: numberMs, values: { [seriesKey]: number|null } }]` — merges by ascending t (sort + drop points older than window/capacity), sets `lastRecord`/`latest`/legends from the newest values, re-renders once, persists to localStorage once. Task 4 reuses nothing new here.

- [ ] **Step 1: Write failing browser test** `test_dashboard_seeds_charts_from_server_history` (in `tests/browser/test_console_browser.py`): mock `**/api/v1/system/metrics/history` to return 3 samples spaced 5 s (cpu 10/20/30, mem 40/50/60, input 1000/2000/3000 with matching t's); live metrics route returns a single static sample with **no counter delta** (so live pushes add no points); goto dashboard; assert within 3 s (well under the 5 s downsample) that both charts already have ≥1 `polyline.chart-line` whose point count equals the mocked sample count, and legends show the last server values (e.g. `CPU 30.0%`, `Input 3.00 KB/s` — use the 2-decimal fmt). Also assert a second test case in the same function or a sibling: `/history` route aborted (request failed) → dashboard still renders (localStorage path) without page errors.
- [ ] **Step 2: Run and watch it fail.**
- [ ] **Step 3: Implement** `replay()` in `createChart` (per Produces; reuse internal history/stamps arrays, prune, single `render()` + `saveHistory()`), and in `dashboard.js` `init()`: `try { const rows = await api('/api/v1/system/metrics/history'); charts.cpuMemory.reset(); charts.network.reset(); replay both with cpu/mem/input/output mapped per row; } catch { /* keep localStorage restore */ }` — do this **before** starting `poll(refreshMetrics, 1000)`.
- [ ] **Step 4: Run the browser test to green**, then the full browser suite.
- [ ] **Step 5: Commit** — `git add app/static/js/core.js app/static/js/pages/dashboard.js tests/browser/test_console_browser.py && git commit -m "Seed dashboard charts from server history on load"`.

### Task 4: Chart hover tooltip

**Files:**
- Modify: `app/static/js/core.js` (`createChart` tooltip), `app/templates/dashboard.html` (tooltip div per chart card), `app/static/css/components.css` (`.chart-tooltip` for dark+light)
- Test: `tests/browser/test_console_browser.py` (extend)

**Interfaces:**
- Consumes: Task 3 `replay()` (charts may hold history immediately); internal `stamps`/`history`/`series`/`formatValue` in `createChart`.
- Produces: markup contract `<div class="chart-tooltip" data-chart-tooltip hidden></div>` inside each `.chart-card` (card is `position: relative`); tooltip text = `toLocaleTimeString()` of the point + one line per series `"{label} {formatValue(value)}"`.

- [ ] **Step 1: Write failing browser test** `test_chart_tooltip_shows_point_values`: mock `/history` with 3 well-spaced samples (large value differences, e.g. cpu 10/50/90); load dashboard; `page.mouse.move` to the center of the `[data-chart="cpu-memory"]` bounding box; assert a `.chart-tooltip:not([hidden])` exists inside that card and its text contains a `CPU` label, a `%` value from the mocked set, and a time-looking token (`\d{1,2}:\d{2}`); move mouse far away (e.g. `(5,5)`) → tooltip hidden again.
- [ ] **Step 2: Run and watch it fail.**
- [ ] **Step 3: Implement**: add the tooltip div to both chart cards in `dashboard.html`; in `createChart`, when `svg.closest('.chart-card')?.querySelector('[data-chart-tooltip]')` exists, attach `pointermove`/`pointerleave` listeners: nearest index = clamp(round((clientX - rect.left - lastPadLeft) / lastPlotW * (capacity - 1)), 0, points-1) using pad/plot values stashed in closure vars during `render()`; build text from `stamps`+`history`; position tooltip (`left` clamped inside card, `top` near plot top), unhide on move, hide on leave; guard: fewer than 1 recorded point → always hidden. CSS `.chart-tooltip`: absolute, `pointer-events: none`, theme tokens (`--surface-3`, `--border`, `--text-1`, `--font-mono`, `--text-xs`), small radius+padding.
- [ ] **Step 4: Run browser tests to green** (new test + full suite); check light theme via the existing theme matrix smoke test still passes.
- [ ] **Step 5: Commit** — `git add app/static/js/core.js app/templates/dashboard.html app/static/css/components.css tests/browser/test_console_browser.py && git commit -m "Add hover tooltip to dashboard charts"`.

### Task 5: Release v0.7.12

**Files:**
- Modify: `VERSION`, `tests/integration/test_packaging.py` (5 × `0.7.11`→`0.7.12`), `tests/unit/test_monitoring_poll_1s.py` (1 spot), `tests/browser/test_console_browser.py` docstring
- Create: `docs/RELEASE-0.7.12.md`

**Interfaces:**
- Consumes: all previous tasks.
- Produces: tagged, uploaded, sha256-verified release; Bengali upgrade commands for the operator.

- [ ] **Step 1: Bump version metadata** to `0.7.12` everywhere listed; grep for leftover `0.7.11` in tests.
- [ ] **Step 2: Write `docs/RELEASE-0.7.12.md`** (server-side history, hover tooltip, fallback behavior, no migration, verification counts).
- [ ] **Step 3: Run both full suites** (Docker non-browser + Playwright browser) → green; capture a chart preview screenshot with the existing temp script extended to hover the mouse over a chart so the tooltip is visible; show it to the operator.
- [ ] **Step 4: Ship** — commit, `git tag -a v0.7.12`, push main+tag, `git archive` ZIP, create GitHub release with notes body, upload asset, re-download and compare sha256.
- [ ] **Step 5: Hand off** — Bengali upgrade commands (`fresh/` extraction pattern, `DNS_MANAGER_INTERNAL_PROXY_IP='157.15.20.132'`, hard-reload; no `daemon-reload` needed) + note that history starts recording from install time.
