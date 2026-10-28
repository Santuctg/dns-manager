# Dashboard monitoring charts — design (2026-10-29)

## Intent
Replace the dashboard's four tiny sparklines (CPU, Memory, Network RX/TX) with
two larger, richer charts that match the operator's reference: a "CPU & Memory"
chart and a "Network Traffic" chart, each with a labelled y-axis, gridlines, a
time-labelled x-axis, filled area under the lines, and a bottom legend showing
the current values. Purely a presentation change; no new data source.

## Goals
- Two combined charts: CPU & Memory (both %) and Network Traffic (Input/Output).
- Axis labels, gridlines, x-axis time labels, and a value legend like the reference.
- Keep dark + light theme, Bengali + English labels, offline assets, no framework/build/CDN.
- Reuse the existing `/api/v1/system/metrics` data flow (cpu%, mem%, rxRate, txRate).

## Non-goals / anti-goals
- No new backend endpoint, DB table, or migration.
- No charting library; hand-rolled SVG (consistent with existing sparkline approach).
- No interactive zoom/pan/hover tooltips in this pass (static chart + live legend).

## Constraints
- Plain JS + SVG; rendering must stay cheap (bounded point count).
- Existing `poll(refreshMetrics, 1000)` stays; the chart downsamples so it does
  not re-render thousands of points every second.

## Approaches considered
1. **New `createChart()` multi-series SVG renderer in core.js (chosen).**
   Renders gridlines, y-axis ticks, x-axis time labels, two polylines with fills,
   and a legend. Two instances wired to the existing pushed metrics. Best match
   to the reference; reuses current data flow.
2. Keep the four sparklines and overlay axes/legend via CSS grid. Rejected: a
   sparkline is a single tiny series with no shared axis, so it cannot look like
   the combined reference charts.

## Decisions
- **Charts:** "CPU & Memory" (CPU blue/accent + Memory teal/info, y in %) and
  "Network Traffic" (Input blue + Output teal, y auto-formatted bytes/s).
- **History window:** ~1 hour. Samples are recorded at most once per ~5s
  (`minIntervalMs`), capacity ~720 points; x-axis shows relative time labels.
- **Y-axis:** CPU/Memory 0–100 (%); Network 0–max with human units (B/Kb/Mb/Gb per s).
- **Legend:** bottom row, live current value per series (e.g. "CPU 14.3%", "Input 463 Mb/s").
- **Theming:** existing CSS variables for colors/grid; dark + light both work.
- **i18n:** chart titles/labels via existing `t()` keys (Bengali + English).

## What's left to the builder
Implement `createChart()` in core.js, replace the sparkline block in
`dashboard.html` with the two chart cards, update `dashboard.js` wiring and
metrics push to feed the two charts with downsampling, add CSS for the chart
card/axes/legend, add/extend i18n keys, and add browser regression tests
covering the two charts render and update. Ship as the next patch release.
