# DNS Manager 0.6.9 — System Monitoring

Adds authenticated read-only host metrics at `/api/v1/system/metrics` and Dashboard/System resource cards: CPU sampled tick utilization/load, MemAvailable-based RAM, per-interface RX/TX rate using client-side byte deltas and server timestamps, filesystem usage, uptime and systemd service state. Visible-tab refresh every five seconds; hidden tabs pause. Metrics are ephemeral and do not modify firewall/DNS settings.

## Acceptance checks
- Run installer with `DNS_MANAGER_INTERNAL_PROXY_IP=157.15.20.132` after backing up SQLite and UFW state.
- Verify `VERSION=0.6.9`, service health, UFW status unchanged, and GET `/api/v1/system/metrics` with an authorized session.
- View Dashboard and System, confirm first network sample reads `Sampling…`, later RX/TX speed appears, hidden tab stops polling.
- Metrics require `system.view` access. No server-side network rates/historical samples are retained.
