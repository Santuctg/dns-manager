# DNS Manager v0.6.11 — Release Notes

Date: 2026-10-18

## Highlights
- Dashboard and System live monitoring at a 1-second interval
- Request scheduling without overlap, pause on hidden tabs and retry/backoff after errors
- CPU, RAM, network RX/TX, disk, uptime and services monitoring (introduced in v0.6.9)
- Monitoring layout and spacing refinements (v0.6.10)
- UFW multi-source CIDR support (v0.6.6)
- Installer restart/readiness improvements (v0.6.7)
- Mapping configuration preview field fix (v0.6.8)

## Upgrade guidance
Back up the SQLite database and record UFW state before an upgrade. Install the full cumulative package using `packaging/install.sh` with the appropriate `DNS_MANAGER_INTERNAL_PROXY_IP`. Verify the application version, service status, health endpoint and the existing firewall rules.

## Cautions
Monitoring at a 1-second interval increases API traffic with concurrent viewers. Firewall changes require explicit preview, validate, apply and confirmation. Application readiness checks do not constitute a full security audit.

## Publication status
The complete source ZIP and GitHub Release asset have not yet been uploaded. This notes file alone is not a published GitHub Release.
