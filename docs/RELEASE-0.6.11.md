# DNS Manager v0.6.11 — release notes

**Release:** v0.6.11 · **Date:** 2026-10-18

## Highlights

- 1-second monitoring polling on Dashboard and System pages
- Non-overlapping requests, pause on hidden browser tabs, error retry/backoff
- CPU, RAM, network RX/TX, disk, uptime and service status live panels (introduced in v0.6.9)
- Monitoring page layout/spacing improvements (v0.6.10)
- Multi-source CIDR managed UFW firewall rules (v0.6.6)
- Installer forced restart/health readiness (v0.6.7)
- Mapping configuration preview field fix (v0.6.8)

## Upgrade guidance

Back up the SQLite DB and record UFW rules. Apply the cumulative ZIP using `packaging/install.sh` with the correct `DNS_MANAGER_INTERNAL_PROXY_IP`; verify version, services, health and firewall state. See [Installation](INSTALLATION.md).

## Compatibility and cautions

This is a full cumulative source release; no container image or GitHub Actions deployment artifact is provided. Monitoring polling may consume additional resources with many concurrent viewers. Do not alter firewall rules merely to install this update. Release checks must be rerun on the target server.

## Publication status

Documentation and code are packaged for GitHub publication. This document does not assert that a GitHub tag or hosted Release exists.
