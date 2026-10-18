# DNS Manager — v0.6.11

Web-based DNS, reverse-proxy, SSL, firewall, and server administration for Linux hosts.

**Current release:** `0.6.11` · **Status:** deployment package; validate against your environment before production changes.

## Features

- Domain-to-upstream HTTP/HTTPS mappings with generated Nginx proxy configuration
- Managed local DNS via dnsmasq; split-DNS deployments with separately managed public DNS
- Preview → Validate → Apply workflow, revision history and rollback for configuration
- Authenticated web panel with role-based permissions, CSRF protection, and audit events
- SSL certificate management and ACME DNS workflows
- Managed UFW rules with multi-source IPv4/IPv6 CIDRs, validation, confirm and timed rollback
- Backup creation, upload, download and restore
- CPU, RAM, disk, uptime, network throughput and service-status monitoring on Dashboard and System pages; 1-second client polling

## Documentation

- [Installation and upgrades](docs/INSTALLATION.md)
- [Administration guide](docs/ADMINISTRATION.md)
- [Architecture and security](docs/ARCHITECTURE.md)
- [API reference and testing](docs/API_AND_TESTING.md)
- [Operations and troubleshooting](docs/OPERATIONS.md)
- [v0.6.11 release notes](docs/RELEASE-0.6.11.md)
- [Historical design documents](docs/superpowers/)

## Quick start (existing installation upgrades)

```bash
# On host, after uploading the release ZIP to /root:
cd /root
unzip -q dns-manager-0.6.11-documented.zip -d /tmp/dnsmgr-release
DNS_MANAGER_INTERNAL_PROXY_IP=<YOUR_DNS_LISTEN_IP> \
  bash /tmp/dnsmgr-release/dns-manager/packaging/install.sh
curl -fsS http://127.0.0.1:8500/health
```

**IMPORTANT:** Replace the placeholder with the correct host address. The installer requires root privileges and modifies system services, Nginx, dnsmasq, and related configuration. Back up database and active firewall rules first; read the installation guide.

## Source tree

`app/` API, models, templates, static UI; `migrations/` Alembic; `privileged/` controlled helper; `packaging/` install/system integration; `tests/` verification; `docs/` runbooks.

## Security

Do not commit `.env`, database files, backup archives, DNS API credentials, TLS private keys, or production configuration secrets. Review generated configurations before Apply. Preserve out-of-band SSH access when changing firewall rules.

## License

No license is included in this release package. Do not assume an open-source license until the project owner chooses one.
