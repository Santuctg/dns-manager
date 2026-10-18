# DNS Manager — v0.6.11

Web-based DNS, reverse-proxy, SSL, firewall and Linux server management platform.

**Current version:** `0.6.11`

## Features

- Domain-to-upstream mapping with Nginx configuration generation
- dnsmasq split-DNS support, preview/validate/apply and rollback
- Role-based access, CSRF protection and audit events
- SSL and ACME DNS management
- Managed UFW firewall with multiple source CIDRs and timed rollback
- Backup and restore
- Dashboard and System monitoring for CPU, RAM, network, disk, uptime and services; 1-second refresh

## Release package

The full cumulative **v0.6.11** source and documentation package is prepared for publication. The repository will be populated with the complete source tree in the next upload step.

Documentation included with the package: installation, administration, architecture, API/testing, operations and release notes.

## Deployment cautions

Back up the application SQLite database and current UFW rules before upgrades. Review the installer and set the correct `DNS_MANAGER_INTERNAL_PROXY_IP`. Do not commit database files, API credentials, private keys or other production secrets.

## License

No open-source license has been designated yet.
