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

The full cumulative **v0.6.11** source and documentation package has been prepared, but the complete application source has not yet been uploaded to this repository. Do not treat this repository as deployable until the full source publication is verified.

Documentation included with the prepared package: installation, administration, architecture, API/testing, operations and release notes.

## Deployment cautions

Back up the application SQLite database and current UFW rules before upgrades. Review the installer and set the correct `DNS_MANAGER_INTERNAL_PROXY_IP`. Do not commit database files, API credentials, private keys or other production secrets.

## License

No open-source license has been designated yet.
