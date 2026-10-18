# Administration guide

## Workflow

Sign in to the authenticated web panel. Use Dashboard for service and monitoring overview, Mappings for domain routing, System for configuration previews and monitoring, SSL for certificates, Firewall for managed UFW rules, and the role/backup/audit pages as permitted.

### Mappings and deployment

Create a domain mapping with upstream protocol, host, port and optional routing settings. Changes are **desired state**, not immediately applied to Nginx/dnsmasq. Use Preview to inspect rendered configuration, Validate before deployment, then Apply. Check external DNS separately: application-managed local DNS does not automatically modify authoritative public DNS.

### Multi-source firewall

A logical firewall rule can contain multiple IPv4/IPv6 CIDR entries (up to 32). Each source/protocol is emitted as a separate managed UFW rule. The public `0.0.0.0/0` CIDR explicitly means IPv4 from anywhere. Do not assume restricting HTTP port 80 also restricts HTTPS port 443. Before Apply, preview rules and ensure the management/SSH path remains allowed. Following Apply, use the confirmation flow before its 120-second timeout, or rely on its rollback safeguards.

### SSL

Certificate issuance and renewal require correct DNS ownership, connectivity and ACME provider settings. Existing runbooks describe hosted ACME DNS and delegation options. Verify the active Nginx certificate and renewal timer after issuing or applying certs.

### Monitoring (0.6.11)

Dashboard and System show CPU/load, RAM, network RX/TX, filesystem usage, server uptime and key service states. When the browser tab is visible, the client polls the authenticated `/api/v1/system/metrics` endpoint at about a 1-second cadence (after each request completes); slow requests can lengthen observed refresh time. Hidden tabs pause polling. Network Mbps requires two network-byte counter samples; the first may show `Sampling…`. If API errors occur, the UI uses retry/backoff.

### Users and roles

Use least-privilege roles. Monitoring access requires `system.view`; UFW changes require `firewall.manage`. Mutating API requests use CSRF protection in addition to login/session authorization.

### Backups

Regularly create and test backups. Restore is a disruptive administrative operation: create a fresh recovery copy first, confirm compatible app/schema versions, and schedule downtime where needed.
