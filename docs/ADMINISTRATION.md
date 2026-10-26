# Administration guide

## Workflow

Sign in to the authenticated web panel. The console groups pages in the sidebar:

| Group | Pages |
| --- | --- |
| Overview | Dashboard |
| Routing | Mappings, SSL |
| Network | Firewall, System |
| Access | Users, Roles, Audit |
| Maintenance | Backups |

The sidebar can collapse to an icon rail; the choice is remembered in the browser. On phones the same navigation appears as a bottom tab bar with a **More** sheet.

### Language and theme (0.7.0)

The console is available in English and Bengali. Technical terms stay in English. The language and theme (dark by default, light optional) are stored in the `dns_manager_lang` and `dns_manager_theme` cookies, so they apply to the sign-in page and every later page. Without a cookie the language follows the browser's `Accept-Language` header (Bengali when it prefers `bn`, otherwise English). Both switches are in the top bar and in the mobile **More** sheet.

All assets are served locally; the console does not load fonts, scripts or styles from the internet.

### Mappings and deployment

Create a domain mapping with upstream protocol, host, port and optional routing settings. Changes are **desired state**, not immediately applied to Nginx/dnsmasq. The Mappings page shows a pending-change banner, per-domain SSL status, backend health and the generated Nginx/dnsmasq snippet in the detail panel. Use Preview to inspect rendered configuration, Validate before deployment, then Apply. Check external DNS separately: application-managed local DNS does not automatically modify authoritative public DNS.

When an apply succeeds, every enabled mapping whose certificate is `ISSUED` or `EXPIRING` also gets its HTTPS vhost rewritten. A failure in that sync is reported in the apply result and audited as `SSL_SYNC_FAILED`; it never rolls back the configuration apply.

### Configuration revisions

System → Configuration shows the active revision, a line diff against the pending state, and a paged revision list (50 per page) with the user who created each revision. Rollback restores an earlier `superseded` revision and is protected by `config.rollback`.

### Multi-source firewall

A logical firewall rule can contain multiple IPv4/IPv6 CIDR entries (up to 32). Each source/protocol is emitted as a separate managed UFW rule. The public `0.0.0.0/0` CIDR explicitly means IPv4 from anywhere. Do not assume restricting HTTP port 80 also restricts HTTPS port 443. Before Apply, preview rules and ensure the management/SSH path remains allowed. Following Apply, confirm before the 120-second timeout; the page counts down the remaining time and rolls back automatically if the deadline passes.

### SSL

Certificate issuance and renewal require correct DNS ownership, connectivity and ACME provider settings. The SSL page lists every certificate with its status, expiry and provider, and rows expose apply, renew and delete actions in an overflow menu. The provider selector shows the token field only for Cloudflare; other providers use hosted ACME DNS or delegation. Existing runbooks describe hosted ACME DNS and delegation options. Verify the active Nginx certificate and renewal timer after issuing or applying certs.

### Monitoring

Dashboard and System show CPU/load, RAM, network RX/TX, filesystem usage, server uptime and key service states. When the browser tab is visible, the client polls the authenticated `/api/v1/system/metrics` endpoint at about a 1-second cadence (after each request completes); slow requests can lengthen observed refresh time. Hidden tabs pause polling. Network Mbps requires two network-byte counter samples; the first may show `Sampling…`. If the metrics endpoint is unavailable (for example on a host without the required `/proc` data), the page shows `Status unavailable` and empty states instead of stale values. If API errors occur, the UI uses retry/backoff.

### Users and roles

Use least-privilege roles. Monitoring access requires `system.view`; UFW changes require `firewall.manage`; SSL actions require the Super Admin role. Mutating API requests use CSRF protection in addition to login/session authorization. Audit records sign-ins, mapping, firewall, configuration, SSL and backup operations.

### Backups

Regularly create and test backups. Creating a backup downloads it, or uploads an archive through the page; both appear in the backup list. Restore is a disruptive administrative operation: the restore button stays disabled until the exact backup identifier is typed. Create a fresh recovery copy first, confirm compatible app/schema versions, and schedule downtime where needed.
