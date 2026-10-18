# Architecture, data flow and security

## Components

- **Web API:** FastAPI, served by Gunicorn on localhost `127.0.0.1:8500` in the reference deployment.
- **Frontend:** server-rendered templates with JavaScript UI, authentication and permission-gated actions.
- **Database:** SQLite at `/var/lib/dns-manager/dns-manager.db` in the reference deployment; Alembic migrations in `migrations/`.
- **DNS:** dnsmasq-generated local/split-DNS configuration.
- **Proxy:** Nginx configuration generated from domain mappings.
- **Privileged helper:** separate service/socket for carefully validated administrative changes. The application does not need unrestricted root privileges.
- **Firewall:** UFW managed-rule logic, preview/validate/apply/confirm/rollback.
- **Certificates:** ACME and SSL helper workflows, with documented hosted and delegated DNS procedures.
- **Metrics:** read-only Linux host counters, acquired by `app/services/system_metrics.py`. Browser computes network rates from consecutive snapshots.

## Trust boundaries

The browser submits authenticated requests; RBAC and CSRF checks are enforced by the server. UI validation is only a convenience; privileged operations must be validated server-side again. The privileged helper is a security-sensitive boundary and must not accept arbitrary shell commands. Do not expose the localhost application listener or helper socket directly to untrusted networks.

## Configuration lifecycle

1. Save desired mappings in SQLite.
2. Preview/validate generated DNS and Nginx configuration.
3. Explicitly apply and record a revision/audit event.
4. Verify service health and client reachability; rollback when necessary.

Firewall deployment uses a separate protected workflow with emergency timeout and explicit confirmation. Manual host edits may cause drift; inspect actual UFW/Nginx state when troubleshooting.

## Deployment safety

Protect DB backups, ACME tokens, API credentials and TLS keys. Limit access to the management site with network policy consistent with the operator's intent; do not accidentally restrict the current SSH source. Public and LAN DNS records are not interchangeable: plan resolvers and access paths explicitly.
