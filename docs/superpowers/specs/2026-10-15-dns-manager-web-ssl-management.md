# DNS Manager Web SSL Management — Design Specification

**Date:** 2026-10-15
**Scope:** Add browser-based SSL/TLS certificate management to DNS Manager.

## Goal

Allow a Super Admin to issue, inspect, renew, test, and apply TLS certificates from the DNS Manager web UI without using the shell, while preserving the existing least-privilege systemd helper architecture.

## Supported Certificate Flow

### Cloudflare DNS-01
- Super Admin enters a restricted Cloudflare API token.
- Token is never returned by the API after saving.
- Token is stored encrypted at rest.
- Root helper invokes Certbot using a temporary credentials file with restrictive permissions.
- Credentials file is removed after the operation.
- Automatic renewal is supported.

### Manual DNS-01
- UI starts a manual DNS-01 order.
- UI displays the `_acme-challenge.<domain>` TXT record name and required value.
- Operator adds the TXT record externally.
- UI can check TXT propagation before continuing.
- Manual certificates are clearly marked as not automatically renewable unless converted to an automated provider.

## Web UI

Add an **SSL / Certificates** section under System.

Each managed certificate shows:
- Domain
- Certificate status: `ISSUED`, `EXPIRING`, `EXPIRED`, `ERROR`, `NOT_ISSUED`
- Issuer
- Issued at
- Expires at
- Days remaining
- Renewal mode: automatic/manual
- Certificate path
- Last renewal result

Available Super Admin actions:
- Issue Certificate
- Renew
- Test Renewal
- Apply to Nginx
- Enable/Disable Auto Renew
- Delete managed certificate configuration

HTTP → HTTPS redirect can be enabled per management hostname.

## API

Super Admin-only, CSRF-protected endpoints:
- `GET /api/v1/ssl/certificates`
- `GET /api/v1/ssl/certificates/{domain}`
- `POST /api/v1/ssl/certificates`
- `POST /api/v1/ssl/certificates/{domain}/renew`
- `POST /api/v1/ssl/certificates/{domain}/test-renewal`
- `POST /api/v1/ssl/certificates/{domain}/apply`
- `DELETE /api/v1/ssl/certificates/{domain}`
- `PUT /api/v1/ssl/settings/{domain}`
- `POST /api/v1/ssl/manual-dns/{domain}/check`

Viewer/Admin roles cannot mutate SSL settings.

## Privileged Helper

Extend the existing root systemd socket helper with fixed SSL commands only:
- `ssl_status`
- `ssl_issue`
- `ssl_renew`
- `ssl_test_renewal`
- `ssl_apply`
- `ssl_delete`

No arbitrary command execution, paths, or shell fragments are accepted from the web process.

The helper:
1. Validates domain format.
2. Uses fixed Let's Encrypt directories.
3. Runs Certbot with explicit arguments.
4. Generates managed Nginx HTTPS config.
5. Runs `nginx -t`.
6. Reloads Nginx only after validation passes.
7. Rolls back managed Nginx config on failure.

## Nginx

Managed SSL vhost configuration supports:
- Port 80 redirect to HTTPS
- Port 443 TLS termination
- Reverse proxy to `127.0.0.1:8500`
- Existing forwarded headers
- TLS 1.2 and TLS 1.3
- Existing certificate paths under `/etc/letsencrypt/live/<domain>/`

The app never writes `/etc/nginx` directly; only the privileged helper does.

## Secret Storage

Cloudflare API tokens:
- Must not be stored plaintext.
- Encryption key is stored outside SQLite in a root-owned systemd environment/credential file.
- Database stores only ciphertext and metadata.
- UI/API never returns the raw token after save.
- Audit logs never contain the token.
- Token input is write-only.

## Auto Renewal

Use a dedicated systemd timer/service owned by root.

Renewal flow:
1. Detect certificates approaching expiry.
2. Run Certbot renewal.
3. Validate generated/renewed certificate.
4. Run `nginx -t`.
5. Reload Nginx.
6. Record result for UI/audit.

No browser session is required for renewal.

## Audit Events

Add:
- `SSL_CERT_ISSUE_STARTED`
- `SSL_CERT_ISSUED`
- `SSL_CERT_ISSUE_FAILED`
- `SSL_CERT_RENEWED`
- `SSL_CERT_RENEW_FAILED`
- `SSL_CERT_APPLIED`
- `SSL_CERT_DELETED`
- `SSL_SETTINGS_UPDATED`

Secrets are excluded from audit old/new values.

## Backup / Restore

Backup includes SSL management metadata and encrypted provider credentials from SQLite.

Private key material under `/etc/letsencrypt` is not copied into DNS Manager backup archives.

After restore, certificate status is reconciled against the local `/etc/letsencrypt` state.

## Security Requirements

- Super Admin-only certificate mutation.
- CSRF required for every mutation.
- Strict domain validation.
- No arbitrary filesystem paths from user input.
- No arbitrary shell command execution.
- Cloudflare token never logged or echoed.
- Root helper stays systemd-socket isolated.
- App service keeps `NoNewPrivileges=yes`.
- Existing DNS safety protections remain unchanged.
- Certificate/Nginx validation must succeed before reload.

## Testing / Acceptance

Tests must cover:
- RBAC and CSRF
- Domain validation
- Secret redaction
- Encrypted token storage
- Helper fixed-command protocol
- Certbot argument construction
- Successful issuance
- Certbot failure
- Nginx validation failure and rollback
- Renewal status
- Auto-renew timer packaging
- Manual DNS-01 state
- UI visibility
- Existing regression suite

Production acceptance for `dns.connect3.net.bd`:
1. Detect current certificate.
2. Display expiry/status.
3. Configure Cloudflare or manual DNS-01.
4. Run renewal test.
5. Apply certificate to managed Nginx vhost.
6. Confirm HTTPS login and Secure session cookie.
7. Confirm auto-renew timer state.
