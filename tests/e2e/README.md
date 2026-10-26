# DNS Manager Task 19 E2E Acceptance

The automated acceptance suite uses a temporary file-backed SQLite database, the real FastAPI routes, real RBAC/authentication/config-generation/revision/backup code, and a CI-safe fake privileged helper. It never writes to `/etc` or reloads host services.

Run automated acceptance only:

```bash
python3 -m pytest tests/e2e -v
```

Run the complete regression suite:

```bash
python3 -m pytest -q
```

## Ubuntu 24.04 production/VM acceptance

Run this section only on an installed DNS Manager host after Tasks 17–18 are deployed. It intentionally tests real systemd, dnsmasq, Nginx, DNS and HTTPS paths.

1. Verify service hardening and helper socket:

```bash
systemctl is-active dns-manager dns-manager-helper.socket dnsmasq nginx
systemctl show dns-manager -p NoNewPrivileges -p ReadWritePaths --no-pager
stat -c '%a %U %G %n' /run/dns-manager/helper.sock
```

2. Verify DNS safety and readiness:

```bash
PYTHONPATH=/opt/dns-manager/dns-manager python3 -m app.services.dns_safety \
  --check-base /etc/dnsmasq.d/00-dns-manager-base.conf \
  --expected-ip "$DNS_MANAGER_INTERNAL_PROXY_IP"
curl -fsS http://127.0.0.1:8500/ready | python3 -m json.tool
ss -H -lnut 'sport = :53'
```

3. Use a dedicated temporary hostname (for example `task19-acceptance.internal`) through the UI/API. Create it, preview, validate and apply. Verify:

```bash
dig @192.168.128.2 task19-acceptance.internal
curl --resolve task19-acceptance.internal:80:192.168.128.2 http://task19-acceptance.internal/health
```

4. Edit and re-apply the mapping; then create a backup before destructive acceptance work.

5. Delete and apply the test mapping; verify DNS no longer answers the managed address.

6. Restore the controlled backup from the Backups page. Re-login if the restored session state invalidates the current browser session. Verify the mapping and live DNS/Nginx config return.

7. Verify audit actions, pending changes, helper status and DNS safety are clean. Remove the acceptance mapping and apply one final time so production returns to its pre-test state.

## Reboot persistence (VM/maintenance-window only)

Do not reboot a live host solely for CI. During an approved VM or maintenance-window run:

```bash
systemctl reboot
```

After boot, verify:

```bash
systemctl is-active dns-manager dns-manager-helper.socket dnsmasq nginx
curl -fsS http://127.0.0.1:8500/ready | python3 -m json.tool
dig @192.168.128.2 <known-managed-domain>
curl -fsS https://<management-host>/login >/dev/null
```

A release candidate passes Task 19 only when the automated E2E suite is green and the production/VM checklist has no unresolved failures.

## DNS Manager 0.3.0 ACME DNS Delegation acceptance

The 0.3.0 automated suite also covers the in-app one-time CNAME delegation flow, verified-delegation gate, staging-renewal state gate, and multi-value TXT cleanup semantics. It does not publish public DNS from CI.

Production authoritative DNS activation and the real Let's Encrypt staging challenge are deliberately operator-gated. Follow:

```text
docs/acme-dns-delegation-runbook.md
```

A 0.3.0 production candidate is accepted only after the runbook confirms a non-conflicting Knot listen IP, parent NS/A delegation, authoritative TCP+UDP 53, recursion disabled, successful staging `Test renewal`, TXT cleanup, and unchanged dnsmasq/systemd-resolved listeners.

## DNS Manager 0.4.0 Hosted ACME-DNS acceptance

Hosted ACME-DNS uses outbound HTTPS to `auth.acme-dns.io` and a one-time customer CNAME. It does **not** require Knot, inbound TCP/UDP 53, a dummy interface, or MikroTik DNS NAT.

Automated acceptance covers registration, safe credential handling, CNAME verification state, staging-test state, and auto-renew gating with a CI-safe provider stub. For production, follow `docs/hosted-acme-dns-runbook.md` and complete a real Let's Encrypt staging `Test renewal` before enabling auto renew.
