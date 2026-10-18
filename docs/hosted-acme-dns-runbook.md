# Hosted ACME-DNS production runbook

## 1. Upgrade

Install DNS Manager 0.4.0 normally. Hosted mode requires outbound HTTPS/DNS only and does not require Knot.

Verify:

```bash
cat /opt/dns-manager/dns-manager/VERSION
cd /opt/dns-manager/dns-manager && alembic current
systemctl is-active dns-manager dns-manager-helper.socket dns-manager-ssl-renew.timer
```

Expected version/schema: `0.4.0` and `0008_hosted_acme_dns`.

## 2. Provider configuration

`/etc/dns-manager/hosted-acme.conf`:

```ini
HOSTED_ACME_ENABLED=true
HOSTED_ACME_SERVER_URL=https://auth.acme-dns.io
HOSTED_ACME_HTTP_TIMEOUT=15
HOSTED_ACME_PROPAGATION_TIMEOUT=120
```

Permissions:

```bash
chown root:root /etc/dns-manager/hosted-acme.conf
chmod 600 /etc/dns-manager/hosted-acme.conf
systemctl restart dns-manager dns-manager-helper.service
```

## 3. Convert a manual certificate

System → SSL / Certificates → **Convert to Hosted ACME-DNS**.

DNS Manager registers with the hosted service and shows only the permanent CNAME requirement, for example:

```dns
_acme-challenge.example.com. CNAME <generated>.auth.acme-dns.io.
```

Do not remove this CNAME after issuance.

## 4. Verify and test

After public DNS propagation:

1. Click **Verify CNAME**.
2. Confirm status becomes `VERIFIED`.
3. Click **Test renewal**.
4. Confirm `TEST_SUCCESS`.
5. Click **Enable auto renew**.

Do not enable auto renew before the staging test succeeds.

## 5. Renewal behavior

`dns-manager-ssl-renew.timer` remains the only scheduler. When a certificate enters the renewal window, DNS Manager re-verifies the CNAME, updates the hosted TXT challenge over HTTPS, waits for propagation, renews the certificate, validates Nginx, and reloads it. A provider outage or stale CNAME leaves the existing certificate and Nginx configuration in place.

## 6. Network cleanup from 0.3.x tests

Only after Hosted ACME-DNS is verified and no production certificate depends on `acme_delegation`, remove the old test infrastructure.

The Hosted mode does not need:

- Knot DNS;
- `10.255.53.53` dummy address;
- `103.193.10.243:53 -> 192.168.128.2:5353` MikroTik rules;
- `acme-dns.connect3.net.bd` / `ns1-acme.connect3.net.bd` delegation.

On MikroTik, identify rules by comment before removing them; do not remove unrelated DNS/NAT rules.

## 7. Health checks

```bash
curl -fsS http://127.0.0.1:8500/ready | python3 -m json.tool
systemctl is-active dns-manager-ssl-renew.timer
```

Hosted provider reachability is informational and does not make core DNS Manager readiness fail.
