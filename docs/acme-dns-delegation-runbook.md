# DNS Manager 0.3.0 — ACME DNS Delegation Production Runbook

This runbook activates the optional authoritative ACME DNS subsystem after the 0.3.0 package is installed. Do not enable Knot until a non-conflicting listen IP is selected.

## 1. Preflight: select the authoritative listen IP

```bash
ip -br addr
ss -lntup | grep ':53 ' || true
```

Requirements:

- do not reuse the IP currently bound by dnsmasq;
- do not bind Knot to `0.0.0.0:53`;
- do not disturb `127.0.0.53/127.0.0.54` systemd-resolved listeners;
- for NAT, forward public TCP+UDP 53 to the selected dedicated local IP.

Set shell variables only after confirming the address:

```bash
ACME_DNS_LISTEN_IP='<DEDICATED_LOCAL_OR_PUBLIC_IP>'
ACME_DNS_PUBLIC_IP='<PUBLIC_IP_PUBLISHED_IN_DNS>'
ACME_DNS_ZONE='acme-dns.connect3.net.bd'
ACME_DNS_NS='ns1-acme.connect3.net.bd'
```

Verify the local address exists and port 53 is free on that exact IP:

```bash
ip -br addr | grep -F "$ACME_DNS_LISTEN_IP"
ss -H -lnut | grep -F "$ACME_DNS_LISTEN_IP:53" && { echo 'STOP: port 53 already in use'; exit 1; } || true
```

## 2. Parent DNS delegation

In the authoritative DNS for `connect3.net.bd`, create:

```dns
acme-dns.connect3.net.bd. NS ns1-acme.connect3.net.bd.
ns1-acme.connect3.net.bd. A <ACME_DNS_PUBLIC_IP>
```

Do not publish a DS record for the child zone in 0.3.0.

If the server is behind NAT, forward both protocols:

```text
PUBLIC_IP:53/udp -> ACME_DNS_LISTEN_IP:53/udp
PUBLIC_IP:53/tcp -> ACME_DNS_LISTEN_IP:53/tcp
```

## 3. Configure DNS Manager ACME DNS settings

```bash
cat >/etc/dns-manager/acme-dns.conf <<EOF
ACME_DNS_ENABLED=true
ACME_DNS_ZONE=$ACME_DNS_ZONE
ACME_DNS_NS=$ACME_DNS_NS
ACME_DNS_LISTEN_IP=$ACME_DNS_LISTEN_IP
ACME_DNS_TTL=30
EOF
chown root:root /etc/dns-manager/acme-dns.conf
chmod 0600 /etc/dns-manager/acme-dns.conf
```

Run the application preflight without starting Knot:

```bash
cd /opt/dns-manager/dns-manager
PYTHONPATH=. python3 - <<'PY'
from privileged.acme_dns_helper import AcmeDnsHelperOps
print(AcmeDnsHelperOps().preflight())
print(AcmeDnsHelperOps().render_knot_config())
PY
```

Expected: `safe: True` and the selected listen IP.

## 4. Create the initial authoritative zone

```bash
install -d -o root -g knot -m 0750 /var/lib/dns-manager/acme-dns
setfacl -m u:knot:--x /var/lib/dns-manager
SERIAL="$(date -u +%Y%m%d%H)"
cat >/var/lib/dns-manager/acme-dns/acme-dns.connect3.net.bd.zone <<EOF
\$ORIGIN acme-dns.connect3.net.bd.
\$TTL 30
@ IN SOA ns1-acme.connect3.net.bd. hostmaster.acme-dns.connect3.net.bd. (
  $SERIAL 300 60 86400 30
)
@ IN NS ns1-acme.connect3.net.bd.
EOF
chown root:knot /var/lib/dns-manager/acme-dns/acme-dns.connect3.net.bd.zone
chmod 0640 /var/lib/dns-manager/acme-dns/acme-dns.connect3.net.bd.zone
```

## 5. Configure Knot authoritative-only DNS

Back up an existing Knot config if one exists:

```bash
if [ -f /etc/knot/knot.conf ]; then
  cp -a /etc/knot/knot.conf "/etc/knot/knot.conf.pre-dns-manager.$(date -u +%Y%m%dT%H%M%SZ)"
fi
```

Write the dedicated configuration:

```bash
cat >/etc/knot/knot.conf <<EOF
server:
  listen: $ACME_DNS_LISTEN_IP@53

database:
  storage: /var/lib/knot

zone:
  - domain: $ACME_DNS_ZONE
    storage: /var/lib/dns-manager/acme-dns
    file: $ACME_DNS_ZONE.zone
EOF
chown root:knot /etc/knot/knot.conf
chmod 0640 /etc/knot/knot.conf
```

Start only after the listen IP is confirmed safe:

```bash
systemctl enable --now knot
systemctl --no-pager --full status knot
journalctl -u knot -n 50 --no-pager
```

Confirm it is bound only to the intended address:

```bash
ss -lntup | grep ':53 '
```

## 6. Authoritative DNS checks

From the DNS Manager host:

```bash
dig @"$ACME_DNS_LISTEN_IP" "$ACME_DNS_ZONE" SOA +norecurse
dig @"$ACME_DNS_LISTEN_IP" "$ACME_DNS_ZONE" NS +norecurse
dig +tcp @"$ACME_DNS_LISTEN_IP" "$ACME_DNS_ZONE" SOA +norecurse
```

The response must be authoritative (`aa` flag).

Confirm recursion is not provided:

```bash
dig @"$ACME_DNS_LISTEN_IP" example.org A +recurse
```

The server must not behave as a general recursive resolver.

After parent records propagate, verify externally:

```bash
dig @1.1.1.1 acme-dns.connect3.net.bd NS
dig @8.8.8.8 acme-dns.connect3.net.bd NS
dig @1.1.1.1 ns1-acme.connect3.net.bd A
```

## 7. Restart DNS Manager and check status

```bash
systemctl restart dns-manager-helper.service
systemctl restart dns-manager
curl -fsS http://127.0.0.1:8500/ready | python3 -m json.tool
```

Expected `acme_dns` fields when enabled:

```text
configured: true
service: active
zone_loaded: true
tcp_53: true
udp_53: true
```

Core dnsmasq and Nginx readiness must remain healthy.

## 8. One-time CNAME workflow

In DNS Manager, convert a Manual certificate to **ACME Delegation** or create one with that provider.

The UI will display a record similar to:

```dns
_acme-challenge.example.com. CNAME dns-123456abcdef.acme-dns.connect3.net.bd.
```

Create that CNAME once in the domain's existing DNS provider.

Then click:

```text
Verify delegation
```

Only after verification succeeds, run:

```text
Test renewal
```

The test uses Let's Encrypt staging/dry-run and must finish without leaving the temporary TXT record behind.

After `TEST_SUCCESS`, click:

```text
Enable auto renew
```

## 9. Inspect delegated TXT behavior

During a controlled test challenge:

```bash
dig @"$ACME_DNS_LISTEN_IP" dns-<id>.acme-dns.connect3.net.bd TXT +norecurse
dig @1.1.1.1 dns-<id>.acme-dns.connect3.net.bd TXT
dig @8.8.8.8 dns-<id>.acme-dns.connect3.net.bd TXT
```

After Certbot completes, the challenge TXT should be removed. A second simultaneous validation must not be removed when only the first token is cleaned up.

## 10. Renewal scheduler

Keep only the DNS Manager renewal timer:

```bash
systemctl is-enabled certbot.timer 2>/dev/null || true
systemctl is-active certbot.timer 2>/dev/null || true
systemctl is-enabled dns-manager-ssl-renew.timer
systemctl is-active dns-manager-ssl-renew.timer
```

Desired state:

```text
certbot.timer: disabled / inactive
dns-manager-ssl-renew.timer: enabled / active
```

## 11. Security checks

```bash
systemctl show dns-manager -p User -p NoNewPrivileges -p ProtectSystem -p ReadWritePaths --no-pager
systemctl show dns-manager-helper.service -p User -p NoNewPrivileges -p ProtectSystem -p RestrictAddressFamilies -p ReadWritePaths --no-pager
stat -c '%a %U %G %n' /etc/dns-manager/acme-dns.conf /var/lib/dns-manager/acme-dns
getfacl -p /var/lib/dns-manager | sed -n '1,40p'
```

The Knot user should have only parent-directory traverse access via ACL; the ACME zone directory itself is `root:knot` and not world-readable.

Search recent logs for accidental challenge/token output before release acceptance:

```bash
journalctl -u dns-manager -u dns-manager-helper.service -u knot --since '1 hour ago' --no-pager
```

Do not paste real ACME validation values or DNS-provider credentials into support logs.

## 12. Rollback

If Knot activation causes any unexpected DNS behavior:

```bash
systemctl disable --now knot
```

Confirm existing LAN DNS remains healthy:

```bash
systemctl is-active dnsmasq
ss -lntup | grep ':53 '
curl -fsS http://127.0.0.1:8500/ready | python3 -m json.tool
```

Set the subsystem disabled without deleting certificate/delegation metadata:

```bash
sed -i 's/^ACME_DNS_ENABLED=.*/ACME_DNS_ENABLED=false/' /etc/dns-manager/acme-dns.conf
systemctl restart dns-manager
```

The current production certificates and Nginx TLS configuration remain unchanged by this rollback.
