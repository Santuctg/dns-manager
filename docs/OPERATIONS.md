# Operations and troubleshooting

## Daily checks

```bash
systemctl is-active dns-manager dns-manager-helper.service nginx dnsmasq
curl -fsS http://127.0.0.1:8500/health
ss -lntp | grep ':8500'
systemctl status dns-manager --no-pager
ufw status verbose
```

## HTTP 422 on firewall source CIDRs

After an upgrade, validate the active `/openapi.json` contract and restart the app if old Gunicorn workers are still running. 0.6.11 installer explicitly restarts `dns-manager.service` and waits for health readiness.

## Monitoring not updating

Confirm page visibility and authenticated session, inspect browser network requests for `/api/v1/system/metrics`, and check app service logs. RX/TX rate requires two consecutive counter snapshots; an empty or unsupported interface may show no rate.

## UI shows pending changes but blank preview

Verify UI/static asset cache and the `/api/v1/config/preview` response. Force browser refresh after upgrades. Apply only after inspecting generated configs and validating changes.

## DNS vs proxy reachability

Use `dig @<DNS_SERVER_IP> example.com` to test resolver answers and `curl --resolve domain:443:<PROXY_IP> https://domain/` to isolate proxy behavior from public DNS. Use actual deployment IPs; public DNS is administered separately.

## Service startup

`systemctl is-active` can report active while the listener is starting. Query `/health` with limited connection-refused retries or inspect `journalctl -u dns-manager -n 100 --no-pager`.

## Firewall safety

`ufw status numbered` and `ufw show added` are useful read-only checks. Port 80 and 443 are distinct. Keep SSH access from an authorized source, and do not run `ufw reset` or remove rules until the current managed/unmanaged state has been reconciled.

## Recovery

Restore from verified backups and a known compatible application version. Review Alembic migration versions before database rollback. Recover network service configurations only with console/out-of-band access available.
