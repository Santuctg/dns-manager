# Installation and upgrade

## Deployment requirements

The installer is designed for Linux systems using systemd, Nginx and dnsmasq; prior deployments used Ubuntu 24.04 with Python 3.12. Review `packaging/install.sh` and the service templates for target-host requirements and side effects. This package does not include site-specific public DNS changes.

## Preflight

Run from a persistent SSH session and retain a separate recovery session. Record network addresses and existing firewall rules.

```bash
sudo -i
mkdir -p /root/dns-manager-upgrade
chmod 700 /root/dns-manager-upgrade
sqlite3 /var/lib/dns-manager/dns-manager.db   ".backup '/root/dns-manager-upgrade/database-before.db'"
ufw status numbered > /root/dns-manager-upgrade/ufw-before.txt
ufw show added > /root/dns-manager-upgrade/ufw-added-before.txt
nginx -t
```

For first-time installations, the database backup command only applies if the database exists. Keep copies of `/etc/nginx`, `/etc/dnsmasq.d`, and `/etc/dns-manager` in a secured location according to your operational backup policy.

## Install or upgrade

```bash
cd /root
unzip -t dns-manager-0.6.11-documented.zip
mkdir -p /tmp/dnsmgr-release
unzip -q dns-manager-0.6.11-documented.zip -d /tmp/dnsmgr-release
DNS_MANAGER_INTERNAL_PROXY_IP=<YOUR_DNS_LISTEN_IP>   bash /tmp/dnsmgr-release/dns-manager/packaging/install.sh
```

The installer installs Python packages system-wide (without a virtualenv), performs database migrations, manages service units and restarts the app. A successful installer waits for `/health`. Review package installation output for warnings.

## Verification

```bash
cat /opt/dns-manager/dns-manager/VERSION
cd /opt/dns-manager/dns-manager && python3 -m alembic current
systemctl is-active dns-manager dns-manager-helper.service nginx dnsmasq
curl -fsS http://127.0.0.1:8500/health
ufw status verbose
journalctl -u dns-manager -n 100 --no-pager
```

Expected version `0.6.11`; health typically returns `{"status":"ok","database":"ok"}`. Service health does not prove public DNS routing or firewall reachability; test those from appropriate client networks.

## First-time account setup

Use the installed `dns-manager` management CLI and its `--help` for available account-creation commands. Never commit passwords or bootstrap material; complete initial admin setup on the target host.

## Rollback

Retain the previous release directory created by the installer and your SQLite backup. Do **not** replace a migrated database with an older schema without an explicit migration compatibility review. For UFW, use the application's Confirm/Rollback workflow and preserve emergency management access.
