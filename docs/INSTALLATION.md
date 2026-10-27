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

### Option A: release ZIP

```bash
cd /root
unzip -t dns-manager-0.7.4-documented.zip
rm -rf /tmp/dnsmgr-release
mkdir -p /tmp/dnsmgr-release
unzip -q dns-manager-0.7.4-documented.zip -d /tmp/dnsmgr-release
cat /tmp/dnsmgr-release/dns-manager/VERSION    # expected: 0.7.4
DNS_MANAGER_INTERNAL_PROXY_IP=<HOST_LAN_IP> \
  bash /tmp/dnsmgr-release/dns-manager/packaging/install.sh
```

### Option B: clone the tagged source from GitHub

```bash
apt-get install -y git    # only if git is missing
cd /root
rm -rf /tmp/dnsmgr-release
git clone --depth 1 --branch v0.7.4 \
  https://github.com/Santuctg/dns-manager.git /tmp/dnsmgr-release
rm -rf /tmp/dnsmgr-release/.git
cat /tmp/dnsmgr-release/VERSION    # expected: 0.7.4
DNS_MANAGER_INTERNAL_PROXY_IP=<HOST_LAN_IP> \
  bash /tmp/dnsmgr-release/packaging/install.sh
```

Pinning `--branch v0.7.4` installs exactly the released source; use `main` only for development. The installer copies the checkout into `/opt/dns-manager/dns-manager`, so the source directory can stay under `/tmp`.

`DNS_MANAGER_INTERNAL_PROXY_IP` must be the host's own LAN address (check with `ip -4 addr show scope global`), not a loopback or documentation address. On an upgrade, reuse the value the existing installation already uses; the installer validates dnsmasq and aborts before restarting services if the address is unusable.

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

Expected version `0.7.4`; health typically returns `{"status":"ok","database":"ok"}`. Service health does not prove public DNS routing or firewall reachability; test those from appropriate client networks.

## First-time account setup

Use the installed `dns-manager` management CLI and its `--help` for available account-creation commands. Never commit passwords or bootstrap material; complete initial admin setup on the target host.

## Rollback

Retain the previous release directory created by the installer and your SQLite backup. Do **not** replace a migrated database with an older schema without an explicit migration compatibility review. For UFW, use the application's Confirm/Rollback workflow and preserve emergency management access.
