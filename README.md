# DNS Manager
### Web-based DNS, Reverse Proxy, SSL, Firewall & Linux Server Management

[![Release](https://img.shields.io/github/v/release/Santuctg/dns-manager?label=Latest%20Release&style=for-the-badge)](https://github.com/Santuctg/dns-manager/releases/latest)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%2F%20Ubuntu-4B5563?style=for-the-badge&logo=ubuntu)](docs/INSTALLATION.md)
[![Backend](https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi)](docs/ARCHITECTURE.md)
[![Docs](https://img.shields.io/badge/Documentation-Read%20Guides-2563EB?style=for-the-badge&logo=readthedocs)](docs/ADMINISTRATION.md)

> **DNS Manager** is a self-hosted web control panel for managing domain-to-service routing, local/split DNS, Nginx reverse proxies, TLS certificates, UFW firewall rules and Linux server health from one authenticated interface.
>
> **Typical use:** Route `app.example.com` to `192.168.1.20:8080`, preview its Nginx and local DNS configuration, validate and apply it, manage HTTPS, restrict inbound access by CIDR and monitor the server.

**Current release:** [v0.6.11](https://github.com/Santuctg/dns-manager/releases/tag/v0.6.11) · **Deployment:** Linux host with systemd, Nginx and dnsmasq · **Docker image:** not provided.

---

## ✨ What can you do with DNS Manager?

| Capability | What it lets you do |
| --- | --- |
| 🌐 **Domain mappings** | Point a hostname at an internal HTTP/HTTPS service identified by IP and port. |
| 🔀 **Nginx reverse proxy** | Generate proxy configuration from saved mappings rather than editing each server block by hand. |
| 🧭 **Local / split DNS** | Manage dnsmasq-backed LAN answers while keeping public authoritative DNS independently managed. |
| 🔍 **Preview, validate & apply** | Review generated dnsmasq and Nginx configuration before activating pending changes. |
| 🕘 **Revisions & audit** | Inspect configuration revision history and activity logs for administrative changes. |
| 🔐 **SSL / HTTPS** | Manage TLS certificates and ACME DNS workflows, including documented hosted/delegated DNS options. |
| 🛡️ **Managed UFW firewall** | Configure port, protocol and multiple allowed source IPv4/IPv6 CIDRs per logical rule (up to 32 sources). |
| ↩️ **Firewall safety** | Preview/validate/apply with explicit confirmation and a 120-second emergency rollback window. |
| 📊 **Server monitoring** | View CPU/load, RAM, per-interface network throughput, disk, uptime and service status. |
| ⚡ **Live dashboard** | Refresh monitoring at about 1-second intervals in visible browser tabs; pause while hidden. |
| 👥 **Users & permissions** | Role-based access control, authenticated sessions and CSRF protection on modifying requests. |
| 💾 **Backup & restore** | Create, download, upload and restore backups with administrative controls. |

### Example: Publish an internal application

```text
Client: https://app.example.com
              │
              ▼
      DNS / Nginx host
              │
              ▼
       192.168.1.20:8080
           (your app)
```

1. Create the hostname-to-upstream mapping in the web UI.
2. Open **Preview** to inspect generated configuration.
3. **Validate** and **Apply** the pending changes.
4. Configure authoritative **public DNS separately** if internet resolution is needed.
5. Add SSL and source-based firewall rules according to your access policy.

Saving a mapping updates desired state; **it does not instantly publish DNS or activate Nginx changes**.

### Example: Restrict HTTP and HTTPS to selected networks

A single logical UFW rule can contain multiple source entries:

```text
192.168.0.0/24
192.167.10.0/23
```

The system expands enabled source/protocol combinations into individual managed UFW operations. **Ports 80 and 443 are separate rules**: restricting HTTP does not automatically restrict HTTPS. Maintain a safe SSH path before applying firewall changes.

---

## 🖥️ Dashboard & System Monitoring

See CPU utilization and load average, memory used/available, network RX/TX Mbps (computed from counter deltas), filesystem usage, server uptime and key service states.

- **Dashboard:** at-a-glance host overview.
- **System:** more detailed network, filesystem and service information.
- **Polling:** approximately every 1 second after the preceding request completes; hidden tabs pause; failed requests back off.
- **Access:** monitoring requires the `system.view` permission.

Network speed needs consecutive samples, so the first reading may display **Sampling…**.

> **Screenshots:** Real product screenshots have not yet been added to this repository. Add redacted Dashboard, Mappings, System and Firewall images under `docs/images/` before embedding screenshots here. Never expose tokens, sessions or internal-only addresses unintentionally.

---

## 🧩 Technology & architecture

| Layer | Technology |
| --- | --- |
| Web/API | Python, FastAPI, Gunicorn |
| Frontend | Jinja templates, JavaScript, CSS |
| Configuration database | SQLite with Alembic migrations |
| LAN DNS | dnsmasq |
| Reverse proxy | Nginx |
| Firewall | UFW |
| Services & tasks | systemd |
| Sensitive operations | Validated, separate privileged helper |
| TLS | ACME-related certificate workflows |

```text
Browser → Authenticated web API → SQLite desired configuration
                      │
                      ├── Read-only host metrics
                      │
                      └── Validated privileged helper
                                  ├── dnsmasq
                                  ├── Nginx / SSL
                                  └── UFW firewall
```

See [Architecture & Security](docs/ARCHITECTURE.md) for trust boundaries and change lifecycle.

---

## ✅ Requirements

- A supported Linux/systemd host; previous deployments used **Ubuntu 24.04 with Python 3.12**.
- Working Nginx and dnsmasq deployment with planned bind addresses / DNS resolution.
- Root access for initial setup or upgrades, and a separate recovery SSH session.
- A host-specific `DNS_MANAGER_INTERNAL_PROXY_IP` value.
- Correct public DNS records configured separately when exposing hostnames on the internet.
- Database/configuration backups before upgrading.

This is a **host-installed application**, **not a Docker Compose stack**. Review the [installation guide](docs/INSTALLATION.md) and `packaging/install.sh` before running privileged installation commands.

---

## 🚀 Installation / Upgrade

### 1. Download the versioned package

Download the ZIP asset from **[Releases](https://github.com/Santuctg/dns-manager/releases/tag/v0.6.11)** and transfer it to the target server. For a fresh install, follow the installation guide for initial account bootstrap and host preparation.

### 2. Back up an existing installation

```bash
sudo -i
mkdir -p /root/dns-manager-upgrade
chmod 700 /root/dns-manager-upgrade

# Existing installations only:
sqlite3 /var/lib/dns-manager/dns-manager.db \
  ".backup '/root/dns-manager-upgrade/database-before.db'"

ufw status numbered > /root/dns-manager-upgrade/ufw-before.txt
ufw show added > /root/dns-manager-upgrade/ufw-added-before.txt
```

Also back up the relevant Nginx, dnsmasq and application settings outside this working directory.

### 3. Inspect and install

```bash
cd /root
unzip -t dns-manager-0.6.11-documented.zip
mkdir -p /tmp/dnsmgr-release
unzip -q dns-manager-0.6.11-documented.zip -d /tmp/dnsmgr-release

# Replace the example with the DNS/proxy address intended for your host:
DNS_MANAGER_INTERNAL_PROXY_IP=192.0.2.10 \
  bash /tmp/dnsmgr-release/dns-manager/packaging/install.sh
```

**Important:** `192.0.2.10` is an illustrative documentation address, **not** a default suitable for deployment. Set the correct local/public listen address for your network. The installer can install packages, migrate the database and modify/restart services.

### 4. Verify

```bash
cat /opt/dns-manager/dns-manager/VERSION
cd /opt/dns-manager/dns-manager && python3 -m alembic current
systemctl is-active dns-manager dns-manager-helper.service nginx dnsmasq
curl -fsS http://127.0.0.1:8500/health
ufw status verbose
```

Expected version: `0.6.11`. The health endpoint normally returns:

```json
{"status":"ok","database":"ok"}
```

Health checks alone do not prove that DNS resolves externally or that firewall reachability works from every client network.

---

## 📁 Project structure

```text
dns-manager/
├── app/                  # FastAPI routes, data models, services, UI
│   ├── api/
│   ├── services/
│   ├── static/
│   └── templates/
├── migrations/           # Alembic schema migrations
├── privileged/           # Validated privileged operations
├── packaging/            # Installer and systemd integration
├── tests/                # Unit, integration, security, E2E
├── docs/                 # Guides, runbooks, historical designs
├── requirements.txt
└── VERSION
```

---

## 📚 Documentation

| Guide | Contents |
| --- | --- |
| [Installation & upgrades](docs/INSTALLATION.md) | Host preparation, backups, installer and verification |
| [Administration](docs/ADMINISTRATION.md) | Mappings, firewall, SSL, monitoring, users and backups |
| [Architecture & security](docs/ARCHITECTURE.md) | Components, trust boundaries and state transitions |
| [API & testing](docs/API_AND_TESTING.md) | API overview, authentication and test procedures |
| [Operations / troubleshooting](docs/OPERATIONS.md) | Health, diagnostics, recovery and operations |
| [Release notes](docs/RELEASE-0.6.11.md) | Changes through v0.6.11 |
| [Design history](docs/superpowers/) | Detailed development plans and specifications |

---

## 🧯 Troubleshooting

**Web panel unreachable?** Check `systemctl status dns-manager nginx`, `curl http://127.0.0.1:8500/health` and `journalctl -u dns-manager -n 100 --no-pager`.

**Saved mapping not live?** Check for pending changes, inspect **Preview → Validate → Apply**, then test local and authoritative public DNS separately.

**Firewall access still open?** Inspect `ufw status verbose` and both HTTP **80/tcp** and HTTPS **443/tcp**. Never run `ufw reset` during remote troubleshooting without a verified recovery path.

**Network Mbps shows “Sampling…”?** Leave the visible page open for another sample; the rate requires two counter readings.

**SSL issuance fails?** Verify DNS ownership/delegation and the chosen ACME workflow; consult the [ACME DNS runbooks](docs/).

For more scenarios, see [Operations](docs/OPERATIONS.md).

---

## 🔒 Security notes

- Keep the application listener and privileged-helper socket off untrusted public networks.
- Protect secrets, SQLite backups, credentials and TLS private keys; do not commit them.
- Enforce least-privilege roles; firewall management requires `firewall.manage`.
- Preserve SSH/admin access before changing UFW rules; confirm pending firewall changes within the rollback window.
- Audit your deployment settings and generated configuration before Apply.

## 📦 Releases and support

**Download:** [GitHub Releases](https://github.com/Santuctg/dns-manager/releases)

**Report a bug or request a feature:** [GitHub Issues](https://github.com/Santuctg/dns-manager/issues)

## 📄 License

No license file is included in v0.6.11. **Public source availability does not grant an open-source license.** The project owner should select and publish a license before third-party redistribution or reuse is encouraged.

---

*Project maintained by [Santuctg](https://github.com/Santuctg).*
