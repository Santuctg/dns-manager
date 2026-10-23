#!/bin/bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "ERROR: run as root" >&2
  exit 1
fi

SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR=/opt/dns-manager/dns-manager


migrate_legacy_dns_manager_catchall() {
  local legacy=/etc/nginx/sites-enabled/dns-manager
  [[ -e "$legacy" || -L "$legacy" ]] || return 0

  # Only remove the old DNS Manager catch-all that proxied every unknown Host
  # to the local FastAPI service. Leave unrelated/custom site files untouched.
  if grep -Eq 'server_name[[:space:]]+_[[:space:]]*;' "$legacy" \
     && grep -Eq 'proxy_pass[[:space:]]+http://127\.0\.0\.1:8500[[:space:]]*;' "$legacy"; then
    rm -f "$legacy"
  fi
}

check_foreign_nginx_default_server() {
  local managed=/etc/nginx/conf.d/00-dns-manager-default-deny.conf
  local dump current line
  if [[ ! -x /usr/sbin/nginx ]]; then
    echo "ERROR: nginx is required but /usr/sbin/nginx is missing" >&2
    return 1
  fi
  if ! dump="$(/usr/sbin/nginx -T 2>&1)"; then
    echo "ERROR: existing nginx configuration is invalid; refusing to install direct-IP deny vhost" >&2
    printf '%s\n' "$dump" >&2
    return 1
  fi
  current=""
  while IFS= read -r line; do
    if [[ "$line" =~ ^#[[:space:]]configuration[[:space:]]file[[:space:]]([^:]+): ]]; then
      current="${BASH_REMATCH[1]}"
      continue
    fi
    if [[ "$line" =~ listen[[:space:]].*default_server ]] && [[ "$current" != "$managed" ]]; then
      echo "ERROR: another nginx default_server already exists in ${current:-unknown config}; disable it before installing DNS Manager direct-IP protection" >&2
      return 1
    fi
  done <<< "$dump"
}

if ! getent group dnsmanager >/dev/null; then
  groupadd --system dnsmanager
fi
if ! id dnsmanager >/dev/null 2>&1; then
  useradd --system --gid dnsmanager --home-dir /nonexistent --shell /usr/sbin/nologin dnsmanager
fi

mkdir -p /opt/dns-manager /etc/dns-manager
if [[ "$(realpath "$SOURCE_ROOT")" != "$(realpath -m "$APP_DIR")" ]]; then
  rm -rf "$APP_DIR.new"
  mkdir -p "$APP_DIR.new"
  cp -a "$SOURCE_ROOT/." "$APP_DIR.new/"
  chown -R root:dnsmanager "$APP_DIR.new"
  chmod -R g=rX,o= "$APP_DIR.new"
  if [[ -d "$APP_DIR" ]]; then
    mv "$APP_DIR" "${APP_DIR}.previous.$(date -u +%Y%m%dT%H%M%SZ)"
  fi
  mv "$APP_DIR.new" "$APP_DIR"
fi

# The installer may be launched from the live application directory. If that
# directory was just moved aside during the atomic package swap, Python would
# otherwise keep the stale cwd ahead of PYTHONPATH and import old modules.
cd /

/usr/bin/python3 -m pip install --break-system-packages --ignore-installed 'cryptography>=42,<47' 'dnspython>=2.6,<3'
/usr/bin/python3 -m pip install --break-system-packages -r "$APP_DIR/requirements.txt"

if ! command -v certbot >/dev/null 2>&1 || ! /usr/bin/python3 -c 'import certbot_dns_cloudflare' >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y certbot python3-certbot-dns-cloudflare
fi

# Legacy self-hosted ACME DNS is optional in 0.4.x. Hosted ACME-DNS does not require Knot.
if [[ "${DNS_MANAGER_ENABLE_LEGACY_ACME_DNS:-false}" == "true" ]]; then
  # Knot is installed for the optional ACME authoritative DNS subsystem, but it
  # must not auto-start during package installation because port 53 is network-specific.
  KNOT_INSTALLED_BY_DNS_MANAGER=false
  NEED_KNOT=false
  NEED_ACL=false
  if ! command -v knotd >/dev/null 2>&1; then NEED_KNOT=true; fi
  if ! command -v setfacl >/dev/null 2>&1; then NEED_ACL=true; fi
  if ! command -v knotd >/dev/null 2>&1 || ! command -v setfacl >/dev/null 2>&1; then
    apt-get update
    POLICY_RCD=/usr/sbin/policy-rc.d
    POLICY_BACKUP="$(mktemp /tmp/dns-manager-policy-rc.d.XXXXXX)"
    POLICY_HAD_ORIGINAL=false
    restore_policy_rcd() {
      if $POLICY_HAD_ORIGINAL; then
        cp -a "$POLICY_BACKUP" "$POLICY_RCD"
      else
        rm -f "$POLICY_RCD"
      fi
      rm -f "$POLICY_BACKUP"
    }
    if [[ -e "$POLICY_RCD" ]]; then
      cp -a "$POLICY_RCD" "$POLICY_BACKUP"
      POLICY_HAD_ORIGINAL=true
    fi
    printf '#!/bin/sh\nexit 101\n' > "$POLICY_RCD"
    chmod 0755 "$POLICY_RCD"
    trap restore_policy_rcd EXIT
    DEBIAN_FRONTEND=noninteractive apt-get install -y knot acl
    if $NEED_KNOT; then KNOT_INSTALLED_BY_DNS_MANAGER=true; fi
    restore_policy_rcd
    trap - EXIT
  fi
  if $KNOT_INSTALLED_BY_DNS_MANAGER; then
    systemctl disable --now knot.service 2>/dev/null || true
  fi

fi

install -d -o root -g root -m 0755 /usr/local/libexec /usr/local/sbin

install -o root -g root -m 0755 "$APP_DIR/privileged/dns-manager-helper-server" /usr/local/libexec/dns-manager-helper-server
install -o root -g root -m 0755 "$APP_DIR/privileged/dns-manager-firewall-rollback" /usr/local/libexec/dns-manager-firewall-rollback
install -o root -g root -m 0755 "$APP_DIR/privileged/manual_dns_hook.py" /usr/local/libexec/dns-manager-manual-dns-hook
install -o root -g root -m 0755 "$APP_DIR/privileged/dns-manager-acme-dns-hook" /usr/local/libexec/dns-manager-acme-dns-hook
install -o root -g root -m 0755 "$APP_DIR/privileged/dns-manager-hosted-acme-hook" /usr/local/libexec/dns-manager-hosted-acme-hook
install -o root -g root -m 0755 "$APP_DIR/privileged/dns-manager-helper" /usr/local/sbin/dns-manager-helper
install -o root -g root -m 0644 "$APP_DIR/packaging/systemd/dns-manager.service" /etc/systemd/system/dns-manager.service
install -o root -g root -m 0644 "$APP_DIR/packaging/systemd/dns-manager-helper.service" /etc/systemd/system/dns-manager-helper.service
install -o root -g root -m 0644 "$APP_DIR/packaging/systemd/dns-manager-helper.socket" /etc/systemd/system/dns-manager-helper.socket
install -o root -g root -m 0644 "$APP_DIR/packaging/systemd/dns-manager-firewall-rollback@.service" /etc/systemd/system/dns-manager-firewall-rollback@.service
install -o root -g root -m 0644 "$APP_DIR/packaging/tmpfiles.d/dns-manager.conf" /etc/tmpfiles.d/dns-manager.conf
install -o root -g root -m 0644 "$APP_DIR/packaging/knot/dns-manager-acme.conf.example" /etc/dns-manager/acme-dns.conf.example
install -o root -g root -m 0644 "$APP_DIR/packaging/knot/knot.conf.fragment" /etc/dns-manager/knot.conf.fragment
if [[ ! -e /etc/dns-manager/acme-dns.conf ]]; then
  install -o root -g root -m 0600 "$APP_DIR/packaging/knot/dns-manager-acme.conf.example" /etc/dns-manager/acme-dns.conf
fi
install -o root -g root -m 0644 "$APP_DIR/packaging/hosted-acme/hosted-acme.conf.example" /etc/dns-manager/hosted-acme.conf.example
if [[ ! -e /etc/dns-manager/hosted-acme.conf ]]; then
  install -o root -g dnsmanager -m 0640 "$APP_DIR/packaging/hosted-acme/hosted-acme.conf.example" /etc/dns-manager/hosted-acme.conf
fi
# The unprivileged application reads hosted provider settings directly.
# Keep the file root-owned, grant only the dnsmanager group read access,
# and repair permissions on upgrades from 0.4.0.
chown root:dnsmanager /etc/dns-manager/hosted-acme.conf
chmod 0640 /etc/dns-manager/hosted-acme.conf

install -o root -g root -m 0644 "$APP_DIR/packaging/systemd/dns-manager-ssl-renew.service" /etc/systemd/system/dns-manager-ssl-renew.service
install -o root -g root -m 0644 "$APP_DIR/packaging/systemd/dns-manager-ssl-renew.timer" /etc/systemd/system/dns-manager-ssl-renew.timer
install -o root -g root -m 0755 "$APP_DIR/packaging/dns-manager-ssl-renew" /usr/local/sbin/dns-manager-ssl-renew
if [[ ! -s /etc/dns-manager/ssl-secret.key ]]; then
  /usr/bin/python3 - <<'PYKEY'
from cryptography.fernet import Fernet
from pathlib import Path
p=Path('/etc/dns-manager/ssl-secret.key'); p.write_bytes(Fernet.generate_key()+b'\n')
PYKEY
  chown root:root /etc/dns-manager/ssl-secret.key
  chmod 0600 /etc/dns-manager/ssl-secret.key
fi

# Remove the legacy sudo privilege path. Keep unrelated drop-ins such as network.conf.
rm -f /etc/sudoers.d/dns-manager
rm -f /etc/systemd/system/dns-manager.service.d/privileged-helper.conf

systemd-tmpfiles --create /etc/tmpfiles.d/dns-manager.conf
if [[ ! -x /usr/sbin/ufw ]]; then echo "DNS Manager firewall management: UFW not installed; feature will remain unavailable."; fi
# Root-only helper state lives outside the service-owned /var/lib/dns-manager tree,
# where the service user could rename or replace a root-owned subdirectory.
HELPER_STATE=/var/lib/dns-manager-helper
install -d -o root -g root -m 0700 "$HELPER_STATE" "$HELPER_STATE/config" "$HELPER_STATE/config/known-good" "$HELPER_STATE/acme" "$HELPER_STATE/firewall"
# One-time move of firewall state from its old location (still root-owned
# here, before the chown below).
if [[ -d /var/lib/dns-manager/firewall && ! -L /var/lib/dns-manager/firewall && ! -e "$HELPER_STATE/firewall/current-managed.json" ]]; then
  find /var/lib/dns-manager/firewall -maxdepth 1 -type f -user root -exec cp -p {} "$HELPER_STATE/firewall/" \;
fi
# Seed known-good from the root-owned live files; the old service-writable copy is not trusted.
for pair in "/etc/dnsmasq.d/dns-manager.conf:dnsmasq.conf" "/etc/nginx/conf.d/dns-manager.conf:nginx.conf"; do
  live="${pair%%:*}"; good="$HELPER_STATE/config/known-good/${pair##*:}"
  if [[ ! -e "$good" && -f "$live" ]]; then install -o root -g root -m 0644 "$live" "$good"; fi
done
chown -R root:root "$HELPER_STATE"
find "$HELPER_STATE" -type d -exec chmod 0700 {} +
find "$HELPER_STATE/firewall" -type f -exec chmod 0600 {} +
chown -R dnsmanager:dnsmanager /var/lib/dns-manager
chmod 0750 /var/lib/dns-manager
if [[ "${DNS_MANAGER_ENABLE_LEGACY_ACME_DNS:-false}" == "true" ]] && getent group knot >/dev/null; then
  install -d -o root -g knot -m 0750 /var/lib/dns-manager/acme-dns
  chown -R root:knot /var/lib/dns-manager/acme-dns
  find /var/lib/dns-manager/acme-dns -type f -exec chmod 0640 {} +
  setfacl -m u:knot:--x /var/lib/dns-manager
fi

# Validate the pre-existing dnsmasq safety base file before starting services.
# The installer never overwrites this network-specific configuration.
DNS_BASE=/etc/dnsmasq.d/00-dns-manager-base.conf
EXPLICIT_DNS_IP="${DNS_MANAGER_INTERNAL_PROXY_IP:-}"
EXPECTED_DNS_IP="$EXPLICIT_DNS_IP"
if [[ -z "$EXPECTED_DNS_IP" && -f /etc/systemd/system/dns-manager.service.d/zz-internal-proxy.conf ]]; then
  EXPECTED_DNS_IP="$(sed -n 's/.*DNS_MANAGER_INTERNAL_PROXY_IP=\([^"[:space:]]*\).*/\1/p' /etc/systemd/system/dns-manager.service.d/zz-internal-proxy.conf | tail -1)"
fi
if [[ -z "$EXPECTED_DNS_IP" && -f /etc/systemd/system/dns-manager.service.d/network.conf ]]; then
  EXPECTED_DNS_IP="$(sed -n 's/.*DNS_MANAGER_INTERNAL_PROXY_IP=\([^"[:space:]]*\).*/\1/p' /etc/systemd/system/dns-manager.service.d/network.conf | tail -1)"
fi
if [[ -z "$EXPECTED_DNS_IP" ]]; then
  echo "ERROR: DNS_MANAGER_INTERNAL_PROXY_IP is required for dnsmasq safety validation" >&2
  exit 1
fi
if [[ ! -f "$DNS_BASE" ]]; then
  echo "ERROR: required dnsmasq safety base config is missing: $DNS_BASE" >&2
  exit 1
fi

if [[ -n "$EXPLICIT_DNS_IP" ]]; then
  PYTHONPATH="$APP_DIR" /usr/bin/python3 -m app.services.dns_safety \
    --reconcile-base "$DNS_BASE" \
    --expected-ip "$EXPECTED_DNS_IP"
  install -d -o root -g root -m 0755 /etc/systemd/system/dns-manager.service.d
  cat > /etc/systemd/system/dns-manager.service.d/zz-internal-proxy.conf <<EOF
[Service]
Environment=DNS_MANAGER_INTERNAL_PROXY_IP=$EXPECTED_DNS_IP
EOF
  chmod 0644 /etc/systemd/system/dns-manager.service.d/zz-internal-proxy.conf
else
  PYTHONPATH="$APP_DIR" /usr/bin/python3 -m app.services.dns_safety \
    --check-base "$DNS_BASE" \
    --expected-ip "$EXPECTED_DNS_IP"
fi

# Remove only the legacy DNS Manager generic catch-all before installing the
# managed fail-closed default vhost. Keep rollback material until nginx -t
# confirms that the complete migration is valid.
LEGACY_NGINX_SITE=/etc/nginx/sites-enabled/dns-manager
LEGACY_NGINX_BACKUP=""
LEGACY_NGINX_LINK=""
if [[ -L "$LEGACY_NGINX_SITE" ]]; then
  LEGACY_NGINX_LINK="$(readlink "$LEGACY_NGINX_SITE")"
elif [[ -f "$LEGACY_NGINX_SITE" ]]; then
  LEGACY_NGINX_BACKUP="$(mktemp /tmp/dns-manager-legacy-site.XXXXXX)"
  cp -a "$LEGACY_NGINX_SITE" "$LEGACY_NGINX_BACKUP"
fi
migrate_legacy_dns_manager_catchall

# Existing 0.5.6 generated mapping configs may still contain port-80 proxy
# blocks for domains now owned by an SSL redirect vhost. Remove only those
# blocks from the DNS Manager generated file; future Apply operations generate
# the deduplicated form directly.
NGINX_MAPPING=/etc/nginx/conf.d/dns-manager.conf
NGINX_MAPPING_BACKUP=""
if [[ -f "$NGINX_MAPPING" ]]; then
  NGINX_MAPPING_BACKUP="$(mktemp /tmp/dns-manager-nginx-mapping.XXXXXX)"
  cp -a "$NGINX_MAPPING" "$NGINX_MAPPING_BACKUP"
  PYTHONPATH="$APP_DIR" /usr/bin/python3 -m app.services.nginx_dedup \
    --config "$NGINX_MAPPING" --confd /etc/nginx/conf.d
fi

# Install a fail-closed Nginx default vhost so direct-IP and unknown-host
# requests never reach the DNS Manager UI or a mapped upstream. Refuse to
# override a foreign default_server because doing so could steal unrelated
# traffic from another application on the host.
check_foreign_nginx_default_server
NGINX_DENY_SRC="$APP_DIR/packaging/nginx/dns-manager-default-deny.conf"
NGINX_DENY_DST=/etc/nginx/conf.d/00-dns-manager-default-deny.conf
NGINX_DENY_BACKUP=""
if [[ -e "$NGINX_DENY_DST" ]]; then
  NGINX_DENY_BACKUP="$(mktemp /tmp/dns-manager-nginx-deny.XXXXXX)"
  cp -a "$NGINX_DENY_DST" "$NGINX_DENY_BACKUP"
fi
install -o root -g root -m 0644 "$NGINX_DENY_SRC" "$NGINX_DENY_DST"
if ! /usr/sbin/nginx -t; then
  if [[ -n "$NGINX_DENY_BACKUP" ]]; then
    cp -a "$NGINX_DENY_BACKUP" "$NGINX_DENY_DST"
  else
    rm -f "$NGINX_DENY_DST"
  fi
  if [[ -n "$NGINX_MAPPING_BACKUP" ]]; then
    cp -a "$NGINX_MAPPING_BACKUP" "$NGINX_MAPPING"
  fi
  if [[ -n "$LEGACY_NGINX_LINK" && ! -e "$LEGACY_NGINX_SITE" && ! -L "$LEGACY_NGINX_SITE" ]]; then
    ln -s "$LEGACY_NGINX_LINK" "$LEGACY_NGINX_SITE"
  elif [[ -n "$LEGACY_NGINX_BACKUP" && ! -e "$LEGACY_NGINX_SITE" ]]; then
    cp -a "$LEGACY_NGINX_BACKUP" "$LEGACY_NGINX_SITE"
  fi
  rm -f "$NGINX_DENY_BACKUP" "$NGINX_MAPPING_BACKUP" "$LEGACY_NGINX_BACKUP"
  echo "ERROR: nginx validation failed after DNS Manager vhost migration; previous state restored" >&2
  exit 1
fi
rm -f "$NGINX_DENY_BACKUP" "$NGINX_MAPPING_BACKUP" "$LEGACY_NGINX_BACKUP"
systemctl reload nginx

# Upgrade the schema explicitly during installation.  Run as dnsmanager so
# SQLite/WAL files remain owned by the service account.
cd "$APP_DIR"
runuser -u dnsmanager -- env PYTHONPATH="$APP_DIR" /usr/bin/python3 -m alembic upgrade head

systemctl daemon-reload
if [[ -n "$EXPLICIT_DNS_IP" ]]; then
  systemctl restart dnsmasq
fi
systemctl enable --now dns-manager-helper.socket
# The helper is socket-activated and can survive package replacement with old
# Python code in memory, so force it to reload the freshly installed release.
systemctl restart dns-manager-helper.service
systemctl enable --now dns-manager.service
# enable --now does not reload a previously running Gunicorn process after
# swapping application files. Always start fresh workers for this release.
systemctl restart dns-manager.service

# A systemd unit can be "active" before Gunicorn binds 127.0.0.1:8500.
# Wait for the actual app health endpoint before reporting install success.
wait_for_dns_manager_health() {
  local attempt
  for ((attempt=1; attempt<=30; attempt++)); do
    if curl --fail --silent --show-error --max-time 2 \
      http://127.0.0.1:8500/health >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "ERROR: DNS Manager health readiness timed out after 30 attempts; check journalctl -u dns-manager.service" >&2
  return 1
}
if ! wait_for_dns_manager_health; then
  exit 1
fi
systemctl enable --now dns-manager-ssl-renew.timer

echo "DNS Manager $(cat "$APP_DIR/VERSION") installed."
