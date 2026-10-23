#!/bin/bash
set -euo pipefail

PURGE_DATA=false
if [[ ${1:-} == "--purge-data" ]]; then
  PURGE_DATA=true
fi
if [[ ${EUID} -ne 0 ]]; then
  echo "ERROR: run as root" >&2
  exit 1
fi

systemctl disable --now dns-manager.service dns-manager-helper.socket dns-manager-ssl-renew.timer 2>/dev/null || true
systemctl stop dns-manager-helper.service 2>/dev/null || true
rm -f /etc/systemd/system/dns-manager.service
rm -f /etc/systemd/system/dns-manager-helper.service
rm -f /etc/systemd/system/dns-manager-helper.socket
rm -f /etc/systemd/system/dns-manager-ssl-renew.service
rm -f /etc/systemd/system/dns-manager-ssl-renew.timer
rm -f /etc/tmpfiles.d/dns-manager.conf
rm -f /usr/local/libexec/dns-manager-helper-server
rm -f /usr/local/libexec/dns-manager-manual-dns-hook
rm -f /usr/local/sbin/dns-manager-helper
rm -f /usr/local/sbin/dns-manager-ssl-renew
rm -rf /opt/dns-manager/dns-manager
systemctl daemon-reload

if $PURGE_DATA; then
  rm -rf /var/lib/dns-manager /var/lib/dns-manager-helper /etc/dns-manager
else
  echo "Preserved /var/lib/dns-manager, /var/lib/dns-manager-helper and /etc/dns-manager (use --purge-data to remove)."
fi

rm -f /usr/local/libexec/dns-manager-acme-dns-hook

rm -f /usr/local/libexec/dns-manager-hosted-acme-hook
