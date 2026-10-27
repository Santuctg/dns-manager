from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SYSTEMD = ROOT / "packaging" / "systemd"


def text(name: str) -> str:
    return (SYSTEMD / name).read_text()


def test_application_service_restores_no_new_privileges_and_does_not_mount_etc_writable():
    unit = text("dns-manager.service")
    assert "NoNewPrivileges=true" in unit
    assert "ProtectSystem=strict" in unit
    assert "ReadWritePaths=/var/lib/dns-manager /run/dns-manager" in unit
    assert "/etc/dnsmasq.d" not in unit
    assert "/etc/nginx/conf.d" not in unit
    assert "ExecStartPre=/usr/bin/python3 -m alembic upgrade head" in unit


def test_privileged_helper_socket_is_group_restricted():
    unit = text("dns-manager-helper.socket")
    assert "ListenStream=/run/dns-manager/helper.sock" in unit
    assert "SocketMode=0660" in unit
    assert "SocketUser=root" in unit
    assert "SocketGroup=dnsmanager" in unit


def test_privileged_helper_service_is_root_and_only_managed_paths_are_writable():
    unit = text("dns-manager-helper.service")
    assert "User=root" in unit
    assert "NoNewPrivileges=true" in unit
    assert "ProtectSystem=strict" in unit
    assert "ReadWritePaths=/var/lib/dns-manager -/var/lib/dns-manager-acme-dns /var/lib/dns-manager-helper /etc/dnsmasq.d /etc/nginx/conf.d /etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt /var/log/nginx /var/lib/nginx /etc/ufw /etc/default/ufw /lib/ufw /run/dns-manager /run/systemd" in unit
    assert "ExecStart=/usr/local/libexec/dns-manager-helper-server" in unit
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK" in unit


def test_tmpfiles_and_installer_define_expected_permissions_and_remove_legacy_sudo_path():
    tmpfiles = (ROOT / "packaging" / "tmpfiles.d" / "dns-manager.conf").read_text()
    installer = (ROOT / "packaging" / "install.sh").read_text()
    assert "d /var/lib/dns-manager 0750 dnsmanager dnsmanager" in tmpfiles
    assert "d /run/dns-manager 0750 dnsmanager dnsmanager" in tmpfiles
    assert "/etc/sudoers.d/dns-manager" in installer
    assert "privileged-helper.conf" in installer
    assert "install -d -o root -g root -m 0755 /usr/local/libexec /usr/local/sbin" in installer
    assert "dns-manager-helper.socket" in installer
    assert "systemctl enable --now dns-manager-helper.socket" in installer


def test_package_has_version_metadata():
    version = (ROOT / "VERSION").read_text().strip()
    assert version == "0.7.5"


def test_installer_overlays_python_crypto_dependencies_before_requirements():
    text = (ROOT / 'packaging/install.sh').read_text()
    overlay = "pip install --break-system-packages --ignore-installed 'cryptography>=42,<47' 'dnspython>=2.6,<3'"
    assert overlay in text
    assert text.index(overlay) < text.index('pip install --break-system-packages -r')


def test_app_service_allows_long_running_certbot_requests():
    unit = text("dns-manager.service")
    assert "--timeout 360" in unit


def test_acme_delegation_packaging_installs_knot_without_auto_activation():
    installer=(ROOT/'packaging/install.sh').read_text()
    assert 'apt-get install -y knot' in installer
    assert 'policy-rc.d' in installer
    assert 'systemctl enable --now knot' not in installer
    assert 'dns-manager-acme.conf.example' in installer
    assert 'knot.conf.fragment' in installer
    assert 'dns-manager-acme-dns-hook' in installer


def test_acme_zone_storage_is_root_owned_and_outside_service_tree():
    tmpfiles=(ROOT/'packaging/tmpfiles.d/dns-manager.conf').read_text()
    helper=text('dns-manager-helper.service')
    fragment=(ROOT/'packaging/knot/knot.conf.fragment').read_text()
    installer=(ROOT/'packaging/install.sh').read_text()
    assert '/var/lib/dns-manager/acme-dns' not in tmpfiles
    # Optional path: the unit must still start when the legacy feature is off.
    assert ' -/var/lib/dns-manager-acme-dns ' in helper
    assert 'storage: /var/lib/dns-manager-acme-dns' in fragment
    assert 'install -d -o root -g knot -m 0750 "$ACME_DNS_STATE"' in installer


def test_release_version_is_042_metadata():
    assert (ROOT/'VERSION').read_text().strip()=='0.7.5'


def test_knot_no_longer_gets_access_to_the_service_owned_tree():
    installer=(ROOT/'packaging/install.sh').read_text()
    assert 'setfacl -m u:knot' not in installer
    assert 'setfacl -x u:knot /var/lib/dns-manager' in installer
    assert 'apt-get install -y knot acl' in installer


def test_installer_migrates_acme_zone_before_general_chown_and_repoints_knot():
    installer=(ROOT/'packaging/install.sh').read_text()
    general=installer.index('chown -R dnsmanager:dnsmanager /var/lib/dns-manager')
    assert installer.index("find /var/lib/dns-manager/acme-dns -maxdepth 1 -type f -name '*.zone' -user root") < general
    assert 'chown -R root:knot "$ACME_DNS_STATE"' in installer
    assert 'find "$ACME_DNS_STATE" -type f -exec chmod 0640 {} +' in installer
    assert "sed -i 's#storage: /var/lib/dns-manager/acme-dns#storage: /var/lib/dns-manager-acme-dns#' /etc/knot/knot.conf" in installer
    assert 'knot.conf.pre-acme-dns-move' in installer


def test_knot_install_temporarily_overrides_and_restores_policy_rcd_even_on_failure():
    installer=(ROOT/'packaging/install.sh').read_text()
    assert 'POLICY_RCD=/usr/sbin/policy-rc.d' in installer
    assert 'POLICY_BACKUP=' in installer
    assert 'trap restore_policy_rcd EXIT' in installer
    assert 'cp -a "$POLICY_RCD" "$POLICY_BACKUP"' in installer
    assert 'restore_policy_rcd' in installer


def test_acme_hook_launcher_adds_project_root_to_python_path():
    launcher=(ROOT/'privileged/dns-manager-acme-dns-hook').read_text()
    assert 'PROJECT_ROOT="/opt/dns-manager/dns-manager"' in launcher
    assert 'sys.path.insert(0, PROJECT_ROOT)' in launcher
    assert 'from privileged.acme_dns_hook import main' in launcher


def test_installer_installs_acl_even_when_knot_is_already_present():
    installer=(ROOT/'packaging/install.sh').read_text()
    assert 'if ! command -v knotd >/dev/null 2>&1 || ! command -v setfacl >/dev/null 2>&1; then' in installer
    assert 'NEED_KNOT=false' in installer
    assert 'NEED_ACL=false' in installer


def test_acme_dns_packaging_exposes_configurable_internal_listen_port():
    example = open('packaging/knot/dns-manager-acme.conf.example').read()
    fragment = open('packaging/knot/knot.conf.fragment').read()
    assert 'ACME_DNS_PORT=53' in example
    assert '__ACME_DNS_LISTEN_IP__@__ACME_DNS_PORT__' in fragment


def test_hosted_acme_config_template_is_root_managed_and_has_safe_defaults():
    root = ROOT
    example = (root/'packaging/hosted-acme/hosted-acme.conf.example').read_text()
    assert 'HOSTED_ACME_ENABLED=true' in example
    assert 'HOSTED_ACME_SERVER_URL=https://auth.acme-dns.io' in example
    assert 'HOSTED_ACME_HTTP_TIMEOUT=15' in example
    assert 'HOSTED_ACME_PROPAGATION_TIMEOUT=120' in example


def test_hosted_release_installs_hosted_hook_and_config_without_default_knot_dependency():
    installer=(ROOT/'packaging/install.sh').read_text()
    assert 'dns-manager-hosted-acme-hook' in installer
    assert 'hosted-acme.conf.example' in installer
    assert 'DNS_MANAGER_ENABLE_LEGACY_ACME_DNS' in installer
    assert 'if [[ "${DNS_MANAGER_ENABLE_LEGACY_ACME_DNS:-false}" == "true" ]]' in installer


def test_hosted_release_version_is_042():
    assert (ROOT/'VERSION').read_text().strip()=='0.7.5'


def test_041_installer_migrates_database_explicitly_before_starting_application_service():
    installer=(ROOT/'packaging/install.sh').read_text()
    migrate='runuser -u dnsmanager -- env PYTHONPATH="$APP_DIR" /usr/bin/python3 -m alembic upgrade head'
    start='systemctl enable --now dns-manager.service'
    assert migrate in installer
    assert installer.index(migrate) < installer.index(start)


def test_041_installer_makes_hosted_config_readable_by_dnsmanager_without_world_access():
    installer=(ROOT/'packaging/install.sh').read_text()
    assert 'install -o root -g dnsmanager -m 0640 "$APP_DIR/packaging/hosted-acme/hosted-acme.conf.example" /etc/dns-manager/hosted-acme.conf' in installer
    assert 'chown root:dnsmanager /etc/dns-manager/hosted-acme.conf' in installer
    assert 'chmod 0640 /etc/dns-manager/hosted-acme.conf' in installer


def test_041_installer_restarts_privileged_helper_after_installing_new_code():
    installer=(ROOT/'packaging/install.sh').read_text()
    socket='systemctl enable --now dns-manager-helper.socket'
    restart='systemctl restart dns-manager-helper.service'
    app='systemctl enable --now dns-manager.service'
    assert restart in installer
    assert installer.index(socket) < installer.index(restart) < installer.index(app)


def test_release_version_is_042():
    assert (ROOT/'VERSION').read_text().strip()=='0.7.5'


def test_053_installer_escapes_replaced_working_directory_before_python_module_calls():
    installer=(ROOT/'packaging/install.sh').read_text()
    swap='mv "$APP_DIR.new" "$APP_DIR"'
    escape='cd /'
    reconcile='PYTHONPATH="$APP_DIR" /usr/bin/python3 -m app.services.dns_safety'
    assert swap in installer
    assert reconcile in installer
    assert escape in installer
    assert installer.index(swap) < installer.index(escape) < installer.index(reconcile)


def test_056_packaging_blocks_direct_ip_and_unknown_hosts_by_default():
    deny = (ROOT / 'packaging/nginx/dns-manager-default-deny.conf').read_text()
    assert 'listen 80 default_server;' in deny
    assert 'server_name _;' in deny
    assert 'return 444;' in deny
    assert 'listen 443 ssl default_server;' in deny
    assert 'ssl_reject_handshake on;' in deny


def test_056_installer_detects_foreign_default_server_before_installing_deny_vhost():
    installer = (ROOT / 'packaging/install.sh').read_text()
    assert 'check_foreign_nginx_default_server' in installer
    assert 'another nginx default_server already exists' in installer
    assert '00-dns-manager-default-deny.conf' in installer
    check = installer.index('check_foreign_nginx_default_server')
    install = installer.index('packaging/nginx/dns-manager-default-deny.conf')
    assert check < install


def test_056_installer_validates_and_reloads_nginx_after_installing_deny_vhost():
    installer = (ROOT / 'packaging/install.sh').read_text()
    install = installer.index('packaging/nginx/dns-manager-default-deny.conf')
    test = installer.index('/usr/sbin/nginx -t', install)
    reload = installer.index('systemctl reload nginx', test)
    assert install < test < reload


def test_057_installer_disables_only_legacy_dns_manager_catchall_before_default_deny():
    installer = (ROOT / 'packaging/install.sh').read_text()
    assert 'migrate_legacy_dns_manager_catchall' in installer
    assert '/etc/nginx/sites-enabled/dns-manager' in installer
    assert 'server_name[[:space:]]+_' in installer
    assert 'proxy_pass[[:space:]]+http://127\\.0\\.0\\.1:8500' in installer
    assert 'rm -f "$legacy"' in installer
    migrate = installer.index('migrate_legacy_dns_manager_catchall')
    check = installer.index('check_foreign_nginx_default_server')
    assert migrate < check


def test_058_packages_firewall_rollback_without_enabling_ufw():
    installer=(ROOT/'packaging/install.sh').read_text()
    tmpfiles=(ROOT/'packaging/tmpfiles.d/dns-manager.conf').read_text()
    unit=(ROOT/'packaging/systemd/dns-manager-firewall-rollback@.service').read_text()
    assert 'dns-manager-firewall-rollback@.service' in installer
    assert 'dns-manager-firewall-rollback' in installer
    assert 'd /var/lib/dns-manager-helper/firewall 0700 root root -' in tmpfiles
    assert 'ReadWritePaths=/var/lib/dns-manager-helper/firewall ' in unit
    assert 'ExecStart=/bin/sleep 120' in unit
    assert '/usr/local/libexec/dns-manager-firewall-rollback %i' in unit
    assert 'ufw enable' not in installer
    assert 'ufw reset' not in installer

def test_helper_private_state_is_root_only_and_outside_service_owned_tree():
    installer=(ROOT/'packaging/install.sh').read_text()
    tmpfiles=(ROOT/'packaging/tmpfiles.d/dns-manager.conf').read_text()
    for sub in ('', '/config', '/config/known-good', '/acme', '/firewall'):
        assert f'd /var/lib/dns-manager-helper{sub} 0700 root root -' in tmpfiles
    # The old service-writable locations must no longer be provisioned.
    assert '/var/lib/dns-manager/known-good' not in tmpfiles
    assert 'd /var/lib/dns-manager/acme ' not in tmpfiles
    assert 'd /var/lib/dns-manager/firewall ' not in tmpfiles
    general=installer.index('chown -R dnsmanager:dnsmanager /var/lib/dns-manager')
    # Old firewall state is copied while it is still root-owned, i.e. before the general chown.
    assert installer.index('find /var/lib/dns-manager/firewall -maxdepth 1 -type f -user root') < general
    assert 'chown -R root:root "$HELPER_STATE"' in installer
    assert 'find "$HELPER_STATE/firewall" -type f -exec chmod 0600 {} +' in installer


def test_058_helper_sandbox_allows_ufw_netlink_without_shell_access():
    helper=text('dns-manager-helper.service')
    rollback=text('dns-manager-firewall-rollback@.service')
    assert 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' in helper
    assert 'ProtectKernelTunables=false' in helper
    assert '/etc/default/ufw' in helper
    assert '/etc/default/ufw' in rollback


def test_067_installer_restarts_app_after_upgrade_and_waits_for_health():
    installer = (ROOT / 'packaging/install.sh').read_text()
    helper_restart = installer.index('systemctl restart dns-manager-helper.service')
    app_enable = installer.index('systemctl enable --now dns-manager.service')
    app_restart = installer.index('systemctl restart dns-manager.service')
    readiness = installer.index('wait_for_dns_manager_health')
    success = installer.index('echo "DNS Manager $(cat "$APP_DIR/VERSION") installed."')
    assert helper_restart < app_enable < app_restart < readiness < success
    assert 'http://127.0.0.1:8500/health' in installer
    assert 'curl --fail --silent --show-error' in installer
    assert 'sleep 1' in installer
    assert 'ERROR: DNS Manager health readiness timed out' in installer
    assert 'exit 1' in installer


def test_067_release_version_metadata():
    assert (ROOT / 'VERSION').read_text().strip() == '0.7.5'
