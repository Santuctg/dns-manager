from pathlib import Path

def test_ssl_renew_units_and_installer_contract():
    service=Path('packaging/systemd/dns-manager-ssl-renew.service').read_text()
    timer=Path('packaging/systemd/dns-manager-ssl-renew.timer').read_text()
    install=Path('packaging/install.sh').read_text()
    app_unit=Path('packaging/systemd/dns-manager.service').read_text()
    assert 'Type=oneshot' in service
    assert 'Persistent=true' in timer
    assert 'RandomizedDelaySec=' in timer
    assert 'dns-manager-ssl-renew.timer' in install
    assert 'ssl-secret.key' in install
    assert 'LoadCredential=ssl-secret.key:/etc/dns-manager/ssl-secret.key' in app_unit

def test_installer_checks_certbot_cloudflare_plugin():
    install=Path('packaging/install.sh').read_text()
    assert 'python3-certbot-dns-cloudflare' in install
    assert 'certbot' in install

def test_renew_script_supports_acme_delegation_and_rechecks_cname():
    script=Path('packaging/dns-manager-ssl-renew').read_text()
    assert "'acme_delegation'" in script
    assert 'verify_delegation' in script
    assert 'selectinload(SslCertificate.delegation)' in script

def test_renew_script_audits_acme_success_and_failure_without_tokens():
    script=Path('packaging/dns-manager-ssl-renew').read_text()
    assert 'ACME_RENEWAL_SUCCESS' in script
    assert 'ACME_RENEWAL_FAILED' in script
    assert 'record_audit_event' in script
    assert "error_message='Automatic renewal failed'" in script

def test_renew_script_supports_hosted_acme_and_rechecks_cname():
    script=Path('packaging/dns-manager-ssl-renew').read_text()
    assert "'acme_dns_hosted'" in script
    assert 'verify_hosted_cname' in script
    assert 'selectinload(SslCertificate.hosted_acme)' in script
