import json
from pathlib import Path
from privileged.manual_dns_hook import write_challenge_state, read_challenge_state


def test_manual_dns_state_round_trip(tmp_path):
    write_challenge_state(tmp_path,'dns.example.com','_acme-challenge.dns.example.com','abc123')
    state=read_challenge_state(tmp_path,'dns.example.com')
    assert state['challenge_name']=='_acme-challenge.dns.example.com'
    assert state['challenge_value']=='abc123'
    assert state['status']=='WAITING_DNS'


def test_manual_dns_timeout_marks_challenge_expired(tmp_path, monkeypatch):
    from privileged.manual_dns_hook import certbot_auth_hook
    monkeypatch.setenv('DNS_MANAGER_ACME_STATE_DIR', str(tmp_path))
    monkeypatch.setenv('DNS_MANAGER_ACME_WAIT_SECONDS', '0')
    monkeypatch.setenv('CERTBOT_DOMAIN', 'dns.example.com')
    monkeypatch.setenv('CERTBOT_VALIDATION', 'abc123')
    assert certbot_auth_hook() == 1
    state = read_challenge_state(tmp_path, 'dns.example.com')
    assert state['status'] == 'EXPIRED'
