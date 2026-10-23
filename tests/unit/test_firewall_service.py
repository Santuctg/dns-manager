import pytest
from app.services.firewall_service import normalize_rule, validate_policy, build_preview

class P:
    enabled=True; default_incoming='deny'; default_outgoing='allow'

def rule(**kw):
    base=dict(id=1,action='allow',protocol='tcp',port_start=2222,port_end=None,source_cidr='203.0.113.4/32',purpose='ssh',enabled=True,sort_key=10,comment='mgmt')
    base.update(kw); return base

def test_normalizes_cidr_and_both_expands_in_preview():
    r=normalize_rule(rule(protocol='both',source_cidr='10.0.0.4/24'))
    assert r.source_cidr=='10.0.0.0/24'
    preview=build_preview(P(),[r])
    assert [x['protocol'] for x in preview['operations']]==['tcp','udp']
    assert all(x['comment'].startswith('DNSMGR:1:') for x in preview['operations'])

def test_rejects_bad_ranges_and_public_8500():
    with pytest.raises(ValueError): normalize_rule(rule(port_start=70000))
    v=validate_policy(P(),[rule(port_start=8500,source_cidr='0.0.0.0/0')],ssh_port=2222,source_ip='203.0.113.4')
    assert any('8500' in e for e in v.errors)

def test_world_open_dns_v4_and_v6_require_high_risk_confirmation():
    for cidr in ('0.0.0.0/0','::/0'):
        v=validate_policy(P(),[rule(port_start=53,protocol='both',purpose='dns',source_cidr=cidr),rule()],ssh_port=2222,source_ip='203.0.113.4')
        assert v.requires_high_risk_confirmation
        assert any('DNS 53' in w for w in v.warnings)

def test_restrictive_policy_requires_ssh_allow_covering_source():
    v=validate_policy(P(),[rule(source_cidr='198.51.100.0/24')],ssh_port=2222,source_ip='203.0.113.4')
    assert any('SSH' in e for e in v.errors)
    ok=validate_policy(P(),[rule(source_cidr='203.0.113.0/24')],ssh_port=2222,source_ip='203.0.113.4')
    assert ok.valid

def test_multi_source_normalization_and_preview_expansion():
    r=normalize_rule(rule(protocol='both',source_cidrs=['203.0.113.4/32','198.51.100.0/24','2001:db8::/64']))
    assert r.source_cidrs == ('203.0.113.4/32','198.51.100.0/24','2001:db8::/64')
    ops=build_preview(P(),[r])['operations']
    assert len(ops)==6
    assert len({op['comment'] for op in ops})==6
    assert ops==build_preview(P(),[r])['operations']

def test_multi_source_rejects_duplicate_and_excessive_sources():
    with pytest.raises(ValueError): normalize_rule(rule(source_cidrs=['10.1.2.3','10.1.2.3/32']))
    with pytest.raises(ValueError): normalize_rule(rule(source_cidrs=[]))
    with pytest.raises(ValueError): normalize_rule(rule(source_cidrs=[f'10.1.0.{i}/32' for i in range(33)]))

def test_multi_source_safety_checks_all_sources():
    r=rule(source_cidrs=['203.0.113.4/32','0.0.0.0/0'],port_start=8500)
    result=validate_policy(P(),[r,rule(id=2)],source_ip='203.0.113.4')
    assert any('8500' in error for error in result.errors)
    ssh=rule(source_cidrs=['198.51.100.0/24','203.0.113.4/32'])
    assert validate_policy(P(),[ssh],source_ip='203.0.113.4').valid

def test_multi_source_expansion_size_cap_and_disabled_rule():
    sources=[f'10.3.0.{i}/32' for i in range(32)]
    enabled=[rule(id=i,protocol='both',source_cidrs=sources) for i in range(1,10)]
    with pytest.raises(ValueError,match='512'):
        build_preview(P(),enabled)
    exact=build_preview(P(),enabled[:8])
    assert len(exact['operations'])==512
    assert len({x['comment'] for x in exact['operations']})==512
    assert build_preview(P(),[rule(enabled=False,source_cidrs=sources)])['operations']==[]


def test_multi_source_world_open_in_second_source_requires_confirmation():
    r=rule(id=7,source_cidrs=['203.0.113.4/32','::/0'],port_start=53,protocol='both')
    result=validate_policy(P(),[r,rule(id=1)],ssh_port=2222,source_ip='203.0.113.4')
    assert result.requires_high_risk_confirmation
    assert any('DNS 53' in warning for warning in result.warnings)


def test_multi_source_rejects_newline_and_comma():
    for bad in ('203.0.113.4/32\n','203.0.113.4/32,198.51.100.0/24'):
        with pytest.raises(ValueError): normalize_rule(rule(source_cidrs=[bad]))


def test_earlier_deny_rule_on_ssh_port_blocks_the_safe_path():
    deny=rule(id=2,action='deny',source_cidr='0.0.0.0/0',sort_key=5,comment='block-all-ssh')
    allow=rule(id=1,source_cidr='203.0.113.0/24',sort_key=10)
    v=validate_policy(P(),[allow,deny],ssh_port=2222,source_ip='203.0.113.4')
    assert not v.valid and any('block-all-ssh' in e for e in v.errors)
    # The same deny ordered after the allow is harmless: the allow matches first.
    later=rule(id=2,action='deny',source_cidr='0.0.0.0/0',sort_key=50)
    assert validate_policy(P(),[allow,later],ssh_port=2222,source_ip='203.0.113.4').valid


def test_deny_overlapping_only_part_of_management_range_is_unsafe():
    deny=rule(id=2,action='deny',source_cidr='10.0.0.128/25',sort_key=5)
    allow=rule(id=1,source_cidr='10.0.0.0/24',sort_key=10)
    v=validate_policy(P(),[deny,allow],ssh_port=2222,management_cidr='10.0.0.0/24')
    assert not v.valid
    assert validate_policy(P(),[deny,allow],ssh_port=2222,management_cidr='10.0.0.0/25').valid


def test_deny_rules_on_other_ports_protocols_or_disabled_do_not_count():
    allow=rule(id=1,source_cidr='203.0.113.0/24',sort_key=10)
    others=[rule(id=2,action='deny',source_cidr='0.0.0.0/0',sort_key=1,port_start=443),
            rule(id=3,action='deny',source_cidr='0.0.0.0/0',sort_key=2,protocol='udp'),
            rule(id=4,action='deny',source_cidr='0.0.0.0/0',sort_key=3,enabled=False),
            rule(id=5,action='deny',source_cidr='::/0',sort_key=4)]
    assert validate_policy(P(),[allow,*others],ssh_port=2222,source_ip='203.0.113.4').valid
    both=rule(id=6,action='deny',source_cidr='0.0.0.0/0',sort_key=1,protocol='both')
    assert not validate_policy(P(),[allow,both],ssh_port=2222,source_ip='203.0.113.4').valid
