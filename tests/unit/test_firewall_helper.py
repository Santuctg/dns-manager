from pathlib import Path
from privileged.firewall_helper import FirewallHelperOps, UFW, SYSTEMCTL

class R:
    def __init__(self,code=0,out='',err=''): self.returncode=code; self.stdout=out; self.stderr=err
class Runner:
    def __init__(self): self.calls=[]
    def __call__(self,argv,**kw):
        self.calls.append(argv)
        if argv[:3]==[UFW,'status','verbose']: return R(out='Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n')
        if argv[:3]==[UFW,'status','numbered']: return R(out='[ 1] 443/tcp ALLOW IN Anywhere # DNSMGR:1:tcp\n[ 2] 22/tcp ALLOW IN 10.0.0.0/8 # manual\n')
        if argv[0].endswith('/ss'): return R(out='LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n')
        return R()

def test_status_counts_managed_and_unmanaged_and_ssh(tmp_path):
    r=Runner(); s=FirewallHelperOps(runner=r,state_dir=tmp_path).status()
    assert s['active'] is True and s['managed_count']==1 and s['unmanaged_count']==1
    assert s['ssh_ports']==[2222]

def test_preview_rejects_unknown_fields(tmp_path):
    ops=FirewallHelperOps(runner=Runner(),state_dir=tmp_path)
    try: ops.preview({'enabled':False,'default_incoming':'deny','default_outgoing':'allow','operations':[],'evil':1})
    except ValueError as e: assert 'unsupported' in str(e)
    else: assert False

def test_both_protocol_is_already_expanded_and_apply_arms_rollback(tmp_path):
    import json
    r=Runner(); ops=FirewallHelperOps(runner=r,state_dir=tmp_path)
    (tmp_path/'current-managed.json').write_text(json.dumps({'enabled':True,'default_incoming':'deny','default_outgoing':'allow','operations':[{'action':'allow','protocol':'tcp','port':'443','source':'0.0.0.0/0','comment':'DNSMGR:1:tcp'}]}))
    payload={'enabled':True,'default_incoming':'deny','default_outgoing':'allow','revision':3,'operations':[{'action':'allow','protocol':'tcp','port':'2222','source':'203.0.113.4/32','comment':'DNSMGR:9:tcp'}]}
    result=ops.apply(payload)
    assert result['pending_confirmation'] is True and result['rollback_seconds']==120
    assert any(c[:3]==[SYSTEMCTL,'--no-block','start'] for c in r.calls)

def test_delete_managed_uses_show_added_when_numbered_status_has_no_rules(tmp_path):
    """Managed UFW rules must be removable even while UFW is inactive."""

    class InactiveRunner:
        def __init__(self):
            self.calls = []

        def __call__(self, argv, **kw):
            self.calls.append(argv)

            if argv[:3] == [UFW, 'status', 'numbered']:
                return R(out='Status: inactive\n')

            if argv[:3] == [UFW, 'show', 'added']:
                return R(out=(
                    "Added user rules (see 'ufw status' for running firewall):\n"
                    "ufw allow 80/tcp comment 'DNSMGR:1:tcp'\n"
                    "ufw allow 80/udp comment 'DNSMGR:1:udp'\n"
                    "ufw allow from 10.0.0.0/8 to any port 22 proto tcp comment 'manual ssh'\n"
                ))

            return R()

    r = InactiveRunner()
    ops = FirewallHelperOps(runner=r, state_dir=tmp_path)

    ops._delete_managed()

    assert [
        UFW,
        '--force',
        'delete',
        'allow',
        '80/tcp',
        'comment',
        'DNSMGR:1:tcp',
    ] in r.calls

    assert [
        UFW,
        '--force',
        'delete',
        'allow',
        '80/udp',
        'comment',
        'DNSMGR:1:udp',
    ] in r.calls

    assert not any(
        'manual ssh' in ' '.join(call)
        and 'delete' in call
        for call in r.calls
    )


def test_helper_multi_source_comments_are_strict_and_bounded(tmp_path):
    import pytest
    helper=FirewallHelperOps(runner=Runner(),state_dir=tmp_path)
    base={'enabled':True,'default_incoming':'deny','default_outgoing':'allow'}
    def op(comment): return {'action':'allow','protocol':'tcp','port':'2222','source':'203.0.113.4/32','comment':comment}
    helper.preview({**base,'operations':[op('DNSMGR:9:0:tcp'),op('DNSMGR:9:1:tcp'),op('DNSMGR:9:tcp')]})
    for bad in ('DNSMGR:9:evil','DNSMGR:9:0:tcp;evil','DNSMGR:9:999999999999999999999999:tcp','DNSMGR:garbage'):
        with pytest.raises(ValueError): helper.preview({**base,'operations':[op(bad)]})
    with pytest.raises(ValueError): helper.preview({**base,'operations':[op('DNSMGR:9:0:tcp')]*513})
    with pytest.raises(ValueError): helper.preview({**base,'operations':[op('DNSMGR:9:0:tcp'),op('DNSMGR:9:0:tcp')]})

def test_multi_source_apply_confirm_and_rollback_restore_exact_old_manifest(tmp_path):
    import json
    runner=Runner()
    ops=FirewallHelperOps(runner=runner,state_dir=tmp_path)
    old={'enabled':True,'default_incoming':'deny','default_outgoing':'allow','operations':[
        {'action':'allow','protocol':'tcp','port':'2222','source':'203.0.113.4/32','comment':'DNSMGR:9:tcp'},
        {'action':'allow','protocol':'tcp','port':'2222','source':'198.51.100.0/24','comment':'DNSMGR:10:0:tcp'},
    ]}
    new={'enabled':True,'default_incoming':'deny','default_outgoing':'allow','revision':15,'operations':[
        {'action':'allow','protocol':'tcp','port':'2222','source':'203.0.113.4/32','comment':'DNSMGR:9:0:tcp'},
        {'action':'allow','protocol':'tcp','port':'2222','source':'192.0.2.0/24','comment':'DNSMGR:9:1:tcp'},
    ]}
    (tmp_path/'current-managed.json').write_text(json.dumps(old))
    token=ops.apply(new)['rollback_token']
    assert json.loads((tmp_path/f'{token}.rollback.json').read_text())==old
    assert ops.confirm(token)=={'confirmed':True}
    assert json.loads((tmp_path/'current-managed.json').read_text())==new
    start=len(runner.calls)
    assert ops.rollback(token)=={'rolled_back':True}
    assert json.loads((tmp_path/'current-managed.json').read_text())==old
    new_calls=runner.calls[start:]
    assert any(c[0]==UFW and '198.51.100.0/24' in c and 'DNSMGR:10:0:tcp' in c for c in new_calls)
    assert any(c[0]==UFW and '203.0.113.4/32' in c and 'DNSMGR:9:tcp' in c for c in new_calls)
