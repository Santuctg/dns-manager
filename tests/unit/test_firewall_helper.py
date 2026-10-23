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


class StatefulUfw:
    """Minimal UFW model: tracks the managed rule list so rollback effects are observable."""
    def __init__(self): self.calls=[]; self.rules=[]
    def __call__(self,argv,**kw):
        self.calls.append(argv)
        if argv[:3]==[UFW,'status','verbose']: return R(out='Status: active\nDefault: deny (incoming), allow (outgoing)\n')
        if argv[:3]==[UFW,'status','numbered']: return R(out=''.join(f'[{i+1}] {r}\n' for i,r in enumerate(self.rules)))
        if argv[:3]==[UFW,'--force','delete']: self.rules.pop(int(argv[3])-1)
        elif len(argv)>1 and argv[0]==UFW and argv[1] in ('allow','deny'): self.rules.append(' '.join(argv[1:]))
        return R()

OLD={'enabled':True,'default_incoming':'deny','default_outgoing':'allow','operations':[]}
NEW={'enabled':True,'default_incoming':'deny','default_outgoing':'allow','revision':2,'operations':[
    {'action':'allow','protocol':'tcp','port':'443','source':'10.0.0.0/8','comment':'DNSMGR:1:tcp'}]}

def _applied(tmp_path):
    import json
    ufw=StatefulUfw(); ops=FirewallHelperOps(runner=ufw,state_dir=tmp_path)
    (tmp_path/'current-managed.json').write_text(json.dumps(OLD))
    token=ops.apply(NEW)['rollback_token']
    return ufw,ops,token

def test_confirm_after_emergency_rollback_is_refused_and_does_not_record_the_new_policy(tmp_path):
    import json
    ufw,ops,token=_applied(tmp_path)
    assert ops.auto_rollback(token)=={'rolled_back':True}
    assert ufw.rules==[]

    assert ops.confirm(token)=={'confirmed':False,'rolled_back':True}
    assert json.loads((tmp_path/'current-managed.json').read_text())==OLD
    assert ufw.rules==[]

def test_emergency_rollback_after_confirm_is_a_no_op(tmp_path):
    import json
    ufw,ops,token=_applied(tmp_path)
    assert ops.confirm(token)=={'confirmed':True}
    assert [SYSTEMCTL,'stop',f'dns-manager-firewall-rollback@{token}.service'] in ufw.calls
    rules=list(ufw.rules)

    # Even if stopping the timer failed, the late timer must not undo a confirmed change.
    assert ops.auto_rollback(token)=={'rolled_back':False}
    assert ufw.rules==rules
    assert json.loads((tmp_path/'current-managed.json').read_text())['operations']==NEW['operations']
    assert ops.confirm(token)=={'confirmed':True,'already_confirmed':True}

def test_explicit_rollback_of_pending_change_blocks_later_confirm(tmp_path):
    ufw,ops,token=_applied(tmp_path)
    assert ops.rollback(token)=={'rolled_back':True}
    assert ops.confirm(token)=={'confirmed':False,'rolled_back':True}
    assert ops.auto_rollback(token)=={'rolled_back':False}

def test_confirm_waits_for_an_in_progress_emergency_rollback(tmp_path):
    import threading, time
    ufw,ops,token=_applied(tmp_path)
    entered=threading.Event(); release=threading.Event()
    original=ops._restore_manifest
    def slow_restore(manifest):
        entered.set(); release.wait(5); original(manifest)
    roller=FirewallHelperOps(runner=ufw,state_dir=tmp_path); roller._restore_manifest=slow_restore
    t=threading.Thread(target=roller.auto_rollback,args=(token,)); t.start()
    assert entered.wait(5)
    result={}
    c=threading.Thread(target=lambda: result.update(ops.confirm(token))); c.start()
    time.sleep(0.2)
    assert not result, 'confirm must block while rollback holds the lock'
    release.set(); t.join(5); c.join(5)
    assert result=={'confirmed':False,'rolled_back':True}

def test_tokens_are_validated_before_touching_paths_or_unit_names(tmp_path):
    import pytest
    ops=FirewallHelperOps(runner=StatefulUfw(),state_dir=tmp_path)
    for bad in ('../../etc/passwd','abc123','x'*32,'A'*32,'0'*32+'\n',None):
        for method in (ops.confirm,ops.rollback,ops.auto_rollback):
            with pytest.raises(ValueError): method(bad)

def test_firewall_state_dir_must_be_private(tmp_path):
    import pytest
    target=tmp_path/'service-owned'; target.mkdir()
    link=tmp_path/'firewall'; link.symlink_to(target)
    ops=FirewallHelperOps(runner=StatefulUfw(),state_dir=link)
    with pytest.raises(RuntimeError): ops.confirm('0'*32)
