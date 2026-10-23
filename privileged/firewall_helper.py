from __future__ import annotations
import fcntl, json, os, re, secrets, shlex, subprocess, tempfile
from contextlib import contextmanager
from ipaddress import ip_network
from pathlib import Path
from typing import Callable
from privileged.helper_lib import PRIVATE_ROOT, ensure_private_dir

UFW='/usr/sbin/ufw'; SYSTEMCTL='/usr/bin/systemctl'; SS='/usr/bin/ss'; SSHD='/usr/sbin/sshd'
STATE_DIR=PRIVATE_ROOT/'firewall'
ROLLBACK_UNIT='dns-manager-firewall-rollback@{}.service'
_TOKEN_RE=re.compile(r'[0-9a-f]{32}')

class FirewallHelperOps:
    def __init__(self, runner:Callable|None=None, state_dir:Path=STATE_DIR):
        self.runner=runner or subprocess.run; self.state_dir=Path(state_dir)
    def _state(self):
        return ensure_private_dir(self.state_dir)
    @contextmanager
    def _locked(self):
        # Serialises confirm with the emergency rollback, which runs in another process.
        with open(self._state()/'.lock','a') as fp:
            fcntl.flock(fp.fileno(),fcntl.LOCK_EX)
            try: yield
            finally: fcntl.flock(fp.fileno(),fcntl.LOCK_UN)
    @staticmethod
    def _token(token):
        if not isinstance(token,str) or not _TOKEN_RE.fullmatch(token): raise ValueError('invalid firewall rollback token')
        return token
    def _run(self, argv, timeout=15):
        return self.runner(argv,text=True,capture_output=True,check=False,timeout=timeout)
    def _ufw(self,*args,timeout=15):
        if not os.path.exists(UFW) and self.runner is subprocess.run: raise RuntimeError('UFW is not installed')
        r=self._run([UFW,*args],timeout=timeout)
        if getattr(r,'returncode',1)!=0: raise RuntimeError((getattr(r,'stderr','') or getattr(r,'stdout','') or 'UFW command failed').strip())
        return getattr(r,'stdout','') or ''
    def _status_text(self): return self._ufw('status','verbose')
    def _numbered_text(self): return self._ufw('status','numbered')
    def _ssh_ports(self):
        try:
            r=self._run([SS,'-lntp']); text=getattr(r,'stdout','') or ''
        except Exception: return []
        ports=[]
        for line in text.splitlines():
            if 'sshd' not in line: continue
            m=re.search(r':(\d+)\s',line+' ')
            if m: ports.append(int(m.group(1)))
        return sorted(set(ports))
    def status(self):
        if not os.path.exists(UFW) and self.runner is subprocess.run:
            return {'installed':False,'active':False,'default_incoming':None,'default_outgoing':None,'managed_count':0,'unmanaged_count':0,'ipv6':None,'ssh_ports':self._ssh_ports()}
        try: verbose=self._status_text(); numbered=self._numbered_text()
        except Exception as e: return {'installed':True,'available':False,'error':str(e),'ssh_ports':self._ssh_ports()}
        active='Status: active' in verbose
        defaults=re.search(r'Default:\s*([^,]+) \(incoming\),\s*([^,]+) \(outgoing\)',verbose,re.I)
        lines=[l for l in numbered.splitlines() if re.match(r'^\[\s*\d+\]',l.strip())]
        managed=sum('DNSMGR:' in l for l in lines)
        world_dns53=any('ALLOW' in l.upper() and re.search(r'(^|\s)53(/|\s)',l) and ('Anywhere' in l or '0.0.0.0/0' in l or '::/0' in l) for l in lines)
        ssh_ports=self._ssh_ports(); world_ssh=any('ALLOW' in l.upper() and any(re.search(rf'(^|\s){p}(/|\s)',l) for p in ssh_ports) and ('Anywhere' in l or '0.0.0.0/0' in l or '::/0' in l) for l in lines)
        root_login=None; password_auth=None
        try:
            rr=self._run([SSHD,'-T']); st=getattr(rr,'stdout','') or ''
            for ln in st.splitlines():
                if ln.startswith('permitrootlogin '): root_login=ln.split(None,1)[1]
                elif ln.startswith('passwordauthentication '): password_auth=ln.split(None,1)[1]
        except Exception: pass
        ssl_timer=None
        try:
            tr=self._run([SYSTEMCTL,'is-active','dns-manager-ssl-renew.timer']); ssl_timer=(getattr(tr,'stdout','') or '').strip()
        except Exception: pass
        listener_text=''
        try:
            lr=self._run([SS,'-lntup']); listener_text=getattr(lr,'stdout','') or ''
        except Exception: pass
        dns53_public_listener=any(':53' in ln and not any(x in ln for x in ('127.0.0.1:53','127.0.0.53','127.0.0.54','[::1]:53')) for ln in listener_text.splitlines())
        fastapi_loopback=any('127.0.0.1:8500' in ln for ln in listener_text.splitlines()) and not any(':8500' in ln and '127.0.0.1:8500' not in ln for ln in listener_text.splitlines())
        deny=Path('/etc/nginx/conf.d/00-dns-manager-default-deny.conf'); direct_ip_block=False
        try:
            txt=deny.read_text(); direct_ip_block=('listen 80 default_server;' in txt and 'return 444;' in txt and 'ssl_reject_handshake on;' in txt)
        except OSError: pass
        return {'installed':True,'available':True,'active':active,'default_incoming':defaults.group(1).strip().lower() if defaults else None,'default_outgoing':defaults.group(2).strip().lower() if defaults else None,'managed_count':managed,'unmanaged_count':len(lines)-managed,'ipv6':'(v6)' in numbered,'ssh_ports':ssh_ports,'world_open_dns53':world_dns53,'world_open_ssh':world_ssh,'dns53_public_listener':dns53_public_listener,'ssh_root_login':root_login,'ssh_password_auth':password_auth,'ssl_renew_timer':ssl_timer,'fastapi_loopback_safe':fastapi_loopback,'direct_ip_block':direct_ip_block}
    @staticmethod
    def _validate_payload(payload):
        allowed={'enabled','default_incoming','default_outgoing','operations','revision'}
        if set(payload)-allowed: raise ValueError('unsupported firewall policy field')
        if payload.get('default_incoming') not in {'deny','reject'}: raise ValueError('invalid default incoming')
        if payload.get('default_outgoing') not in {'allow','deny'}: raise ValueError('invalid default outgoing')
        operations=payload.get('operations',[])
        if not isinstance(operations,list) or len(operations)>512: raise ValueError('too many firewall operations')
        comments=set()
        for operation in operations:
            if not isinstance(operation,dict) or set(operation)-{'action','protocol','port','source','comment'}: raise ValueError('unsupported firewall rule field')
            if operation.get('action') not in {'allow','deny'} or operation.get('protocol') not in {'tcp','udp'}: raise ValueError('invalid firewall operation')
            comment=operation.get('comment')
            matched=re.fullmatch(r'DNSMGR:(?:[1-9][0-9]{0,9}|new):(?:(0|[1-9][0-9]?):)?(tcp|udp)',str(comment))
            if not matched or (matched.group(1) is not None and int(matched.group(1))>=32) or matched.group(2)!=operation['protocol']:
                raise ValueError('invalid managed firewall comment')
            if comment in comments: raise ValueError('duplicate managed firewall comment')
            comments.add(comment)
            try: ip_network(operation['source'],strict=False)
            except (ValueError,TypeError,KeyError): raise ValueError('invalid firewall source')
            if not isinstance(operation.get('port'),str) or not re.fullmatch(r'[0-9]{1,5}(?::[0-9]{1,5})?',operation['port']):
                raise ValueError('invalid firewall port')
            ports=[int(x) for x in operation['port'].split(':')]
            if not all(1<=p<=65535 for p in ports) or ports[-1]<ports[0]: raise ValueError('invalid firewall port')
    def preview(self,payload): self._validate_payload(payload); return {'operations':payload.get('operations',[]),'active':bool(payload.get('enabled'))}
    def _managed_numbers(self):
        text=self._numbered_text(); out=[]
        for line in text.splitlines():
            m=re.match(r'^\[\s*(\d+)\]\s*(.*)$',line.strip())
            if m and 'DNSMGR:' in m.group(2): out.append(int(m.group(1)))
        return sorted(out,reverse=True)
    def _snapshot(self,token,payload):
        current={'verbose':self._status_text(),'numbered':self._numbered_text(),'managed_manifest':self._extract_managed(),'pending_payload':payload}
        path=self._state()/f'{token}.json'; tmp=path.with_suffix('.tmp'); tmp.write_text(json.dumps(current,sort_keys=True)); os.chmod(tmp,0o600); os.replace(tmp,path); return path
    def _extract_managed(self):
        out=[]
        for line in self._numbered_text().splitlines():
            if 'DNSMGR:' not in line: continue
            # store textual rule for audit/debug; rollback parser only relies on manifest when generated by this helper
            out.append(line)
        return out
    def _delete_managed(self):
        numbers = self._managed_numbers()
        if numbers:
            for n in numbers:
                self._ufw('--force','delete',str(n))
            return

        added = self._ufw('show','added')
        for line in added.splitlines():
            line = line.strip()
            if not line.startswith('ufw ') or 'DNSMGR:' not in line:
                continue

            argv = shlex.split(line)
            if not argv or argv[0] != 'ufw':
                continue

            self._ufw('--force','delete',*argv[1:])
    def _add_operation(self,op):
        port=op['port']; proto=op['protocol']; src=op['source']; comment=op['comment']; action=op['action']
        self._ufw(action,'from',src,'to','any','port',port,'proto',proto,'comment',comment)
    def apply(self,payload):
        self._validate_payload(payload); token=secrets.token_hex(16); self._snapshot(token,payload)
        before=self._capture_managed_payload()
        try:
            self._delete_managed()
            self._ufw('default',payload['default_incoming'],'incoming'); self._ufw('default',payload['default_outgoing'],'outgoing')
            for op in payload.get('operations',[]): self._add_operation(op)
            if payload.get('enabled'): self._ufw('--force','enable')
            else: self._ufw('disable')
            self._write_rollback_manifest(token,before)
            self._run([SYSTEMCTL,'--no-block','start',ROLLBACK_UNIT.format(token)])
            return {'revision':int(payload.get('revision',0)),'pending_confirmation':True,'rollback_token':token,'rollback_seconds':120}
        except Exception:
            self._restore_manifest(before)
            raise
    def _capture_managed_payload(self):
        # deterministic helper-owned backup sourced from sidecar manifest if available
        manifest=self._state()/'current-managed.json'
        if manifest.exists():
            try:return json.loads(manifest.read_text())
            except Exception: pass
        numbered=self._numbered_text()
        if any('DNSMGR:' in line for line in numbered.splitlines()):
            raise RuntimeError('managed UFW rules exist but DNS Manager manifest is missing; refusing unsafe reconciliation')
        st=self.status()
        return {'enabled':bool(st.get('active')),'default_incoming':st.get('default_incoming') or 'deny','default_outgoing':st.get('default_outgoing') or 'allow','operations':[]}
    def _write_current_manifest(self,payload):
        p=self._state()/'current-managed.json'; tmp=p.with_suffix('.tmp'); tmp.write_text(json.dumps(payload,sort_keys=True)); os.chmod(tmp,0o600); os.replace(tmp,p)
    def _write_rollback_manifest(self,token,before):
        p=self._state()/f'{token}.rollback.json'; tmp=p.with_suffix('.tmp'); tmp.write_text(json.dumps(before,sort_keys=True)); os.chmod(tmp,0o600); os.replace(tmp,p)
    def _restore_manifest(self,manifest):
        self._delete_managed()
        self._ufw('default',manifest.get('default_incoming','deny'),'incoming'); self._ufw('default',manifest.get('default_outgoing','allow'),'outgoing')
        for op in manifest.get('operations',[]): self._add_operation(op)
        if manifest.get('enabled'): self._ufw('--force','enable')
        else: self._ufw('disable')
        self._write_current_manifest(manifest)
    def confirm(self,token):
        token=self._token(token)
        with self._locked():
            if (self._state()/f'{token}.rolled-back').exists():
                # Too late: the previous rules are back in force. Never record the
                # rolled-back policy as current.
                return {'confirmed':False,'rolled_back':True}
            snap=self._state()/f'{token}.json'
            if not snap.exists(): return {'confirmed':True,'already_confirmed':True}
            data=json.loads(snap.read_text()); payload=data.get('pending_payload') or {}; self._write_current_manifest(payload)
            # Keep the rollback manifest as last-known-good for explicit rollback;
            # removing the pending snapshot is what tells auto_rollback to stand down.
            snap.unlink()
        self._run([SYSTEMCTL,'stop',ROLLBACK_UNIT.format(token)])
        return {'confirmed':True}
    def _rollback_locked(self,token):
        rb=self._state()/f'{token}.rollback.json'
        if not rb.exists(): raise RuntimeError('rollback snapshot not found')
        self._restore_manifest(json.loads(rb.read_text()))
        (self._state()/f'{token}.json').unlink(missing_ok=True)
        marker=self._state()/f'{token}.rolled-back'; marker.write_text(''); os.chmod(marker,0o600)
    def rollback(self,token):
        token=self._token(token)
        with self._locked(): self._rollback_locked(token)
        self._run([SYSTEMCTL,'stop',ROLLBACK_UNIT.format(token)])
        return {'rolled_back':True}
    def auto_rollback(self,token):
        """Emergency timer entry point: revert only if the change is still unconfirmed."""
        token=self._token(token)
        with self._locked():
            if not (self._state()/f'{token}.json').exists(): return {'rolled_back':False}
            self._rollback_locked(token)
        return {'rolled_back':True}
