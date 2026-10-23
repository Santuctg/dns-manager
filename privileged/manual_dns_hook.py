#!/usr/bin/python3
from __future__ import annotations

import json
import os
import time
from pathlib import Path


def _safe_domain(domain:str)->str:
    if not domain or '/' in domain or '..' in domain or '\\' in domain: raise ValueError('invalid domain')
    return domain.strip().lower().rstrip('.')


def _dir(root:Path|str, domain:str)->Path:
    return Path(root)/_safe_domain(domain)


def write_challenge_state(root:Path|str, domain:str, name:str, value:str)->Path:
    d=_dir(root,domain); d.mkdir(parents=True,exist_ok=True)
    path=d/'challenge.json'; tmp=d/'.challenge.tmp'
    tmp.write_text(json.dumps({'domain':_safe_domain(domain),'challenge_name':name,'challenge_value':value,'status':'WAITING_DNS'}))
    os.chmod(tmp,0o640); os.replace(tmp,path); return path


def read_challenge_state(root:Path|str, domain:str)->dict:
    return json.loads((_dir(root,domain)/'challenge.json').read_text())


def certbot_auth_hook()->int:
    root=Path(os.environ.get('DNS_MANAGER_ACME_STATE_DIR','/var/lib/dns-manager-helper/acme'))
    domain=os.environ['CERTBOT_DOMAIN']; value=os.environ['CERTBOT_VALIDATION']
    name=f'_acme-challenge.{_safe_domain(domain)}'
    write_challenge_state(root,domain,name,value)
    cont=_dir(root,domain)/'continue'
    deadline=time.time()+int(os.environ.get('DNS_MANAGER_ACME_WAIT_SECONDS','600'))
    while time.time()<deadline:
        if cont.exists(): cont.unlink(missing_ok=True); return 0
        time.sleep(1)
    state=read_challenge_state(root,domain)
    state['status']='EXPIRED'
    path=_dir(root,domain)/'challenge.json'
    tmp=_dir(root,domain)/'.challenge.tmp'
    tmp.write_text(json.dumps(state))
    os.chmod(tmp,0o640); os.replace(tmp,path)
    return 1


if __name__=='__main__': raise SystemExit(certbot_auth_hook())
