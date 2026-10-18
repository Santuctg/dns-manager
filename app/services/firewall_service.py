from __future__ import annotations
from dataclasses import dataclass, asdict
from ipaddress import ip_address, ip_network
from typing import Iterable

@dataclass(frozen=True)
class NormalizedFirewallRule:
    id:int|None; action:str; protocol:str; port_start:int; port_end:int|None; source_cidr:str; purpose:str; enabled:bool; sort_key:int; comment:str|None; source_cidrs:tuple[str,...]=()
    def to_dict(self): return asdict(self)
@dataclass
class FirewallValidationResult:
    errors:list[str]; warnings:list[str]; requires_high_risk_confirmation:bool; normalized_rules:list[NormalizedFirewallRule]
    @property
    def valid(self): return not self.errors

def normalize_rule(rule) -> NormalizedFirewallRule:
    get=lambda k,default=None: getattr(rule,k, rule.get(k,default) if isinstance(rule,dict) else default)
    action=str(get('action','')).lower(); protocol=str(get('protocol','')).lower(); purpose=str(get('purpose','custom')).lower(); ps=int(get('port_start')); pe=get('port_end'); pe=int(pe) if pe is not None else None
    if action not in {'allow','deny'}: raise ValueError('unsupported action')
    if protocol not in {'tcp','udp','both'}: raise ValueError('unsupported protocol')
    if purpose not in {'web','dns','ssh','custom'}: raise ValueError('unsupported purpose')
    if not 1<=ps<=65535 or (pe is not None and not 1<=pe<=65535): raise ValueError('port outside 1..65535')
    if pe is not None and pe<ps: raise ValueError('port range is reversed')
    supplied=get('source_cidrs')
    if supplied is None:
        children=get('sources')
        supplied=[c.source_cidr for c in children] if children else [get('source_cidr')]
    if not isinstance(supplied,(list,tuple)) or not 1<=len(supplied)<=32:
        raise ValueError('source_cidrs must contain 1..32 entries')
    normalized=[]
    for entry in supplied:
        if not isinstance(entry,str) or not entry.strip() or ',' in entry or '\n' in entry or '\r' in entry:
            raise ValueError('invalid source CIDR')
        canonical=str(ip_network(entry.strip(),strict=False))
        if canonical in normalized: raise ValueError('duplicate source CIDR')
        normalized.append(canonical)
    return NormalizedFirewallRule(get('id'),action,protocol,ps,pe,normalized[0],purpose,bool(get('enabled',True)),int(get('sort_key',100)),get('comment'),tuple(normalized))

def _covers_port(rule,port): return rule.port_start<=port<=(rule.port_end or rule.port_start)
def _world(cidr): return ip_network(cidr,strict=False).prefixlen==0

def validate_policy(policy, rules:Iterable, *, ssh_port:int=2222, source_ip:str|None=None, management_cidr:str|None=None)->FirewallValidationResult:
    errors=[]; warnings=[]; normalized=[]; high=False
    for raw in rules:
        try: r=normalize_rule(raw); normalized.append(r)
        except Exception as e: errors.append(str(e)); continue
        if not r.enabled: continue
        if r.action=='allow' and _covers_port(r,8500) and any(_world(c) for c in r.source_cidrs): errors.append('public exposure of FastAPI port 8500 is forbidden')
        if r.action=='allow' and (_covers_port(r,53) or _covers_port(r,ssh_port)) and any(_world(c) for c in r.source_cidrs):
            high=True; warnings.append(('DNS 53' if _covers_port(r,53) else 'SSH')+' is world-open')
    enabled=bool(getattr(policy,'enabled',policy.get('enabled',False) if isinstance(policy,dict) else False)); incoming=str(getattr(policy,'default_incoming',policy.get('default_incoming','deny') if isinstance(policy,dict) else 'deny'))
    if enabled and incoming in {'deny','reject'}:
        target=management_cidr or source_ip
        if not target: errors.append('restrictive firewall requires a trusted source IP or management CIDR')
        else:
            try: addr=ip_address(source_ip) if source_ip else None; mgmt=ip_network(target,strict=False)
            except ValueError: errors.append('invalid management source'); addr=None; mgmt=None
            ok=False
            if mgmt:
                for r in normalized:
                    if r.enabled and r.action=='allow' and r.protocol in {'tcp','both'} and _covers_port(r,ssh_port):
                        for cidr in r.source_cidrs:
                            rn=ip_network(cidr,strict=False)
                            if (addr is not None and addr in rn) or (mgmt.version==rn.version and mgmt.subnet_of(rn)):
                                ok=True
            if not ok: errors.append(f'no safe SSH allow path for port {ssh_port}')
    return FirewallValidationResult(errors,warnings,high,normalized)

def build_preview(policy,rules):
    norm=sorted((normalize_rule(r) for r in rules if getattr(r,'enabled',r.get('enabled',True) if isinstance(r,dict) else True)),key=lambda r:(r.sort_key,r.id or 0))
    ops=[]
    for r in norm:
        protos=('tcp','udp') if r.protocol=='both' else (r.protocol,)
        for index,cidr in enumerate(r.source_cidrs):
            for proto in protos:
                port=str(r.port_start) if not r.port_end else f'{r.port_start}:{r.port_end}'
                comment=f'DNSMGR:{r.id or "new"}:{proto}' if len(r.source_cidrs)==1 else f'DNSMGR:{r.id or "new"}:{index}:{proto}'
                ops.append({'action':r.action,'protocol':proto,'port':port,'source':cidr,'comment':comment})
                if len(ops)>512: raise ValueError('firewall policy exceeds 512 operations')
    return {'enabled':bool(getattr(policy,'enabled',False)),'default_incoming':getattr(policy,'default_incoming','deny'),'default_outgoing':getattr(policy,'default_outgoing','allow'),'operations':ops}
