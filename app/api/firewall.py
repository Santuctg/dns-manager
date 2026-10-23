from __future__ import annotations
import json
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload
from app.database import get_db
from app.dependencies import require_permission
from app.models.auth import User
from app.models.firewall import FirewallPolicy, FirewallRule, FirewallRuleSource, FirewallRevision
from app.schemas.firewall import FirewallPolicyUpdate, FirewallRuleCreate, FirewallRuleUpdate, FirewallPolicyRead, FirewallRuleRead, FirewallApplyRequest
from app.security import CSRF_COOKIE, SESSION_COOKIE, token_hash, validate_csrf_tokens
from app.services.auth_service import resolve_session
from app.services.audit_service import record_audit_event
from app.services.firewall_service import validate_policy, build_preview, normalize_rule
from app.services.privileged_helper import PrivilegedHelper, PrivilegedHelperError

router=APIRouter(prefix='/api/v1/firewall',tags=['firewall'])

def _csrf(request:Request,db:Session):
    c=request.cookies.get(CSRF_COOKIE); h=request.headers.get('X-CSRF-Token')
    if not validate_csrf_tokens(c,h): raise HTTPException(403,'CSRF validation failed')
    raw=request.cookies.get(SESSION_COOKIE); sess=resolve_session(db,raw) if raw else None
    if sess is None or sess.csrf_hash!=token_hash(h): raise HTTPException(403,'CSRF validation failed')

def _policy(db:Session)->FirewallPolicy:
    p=db.scalar(select(FirewallPolicy).options(selectinload(FirewallPolicy.rules)).where(FirewallPolicy.id==1))
    if p is None:
        p=FirewallPolicy(id=1,enabled=False,default_incoming='deny',default_outgoing='allow'); db.add(p); db.commit(); db.refresh(p)
        p=db.scalar(select(FirewallPolicy).options(selectinload(FirewallPolicy.rules)).where(FirewallPolicy.id==1))
    return p

def _bump(p): p.desired_revision=(p.desired_revision or 0)+1

def serialize_firewall_rule(rule):
    values={k:getattr(rule,k) for k in ('id','action','protocol','port_start','port_end','source_cidr','purpose','enabled','sort_key','comment')}
    values['source_cidrs']=[source.source_cidr for source in rule.sources] or [rule.source_cidr]
    return FirewallRuleRead.model_validate(values).model_dump()

def _view(p):
    return {'id':p.id,'enabled':p.enabled,'default_incoming':p.default_incoming,'default_outgoing':p.default_outgoing,'desired_revision':p.desired_revision,'applied_revision':p.applied_revision,'pending_revision':p.pending_revision,'rules':[serialize_firewall_rule(r) for r in sorted(p.rules,key=lambda x:(x.sort_key,x.id or 0))]}

def _source(request:Request)->str|None:
    # Deliberately ignore X-Forwarded-For/X-Real-IP: request.client is the ASGI trust boundary.
    return request.client.host if request.client else None

def _audit(db,actor,request,action,old=None,new=None,status='success',error=None,obj='firewall'):
    record_audit_event(db,user=actor,action=action,object_type=obj,source_ip=_source(request),user_agent=request.headers.get('user-agent'),old_value=old,new_value=new,status=status,error_message=error)

@router.get('/status')
def status(_actor:User=Depends(require_permission('firewall.manage'))):
    try: s=PrivilegedHelper().firewall_status()
    except Exception as e: s={'installed':False,'available':False,'error':str(e),'ssh_ports':[]}
    findings=[]
    if not s.get('active'): findings.append({'severity':'critical','code':'UFW_INACTIVE','message':'UFW is inactive'})
    if s.get('world_open_dns53') or (not s.get('active') and s.get('dns53_public_listener')): findings.append({'severity':'critical','code':'DNS53_WORLD_OPEN','message':'DNS TCP/UDP 53 is publicly listening without an active restrictive firewall'})
    if s.get('world_open_ssh'): findings.append({'severity':'critical','code':'SSH_WORLD_OPEN','message':'SSH management port appears world-open'})
    if s.get('ssh_root_login') == 'yes': findings.append({'severity':'warning','code':'SSH_ROOT_LOGIN','message':'SSH root login is enabled'})
    if s.get('ssh_password_auth') == 'yes': findings.append({'severity':'warning','code':'SSH_PASSWORD_AUTH','message':'SSH password authentication is enabled'})
    findings.append({'severity':'info' if s.get('fastapi_loopback_safe') else 'critical','code':'FASTAPI_LOOPBACK','message':'FastAPI is loopback-only on 127.0.0.1:8500' if s.get('fastapi_loopback_safe') else 'FastAPI loopback-only bind could not be verified'})
    findings.append({'severity':'info' if s.get('direct_ip_block') else 'warning','code':'DIRECT_IP_BLOCK','message':'Direct-IP Nginx block is active' if s.get('direct_ip_block') else 'Direct-IP Nginx block could not be verified'})
    if s.get('ssh_ports'): findings.append({'severity':'warning','code':'SSH_PUBLIC_LISTENER','message':'SSH listener detected on '+','.join(map(str,s['ssh_ports']))})
    if s.get('ssl_renew_timer') not in (None,'active'): findings.append({'severity':'warning','code':'SSL_RENEW_TIMER','message':'SSL renewal timer is not active'})
    s['findings']=findings; return s

@router.get('/policy')
def policy(db:Session=Depends(get_db),_actor:User=Depends(require_permission('firewall.manage'))): return _view(_policy(db))

@router.put('/policy')
def update_policy(payload:FirewallPolicyUpdate,request:Request,db:Session=Depends(get_db),actor:User=Depends(require_permission('firewall.manage'))):
    _csrf(request,db); p=_policy(db); old=_view(p); p.enabled=payload.enabled;p.default_incoming=payload.default_incoming;p.default_outgoing=payload.default_outgoing;_bump(p);db.commit();p=_policy(db);_audit(db,actor,request,'FIREWALL_POLICY_UPDATED',old,_view(p));return _view(p)

@router.post('/rules',status_code=201)
def create_rule(payload:FirewallRuleCreate,request:Request,db:Session=Depends(get_db),actor:User=Depends(require_permission('firewall.manage'))):
    _csrf(request,db)
    try:n=normalize_rule(payload.model_dump())
    except ValueError as e: raise HTTPException(422,str(e))
    p=_policy(db); r=FirewallRule(policy_id=p.id,**{k:v for k,v in n.to_dict().items() if k not in ('id','source_cidrs')});r.sources=[FirewallRuleSource(source_cidr=cidr,sort_key=i) for i,cidr in enumerate(n.source_cidrs)];db.add(r);_bump(p);db.commit();db.refresh(r);new=serialize_firewall_rule(r);_audit(db,actor,request,'FIREWALL_RULE_CREATED',new=new,obj='firewall_rule');return new

@router.put('/rules/{rule_id}')
def update_rule(rule_id:int,payload:FirewallRuleUpdate,request:Request,db:Session=Depends(get_db),actor:User=Depends(require_permission('firewall.manage'))):
    _csrf(request,db); r=db.get(FirewallRule,rule_id)
    if not r: raise HTTPException(404,'Firewall rule not found')
    old=serialize_firewall_rule(r)
    try:n=normalize_rule({'id':rule_id,**payload.model_dump()})
    except ValueError as e: raise HTTPException(422,str(e))
    for k,v in n.to_dict().items():
        if k not in ('id','source_cidrs'): setattr(r,k,v)
    r.sources.clear();db.flush();r.sources=[FirewallRuleSource(source_cidr=cidr,sort_key=i) for i,cidr in enumerate(n.source_cidrs)]
    p=_policy(db);_bump(p);db.commit();db.refresh(r);new=serialize_firewall_rule(r);_audit(db,actor,request,'FIREWALL_RULE_UPDATED',old,new,obj='firewall_rule');return new

@router.delete('/rules/{rule_id}',status_code=204)
def delete_rule(rule_id:int,request:Request,db:Session=Depends(get_db),actor:User=Depends(require_permission('firewall.manage'))):
    _csrf(request,db); r=db.get(FirewallRule,rule_id)
    if not r: raise HTTPException(404,'Firewall rule not found')
    old=serialize_firewall_rule(r);p=_policy(db);db.delete(r);_bump(p);db.commit();_audit(db,actor,request,'FIREWALL_RULE_DELETED',old=old,obj='firewall_rule');return None

@router.post('/preview')
def preview(db:Session=Depends(get_db),_actor:User=Depends(require_permission('firewall.manage'))):
    p=_policy(db)
    try: return build_preview(p,p.rules)
    except ValueError as exc: raise HTTPException(422,str(exc))

@router.post('/validate')
def validate(payload:FirewallApplyRequest,request:Request,db:Session=Depends(get_db),_actor:User=Depends(require_permission('firewall.manage'))):
    p=_policy(db)
    try: hs=PrivilegedHelper().firewall_status(); ssh=(hs.get('ssh_ports') or [2222])[0]
    except Exception: ssh=2222
    result=validate_policy(p,p.rules,ssh_port=ssh,source_ip=_source(request),management_cidr=payload.management_cidr)
    return {'valid':result.valid,'errors':result.errors,'warnings':result.warnings,'requires_high_risk_confirmation':result.requires_high_risk_confirmation,'source_ip':_source(request),'ssh_port':ssh}

@router.post('/apply')
def apply_firewall(payload:FirewallApplyRequest,request:Request,db:Session=Depends(get_db),actor:User=Depends(require_permission('firewall.manage'))):
    _csrf(request,db);p=_policy(db)
    try: hs=PrivilegedHelper().firewall_status();ssh=(hs.get('ssh_ports') or [2222])[0]
    except Exception: ssh=2222
    val=validate_policy(p,p.rules,ssh_port=ssh,source_ip=_source(request),management_cidr=payload.management_cidr)
    if val.errors: raise HTTPException(409,detail={'errors':val.errors,'warnings':val.warnings})
    if val.requires_high_risk_confirmation and not payload.high_risk_confirmed: raise HTTPException(409,detail={'high_risk_confirmation_required':True,'warnings':val.warnings})
    try: doc=build_preview(p,p.rules)
    except ValueError as exc: raise HTTPException(422,str(exc))
    doc['revision']=p.desired_revision
    try: result=PrivilegedHelper().firewall_apply(doc)
    except Exception as e:
        _audit(db,actor,request,'FIREWALL_APPLY_FAILED',new={'revision':p.desired_revision},status='error',error=str(e)); raise HTTPException(502,str(e))
    p.pending_revision=p.desired_revision; db.add(FirewallRevision(revision=p.desired_revision,status='pending',snapshot_token=result.get('rollback_token'),payload_json=json.dumps(doc)));db.commit();_audit(db,actor,request,'FIREWALL_APPLY_PENDING',new={'revision':p.desired_revision})
    deadline=(datetime.now(timezone.utc)+timedelta(seconds=int(result.get('rollback_seconds',120)))).isoformat()
    return {'revision':p.desired_revision,'pending_confirmation':True,'rollback_token':result.get('rollback_token'),'rollback_deadline':deadline}

@router.post('/confirm')
def confirm(request:Request,db:Session=Depends(get_db),actor:User=Depends(require_permission('firewall.manage'))):
    _csrf(request,db);p=_policy(db)
    rev=db.scalar(select(FirewallRevision).where(FirewallRevision.revision==p.pending_revision,FirewallRevision.status=='pending').order_by(FirewallRevision.id.desc())) if p.pending_revision is not None else None
    if not rev: return {'confirmed':True,'already_confirmed':True,'revision':p.applied_revision}
    result=PrivilegedHelper().firewall_confirm(rev.snapshot_token)
    if result.get('rolled_back') and not result.get('confirmed'):
        rev.status='rolled_back';p.pending_revision=None;db.commit();_audit(db,actor,request,'FIREWALL_CONFIRM_TOO_LATE',new={'revision':rev.revision},status='failed',error='emergency rollback already restored the previous rules')
        raise HTTPException(409,'Confirmation window expired: the firewall was rolled back to the previous rules. Apply again to retry.')
    p.applied_revision=rev.revision;p.pending_revision=None;p.last_applied_at=datetime.now(timezone.utc);p.last_applied_user_id=actor.id;rev.status='applied';db.commit();_audit(db,actor,request,'FIREWALL_APPLIED',new={'revision':p.applied_revision});return {'confirmed':True,'revision':p.applied_revision}

@router.post('/rollback')
def rollback(request:Request,db:Session=Depends(get_db),actor:User=Depends(require_permission('firewall.manage'))):
    _csrf(request,db);p=_policy(db)
    rev=db.scalar(select(FirewallRevision).where(FirewallRevision.snapshot_token.is_not(None)).order_by(FirewallRevision.id.desc()))
    if not rev: raise HTTPException(409,'No firewall rollback snapshot is available')
    PrivilegedHelper().firewall_rollback(rev.snapshot_token);rev.status='rolled_back';p.pending_revision=None;db.commit();_audit(db,actor,request,'FIREWALL_ROLLED_BACK',new={'revision':rev.revision});return {'rolled_back':True,'revision':rev.revision}
