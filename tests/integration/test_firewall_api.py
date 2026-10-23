from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from app.database import Base,get_db
from app.main import app
from app.models.auth import Permission,Role,User
from app.security import hash_password
from app.services.auth_service import ALL_PERMISSIONS,create_session

class FakeHelper:
    def firewall_status(self): return {'installed':True,'available':True,'active':False,'managed_count':0,'unmanaged_count':0,'ssh_ports':[2222],'default_incoming':'deny','default_outgoing':'allow'}
    def firewall_apply(self,policy): return {'rollback_token':'abc123','rollback_seconds':120,'pending_confirmation':True,'revision':policy['revision']}
    def firewall_confirm(self,token): return {'confirmed':True}
    def firewall_rollback(self,token): return {'rolled_back':True}

def env(role='super_admin'):
    engine=create_engine('sqlite+pysqlite:///:memory:',connect_args={'check_same_thread':False},poolclass=StaticPool);Base.metadata.create_all(engine)
    with Session(engine) as db:
        perms={n:Permission(name=n) for n in sorted(ALL_PERMISSIONS)}; names=ALL_PERMISSIONS if role=='super_admin' else {'system.view'}
        r=Role(name=role,permissions=[perms[n] for n in names]);u=User(username=role,password_hash=hash_password('very-secure-password'),role=r);db.add_all([*perms.values(),r,u]);db.commit();raw=create_session(db,u,'csrf-token')
    def odb():
        with Session(engine) as db: yield db
    app.dependency_overrides[get_db]=odb;c=TestClient(app,base_url='https://testserver');c.cookies.set('dns_manager_session',raw);c.cookies.set('dns_manager_csrf','csrf-token');return c

def test_firewall_is_super_admin_only_and_csrf_protected():
    c=env('viewer')
    try: assert c.get('/api/v1/firewall/status').status_code==403
    finally: app.dependency_overrides.clear()
    c=env()
    try: assert c.put('/api/v1/firewall/policy',json={'enabled':False,'default_incoming':'deny','default_outgoing':'allow'}).status_code==403
    finally: app.dependency_overrides.clear()

def test_firewall_crud_preview_and_forged_forwarded_header_ignored(monkeypatch):
    import app.api.firewall as fw; monkeypatch.setattr(fw,'PrivilegedHelper',lambda:FakeHelper())
    c=env();h={'X-CSRF-Token':'csrf-token','X-Forwarded-For':'203.0.113.99'}
    try:
        r=c.post('/api/v1/firewall/rules',headers=h,json={'action':'allow','protocol':'tcp','port_start':443,'source_cidr':'0.0.0.0/0','purpose':'web','enabled':True,'sort_key':10});assert r.status_code==201
        assert c.get('/api/v1/firewall/policy').json()['rules'][0]['port_start']==443
        prev=c.post('/api/v1/firewall/preview',headers=h).json();assert prev['operations'][0]['comment'].startswith('DNSMGR:')
        val=c.post('/api/v1/firewall/validate',headers=h,json={}).json();assert val['source_ip']!='203.0.113.99'
    finally: app.dependency_overrides.clear()

def test_world_open_dns_requires_high_risk_confirmation(monkeypatch):
    import app.api.firewall as fw; monkeypatch.setattr(fw,'PrivilegedHelper',lambda:FakeHelper())
    c=env();h={'X-CSRF-Token':'csrf-token'}
    try:
        c.post('/api/v1/firewall/rules',headers=h,json={'action':'allow','protocol':'both','port_start':53,'source_cidr':'0.0.0.0/0','purpose':'dns','enabled':True,'sort_key':10})
        r=c.post('/api/v1/firewall/apply',headers=h,json={'high_risk_confirmed':False});assert r.status_code==409;assert r.json()['detail']['high_risk_confirmation_required'] is True
        ok=c.post('/api/v1/firewall/apply',headers=h,json={'high_risk_confirmed':True});assert ok.status_code==200 and ok.json()['pending_confirmation'] is True
        assert c.post('/api/v1/firewall/confirm',headers=h).status_code==200
    finally: app.dependency_overrides.clear()

def test_multi_source_crud_atomic_validation_and_preview(monkeypatch):
    import app.api.firewall as fw
    monkeypatch.setattr(fw,'PrivilegedHelper',lambda:FakeHelper())
    c=env(); h={'X-CSRF-Token':'csrf-token'}
    payload={'action':'allow','protocol':'both','port_start':2222,'source_cidrs':['203.0.113.4/32','198.51.100.0/24','2001:db8::/64'],'purpose':'ssh','enabled':True}
    try:
        created=c.post('/api/v1/firewall/rules',json=payload,headers=h)
        assert created.status_code==201,created.text
        r=created.json()
        assert r['source_cidrs']==payload['source_cidrs']
        assert r['source_cidr']==payload['source_cidrs'][0]
        rid=r['id']
        operations=c.post('/api/v1/firewall/preview',headers=h).json()['operations']
        assert len(operations)==6 and len({x['comment'] for x in operations})==6
        conflict=c.put(f'/api/v1/firewall/rules/{rid}',json={**payload,'source_cidrs':['10.1.2.3','10.1.2.3/32']},headers=h)
        assert conflict.status_code==422
        assert c.get('/api/v1/firewall/policy').json()['rules'][0]['source_cidrs']==payload['source_cidrs']
        updated=c.put(f'/api/v1/firewall/rules/{rid}',json={**payload,'source_cidrs':['203.0.113.4/32']},headers=h)
        assert updated.status_code==200,updated.text
        assert updated.json()['source_cidrs']==['203.0.113.4/32']
        assert len(c.post('/api/v1/firewall/preview',headers=h).json()['operations'])==2
        assert c.delete(f'/api/v1/firewall/rules/{rid}',headers=h).status_code==204
        assert c.get('/api/v1/firewall/policy').json()['rules']==[]
    finally: app.dependency_overrides.clear()

def test_multi_source_rejects_invalid_sources_and_preserves_draft(monkeypatch):
    import app.api.firewall as fw
    monkeypatch.setattr(fw,'PrivilegedHelper',lambda:FakeHelper())
    c=env(); h={'X-CSRF-Token':'csrf-token'}
    payload={'action':'allow','protocol':'tcp','port_start':2222,'source_cidrs':['203.0.113.4/32','198.51.100.0/24'],'purpose':'ssh','enabled':True}
    try:
        r=c.post('/api/v1/firewall/rules',headers=h,json=payload)
        assert r.status_code==201,r.text
        before=c.get('/api/v1/firewall/policy').json()
        rid=r.json()['id']
        bad_lists=[[],['203.0.113.4','203.0.113.4/32'],['203.0.113.4/32,198.51.100.0/24'],['203.0.113.4/32\n'],[f'10.1.0.{i}/32' for i in range(33)]]
        for values in bad_lists:
            response=c.put(f'/api/v1/firewall/rules/{rid}',headers=h,json={**payload,'source_cidrs':values})
            assert response.status_code==422,(values,response.text)
            assert c.get('/api/v1/firewall/policy').json()==before
        contradicted=c.put(f'/api/v1/firewall/rules/{rid}',headers=h,json={**payload,'source_cidr':'192.0.2.0/24'})
        assert contradicted.status_code==422
        assert c.get('/api/v1/firewall/policy').json()==before
        legacy={k:v for k,v in payload.items() if k!='source_cidrs'}
        legacy['source_cidr']='203.0.113.4/32'
        updated=c.put(f'/api/v1/firewall/rules/{rid}',headers=h,json=legacy)
        assert updated.status_code==200,updated.text
        assert updated.json()['source_cidrs']==['203.0.113.4/32']
    finally: app.dependency_overrides.clear()

def test_late_confirm_after_emergency_rollback_returns_conflict_and_marks_revision_rolled_back(monkeypatch):
    import app.api.firewall as fw
    from app.models.firewall import FirewallRevision
    class RolledBackHelper(FakeHelper):
        def firewall_confirm(self,token): return {'confirmed':False,'rolled_back':True}
    monkeypatch.setattr(fw,'PrivilegedHelper',lambda:RolledBackHelper())
    c=env();h={'X-CSRF-Token':'csrf-token'}
    try:
        c.put('/api/v1/firewall/policy',headers=h,json={'enabled':False,'default_incoming':'deny','default_outgoing':'allow'})
        assert c.post('/api/v1/firewall/apply',headers=h,json={}).status_code==200
        r=c.post('/api/v1/firewall/confirm',headers=h)
        assert r.status_code==409 and 'rolled back' in r.json()['detail']
        policy=c.get('/api/v1/firewall/policy').json()
        assert policy['pending_revision'] is None and policy['applied_revision'] != policy['desired_revision']
        db=next(app.dependency_overrides[get_db]())
        assert db.query(FirewallRevision).one().status=='rolled_back'
        # A retry is not misreported as confirmed.
        assert c.post('/api/v1/firewall/confirm',headers=h).json()['revision']==policy['applied_revision']
    finally: app.dependency_overrides.clear()
