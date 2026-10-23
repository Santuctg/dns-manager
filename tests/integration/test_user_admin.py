from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.audit import AuditLog
from app.models.auth import Permission, Role, User, UserSession
from app.security import hash_password, verify_password
from app.services.auth_service import create_session

ALL = [
    'user.view','user.create','user.update','user.delete','role.view','role.manage'
]


def make_env(actor_role='super_admin', actor_permissions=None):
    engine = create_engine('sqlite+pysqlite:///:memory:', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        perms = {}
        for name in sorted(set(ALL + ['mapping.view', 'backup.restore', 'firewall.manage'])):
            p = Permission(name=name); db.add(p); perms[name] = p
        super_role = Role(name='super_admin', permissions=list(perms.values()))
        admin_role = Role(name='admin', permissions=[perms[n] for n in ['mapping.view','user.view','user.create','user.update','user.delete','role.view']])
        viewer_role = Role(name='viewer', permissions=[perms['mapping.view']])
        db.add_all([super_role, admin_role, viewer_role]); db.flush()
        role = {'super_admin': super_role, 'admin': admin_role, 'viewer': viewer_role}[actor_role]
        if actor_permissions is not None:
            role.permissions = [perms[n] for n in actor_permissions]
        actor = User(username='actor', email='actor@example.com', password_hash=hash_password('very-secure-password'), role=role)
        target_admin = User(username='target-admin', email='target-admin@example.com', password_hash=hash_password('very-secure-password'), role=admin_role)
        target_super = User(username='target-super', email='target-super@example.com', password_hash=hash_password('very-secure-password'), role=super_role)
        db.add_all([actor, target_admin, target_super]); db.commit(); db.refresh(actor)
        session = create_session(db, actor, 'csrf-token')
    def override_db():
        with Session(engine) as db:
            yield db
    app.dependency_overrides[get_db] = override_db
    client = TestClient(app, base_url='https://testserver')
    client.cookies.set('dns_manager_session', session)
    client.cookies.set('dns_manager_csrf', 'csrf-token')
    return engine, client


def cleanup():
    app.dependency_overrides.clear()


def csrf_headers():
    return {'X-CSRF-Token':'csrf-token'}


def test_super_admin_can_manage_users_reset_password_and_role_permissions():
    engine, client = make_env()
    try:
        roles = client.get('/api/v1/roles')
        assert roles.status_code == 200
        viewer_id = next(r['id'] for r in roles.json() if r['name'] == 'viewer')
        admin_id = next(r['id'] for r in roles.json() if r['name'] == 'admin')

        created = client.post('/api/v1/users', headers=csrf_headers(), json={
            'username':'bob','email':'bob@example.com','password':'a-strong-password','role_id':viewer_id
        })
        assert created.status_code == 201
        bob = created.json()
        assert bob['username'] == 'bob' and bob['role']['name'] == 'viewer' and bob['is_active'] is True

        updated = client.put(f"/api/v1/users/{bob['id']}", headers=csrf_headers(), json={
            'email':'bob2@example.com','role_id':admin_id,'is_active':True
        })
        assert updated.status_code == 200
        assert updated.json()['email'] == 'bob2@example.com'
        assert updated.json()['role']['name'] == 'admin'

        reset = client.post(f"/api/v1/users/{bob['id']}/reset-password", headers=csrf_headers(), json={'password':'another-strong-password'})
        assert reset.status_code == 200
        with Session(engine) as db:
            row = db.get(User, bob['id'])
            assert verify_password(row.password_hash, 'another-strong-password')

        role_update = client.put(f'/api/v1/roles/{viewer_id}/permissions', headers=csrf_headers(), json={'permissions':['mapping.view','role.view']})
        assert role_update.status_code == 200
        assert set(role_update.json()['permissions']) == {'mapping.view','role.view'}

        deleted = client.delete(f"/api/v1/users/{bob['id']}", headers=csrf_headers())
        assert deleted.status_code == 204
        with Session(engine) as db:
            assert db.get(User, bob['id']).is_active is False
            actions = set(db.scalars(select(AuditLog.action)).all())
            assert {'USER_CREATED','USER_UPDATED','USER_PASSWORD_RESET','USER_DEACTIVATED','ROLE_PERMISSIONS_UPDATED'} <= actions
    finally:
        cleanup()


def test_admin_can_manage_non_super_users_but_cannot_manage_roles_or_super_admin():
    _, client = make_env(actor_role='admin')
    try:
        users = client.get('/api/v1/users')
        assert users.status_code == 200
        target_admin = next(u for u in users.json() if u['username'] == 'target-admin')
        target_super = next(u for u in users.json() if u['username'] == 'target-super')
        roles = client.get('/api/v1/roles')
        assert roles.status_code == 200
        viewer_id = next(r['id'] for r in roles.json() if r['name'] == 'viewer')
        super_id = next(r['id'] for r in roles.json() if r['name'] == 'super_admin')

        assert client.put(f"/api/v1/users/{target_admin['id']}", headers=csrf_headers(), json={'role_id':viewer_id}).status_code == 200
        assert client.put(f"/api/v1/users/{target_super['id']}", headers=csrf_headers(), json={'is_active':False}).status_code == 403
        assert client.post('/api/v1/users', headers=csrf_headers(), json={'username':'evil-super','password':'a-strong-password','role_id':super_id}).status_code == 403
        assert client.put(f'/api/v1/roles/{viewer_id}/permissions', headers=csrf_headers(), json={'permissions':['mapping.view']}).status_code == 403
    finally:
        cleanup()


def test_viewer_cannot_modify_users():
    _, client = make_env(actor_role='viewer')
    try:
        assert client.get('/api/v1/users').status_code == 403
        assert client.post('/api/v1/users', headers=csrf_headers(), json={'username':'bob','password':'a-strong-password','role_id':1}).status_code == 403
    finally:
        cleanup()


def test_deactivation_invalidates_existing_session():
    engine, client = make_env()
    try:
        with Session(engine) as db:
            target = db.scalar(select(User).where(User.username == 'target-admin'))
            target_session = create_session(db, target, 'target-csrf')
            target_id = target.id
        r = client.delete(f'/api/v1/users/{target_id}', headers=csrf_headers())
        assert r.status_code == 204

        target_client = TestClient(app, base_url='https://testserver')
        target_client.cookies.set('dns_manager_session', target_session)
        target_client.cookies.set('dns_manager_csrf', 'target-csrf')
        assert target_client.get('/api/v1/auth/me').status_code in (401, 403)
        with Session(engine) as db:
            rows = list(db.scalars(select(UserSession).where(UserSession.user_id == target_id)))
            assert rows and all(row.revoked_at is not None for row in rows)
    finally:
        cleanup()


def test_cannot_deactivate_self_or_remove_permissions_from_super_admin_role():
    _, client = make_env()
    try:
        users = client.get('/api/v1/users').json()
        actor = next(u for u in users if u['username'] == 'actor')
        roles = client.get('/api/v1/roles').json()
        super_id = next(r['id'] for r in roles if r['name'] == 'super_admin')
        assert client.delete(f"/api/v1/users/{actor['id']}", headers=csrf_headers()).status_code == 409
        assert client.put(f'/api/v1/roles/{super_id}/permissions', headers=csrf_headers(), json={'permissions':['mapping.view']}).status_code == 409
    finally:
        cleanup()


def test_super_admin_can_create_custom_role_with_permissions_and_audit():
    engine, client = make_env()
    try:
        created = client.post('/api/v1/roles', headers=csrf_headers(), json={
            'name':'noc_operator',
            'description':'NOC operations',
            'permissions':['mapping.view','role.view'],
        })
        assert created.status_code == 201
        body = created.json()
        assert body['name'] == 'noc_operator'
        assert body['description'] == 'NOC operations'
        assert set(body['permissions']) == {'mapping.view','role.view'}
        with Session(engine) as db:
            assert db.scalar(select(Role).where(Role.name == 'noc_operator')) is not None
            assert 'ROLE_CREATED' in set(db.scalars(select(AuditLog.action)).all())
    finally:
        cleanup()


def test_role_create_rejects_duplicate_reserved_unknown_permission_and_non_manager():
    _, client = make_env()
    try:
        payload={'name':'noc_operator','description':None,'permissions':['mapping.view']}
        assert client.post('/api/v1/roles', headers=csrf_headers(), json=payload).status_code == 201
        assert client.post('/api/v1/roles', headers=csrf_headers(), json=payload).status_code == 409
        assert client.post('/api/v1/roles', headers=csrf_headers(), json={'name':'super_admin','permissions':['mapping.view']}).status_code == 409
        bad = client.post('/api/v1/roles', headers=csrf_headers(), json={'name':'new_role','permissions':['does.not.exist']})
        assert bad.status_code == 400
        assert bad.json()['detail']['unknown_permissions'] == ['does.not.exist']
    finally:
        cleanup()

    _, admin = make_env(actor_role='admin')
    try:
        assert admin.post('/api/v1/roles', headers=csrf_headers(), json={'name':'noc_operator','permissions':['mapping.view']}).status_code == 403
        roles = admin.get('/api/v1/roles').json()
        viewer_id = next(r['id'] for r in roles if r['name'] == 'viewer')
        assert admin.delete(f'/api/v1/roles/{viewer_id}', headers=csrf_headers()).status_code == 403
    finally:
        cleanup()


def test_super_admin_can_delete_unassigned_custom_role_and_audit():
    engine, client = make_env()
    try:
        created = client.post('/api/v1/roles', headers=csrf_headers(), json={
            'name':'temporary_role',
            'description':'Temporary access',
            'permissions':['mapping.view'],
        })
        assert created.status_code == 201
        role_id = created.json()['id']

        deleted = client.delete(f'/api/v1/roles/{role_id}', headers=csrf_headers())
        assert deleted.status_code == 204
        with Session(engine) as db:
            assert db.get(Role, role_id) is None
            assert 'ROLE_DELETED' in set(db.scalars(select(AuditLog.action)).all())
    finally:
        cleanup()


def test_role_delete_blocks_builtins_and_assigned_custom_role_with_user_count():
    engine, client = make_env()
    try:
        roles = client.get('/api/v1/roles').json()
        for builtin in ('super_admin', 'admin', 'viewer'):
            role_id = next(r['id'] for r in roles if r['name'] == builtin)
            blocked = client.delete(f'/api/v1/roles/{role_id}', headers=csrf_headers())
            assert blocked.status_code == 409
            assert 'built-in' in blocked.json()['detail'].lower()

        created = client.post('/api/v1/roles', headers=csrf_headers(), json={
            'name':'assigned_role',
            'permissions':['mapping.view'],
        })
        assert created.status_code == 201
        role_id = created.json()['id']
        with Session(engine) as db:
            role = db.get(Role, role_id)
            db.add(User(username='assigned-user', email='assigned@example.com', password_hash=hash_password('very-secure-password'), role=role))
            db.commit()

        blocked = client.delete(f'/api/v1/roles/{role_id}', headers=csrf_headers())
        assert blocked.status_code == 409
        assert '1 user' in blocked.json()['detail']
        with Session(engine) as db:
            assert db.get(Role, role_id) is not None
    finally:
        cleanup()


def _add_role(engine, name, permission_names, *, username=None):
    with Session(engine) as db:
        perms = [db.scalar(select(Permission).where(Permission.name == n)) for n in permission_names]
        role = Role(name=name, permissions=perms); db.add(role); db.flush()
        user_id = None
        if username:
            user = User(username=username, email=f'{username}@example.com', password_hash=hash_password('very-secure-password'), role=role)
            db.add(user); db.flush(); user_id = user.id
        db.commit()
        return role.id, user_id


def test_admin_cannot_assign_a_custom_role_with_permissions_the_admin_lacks():
    engine, client = make_env(actor_role='admin')
    try:
        powerful_id, _ = _add_role(engine, 'firewall_operator', ['mapping.view', 'firewall.manage', 'backup.restore'])
        modest_id, _ = _add_role(engine, 'mapping_reader', ['mapping.view'])
        created = client.post('/api/v1/users', headers=csrf_headers(), json={'username':'mallory','password':'a-strong-password','role_id':powerful_id})
        assert created.status_code == 403
        assert 'permissions you do not have' in created.json()['detail']

        ok = client.post('/api/v1/users', headers=csrf_headers(), json={'username':'carol','password':'a-strong-password','role_id':modest_id})
        assert ok.status_code == 201
        upgraded = client.put(f"/api/v1/users/{ok.json()['id']}", headers=csrf_headers(), json={'role_id':powerful_id})
        assert upgraded.status_code == 403
        with Session(engine) as db:
            assert db.scalar(select(User).where(User.username == 'mallory')) is None
            assert db.scalar(select(User).where(User.username == 'carol')).role.name == 'mapping_reader'
    finally:
        cleanup()


def test_admin_cannot_take_over_a_user_whose_role_has_more_permissions():
    engine, client = make_env(actor_role='admin')
    try:
        _, operator_id = _add_role(engine, 'firewall_operator', ['mapping.view', 'firewall.manage'], username='operator')
        assert client.post(f'/api/v1/users/{operator_id}/reset-password', headers=csrf_headers(), json={'password':'attacker-chosen-password'}).status_code == 403
        assert client.put(f'/api/v1/users/{operator_id}', headers=csrf_headers(), json={'email':'attacker@example.com'}).status_code == 403
        assert client.delete(f'/api/v1/users/{operator_id}', headers=csrf_headers()).status_code == 403
        with Session(engine) as db:
            operator = db.get(User, operator_id)
            assert verify_password(operator.password_hash, 'very-secure-password')
            assert operator.email == 'operator@example.com' and operator.is_active
    finally:
        cleanup()


def test_super_admin_can_still_assign_and_manage_any_custom_role():
    engine, client = make_env()
    try:
        powerful_id, operator_id = _add_role(engine, 'firewall_operator', ['firewall.manage', 'backup.restore'], username='operator')
        assert client.post('/api/v1/users', headers=csrf_headers(), json={'username':'dave','password':'a-strong-password','role_id':powerful_id}).status_code == 201
        assert client.post(f'/api/v1/users/{operator_id}/reset-password', headers=csrf_headers(), json={'password':'a-new-strong-password'}).status_code == 200
    finally:
        cleanup()


def test_role_manager_cannot_grant_or_edit_permissions_beyond_their_own():
    manager_perms = ['role.view', 'role.manage', 'mapping.view', 'user.view']
    engine, client = make_env(actor_role='admin', actor_permissions=manager_perms)
    try:
        roles = {r['name']: r['id'] for r in client.get('/api/v1/roles').json()}
        # Creating a role above the actor is refused; a subset is fine.
        assert client.post('/api/v1/roles', headers=csrf_headers(), json={'name':'escalated','permissions':['mapping.view','firewall.manage']}).status_code == 403
        assert client.post('/api/v1/roles', headers=csrf_headers(), json={'name':'reader','permissions':['mapping.view']}).status_code == 201
        # Widening another role beyond the actor's permissions is refused.
        assert client.put(f"/api/v1/roles/{roles['viewer']}/permissions", headers=csrf_headers(), json={'permissions':['mapping.view','backup.restore']}).status_code == 403
        assert client.put(f"/api/v1/roles/{roles['viewer']}/permissions", headers=csrf_headers(), json={'permissions':['mapping.view','user.view']}).status_code == 200
        # The actor's own role cannot be edited, even within scope.
        assert client.put(f"/api/v1/roles/{roles['admin']}/permissions", headers=csrf_headers(), json={'permissions':manager_perms}).status_code == 409
        # Roles that already hold permissions the actor lacks cannot be edited or deleted.
        operator_id, _ = _add_role(engine, 'firewall_operator', ['firewall.manage'])
        assert client.put(f'/api/v1/roles/{operator_id}/permissions', headers=csrf_headers(), json={'permissions':['mapping.view']}).status_code == 403
        assert client.delete(f'/api/v1/roles/{operator_id}', headers=csrf_headers()).status_code == 403
        with Session(engine) as db:
            assert db.scalar(select(Role).where(Role.name == 'escalated')) is None
            assert {p.name for p in db.get(Role, operator_id).permissions} == {'firewall.manage'}
    finally:
        cleanup()
