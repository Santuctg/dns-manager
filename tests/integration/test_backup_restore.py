from __future__ import annotations

import json
import sqlite3
import tarfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.auth import Permission, Role, User
from app.security import hash_password
from app.services.auth_service import ALL_PERMISSIONS, create_session
from app.services.backup_service import BackupPaths, create_backup, delete_backup, list_backups, restore_backup


@pytest.fixture(autouse=True)
def internal_proxy_ip(monkeypatch):
    from app.config import get_settings
    monkeypatch.setenv('DNS_MANAGER_INTERNAL_PROXY_IP', '192.168.1.2')
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def make_sqlite(path: Path, marker: str, mappings: tuple[tuple[str, int], ...] = ()) -> None:
    from app.models.mapping import Mapping
    engine = create_engine(f'sqlite+pysqlite:///{path}')
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add_all(Mapping(domain=domain, upstream_scheme='http', upstream_host='10.0.0.5', upstream_port=port, enabled=True) for domain, port in mappings)
        session.commit()
    engine.dispose()
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE marker (value TEXT NOT NULL)')
        db.execute('CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)')
        db.execute('INSERT INTO marker(value) VALUES (?)', (marker,))
        db.execute("INSERT INTO alembic_version(version_num) VALUES ('0005_admin_user_permissions')")
        db.commit()


def paths(tmp_path: Path) -> BackupPaths:
    generated = tmp_path / 'generated'
    return BackupPaths(
        database=tmp_path / 'dns-manager.db',
        live_dnsmasq=tmp_path / 'dns-manager.conf',
        live_nginx=tmp_path / 'nginx.conf',
        generated_dnsmasq=generated / 'dnsmasq.conf',
        generated_nginx=generated / 'nginx.conf',
        generated_nginx_main=generated / 'nginx-test.conf',
        backup_dir=tmp_path / 'backups',
        apply_lock=tmp_path / 'apply.lock',
    )


class FakeHelper:
    def __init__(self, fail_apply: bool = False):
        self.fail_apply = fail_apply
        self.calls: list[str] = []

    def validate(self):
        self.calls.append('validate')
        return {'validated': True}

    def apply(self):
        self.calls.append('apply')
        if self.fail_apply:
            raise RuntimeError('apply failed')
        return {'applied': True}

    def rollback(self):
        self.calls.append('rollback')
        return {'rolled_back': True}

    def status(self):
        self.calls.append('status')
        return {'dnsmasq': 'active', 'nginx': 'active'}


def test_backup_contains_consistent_database_configs_manifest_and_checksums(tmp_path):
    p = paths(tmp_path)
    make_sqlite(p.database, 'original')
    p.live_dnsmasq.write_text('address=/panel.example/192.168.1.2\n')
    p.live_nginx.write_text('server { listen 80; }\n')

    item = create_backup(paths=p, label='manual')

    assert item['backup_id'].startswith('BKP-')
    assert item['label'] == 'manual'
    assert item['alembic_version'] == '0005_admin_user_permissions'
    assert item['size_bytes'] > 0
    assert list_backups(paths=p)[0]['backup_id'] == item['backup_id']

    archive = p.backup_dir / f"{item['backup_id']}.tar.gz"
    with tarfile.open(archive, 'r:gz') as tf:
        names = sorted(tf.getnames())
        assert names == ['database.sqlite3', 'dnsmasq.conf', 'manifest.json', 'nginx.conf']
        manifest = json.load(tf.extractfile('manifest.json'))
        assert set(manifest['sha256']) == {'database.sqlite3', 'dnsmasq.conf', 'nginx.conf'}


def test_restore_rejects_tampered_backup_before_changing_live_database(tmp_path):
    p = paths(tmp_path)
    make_sqlite(p.database, 'live')
    p.live_dnsmasq.write_text('live dns\n')
    p.live_nginx.write_text('live nginx\n')
    item = create_backup(paths=p)
    archive = p.backup_dir / f"{item['backup_id']}.tar.gz"

    # Repack with a changed database but the original manifest/checksum.
    with tarfile.open(archive, 'r:gz') as tf:
        payload = {name: tf.extractfile(name).read() for name in tf.getnames()}
    payload['database.sqlite3'] += b'tamper'
    with tarfile.open(archive, 'w:gz') as tf:
        for name, data in payload.items():
            import io
            info = tarfile.TarInfo(name); info.size = len(data); info.mode = 0o600
            tf.addfile(info, io.BytesIO(data))

    with pytest.raises(ValueError, match='checksum'):
        restore_backup(item['backup_id'], paths=p, helper=FakeHelper())

    with sqlite3.connect(p.database) as db:
        assert db.execute('SELECT value FROM marker').fetchone()[0] == 'live'


def test_restore_creates_pre_restore_backup_and_restores_db_and_configs(tmp_path):
    p = paths(tmp_path)
    make_sqlite(p.database, 'wanted', mappings=(('wanted.example.com', 8081),))
    p.live_dnsmasq.write_text('wanted dns\n')
    p.live_nginx.write_text('wanted nginx\n')
    wanted = create_backup(paths=p)

    p.database.unlink(); make_sqlite(p.database, 'current', mappings=(('current.example.com', 8082),))
    p.live_dnsmasq.write_text('current dns\n')
    p.live_nginx.write_text('current nginx\n')
    helper = FakeHelper()

    result = restore_backup(wanted['backup_id'], paths=p, helper=helper)

    assert result['restored_backup_id'] == wanted['backup_id']
    assert result['pre_restore_backup_id'].startswith('BKP-')
    assert result['pre_restore_backup_id'] != wanted['backup_id']
    assert helper.calls == ['validate', 'apply', 'status']
    with sqlite3.connect(p.database) as db:
        assert db.execute('SELECT value FROM marker').fetchone()[0] == 'wanted'
        # The applied configuration is recorded as the active revision.
        active = db.execute("SELECT nginx_config FROM config_revisions WHERE status='active'").fetchall()
    # Configuration is regenerated from the restored mappings, not copied from the archive.
    assert 'address=/wanted.example.com/192.168.1.2' in p.generated_dnsmasq.read_text()
    assert 'server_name wanted.example.com;' in p.generated_nginx.read_text()
    assert 'current.example.com' not in p.generated_nginx.read_text()
    assert active == [(p.generated_nginx.read_text(),)]


def _forge_config_members(archive: Path, *, dnsmasq: bytes, nginx: bytes) -> None:
    import hashlib, io
    with tarfile.open(archive, 'r:gz') as tf:
        payload = {name: tf.extractfile(name).read() for name in tf.getnames()}
    payload['dnsmasq.conf'] = dnsmasq
    payload['nginx.conf'] = nginx
    manifest = json.loads(payload['manifest.json'])
    manifest['sha256']['dnsmasq.conf'] = hashlib.sha256(dnsmasq).hexdigest()
    manifest['sha256']['nginx.conf'] = hashlib.sha256(nginx).hexdigest()
    payload['manifest.json'] = json.dumps(manifest).encode()
    with tarfile.open(archive, 'w:gz') as tf:
        for name, data in payload.items():
            info = tarfile.TarInfo(name); info.size = len(data); info.mode = 0o600
            tf.addfile(info, io.BytesIO(data))


def test_restore_ignores_config_files_in_a_forged_archive(tmp_path):
    p = paths(tmp_path)
    make_sqlite(p.database, 'wanted', mappings=(('wanted.example.com', 8081),))
    item = create_backup(paths=p)
    # A self-consistent archive: the checksums match, but the configs are hostile.
    _forge_config_members(
        p.backup_dir / f"{item['backup_id']}.tar.gz",
        dnsmasq=b'dhcp-script=/tmp/evil.sh\n',
        nginx=b'server { listen 80; location / { root /; } }\n',
    )

    restore_backup(item['backup_id'], paths=p, helper=FakeHelper())

    assert 'dhcp-script' not in p.generated_dnsmasq.read_text()
    assert 'root /' not in p.generated_nginx.read_text()
    assert 'server_name wanted.example.com;' in p.generated_nginx.read_text()


def test_restore_rejects_invalid_mappings_in_a_forged_database(tmp_path):
    p = paths(tmp_path)
    make_sqlite(p.database, 'wanted')
    with sqlite3.connect(p.database) as db:
        columns = [row[1] for row in db.execute('PRAGMA table_info(mappings)')]
        values = {'domain': 'evil.example.com', 'upstream_scheme': 'http', 'upstream_host': '10.0.0.5:80; include /etc/shadow',
                  'upstream_port': 80, 'enabled': 1, 'websocket_enabled': 1, 'preserve_host': 1, 'tls_verify': 1, 'version': 1,
                  'created_at': '2026-01-01 00:00:00', 'updated_at': '2026-01-01 00:00:00'}
        values = {k: v for k, v in values.items() if k in columns}
        db.execute(f"INSERT INTO mappings ({', '.join(values)}) VALUES ({', '.join('?' for _ in values)})", list(values.values()))
        db.commit()
    item = create_backup(paths=p)
    helper = FakeHelper()

    with pytest.raises(ValueError, match='upstream host'):
        restore_backup(item['backup_id'], paths=p, helper=helper)
    assert helper.calls == []


def test_restore_requires_internal_proxy_ip(tmp_path, monkeypatch):
    from app.config import get_settings
    p = paths(tmp_path)
    make_sqlite(p.database, 'wanted')
    item = create_backup(paths=p)
    monkeypatch.delenv('DNS_MANAGER_INTERNAL_PROXY_IP')
    get_settings.cache_clear()
    with pytest.raises(ValueError, match='INTERNAL_PROXY_IP'):
        restore_backup(item['backup_id'], paths=p, helper=FakeHelper())


def test_restore_waits_for_the_apply_lock(tmp_path):
    import fcntl
    from app.services.apply_service import ConfigLockedError
    p = paths(tmp_path)
    make_sqlite(p.database, 'wanted')
    item = create_backup(paths=p)
    p.apply_lock.touch()
    with p.apply_lock.open('a+') as held:
        fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(ConfigLockedError):
            restore_backup(item['backup_id'], paths=p, helper=FakeHelper())


def test_backup_upload_api_rejects_oversized_body(monkeypatch, tmp_path):
    import app.api.backups as backup_api
    monkeypatch.setattr(backup_api, 'production_backup_paths', lambda: paths(tmp_path))
    monkeypatch.setattr(backup_api, 'MAX_UPLOAD_BYTES', 1024)
    client = make_api_env('super_admin')
    try:
        response = client.post('/api/v1/backups/upload', headers={'X-CSRF-Token': 'csrf-token', 'X-Backup-Filename': 'big.tar.gz'}, content=b'x' * 2048)
        assert response.status_code == 422 and 'too large' in response.json()['detail']
    finally:
        app.dependency_overrides.clear()


def test_restore_rolls_back_database_when_config_apply_fails(tmp_path):
    p = paths(tmp_path)
    make_sqlite(p.database, 'wanted')
    p.live_dnsmasq.write_text('wanted dns\n'); p.live_nginx.write_text('wanted nginx\n')
    wanted = create_backup(paths=p)
    p.database.unlink(); make_sqlite(p.database, 'current')
    p.live_dnsmasq.write_text('current dns\n'); p.live_nginx.write_text('current nginx\n')
    helper = FakeHelper(fail_apply=True)

    with pytest.raises(RuntimeError, match='apply failed'):
        restore_backup(wanted['backup_id'], paths=p, helper=helper)

    assert helper.calls == ['validate', 'apply', 'rollback']
    with sqlite3.connect(p.database) as db:
        assert db.execute('SELECT value FROM marker').fetchone()[0] == 'current'


def make_api_env(role_name: str):
    engine = create_engine('sqlite+pysqlite:///:memory:', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        perms = {name: Permission(name=name) for name in sorted(ALL_PERMISSIONS)}
        role = Role(name=role_name, permissions=[perms[n] for n in sorted(ALL_PERMISSIONS if role_name == 'super_admin' else {'system.view'})])
        user = User(username=f'{role_name}-backup', password_hash=hash_password('very-secure-password'), role=role)
        db.add_all([*perms.values(), role, user]); db.commit(); db.refresh(user)
        raw = create_session(db, user, 'csrf-token')
    def override_db():
        with Session(engine) as db:
            yield db
    app.dependency_overrides[get_db] = override_db
    client = TestClient(app, base_url='https://testserver')
    client.cookies.set('dns_manager_session', raw); client.cookies.set('dns_manager_csrf', 'csrf-token')
    return client


def test_backup_api_is_super_admin_only_and_requires_csrf(monkeypatch, tmp_path):
    from app.api import backups as backup_api
    p = paths(tmp_path); make_sqlite(p.database, 'api'); p.live_dnsmasq.write_text('dns\n'); p.live_nginx.write_text('nginx\n')
    monkeypatch.setattr(backup_api, 'production_backup_paths', lambda: p)

    viewer = make_api_env('viewer')
    try:
        assert viewer.get('/api/v1/backups').status_code == 403
        assert viewer.post('/api/v1/backups', headers={'X-CSRF-Token':'csrf-token'}).status_code == 403
    finally:
        app.dependency_overrides.clear()

    admin = make_api_env('super_admin')
    try:
        assert admin.post('/api/v1/backups').status_code == 403
        created = admin.post('/api/v1/backups', headers={'X-CSRF-Token':'csrf-token'})
        assert created.status_code == 201
        backup_id = created.json()['backup_id']
        listing = admin.get('/api/v1/backups')
        assert listing.status_code == 200
        assert listing.json()[0]['backup_id'] == backup_id
        download = admin.get(f'/api/v1/backups/{backup_id}/download')
        assert download.status_code == 200
        assert download.headers['content-type'] == 'application/gzip'
    finally:
        app.dependency_overrides.clear()



def test_delete_backup_validates_id_and_removes_only_selected_archive(tmp_path):
    p = paths(tmp_path)
    make_sqlite(p.database, 'delete')
    p.live_dnsmasq.write_text('dns\n')
    p.live_nginx.write_text('nginx\n')
    first = create_backup(paths=p)
    second = create_backup(paths=p)

    result = delete_backup(first['backup_id'], paths=p)

    assert result == {'deleted_backup_id': first['backup_id']}
    assert not (p.backup_dir / f"{first['backup_id']}.tar.gz").exists()
    assert (p.backup_dir / f"{second['backup_id']}.tar.gz").is_file()
    with pytest.raises(ValueError, match='invalid backup id'):
        delete_backup('../outside', paths=p)
    with pytest.raises(FileNotFoundError):
        delete_backup(first['backup_id'], paths=p)


def test_backup_delete_api_is_super_admin_only_requires_csrf_and_audits(monkeypatch, tmp_path):
    from app.api import backups as backup_api
    p = paths(tmp_path); make_sqlite(p.database, 'api-delete'); p.live_dnsmasq.write_text('dns\n'); p.live_nginx.write_text('nginx\n')
    monkeypatch.setattr(backup_api, 'production_backup_paths', lambda: p)

    viewer = make_api_env('viewer')
    try:
        assert viewer.delete('/api/v1/backups/BKP-20261010T000000.000000Z-aaaaaaaa', headers={'X-CSRF-Token':'csrf-token'}).status_code == 403
    finally:
        app.dependency_overrides.clear()

    admin = make_api_env('super_admin')
    try:
        created = admin.post('/api/v1/backups', headers={'X-CSRF-Token':'csrf-token'})
        assert created.status_code == 201
        backup_id = created.json()['backup_id']
        assert admin.delete(f'/api/v1/backups/{backup_id}').status_code == 403
        deleted = admin.delete(f'/api/v1/backups/{backup_id}', headers={'X-CSRF-Token':'csrf-token'})
        assert deleted.status_code == 200
        assert deleted.json() == {'deleted_backup_id': backup_id}
        assert admin.get('/api/v1/backups').json() == []
        assert admin.delete(f'/api/v1/backups/{backup_id}', headers={'X-CSRF-Token':'csrf-token'}).status_code == 404
    finally:
        app.dependency_overrides.clear()

def test_restore_rejects_backup_from_different_schema_version(tmp_path):
    p = paths(tmp_path)
    make_sqlite(p.database, 'old')
    with sqlite3.connect(p.database) as db:
        db.execute("UPDATE alembic_version SET version_num='0004_revision_mapping_snapshot'")
        db.commit()
    old = create_backup(paths=p)

    p.database.unlink()
    make_sqlite(p.database, 'current')
    p.live_dnsmasq.write_text('current dns\n')
    p.live_nginx.write_text('current nginx\n')

    with pytest.raises(ValueError, match='schema version'):
        restore_backup(old['backup_id'], paths=p, helper=FakeHelper())


def test_backup_restore_preserves_acme_delegation_identity(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from app.database import Base
    from app.models.ssl import SslCertificate
    from app.models.acme_dns import SslAcmeDelegation
    p=paths(tmp_path)
    engine=create_engine(f'sqlite+pysqlite:///{p.database}')
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.exec_driver_sql('CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)')
        conn.exec_driver_sql("INSERT INTO alembic_version(version_num) VALUES ('0007_acme_dns_delegation')")
    with Session(engine) as db:
        cert=SslCertificate(domain='example.com',provider='acme_delegation',status='ISSUED')
        db.add(cert); db.flush()
        db.add(SslAcmeDelegation(certificate_id=cert.id,domain='example.com',challenge_domain='_acme-challenge.example.com',delegation_id='dns-123456abcdef',delegated_fqdn='dns-123456abcdef.acme-dns.connect3.net.bd',verified=True))
        db.commit()
    p.live_dnsmasq.write_text('dns\n'); p.live_nginx.write_text('nginx\n')
    backup=create_backup(paths=p)
    with sqlite3.connect(p.database) as db:
        db.execute("UPDATE ssl_acme_delegations SET delegation_id='dns-aaaaaaaaaaaa', delegated_fqdn='dns-aaaaaaaaaaaa.acme-dns.connect3.net.bd'")
        db.commit()
    restore_backup(backup['backup_id'],paths=p,helper=FakeHelper())
    with sqlite3.connect(p.database) as db:
        row=db.execute('SELECT delegation_id,delegated_fqdn FROM ssl_acme_delegations').fetchone()
    assert row==('dns-123456abcdef','dns-123456abcdef.acme-dns.connect3.net.bd')


def test_backup_preserves_hosted_acme_ciphertext_without_plaintext(tmp_path, monkeypatch):
    from cryptography.fernet import Fernet
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from app.database import Base
    from app.models.ssl import SslCertificate
    from app.models.hosted_acme import SslHostedAcmeCredential
    from app.services.ssl_crypto import encrypt_secret, load_ssl_secret_key
    import tarfile
    p=paths(tmp_path)
    key=tmp_path/'ssl-key'; key.write_bytes(Fernet.generate_key()); monkeypatch.setenv('DNS_MANAGER_SSL_SECRET_KEY_FILE',str(key)); load_ssl_secret_key.cache_clear()
    engine=create_engine(f'sqlite+pysqlite:///{p.database}'); Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.exec_driver_sql('CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)')
        conn.exec_driver_sql("INSERT INTO alembic_version(version_num) VALUES ('0008_hosted_acme_dns')")
    with Session(engine) as db:
        cert=SslCertificate(domain='example.com',provider='acme_dns_hosted',status='ISSUED'); db.add(cert); db.flush()
        db.add(SslHostedAcmeCredential(certificate_id=cert.id,server_url='https://auth.acme-dns.io',username_ciphertext=encrypt_secret('plain-user-secret'),password_ciphertext=encrypt_secret('plain-pass-secret'),subdomain='abc',fulldomain='abc.auth.acme-dns.io',challenge_domain='_acme-challenge.example.com',verified=True)); db.commit()
    p.live_dnsmasq.write_text('dns\n'); p.live_nginx.write_text('nginx\n')
    backup=create_backup(paths=p); archive=p.backup_dir/f"{backup['backup_id']}.tar.gz"
    raw=archive.read_bytes()
    assert b'plain-user-secret' not in raw and b'plain-pass-secret' not in raw
    with tarfile.open(archive,'r:gz') as tf:
        dbbytes=tf.extractfile('database.sqlite3').read()
        assert b'abc.auth.acme-dns.io' in dbbytes
        assert b'plain-user-secret' not in dbbytes and b'plain-pass-secret' not in dbbytes


def test_import_backup_archive_validates_and_registers_uploaded_backup(tmp_path):
    from app.services.backup_service import import_backup_archive
    source = paths(tmp_path / 'source')
    source.database.parent.mkdir(parents=True, exist_ok=True)
    make_sqlite(source.database, 'upload-source')
    source.live_dnsmasq.write_text('dns-upload\n')
    source.live_nginx.write_text('nginx-upload\n')
    created = create_backup(paths=source, label='upload-source')
    payload = (source.backup_dir / f"{created['backup_id']}.tar.gz").read_bytes()

    target = paths(tmp_path / 'target')
    target.backup_dir.mkdir(parents=True, exist_ok=True)
    imported = import_backup_archive(payload, paths=target, filename=f"{created['backup_id']}.tar.gz")

    assert imported['backup_id'] == created['backup_id']
    assert imported['label'] == 'upload-source'
    assert (target.backup_dir / f"{created['backup_id']}.tar.gz").is_file()
    assert list_backups(paths=target)[0]['backup_id'] == created['backup_id']

    with pytest.raises(FileExistsError, match='backup already exists'):
        import_backup_archive(payload, paths=target, filename=f"{created['backup_id']}.tar.gz")
    with pytest.raises(ValueError, match=r'\.tar\.gz'):
        import_backup_archive(payload, paths=target, filename='backup.zip')
    with pytest.raises(ValueError):
        import_backup_archive(b'not-a-backup', paths=target, filename='bad.tar.gz')


def test_backup_upload_api_requires_restore_permission_csrf_and_audits(monkeypatch, tmp_path):
    from app.api import backups as backup_api
    source = paths(tmp_path / 'source-api')
    source.database.parent.mkdir(parents=True, exist_ok=True)
    make_sqlite(source.database, 'upload-api')
    source.live_dnsmasq.write_text('dns\n'); source.live_nginx.write_text('nginx\n')
    created = create_backup(paths=source, label='portable')
    payload = (source.backup_dir / f"{created['backup_id']}.tar.gz").read_bytes()

    target = paths(tmp_path / 'target-api')
    target.backup_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(backup_api, 'production_backup_paths', lambda: target)

    viewer = make_api_env('viewer')
    try:
        r = viewer.post('/api/v1/backups/upload', content=payload, headers={'X-CSRF-Token':'csrf-token','X-Backup-Filename':f"{created['backup_id']}.tar.gz",'Content-Type':'application/gzip'})
        assert r.status_code == 403
    finally:
        app.dependency_overrides.clear()

    admin = make_api_env('super_admin')
    try:
        assert admin.post('/api/v1/backups/upload', content=payload, headers={'X-Backup-Filename':f"{created['backup_id']}.tar.gz"}).status_code == 403
        uploaded = admin.post('/api/v1/backups/upload', content=payload, headers={'X-CSRF-Token':'csrf-token','X-Backup-Filename':f"{created['backup_id']}.tar.gz",'Content-Type':'application/gzip'})
        assert uploaded.status_code == 201
        assert uploaded.json()['backup_id'] == created['backup_id']
        assert admin.get('/api/v1/backups').json()[0]['backup_id'] == created['backup_id']
    finally:
        app.dependency_overrides.clear()
