from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.config import get_settings
from app.services.apply_service import (
    DEFAULT_LOCK_PATH,
    _apply_lock,
    _atomic_write,
    _install_staged,
    _nginx_test_config,
    preview_config,
)
from app.services.privileged_helper import PrivilegedHelper
from app.services.revision_service import create_revision, mark_revision_status

BACKUP_FORMAT_VERSION = 1
BACKUP_ID_RE = re.compile(r"^BKP-[0-9]{8}T[0-9]{6}\.[0-9]{6}Z-[0-9a-f]{8}$")
ARCHIVE_MEMBERS = {"manifest.json", "database.sqlite3", "dnsmasq.conf", "nginx.conf"}
MAX_MEMBER_BYTES = 1024 * 1024 * 1024
MAX_UPLOAD_BYTES = 256 * 1024 * 1024


@dataclass(frozen=True)
class BackupPaths:
    database: Path
    live_dnsmasq: Path
    live_nginx: Path
    generated_dnsmasq: Path
    generated_nginx: Path
    generated_nginx_main: Path
    backup_dir: Path
    apply_lock: Path = DEFAULT_LOCK_PATH


def production_backup_paths() -> BackupPaths:
    return BackupPaths(
        database=Path(get_settings().database_path),
        live_dnsmasq=Path('/etc/dnsmasq.d/dns-manager.conf'),
        live_nginx=Path('/etc/nginx/conf.d/dns-manager.conf'),
        generated_dnsmasq=Path('/var/lib/dns-manager/generated/dnsmasq.conf'),
        generated_nginx=Path('/var/lib/dns-manager/generated/nginx.conf'),
        generated_nginx_main=Path('/var/lib/dns-manager/generated/nginx-test.conf'),
        backup_dir=Path('/var/lib/dns-manager/backups'),
    )


def _new_backup_id() -> str:
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    return f'BKP-{stamp}-{secrets.token_hex(4)}'


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _alembic_version(path: Path) -> str | None:
    with sqlite3.connect(path) as db:
        row = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alembic_version'").fetchone()
        if not row:
            return None
        version = db.execute('SELECT version_num FROM alembic_version LIMIT 1').fetchone()
        return version[0] if version else None


def _integrity_check(path: Path) -> None:
    with sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=5) as db:
        result = db.execute('PRAGMA integrity_check').fetchone()
    if result is None or result[0] != 'ok':
        raise ValueError('SQLite integrity check failed')


def _sqlite_snapshot(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise FileNotFoundError(str(source))
    with sqlite3.connect(f'file:{source}?mode=ro', uri=True, timeout=5) as src, sqlite3.connect(destination) as dst:
        src.backup(dst)
        dst.commit()
    _integrity_check(destination)


def _sqlite_restore(source: Path, destination: Path) -> None:
    _integrity_check(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(f'file:{source}?mode=ro', uri=True, timeout=5) as src, sqlite3.connect(destination, timeout=5) as dst:
        src.backup(dst)
        dst.commit()


def _copy_or_empty(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.is_file():
        destination.write_bytes(source.read_bytes())
    else:
        destination.write_bytes(b'')
    os.chmod(destination, 0o600)


def create_backup(*, paths: BackupPaths | None = None, label: str | None = None) -> dict:
    paths = paths or production_backup_paths()
    paths.backup_dir.mkdir(parents=True, exist_ok=True)
    backup_id = _new_backup_id()
    created_at = datetime.now(timezone.utc).isoformat()
    archive = paths.backup_dir / f'{backup_id}.tar.gz'

    with tempfile.TemporaryDirectory(prefix='.backup-', dir=paths.backup_dir) as tmp:
        work = Path(tmp)
        database = work / 'database.sqlite3'
        dnsmasq = work / 'dnsmasq.conf'
        nginx = work / 'nginx.conf'
        _sqlite_snapshot(paths.database, database)
        _copy_or_empty(paths.live_dnsmasq, dnsmasq)
        _copy_or_empty(paths.live_nginx, nginx)
        manifest = {
            'format_version': BACKUP_FORMAT_VERSION,
            'backup_id': backup_id,
            'created_at': created_at,
            'label': label,
            'alembic_version': _alembic_version(database),
            'sha256': {
                'database.sqlite3': _sha256(database),
                'dnsmasq.conf': _sha256(dnsmasq),
                'nginx.conf': _sha256(nginx),
            },
        }
        manifest_path = work / 'manifest.json'
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(',', ':')), encoding='utf-8')
        with tarfile.open(archive, 'w:gz') as tf:
            for name in ('manifest.json', 'database.sqlite3', 'dnsmasq.conf', 'nginx.conf'):
                tf.add(work / name, arcname=name, recursive=False)
    os.chmod(archive, 0o600)
    item = {**manifest, 'size_bytes': archive.stat().st_size}
    return item


def _archive_path(backup_id: str, paths: BackupPaths) -> Path:
    if not BACKUP_ID_RE.fullmatch(backup_id):
        raise ValueError('invalid backup id')
    return paths.backup_dir / f'{backup_id}.tar.gz'


def _read_manifest(archive: Path) -> dict:
    if not archive.is_file():
        raise FileNotFoundError(str(archive))
    with tarfile.open(archive, 'r:gz') as tf:
        members = tf.getmembers()
        if {m.name for m in members} != ARCHIVE_MEMBERS:
            raise ValueError('backup archive has unexpected members')
        for member in members:
            if not member.isfile() or member.size < 0 or member.size > MAX_MEMBER_BYTES:
                raise ValueError('backup archive contains unsafe member')
        raw = tf.extractfile('manifest.json')
        if raw is None:
            raise ValueError('backup manifest missing')
        manifest = json.load(raw)
    if manifest.get('format_version') != BACKUP_FORMAT_VERSION:
        raise ValueError('unsupported backup format')
    if manifest.get('backup_id') != archive.name.removesuffix('.tar.gz'):
        raise ValueError('backup id mismatch')
    return manifest


def list_backups(*, paths: BackupPaths | None = None) -> list[dict]:
    paths = paths or production_backup_paths()
    if not paths.backup_dir.exists():
        return []
    items: list[dict] = []
    for archive in paths.backup_dir.glob('BKP-*.tar.gz'):
        try:
            manifest = _read_manifest(archive)
        except (OSError, ValueError, tarfile.TarError, json.JSONDecodeError):
            continue
        items.append({**manifest, 'size_bytes': archive.stat().st_size})
    items.sort(key=lambda item: item.get('created_at', ''), reverse=True)
    return items




def import_backup_archive(payload: bytes, *, filename: str, paths: BackupPaths | None = None) -> dict:
    paths = paths or production_backup_paths()
    if not filename.lower().endswith(('.tar.gz', '.tgz')):
        raise ValueError('backup upload must be a .tar.gz or .tgz archive')
    if not payload:
        raise ValueError('backup upload is empty')
    if len(payload) > MAX_UPLOAD_BYTES:
        raise ValueError('backup upload is too large')
    paths.backup_dir.mkdir(parents=True, exist_ok=True)
    temp = paths.backup_dir / f'.upload-{secrets.token_hex(8)}.tar.gz'
    temp.write_bytes(payload)
    os.chmod(temp, 0o600)
    final = None
    try:
        with tarfile.open(temp, 'r:gz') as tf:
            members = tf.getmembers()
            if {m.name for m in members} != ARCHIVE_MEMBERS:
                raise ValueError('backup archive has unexpected members')
            for member in members:
                if not member.isfile() or member.size < 0 or member.size > MAX_MEMBER_BYTES:
                    raise ValueError('backup archive contains unsafe member')
            raw = tf.extractfile('manifest.json')
            if raw is None:
                raise ValueError('backup manifest missing')
            manifest = json.load(raw)
        backup_id = str(manifest.get('backup_id') or '')
        if not BACKUP_ID_RE.fullmatch(backup_id):
            raise ValueError('invalid backup id')
        if manifest.get('format_version') != BACKUP_FORMAT_VERSION:
            raise ValueError('unsupported backup format')
        final = _archive_path(backup_id, paths)
        if final.exists():
            raise FileExistsError('backup already exists')
        temp.replace(final)
        with tempfile.TemporaryDirectory(prefix='.upload-validate-', dir=paths.backup_dir) as tmp:
            validated = _extract_validated(backup_id, paths, Path(tmp))
        os.chmod(final, 0o600)
        return {**validated, 'size_bytes': final.stat().st_size}
    except (tarfile.TarError, json.JSONDecodeError) as exc:
        raise ValueError('invalid backup archive') from exc
    except Exception:
        if final is not None and final.exists():
            final.unlink()
        raise
    finally:
        if temp.exists():
            temp.unlink()

def delete_backup(backup_id: str, *, paths: BackupPaths | None = None) -> dict:
    paths = paths or production_backup_paths()
    archive = _archive_path(backup_id, paths)
    if not archive.is_file():
        raise FileNotFoundError(str(archive))
    archive.unlink()
    return {'deleted_backup_id': backup_id}

def get_backup_archive(backup_id: str, *, paths: BackupPaths | None = None) -> Path:
    paths = paths or production_backup_paths()
    archive = _archive_path(backup_id, paths)
    _read_manifest(archive)
    return archive


def _extract_validated(backup_id: str, paths: BackupPaths, destination: Path) -> dict:
    archive = _archive_path(backup_id, paths)
    manifest = _read_manifest(archive)
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, 'r:gz') as tf:
        for name in ('database.sqlite3', 'dnsmasq.conf', 'nginx.conf'):
            src = tf.extractfile(name)
            if src is None:
                raise ValueError(f'{name} missing')
            target = destination / name
            with target.open('wb') as out:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
            expected = manifest.get('sha256', {}).get(name)
            if not expected or _sha256(target) != expected:
                raise ValueError(f'{name} checksum mismatch')
    _integrity_check(destination / 'database.sqlite3')
    if _alembic_version(destination / 'database.sqlite3') != manifest.get('alembic_version'):
        raise ValueError('backup schema metadata mismatch')
    return manifest


def _sqlite_session(path: Path):
    engine = create_engine(f'sqlite+pysqlite:///{path}')
    return engine, Session(engine)


def _render_from_database(database: Path, internal_proxy_ip: str) -> dict[str, str]:
    """Render configuration from a backup's mappings rather than trusting its config files.

    An uploaded archive's nginx.conf / dnsmasq.conf are arbitrary text; the
    mappings go through the same validation as configuration created in the UI.
    """
    engine, db = _sqlite_session(database)
    try:
        return preview_config(db, internal_proxy_ip=internal_proxy_ip)
    finally:
        db.close()
        engine.dispose()


def _stage_configs(paths: BackupPaths, rendered: dict[str, str]) -> None:
    _atomic_write(paths.generated_dnsmasq, rendered['dnsmasq_config'])
    _atomic_write(paths.generated_nginx, rendered['nginx_config'])
    _atomic_write(paths.generated_nginx_main, _nginx_test_config(paths.generated_nginx))


def _record_restored_revision(database: Path, rendered: dict[str, str]) -> None:
    engine, db = _sqlite_session(database)
    try:
        revision = create_revision(db, rendered['dnsmasq_config'], rendered['nginx_config'], created_by=None)
        mark_revision_status(db, revision, 'active')
    finally:
        db.close()
        engine.dispose()


def restore_backup(
    backup_id: str,
    *,
    paths: BackupPaths | None = None,
    helper: PrivilegedHelper | None = None,
    internal_proxy_ip: str | None = None,
) -> dict:
    paths = paths or production_backup_paths()
    helper = helper or PrivilegedHelper()
    internal_proxy_ip = internal_proxy_ip or get_settings().internal_proxy_ip
    if not internal_proxy_ip:
        raise ValueError('DNS_MANAGER_INTERNAL_PROXY_IP is not configured')
    paths.backup_dir.mkdir(parents=True, exist_ok=True)
    with _apply_lock(paths.apply_lock), tempfile.TemporaryDirectory(prefix='.restore-', dir=paths.backup_dir) as tmp:
        work = Path(tmp)
        manifest = _extract_validated(backup_id, paths, work)
        current_version = _alembic_version(paths.database)
        if manifest.get('alembic_version') != current_version:
            raise ValueError('backup schema version does not match current database')
        rendered = _render_from_database(work / 'database.sqlite3', internal_proxy_ip)
        _stage_configs(paths, rendered)
        helper.validate()

        pre = create_backup(paths=paths, label=f'pre-restore:{backup_id}')
        pre_work = work / 'pre'
        _extract_validated(pre['backup_id'], paths, pre_work)
        try:
            _sqlite_restore(work / 'database.sqlite3', paths.database)
            _install_staged(helper, check='restore')
            _record_restored_revision(paths.database, rendered)
        except Exception:
            _sqlite_restore(pre_work / 'database.sqlite3', paths.database)
            raise
    return {
        'restored_backup_id': backup_id,
        'pre_restore_backup_id': pre['backup_id'],
        'alembic_version': manifest.get('alembic_version'),
    }
