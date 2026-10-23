from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.database import get_db, get_engine
from app.dependencies import require_permission
from app.models.auth import User
from app.security import CSRF_COOKIE, SESSION_COOKIE, token_hash, validate_csrf_tokens
from app.services.audit_service import record_audit_event
from app.services.auth_service import resolve_session
from app.services.backup_service import (
    create_backup,
    delete_backup,
    MAX_UPLOAD_BYTES,
    get_backup_archive,
    import_backup_archive,
    list_backups,
    production_backup_paths,
    restore_backup,
)

router = APIRouter(prefix='/api/v1/backups', tags=['backups'])


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else 'unknown'


def _require_csrf(request: Request, db: Session) -> None:
    cookie = request.cookies.get(CSRF_COOKIE)
    submitted = request.headers.get('X-CSRF-Token')
    if not validate_csrf_tokens(cookie, submitted):
        raise HTTPException(status_code=403, detail='CSRF validation failed')
    raw_session = request.cookies.get(SESSION_COOKIE)
    session = resolve_session(db, raw_session) if raw_session else None
    if session is None or session.csrf_hash != token_hash(submitted):
        raise HTTPException(status_code=403, detail='CSRF validation failed')


@router.get('')
def backups_list(_user: User = Depends(require_permission('backup.create'))):
    return list_backups(paths=production_backup_paths())


@router.post('', status_code=status.HTTP_201_CREATED)
def backups_create(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission('backup.create')),
):
    _require_csrf(request, db)
    try:
        item = create_backup(paths=production_backup_paths(), label='manual')
    except Exception as exc:
        record_audit_event(db, user=user, action='BACKUP_CREATE_FAILED', object_type='backup', source_ip=_client_ip(request), status='failed', error_message=str(exc))
        raise HTTPException(status_code=500, detail='Backup creation failed')
    record_audit_event(db, user=user, action='BACKUP_CREATED', object_type='backup', object_id=item['backup_id'], source_ip=_client_ip(request), new_value={'size_bytes': item['size_bytes']})
    return item



async def _read_limited_body(request: Request, limit: int) -> bytes:
    declared = request.headers.get('content-length')
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise ValueError('backup upload is too large')
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            raise ValueError('backup upload is too large')
    return bytes(body)


@router.post('/upload', status_code=status.HTTP_201_CREATED)
async def backups_upload(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission('backup.restore')),
):
    _require_csrf(request, db)
    filename = request.headers.get('X-Backup-Filename', '').strip()
    try:
        payload = await _read_limited_body(request, MAX_UPLOAD_BYTES)
        item = import_backup_archive(payload, filename=filename, paths=production_backup_paths())
    except FileExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except (ValueError, OSError) as exc:
        record_audit_event(db, user=user, action='BACKUP_UPLOAD_FAILED', object_type='backup', source_ip=_client_ip(request), status='failed', error_message=str(exc))
        raise HTTPException(status_code=422, detail=str(exc))
    record_audit_event(db, user=user, action='BACKUP_UPLOADED', object_type='backup', object_id=item['backup_id'], source_ip=_client_ip(request), new_value={'size_bytes': item['size_bytes']})
    return item

@router.get('/{backup_id}/download')
def backups_download(backup_id: str, _user: User = Depends(require_permission('backup.create'))):
    try:
        archive = get_backup_archive(backup_id, paths=production_backup_paths())
    except (ValueError, FileNotFoundError):
        raise HTTPException(status_code=404, detail='Backup not found')
    return FileResponse(archive, media_type='application/gzip', filename=archive.name)


@router.delete('/{backup_id}')
def backups_delete(
    backup_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission('backup.restore')),
):
    _require_csrf(request, db)
    try:
        result = delete_backup(backup_id, paths=production_backup_paths())
    except (ValueError, FileNotFoundError) as exc:
        record_audit_event(
            db,
            user=user,
            action='BACKUP_DELETE_FAILED',
            object_type='backup',
            object_id=backup_id,
            source_ip=_client_ip(request),
            status='failed',
            error_message=str(exc),
        )
        raise HTTPException(status_code=404, detail='Backup not found')
    record_audit_event(
        db,
        user=user,
        action='BACKUP_DELETED',
        object_type='backup',
        object_id=backup_id,
        source_ip=_client_ip(request),
    )
    return result


@router.post('/{backup_id}/restore')
def backups_restore(
    backup_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission('backup.restore')),
):
    _require_csrf(request, db)
    actor_username = user.username
    actor_id = user.id
    record_audit_event(db, user=user, action='BACKUP_RESTORE_STARTED', object_type='backup', object_id=backup_id, source_ip=_client_ip(request))
    db.close()
    try:
        result = restore_backup(backup_id, paths=production_backup_paths())
        get_engine().dispose()
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception:
        raise HTTPException(status_code=500, detail='Backup restore failed')
    # The restored database may no longer contain the same user/session, so avoid reusing ORM state.
    from app.database import SessionLocal
    with SessionLocal(bind=get_engine()) as fresh:
        try:
            from app.services.ssl_service import reconcile_all_certificates
            reconcile_all_certificates(fresh)
        except Exception:
            pass
        record_audit_event(
            fresh,
            username=actor_username,
            action='BACKUP_RESTORED',
            object_type='backup',
            object_id=backup_id,
            source_ip=_client_ip(request),
            new_value={'pre_restore_backup_id': result['pre_restore_backup_id'], 'actor_id_before_restore': actor_id},
        )
    return result
