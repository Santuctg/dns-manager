from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_permission
from app.models.auth import User
from app.models.mapping import Mapping
from app.services.health_service import check_backend, get_system_status
from app.services.metrics_history import read_history
from app.services.system_metrics import collect_metrics

router = APIRouter(tags=["system"])


@router.get("/ready")
def ready(response: Response):
    payload = get_system_status()
    if payload["status"] != "ready":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return payload


@router.get("/api/v1/system/status")
def system_status(
    _user: User = Depends(require_permission("system.view")),
):
    return get_system_status()


@router.get("/api/v1/system/metrics")
def system_metrics(response: Response, _user: User = Depends(require_permission("system.view"))):
    response.headers["Cache-Control"] = "no-store"
    try:
        return collect_metrics()
    except Exception:
        raise HTTPException(status_code=503, detail="System metrics unavailable")


@router.get("/api/v1/system/metrics/history")
def system_metrics_history(response: Response, _user: User = Depends(require_permission("system.view"))):
    """Read-only ~1 h sample history recorded by the background collector."""
    response.headers["Cache-Control"] = "no-store"
    try:
        return read_history()
    except Exception:
        raise HTTPException(status_code=503, detail="Metrics history unavailable")


@router.get("/api/v1/system/backends")
def backends(
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("system.view")),
):
    mappings = list(db.scalars(select(Mapping).order_by(Mapping.domain)).all())
    if len(mappings) <= 1:
        return [check_backend(mapping) for mapping in mappings]
    # Probe upstreams concurrently: each probe can wait for its own timeout, so
    # a sequential loop makes the dashboard wait N × timeout for the slowest
    # host. Order is preserved to match the mapping list.
    with ThreadPoolExecutor(max_workers=min(8, len(mappings))) as pool:
        return list(pool.map(check_backend, mappings))


@router.get("/api/v1/system/backends/{mapping_id}")
def backend(
    mapping_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("system.view")),
):
    mapping = db.get(Mapping, mapping_id)
    if mapping is None:
        raise HTTPException(status_code=404, detail="Mapping not found")
    return check_backend(mapping)
