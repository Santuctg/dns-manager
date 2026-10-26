from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.mapping import Mapping
from app.models.revision import ConfigRevision

# "superseded": was active until a newer revision was applied (a rollback target).
# "rolled_back": was undone by a rollback and must not be restored by another one.
VALID_STATUSES = {"generated", "validated", "active", "failed", "superseded", "rolled_back"}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _mapping_state(mapping: Mapping) -> dict:
    return {
        "domain": mapping.domain,
        "upstream_scheme": mapping.upstream_scheme,
        "upstream_host": mapping.upstream_host,
        "upstream_port": mapping.upstream_port,
        "enabled": bool(mapping.enabled),
        "websocket_enabled": bool(mapping.websocket_enabled),
        "preserve_host": bool(mapping.preserve_host),
        "tls_verify": bool(mapping.tls_verify),
        "custom_timeout": mapping.custom_timeout,
        "description": mapping.description,
        "version": mapping.version,
    }


def _snapshot_current_mappings(db: Session) -> str:
    mappings = db.scalars(select(Mapping).order_by(Mapping.domain)).all()
    snapshot = {mapping.domain: _mapping_state(mapping) for mapping in mappings}
    return json.dumps(snapshot, sort_keys=True, separators=(",", ":"))


def _next_revision_name(db: Session, now: datetime) -> str:
    day = now.astimezone(timezone.utc).strftime("%Y%m%d")
    prefix = f"REV-{day}-"
    existing = db.scalars(
        select(ConfigRevision.revision)
        .where(ConfigRevision.revision.like(f"{prefix}%"))
        .order_by(ConfigRevision.revision.desc())
    ).first()
    sequence = int(existing.rsplit("-", 1)[1]) + 1 if existing else 1
    return f"{prefix}{sequence:06d}"


def create_revision(
    db: Session,
    dnsmasq_config: str,
    nginx_config: str,
    *,
    created_by: int | None,
    now: datetime | None = None,
) -> ConfigRevision:
    created_at = now or _utcnow()
    revision = ConfigRevision(
        revision=_next_revision_name(db, created_at),
        dnsmasq_config=dnsmasq_config,
        nginx_config=nginx_config,
        mapping_snapshot=_snapshot_current_mappings(db),
        created_by=created_by,
        created_at=created_at,
        status="generated",
    )
    db.add(revision)
    db.commit()
    db.refresh(revision)
    return revision


def mark_revision_status(db: Session, revision: ConfigRevision, status: str) -> ConfigRevision:
    if status not in VALID_STATUSES:
        raise ValueError(f"invalid revision status: {status}")
    if status == "active":
        for current in db.scalars(select(ConfigRevision).where(ConfigRevision.status == "active")).all():
            if current.id != revision.id:
                current.status = "superseded"
    revision.status = status
    db.commit()
    db.refresh(revision)
    return revision


def get_active_revision(db: Session) -> ConfigRevision | None:
    return db.scalars(
        select(ConfigRevision)
        .where(ConfigRevision.status == "active")
        .order_by(ConfigRevision.created_at.desc(), ConfigRevision.id.desc())
    ).first()


def get_pending_domains(db: Session) -> list[str]:
    current = json.loads(_snapshot_current_mappings(db))
    active = get_active_revision(db)
    if active is None:
        return sorted(current)
    previous = json.loads(active.mapping_snapshot or "{}")
    domains = set(current) | set(previous)
    return sorted(domain for domain in domains if current.get(domain) != previous.get(domain))


def get_pending_change_count(db: Session) -> int:
    return len(get_pending_domains(db))


def list_revisions(db: Session, *, page: int = 1, per_page: int = 50) -> tuple[list[ConfigRevision], int]:
    page = max(int(page), 1)
    per_page = min(max(int(per_page), 1), 200)
    total = int(db.scalar(select(func.count(ConfigRevision.id))) or 0)
    rows = list(
        db.scalars(
            select(ConfigRevision)
            .order_by(ConfigRevision.created_at.desc(), ConfigRevision.id.desc())
            .offset((page - 1) * per_page)
            .limit(per_page)
        ).all()
    )
    return rows, total
