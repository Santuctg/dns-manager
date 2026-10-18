from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.mapping import Mapping
from app.schemas.mapping import MappingCreate, MappingUpdate


class MappingConflictError(Exception):
    pass


class MappingNotFoundError(Exception):
    pass


def list_mappings(db: Session) -> list[Mapping]:
    return list(db.scalars(select(Mapping).order_by(Mapping.domain)).all())


def get_mapping(db: Session, mapping_id: int) -> Mapping:
    row = db.get(Mapping, mapping_id)
    if row is None:
        raise MappingNotFoundError
    return row


def create_mapping(db: Session, payload: MappingCreate, actor_id: int) -> Mapping:
    row = Mapping(**payload.model_dump(), created_by=actor_id, updated_by=actor_id)
    db.add(row)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise MappingConflictError("domain already exists") from exc
    db.refresh(row)
    return row


def update_mapping(db: Session, mapping_id: int, payload: MappingUpdate, actor_id: int) -> Mapping:
    row = get_mapping(db, mapping_id)
    if row.version != payload.version:
        raise MappingConflictError("mapping changed by another user")
    for key, value in payload.model_dump(exclude={"version"}).items():
        setattr(row, key, value)
    row.updated_by = actor_id
    row.version += 1
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise MappingConflictError("domain already exists") from exc
    db.refresh(row)
    return row


def delete_mapping(db: Session, mapping_id: int) -> None:
    row = get_mapping(db, mapping_id)
    db.delete(row)
    db.commit()
