from datetime import datetime, timezone

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import Base, build_engine
from app.models import AuditLog, Mapping, Role, User


def make_session(tmp_path):
    engine = build_engine(str(tmp_path / 'models.db'))
    Base.metadata.create_all(engine)
    return Session(engine)


def test_username_is_unique(tmp_path):
    db = make_session(tmp_path)
    role = Role(name='viewer', description='Read only')
    db.add(role)
    db.flush()
    db.add(User(username='alice', email='a@example.com', password_hash='x', role_id=role.id))
    db.commit()
    db.add(User(username='alice', email='b@example.com', password_hash='y', role_id=role.id))
    with pytest.raises(IntegrityError):
        db.commit()


def test_mapping_domain_is_unique_and_lowercase(tmp_path):
    db = make_session(tmp_path)
    mapping = Mapping(
        domain='Panel.Example.COM',
        upstream_scheme='http',
        upstream_host='192.168.8.2',
        upstream_port=8082,
    )
    db.add(mapping)
    db.commit()
    db.refresh(mapping)
    assert mapping.domain == 'panel.example.com'

    db.add(Mapping(
        domain='PANEL.EXAMPLE.COM',
        upstream_scheme='http',
        upstream_host='192.168.8.3',
        upstream_port=8080,
    ))
    with pytest.raises(IntegrityError):
        db.commit()


def test_mapping_has_optimistic_concurrency_fields(tmp_path):
    db = make_session(tmp_path)
    mapping = Mapping(
        domain='app.example.com',
        upstream_scheme='https',
        upstream_host='192.168.8.4',
        upstream_port=443,
    )
    db.add(mapping)
    db.commit()
    db.refresh(mapping)
    assert mapping.version == 1
    assert isinstance(mapping.updated_at, datetime)


def test_audit_log_retains_actor_action_and_source_ip(tmp_path):
    db = make_session(tmp_path)
    event = AuditLog(
        username='admin',
        action='MAPPING_UPDATED',
        object_type='mapping',
        object_id='42',
        source_ip='192.168.8.55',
        status='success',
        created_at=datetime.now(timezone.utc),
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    assert event.username == 'admin'
    assert event.action == 'MAPPING_UPDATED'
    assert event.source_ip == '192.168.8.55'
