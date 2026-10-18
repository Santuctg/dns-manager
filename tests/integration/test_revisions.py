from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models.mapping import Mapping
from app.models.revision import ConfigRevision
from app.services.revision_service import (
    create_revision,
    get_active_revision,
    get_pending_change_count,
    mark_revision_status,
)


def make_db():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def add_mapping(db, domain="panel.example.com", port=8082):
    mapping = Mapping(
        domain=domain,
        upstream_scheme="http",
        upstream_host="192.168.8.2",
        upstream_port=port,
        enabled=True,
    )
    db.add(mapping)
    db.commit()
    db.refresh(mapping)
    return mapping


def test_create_revision_generates_daily_sequence_and_retains_configs():
    db = make_db()
    add_mapping(db)
    now = datetime(2026, 10, 10, 1, 2, tzinfo=timezone.utc)

    first = create_revision(db, "dns-a", "nginx-a", created_by=1, now=now)
    second = create_revision(db, "dns-b", "nginx-b", created_by=1, now=now)

    assert first.revision == "REV-20261010-000001"
    assert second.revision == "REV-20261010-000002"
    assert first.dnsmasq_config == "dns-a"
    assert first.nginx_config == "nginx-a"
    assert first.status == "generated"


def test_revision_status_lifecycle_and_active_lookup():
    db = make_db()
    add_mapping(db)
    rev = create_revision(db, "dns", "nginx", created_by=1)

    for status in ("validated", "active", "failed", "rolled_back"):
        mark_revision_status(db, rev, status)
        assert rev.status == status

    rev2 = create_revision(db, "dns2", "nginx2", created_by=1)
    mark_revision_status(db, rev2, "active")
    assert get_active_revision(db).id == rev2.id


def test_pending_change_count_is_zero_when_mapping_state_matches_active_revision():
    db = make_db()
    add_mapping(db)
    rev = create_revision(db, "dns", "nginx", created_by=1)
    mark_revision_status(db, rev, "active")

    assert get_pending_change_count(db) == 0


def test_pending_change_count_tracks_create_update_and_delete_since_active_revision():
    db = make_db()
    existing = add_mapping(db, "panel.example.com", 8082)
    rev = create_revision(db, "dns", "nginx", created_by=1)
    mark_revision_status(db, rev, "active")

    existing.upstream_port = 9090
    existing.version += 1
    db.add(Mapping(
        domain="pbx.example.com",
        upstream_scheme="https",
        upstream_host="192.168.8.4",
        upstream_port=443,
        enabled=True,
    ))
    db.commit()

    assert get_pending_change_count(db) == 2

    db.delete(existing)
    db.commit()
    assert get_pending_change_count(db) == 2
