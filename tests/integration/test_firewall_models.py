"""Migration and relational invariants for firewall multi-source rules."""
import importlib
from sqlalchemy import create_engine, text
from alembic.migration import MigrationContext
from alembic.operations import Operations


def test_migration_0010_backfills_legacy_rules_and_enforces_uniqueness(tmp_path):
    engine=create_engine(f'sqlite:///{tmp_path / "legacy.db"}')
    migration=importlib.import_module('migrations.versions.0010_firewall_rule_sources')
    with engine.begin() as conn:
        conn.execute(text('CREATE TABLE firewall_rules (id INTEGER PRIMARY KEY, source_cidr VARCHAR(64) NOT NULL)'))
        conn.execute(text("INSERT INTO firewall_rules VALUES (1,'0.0.0.0/0'),(2,'203.0.113.4/32')"))
        migration.op=Operations(MigrationContext.configure(conn))
        migration.upgrade()
        rows=conn.execute(text('SELECT rule_id,source_cidr,sort_key FROM firewall_rule_sources ORDER BY rule_id')).all()
        assert rows==[(1,'0.0.0.0/0',0),(2,'203.0.113.4/32',0)]
        from sqlalchemy.exc import IntegrityError
        import pytest
        with pytest.raises(IntegrityError):
            with conn.begin_nested():
                conn.execute(text("INSERT INTO firewall_rule_sources(rule_id,source_cidr,sort_key) VALUES (1,'0.0.0.0/0',1)"))
        migration.downgrade()
        assert conn.execute(text('SELECT COUNT(*) FROM firewall_rules')).scalar_one()==2
