from pathlib import Path

from sqlalchemy import text

from app.database import build_engine


def test_sqlite_connection_enables_required_pragmas(tmp_path: Path):
    db_path = tmp_path / "dns-manager.db"
    engine = build_engine(str(db_path))

    with engine.connect() as connection:
        journal_mode = connection.execute(text("PRAGMA journal_mode")).scalar_one()
        foreign_keys = connection.execute(text("PRAGMA foreign_keys")).scalar_one()
        busy_timeout = connection.execute(text("PRAGMA busy_timeout")).scalar_one()

    assert journal_mode.lower() == "wal"
    assert foreign_keys == 1
    assert busy_timeout == 5000
