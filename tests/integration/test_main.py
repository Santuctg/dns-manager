from pathlib import Path

from fastapi.testclient import TestClient

import app.main as main_module
from app.database import build_engine


def test_health_reports_database_state(tmp_path: Path, monkeypatch):
    test_engine = build_engine(str(tmp_path / "health.db"))
    monkeypatch.setattr(main_module, "get_engine", lambda: test_engine)

    client = TestClient(main_module.app)
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}
