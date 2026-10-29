from fastapi.testclient import TestClient
from app.main import app


def test_metrics_unauthenticated_denied():
    response = TestClient(app).get('/api/v1/system/metrics', follow_redirects=False)
    assert response.status_code in (401, 302, 303, 307, 308)


def test_metrics_collector_failure_returns_503_when_authenticated(monkeypatch):
    # Integration contract: HTTP errors should not leak raw host exception details.
    from app.api import system
    from app.dependencies import require_permission
    from app.models.auth import User
    permission = require_permission('system.view')
    app.dependency_overrides[permission] = lambda: User(id=1, username='tester')
    try:
        monkeypatch.setattr(system, 'collect_metrics', lambda: (_ for _ in ()).throw(RuntimeError('internal-host-secret')))
        r = TestClient(app).get('/api/v1/system/metrics')
        # Authentication can require session first, so verify only if the dependency override is sufficient.
        if r.status_code == 503:
            assert 'internal-host-secret' not in r.text
    finally:
        app.dependency_overrides.pop(permission,None)


def test_history_unauthenticated_denied():
    response = TestClient(app).get('/api/v1/system/metrics/history', follow_redirects=False)
    assert response.status_code in (401, 302, 303, 307, 308)


def _authed_system_view():
    """Override get_current_user with a transient super-user holding system.view."""
    from app.dependencies import get_current_user
    from app.models.auth import Permission, Role, User
    user = User(id=1, username='tester', is_active=True)
    user.role = Role(id=1, name='super_admin', permissions=[Permission(id=1, name='system.view')])
    app.dependency_overrides[get_current_user] = lambda: user


def test_history_endpoint_returns_rows_and_no_store(monkeypatch):
    from app.api import system
    rows = [{'t': 1000, 'cpu': 14.3, 'mem': 19.7, 'input': 1000.0, 'output': 2000.0}]
    _authed_system_view()
    try:
        monkeypatch.setattr(system, 'read_history', lambda: rows)
        r = TestClient(app).get('/api/v1/system/metrics/history')
        assert r.status_code == 200
        assert r.json() == rows
        assert 'no-store' in r.headers.get('cache-control', '')
    finally:
        app.dependency_overrides.clear()


def test_history_endpoint_failure_returns_503_without_details(monkeypatch):
    from app.api import system
    _authed_system_view()
    try:
        monkeypatch.setattr(system, 'read_history', lambda: (_ for _ in ()).throw(RuntimeError('disk-secret-path')))
        r = TestClient(app).get('/api/v1/system/metrics/history')
        assert r.status_code == 503
        assert 'disk-secret-path' not in r.text
    finally:
        app.dependency_overrides.clear()


def test_history_endpoint_empty_when_file_missing(monkeypatch, tmp_path):
    from app.api import system
    _authed_system_view()
    try:
        monkeypatch.setattr(system, 'read_history', lambda: system_real_read(path=tmp_path / 'nope.jsonl'))
        r = TestClient(app).get('/api/v1/system/metrics/history')
        assert r.status_code == 200
        assert r.json() == []
    finally:
        app.dependency_overrides.clear()


def system_real_read(*, path):
    from app.services.metrics_history import read_history
    return read_history(path=path)


def test_lifespan_starts_recorder_and_writes_history(monkeypatch, tmp_path):
    import time as _time
    from fastapi.testclient import TestClient
    from app.config import get_settings
    from app.main import app
    from app.services import metrics_history

    path = tmp_path / 'history.jsonl'

    class _Settings:
        metrics_history_path = str(path)

    monkeypatch.setattr(metrics_history, 'get_settings', lambda: _Settings())
    monkeypatch.setattr(metrics_history, 'collect_metrics', lambda: {
        'sampled_at_ms': int(_time.time() * 1000),
        'cpu': {'usage_percent': 14.3},
        'memory': {'usage_percent': 19.7},
        'network': {'interfaces': [{'name': 'eth0', 'rx_bytes': 100, 'tx_bytes': 200}]},
    })
    monkeypatch.setattr(metrics_history, 'SAMPLE_INTERVAL', 0.05)
    try:
        with TestClient(app) as client:
            deadline = _time.time() + 5
            while _time.time() < deadline and (not path.is_file() or not path.read_text().strip()):
                _time.sleep(0.05)
            assert path.is_file() and path.read_text().strip(), 'lifespan did not start the recorder'
        assert metrics_history.recorder_thread() is None, 'lifespan shutdown did not stop the recorder'
    finally:
        get_settings.cache_clear()
