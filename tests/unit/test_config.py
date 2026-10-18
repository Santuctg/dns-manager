from app.config import Settings


def test_default_bind_host_is_loopback():
    settings = Settings()
    assert settings.bind_host == "127.0.0.1"


def test_default_bind_port_is_8500():
    settings = Settings()
    assert settings.bind_port == 8500


def test_default_database_path_matches_spec():
    settings = Settings()
    assert settings.database_path == "/var/lib/dns-manager/dns-manager.db"
