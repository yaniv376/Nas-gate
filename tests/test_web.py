import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("NASGATE_DATA_DIR", str(tmp_path))
    from nasgate import config, state, engine, web
    for m in (config, state, engine, web):
        importlib.reload(m)
    from tests.test_engine import FakeController
    s = config.load(); s.ui_lock_minutes = 30
    eng = engine.GateEngine(s, state.GateState(),
                            {"quickconnect": FakeController("quickconnect"), "ssh": FakeController("ssh")},
                            notifier=lambda *a: None)
    return TestClient(web.create_app(eng)), s


def test_setup_then_login_then_open(client):
    c, s = client
    assert "setup" in c.get("/").text.lower() or "password" in c.get("/").text.lower()
    assert c.get("/api/status").status_code == 403
    r = c.post("/setup", data={"password": "short", "password2": "short"}, follow_redirects=False)
    assert "password_short" in r.headers["location"]
    r = c.post("/setup", data={"password": "longenough1", "password2": "longenough1"}, follow_redirects=False)
    assert r.status_code == 303 and s.password_hash
    assert c.get("/api/status").json()["is_open"] is False
    r = c.post("/api/open?minutes=15").json()
    assert r["is_open"] and r["errors"] == []
    # lock logs everybody out
    c.post("/lock", follow_redirects=False)
    assert c.get("/api/status").status_code == 401
    r = c.post("/login", data={"password": "wrong"}, follow_redirects=False)
    assert "wrong_password" in r.headers["location"]
    c.post("/login", data={"password": "longenough1"}, follow_redirects=False)
    assert c.get("/api/status").json()["is_open"] is True


def test_api_token_access(client):
    c, s = client
    c.post("/setup", data={"password": "longenough1", "password2": "longenough1"}, follow_redirects=False)
    c.cookies.clear()
    h = {"Authorization": f"Bearer {s.api_token}"}
    assert c.get("/api/status", headers=h).status_code == 200
    assert c.get("/api/token", headers=h).status_code == 403   # token cannot read itself
    assert c.get("/api/status", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_settings_update_keeps_secret_when_blank(client):
    c, s = client
    c.post("/setup", data={"password": "longenough1", "password2": "longenough1"}, follow_redirects=False)
    c.post("/api/settings", json={"dsm_password": "secret1", "ssh_trusted_hosts": "192.168.4.5, 10.0.0.0/24"})
    assert s.dsm_password == "secret1" and s.ssh_trusted_hosts == ["192.168.4.5", "10.0.0.0/24"]
    c.post("/api/settings", json={"dsm_password": "", "ssh_port": "2222"})
    assert s.dsm_password == "secret1" and s.ssh_port == 2222
    assert c.get("/api/settings").json()["dsm_password"] == "••••••"
