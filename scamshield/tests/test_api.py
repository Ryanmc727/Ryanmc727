import pytest
from fastapi.testclient import TestClient

from scamshield import api
from scamshield.config import Config
from scamshield.engine import Engine


@pytest.fixture
def make_client(monkeypatch):
    def make(token=""):
        cfg = Config(ai_enabled=False, api_token=token)
        monkeypatch.setattr(api, "get_cfg", lambda: cfg)
        monkeypatch.setattr(api, "get_engine", lambda: Engine(cfg, ai=None))
        return TestClient(api.app)
    return make


def test_page_loads(make_client):
    assert "Is this a scam?" in make_client().get("/").text


def test_check_endpoint(make_client):
    r = make_client().post("/api/check", json={"body": "Send Bitcoin now or you will be arrested", "alert_guardian": False})
    assert r.status_code == 200 and r.json()["level"] == "scam"
    assert r.json()["notification"].startswith("This is very likely a scam")


def test_token_required(make_client):
    c = make_client("s3cret")
    assert c.post("/api/check", json={"body": "hi"}).status_code == 401
    assert c.post("/api/check", json={"body": "hi"}, headers={"X-ScamShield-Token": "s3cret"}).status_code == 200
