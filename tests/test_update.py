import httpx
import pytest

from nasgate import update
from nasgate.config import Settings


def test_split_image():
    assert update._split_image("ghcr.io/yaniv376/nas-gate") == ("ghcr.io", "yaniv376/nas-gate")
    assert update._split_image("ghcr.io/yaniv376/nas-gate:latest") == ("ghcr.io", "yaniv376/nas-gate")
    assert update._split_image("user/thing") == ("registry-1.docker.io", "user/thing")


def test_check_detects_update(monkeypatch):
    monkeypatch.setattr(update, "VERSION", "abc1234")
    def handler(request):
        if "token" in str(request.url):
            return httpx.Response(200, json={"token": "t"})
        tag = str(request.url).rsplit("/", 1)[-1]
        return httpx.Response(200, headers={"docker-content-digest": "sha256:new" if tag == "latest" else "sha256:old"})
    transport = httpx.MockTransport(handler)
    real = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kw: real(transport=transport, **kw))
    info = update.check(Settings())
    assert info.update_available is True and info.error == ""
    assert update.cached() is info


def test_apply_without_watchtower_config():
    assert update.apply(Settings(watchtower_token=""))["ok"] is False


def test_apply_timeout_counts_as_started(monkeypatch):
    def boom(*a, **k):
        raise httpx.ReadTimeout("slow")
    monkeypatch.setattr(httpx, "post", boom)
    assert update.apply(Settings(watchtower_token="x"))["ok"] is True
