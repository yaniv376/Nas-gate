"""Phone notifications: Home Assistant notify service, or a generic webhook."""

from __future__ import annotations

import logging

import httpx

from .config import Settings

log = logging.getLogger("nasgate.notify")


def send(settings: Settings, title: str, message: str, event: str = "") -> bool:
    """Send a notification. Never raises; returns True on success."""
    try:
        if settings.notify_mode == "ha":
            return _send_ha(settings, title, message, event)
        if settings.notify_mode == "webhook":
            return _send_webhook(settings, title, message, event)
        return False
    except Exception as e:  # noqa: BLE001 - notifications must never break the gate
        log.warning("notification failed: %s", e)
        return False


def _send_ha(s: Settings, title: str, message: str, event: str) -> bool:
    if not s.ha_url or not s.ha_token:
        log.warning("HA notifications selected but URL/token missing")
        return False
    service = s.ha_notify_service.strip()
    if service.startswith("notify."):
        service = service[len("notify."):]
    url = f"{s.ha_url.rstrip('/')}/api/services/notify/{service}"
    payload = {"title": title, "message": message,
               "data": {"tag": "nas-gate", "group": "nas-gate", "event": event}}
    r = httpx.post(url, json=payload, timeout=10,
                   headers={"Authorization": f"Bearer {s.ha_token}"})
    r.raise_for_status()
    return True


def _send_webhook(s: Settings, title: str, message: str, event: str) -> bool:
    if not s.webhook_url:
        return False
    r = httpx.post(s.webhook_url, json={"title": title, "message": message, "event": event},
                   timeout=10)
    r.raise_for_status()
    return True
