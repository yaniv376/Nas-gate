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
    data: dict = {"tag": "nas-gate", "group": "nas-gate", "event": event}
    # Action buttons for the Home Assistant Companion app. An automation in HA
    # listening for `mobile_app_notification_action` turns them into API calls
    # (see README, "Home Assistant integration").
    if event in ("n_opened", "n_reminder", "n_warning"):
        lang = s.language
        data["actions"] = [
            {"action": "NAS_GATE_EXTEND_60", "title": _label(lang, "extend")},
            {"action": "NAS_GATE_CLOSE", "title": _label(lang, "close")},
        ]
    payload = {"title": title, "message": message, "data": data}
    r = httpx.post(url, json=payload, timeout=10,
                   headers={"Authorization": f"Bearer {s.ha_token}"})
    r.raise_for_status()
    return True


def _label(lang: str, key: str) -> str:
    labels = {
        "en": {"extend": "+1 hour", "close": "Close now"},
        "he": {"extend": "+ שעה", "close": "סגור עכשיו"},
    }
    return labels.get(lang, labels["en"])[key]


def _send_webhook(s: Settings, title: str, message: str, event: str) -> bool:
    if not s.webhook_url:
        return False
    r = httpx.post(s.webhook_url, json={"title": title, "message": message, "event": event},
                   timeout=10)
    r.raise_for_status()
    return True
