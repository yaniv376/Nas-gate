"""Settings store for NAS Gate.

All user-editable settings live in one JSON file inside the data volume so
they survive container updates. Secrets (DSM password, HA token) may also be
passed as environment variables, which take precedence on first run and are
then copied into the settings file.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

DATA_DIR = Path(os.environ.get("NASGATE_DATA_DIR", "/data"))
SETTINGS_FILE = DATA_DIR / "settings.json"


@dataclass
class Settings:
    # --- gate behaviour -------------------------------------------------
    language: str = "en"                 # "en" or "he"
    default_open_minutes: int = 60       # preselected duration in the UI
    reminder_minutes: int = 60           # reminder while a window is open
    guard_grace_minutes: int = 5         # warn, then close if no answer
    ui_lock_minutes: int = 30            # settings page auto lock
    timezone: str = "UTC"

    # --- protections: which items the gate manages ------------------------
    manage_quickconnect: bool = True
    manage_ssh: bool = True

    # --- SSH access controller (iptables) -------------------------------
    ssh_port: int = 22
    # Hosts that may always reach SSH, even while the gate is closed.
    # Typical: the Home Assistant machine that pulls backups.
    ssh_trusted_hosts: list[str] = field(default_factory=list)

    # --- DSM API ---------------------------------------------------------
    dsm_url: str = "https://127.0.0.1:5001"
    dsm_user: str = ""
    dsm_password: str = ""
    dsm_verify_tls: bool = False

    # --- notifications ---------------------------------------------------
    # Mode "ha": call a Home Assistant notify service with a long lived token.
    # Mode "webhook": POST JSON {"title","message","event"} to any URL.
    # Mode "none": no notifications.
    notify_mode: str = "none"
    ha_url: str = ""
    ha_token: str = ""
    ha_notify_service: str = "notify.notify"
    webhook_url: str = ""

    # --- self update (see update.py) ------------------------------------
    image: str = "ghcr.io/yaniv376/nas-gate"
    watchtower_url: str = "http://127.0.0.1:8085"
    watchtower_token: str = ""

    # --- security ----------------------------------------------------------
    password_hash: str = ""              # scrypt, "salt$hash" hex
    session_secret: str = ""             # HMAC key for session cookies
    session_epoch: int = 0               # bumped on manual lock -> logs out
    api_token: str = ""                  # for Home Assistant integration

    # ------------------------------------------------------------------
    def public(self) -> dict[str, Any]:
        """Settings safe to show in the UI (secrets masked)."""
        d = asdict(self)
        for key in ("password_hash", "session_secret", "session_epoch"):
            d.pop(key, None)
        for key in ("dsm_password", "ha_token", "api_token", "watchtower_token"):
            d[key] = "••••••" if d.get(key) else ""
        return d


EDITABLE_FIELDS = {
    "language", "default_open_minutes", "reminder_minutes",
    "guard_grace_minutes", "ui_lock_minutes", "timezone",
    "manage_quickconnect", "manage_ssh", "ssh_port", "ssh_trusted_hosts",
    "dsm_url", "dsm_user", "dsm_password", "dsm_verify_tls",
    "notify_mode", "ha_url", "ha_token", "ha_notify_service", "webhook_url",
    "image", "watchtower_url", "watchtower_token",
}

SECRET_FIELDS = {"dsm_password", "ha_token", "api_token", "watchtower_token"}

_lock = threading.RLock()


def _coerce(name: str, value: Any) -> Any:
    """Coerce a value coming from a form/JSON into the dataclass type."""
    ftype = {f.name: f.type for f in fields(Settings)}[name]
    if ftype in ("int", int):
        return int(value)
    if ftype in ("bool", bool):
        if isinstance(value, str):
            return value.lower() in ("1", "true", "on", "yes")
        return bool(value)
    if ftype in ("list[str]",) or name == "ssh_trusted_hosts":
        if isinstance(value, str):
            value = [v.strip() for v in value.replace("\n", ",").split(",")]
        return [str(v).strip() for v in value if str(v).strip()]
    return str(value)


def load() -> Settings:
    with _lock:
        s = Settings()
        if SETTINGS_FILE.exists():
            data = json.loads(SETTINGS_FILE.read_text())
            for f in fields(Settings):
                if f.name in data:
                    setattr(s, f.name, data[f.name])
        changed = False
        # First-run secrets from the environment.
        env_map = {
            "NASGATE_DSM_URL": "dsm_url",
            "NASGATE_DSM_USER": "dsm_user",
            "NASGATE_DSM_PASSWORD": "dsm_password",
            "NASGATE_HA_URL": "ha_url",
            "NASGATE_HA_TOKEN": "ha_token",
            "NASGATE_HA_NOTIFY_SERVICE": "ha_notify_service",
            "NASGATE_LANGUAGE": "language",
            "NASGATE_TIMEZONE": "timezone",
        }
        for env, name in env_map.items():
            val = os.environ.get(env)
            if val and not getattr(s, name):
                setattr(s, name, _coerce(name, val))
                changed = True
        if os.environ.get("NASGATE_HA_URL") and os.environ.get("NASGATE_HA_TOKEN") \
                and s.notify_mode == "none" and not SETTINGS_FILE.exists():
            s.notify_mode = "ha"
            changed = True
        if not s.session_secret:
            s.session_secret = secrets.token_hex(32)
            changed = True
        if not s.api_token:
            s.api_token = secrets.token_urlsafe(32)
            changed = True
        if changed:
            save(s)
        return s


def save(s: Settings) -> None:
    with _lock:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = SETTINGS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(s), indent=2, ensure_ascii=False))
        os.chmod(tmp, 0o600)
        tmp.replace(SETTINGS_FILE)


def update(s: Settings, changes: dict[str, Any]) -> Settings:
    """Apply user edits. Unknown or protected keys are ignored.

    An empty value for a secret field keeps the existing secret, so the UI can
    show a masked field without forcing the user to retype it.
    """
    with _lock:
        for key, value in changes.items():
            if key not in EDITABLE_FIELDS:
                continue
            if key in SECRET_FIELDS and (value in ("", None, "••••••")):
                continue
            setattr(s, key, _coerce(key, value))
        save(s)
        return s


# --- password ------------------------------------------------------------

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    if not stored or "$" not in stored:
        return False
    salt_hex, digest_hex = stored.split("$", 1)
    try:
        digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex),
                                n=2**14, r=8, p=1)
    except ValueError:
        return False
    return secrets.compare_digest(digest.hex(), digest_hex)


def set_password(s: Settings, password: str) -> None:
    with _lock:
        s.password_hash = hash_password(password)
        s.session_epoch += 1
        save(s)
