"""Persistent gate state (survives container restarts)."""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

from .config import DATA_DIR

STATE_FILE = DATA_DIR / "state.json"
_lock = threading.RLock()


@dataclass
class GateState:
    is_open: bool = False
    opened_at: float = 0.0           # unix seconds
    expires_at: float = 0.0          # unix seconds, 0 = none
    last_reminder_at: float = 0.0
    guard_warned_at: float = 0.0     # when the closing warning was sent
    last_closed_at: float = 0.0
    last_close_reason: str = ""
    # Per-protection state the gate last applied: {"quickconnect": "open"/"closed"/"error: ..."}
    applied: dict[str, str] = field(default_factory=dict)
    # Short human-readable log of the latest events (newest last).
    log: list[dict] = field(default_factory=list)

    def remaining_seconds(self, now: float | None = None) -> int:
        if not self.is_open or not self.expires_at:
            return 0
        now = now or time.time()
        return max(0, int(self.expires_at - now))

    def add_log(self, event: str, detail: str = "", now: float | None = None) -> None:
        self.log.append({"t": now or time.time(), "event": event, "detail": detail})
        self.log = self.log[-50:]


def load() -> GateState:
    with _lock:
        st = GateState()
        if STATE_FILE.exists():
            try:
                data = json.loads(STATE_FILE.read_text())
            except json.JSONDecodeError:
                data = {}
            for f in fields(GateState):
                if f.name in data:
                    setattr(st, f.name, data[f.name])
        return st


def save(st: GateState) -> None:
    with _lock:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(st), indent=2, ensure_ascii=False))
        os.chmod(tmp, 0o600)
        tmp.replace(STATE_FILE)
