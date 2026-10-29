"""Persistent gate state (survives container restarts).

Since the per-protection split, every protection has its own window in
`windows` ({"ssh": {...}, "quickconnect": {...}}). The top-level fields
(`is_open`, `expires_at`, ...) are kept as a summary of all windows so older
dashboards and the `/health` endpoint keep working.
"""

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


def new_window() -> dict:
    return {"opened_at": 0.0, "expires_at": 0.0, "last_reminder_at": 0.0, "guard_warned_at": 0.0}


@dataclass
class GateState:
    is_open: bool = False            # summary: any window open
    opened_at: float = 0.0           # summary: earliest open window
    expires_at: float = 0.0          # summary: latest expiry, 0 = none
    last_reminder_at: float = 0.0    # legacy, unused since the split
    guard_warned_at: float = 0.0     # legacy, unused since the split
    last_closed_at: float = 0.0
    last_close_reason: str = ""
    # One window per protection: {"ssh": {"opened_at", "expires_at", "last_reminder_at", "guard_warned_at"}}
    windows: dict[str, dict] = field(default_factory=dict)
    # Per-protection state the gate last applied: {"quickconnect": "open"/"closed"/"error: ..."}
    applied: dict[str, str] = field(default_factory=dict)
    # Short human-readable log of the latest events (newest last).
    log: list[dict] = field(default_factory=list)

    # -- per-protection ------------------------------------------------------------
    def window(self, cid: str) -> dict:
        return self.windows.setdefault(cid, new_window())

    def window_open(self, cid: str) -> bool:
        return bool(self.windows.get(cid, {}).get("expires_at", 0.0))

    def open_ids(self) -> list[str]:
        return [cid for cid, w in self.windows.items() if w.get("expires_at", 0.0)]

    def window_remaining(self, cid: str, now: float | None = None) -> int:
        exp = self.windows.get(cid, {}).get("expires_at", 0.0)
        if not exp:
            return 0
        now = now or time.time()
        return max(0, int(exp - now))

    def refresh_summary(self) -> None:
        open_ = [w for w in self.windows.values() if w.get("expires_at", 0.0)]
        self.is_open = bool(open_)
        self.expires_at = max((w["expires_at"] for w in open_), default=0.0)
        self.opened_at = min((w["opened_at"] for w in open_), default=0.0)

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
            # Migration from the single-window format: one shared window for
            # every protection the gate applied as open.
            if st.is_open and not st.windows:
                for cid, pos in st.applied.items():
                    if pos == "open":
                        st.windows[cid] = {"opened_at": st.opened_at, "expires_at": st.expires_at,
                                           "last_reminder_at": st.last_reminder_at,
                                           "guard_warned_at": st.guard_warned_at}
            st.refresh_summary()
        return st


def save(st: GateState) -> None:
    with _lock:
        st.refresh_summary()
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(st), indent=2, ensure_ascii=False))
        os.chmod(tmp, 0o600)
        tmp.replace(STATE_FILE)
