"""The gate engine: open/close windows, reminders, and the closing guard.

Rules (mirroring the Home Assistant agent gate):
  * Default is closed.
  * The user picks the duration; there is no fixed cap.
  * While open: a reminder every `reminder_minutes`.
  * At expiry: warn first, then close `guard_grace_minutes` later unless the
    window was extended.
  * On startup, if a previous window has already expired, close it.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime
from zoneinfo import ZoneInfo

from . import config, notify, state
from .controllers import Controller, ControllerStatus
from .controllers.quickconnect import QuickConnectController
from .controllers.ssh import SSHController
from .i18n import t

log = logging.getLogger("nasgate.engine")


class GateEngine:
    def __init__(self, settings: config.Settings, st: state.GateState | None = None,
                 controllers: dict[str, Controller] | None = None,
                 clock=time.time, notifier=notify.send):
        self.settings = settings
        self.state = st if st is not None else state.load()
        self.clock = clock
        self.notifier = notifier
        self._lock = threading.RLock()
        self.controllers: dict[str, Controller] = controllers if controllers is not None else {
            "quickconnect": QuickConnectController(settings),
            "ssh": SSHController(settings),
        }

    # -- helpers ------------------------------------------------------------
    def _managed(self, cid: str) -> bool:
        return bool(getattr(self.settings, f"manage_{cid}", False))

    def _fmt_time(self, ts: float) -> str:
        try:
            tz = ZoneInfo(self.settings.timezone)
        except Exception:  # noqa: BLE001
            tz = ZoneInfo("UTC")
        return datetime.fromtimestamp(ts, tz).strftime("%H:%M")

    def _fmt_elapsed(self, seconds: float) -> str:
        m = int(seconds // 60)
        h, m = divmod(m, 60)
        lang = self.settings.language
        if h:
            return f"{h} {t(lang, 'hours')} {m} {t(lang, 'minutes')}"
        return f"{m} {t(lang, 'minutes')}"

    def _notify(self, key: str, body_key: str, **kw) -> None:
        lang = self.settings.language
        self.notifier(self.settings, t(lang, key, **kw), t(lang, body_key, **kw), key)

    def _apply_all(self, open_: bool) -> list[str]:
        """Apply every managed controller; collect errors instead of stopping."""
        errors: list[str] = []
        for cid, ctl in self.controllers.items():
            if not self._managed(cid):
                continue
            try:
                ctl.apply(open_)
                self.state.applied[cid] = "open" if open_ else "closed"
            except Exception as e:  # noqa: BLE001
                msg = f"{cid}: {e}"
                log.error("apply failed: %s", msg)
                self.state.applied[cid] = f"error: {e}"
                errors.append(msg)
        return errors

    # -- public API -----------------------------------------------------------
    def open(self, minutes: int) -> list[str]:
        if minutes <= 0:
            raise ValueError("minutes must be positive")
        with self._lock:
            now = self.clock()
            self.state.is_open = True
            self.state.opened_at = now
            self.state.expires_at = now + minutes * 60
            self.state.last_reminder_at = now
            self.state.guard_warned_at = 0.0
            errors = self._apply_all(True)
            self.state.add_log("open", f"{minutes} min" + (f"; errors: {errors}" if errors else ""), now)
            state.save(self.state)
        self._notify("n_opened", "n_opened_body", minutes=minutes,
                     until=self._fmt_time(self.state.expires_at))
        if errors:
            self.notifier(self.settings, t(self.settings.language, "n_error"), "; ".join(errors), "n_error")
        return errors

    def extend(self, minutes: int) -> None:
        with self._lock:
            if not self.state.is_open:
                raise ValueError("gate is not open")
            now = self.clock()
            base = max(self.state.expires_at, now)
            self.state.expires_at = base + minutes * 60
            self.state.guard_warned_at = 0.0
            self.state.add_log("extend", f"+{minutes} min", now)
            state.save(self.state)

    def close(self, reason: str = "manual") -> list[str]:
        with self._lock:
            now = self.clock()
            was_open = self.state.is_open
            self.state.is_open = False
            self.state.expires_at = 0.0
            self.state.guard_warned_at = 0.0
            self.state.last_closed_at = now
            self.state.last_close_reason = reason
            errors = self._apply_all(False)
            self.state.add_log("close", reason + (f"; errors: {errors}" if errors else ""), now)
            state.save(self.state)
        if was_open:
            self._notify("n_closed", "n_closed_body",
                         reason=t(self.settings.language, f"r_{reason}") if reason in ("manual", "expired", "startup") else reason)
        if errors:
            self.notifier(self.settings, t(self.settings.language, "n_error"), "; ".join(errors), "n_error")
        return errors

    def enforce(self) -> list[str]:
        """Re-apply the current position (used at startup and after settings change)."""
        with self._lock:
            errors = self._apply_all(self.state.is_open)
            state.save(self.state)
        return errors

    def set_managed(self, cid: str, managed: bool) -> list[str]:
        """Toggle one protection on/off. Turning it off releases it (opens it)."""
        if cid not in self.controllers:
            raise KeyError(cid)
        with self._lock:
            setattr(self.settings, f"manage_{cid}", managed)
            config.save(self.settings)
            errors: list[str] = []
            try:
                if managed:
                    self.controllers[cid].apply(self.state.is_open)
                    self.state.applied[cid] = "open" if self.state.is_open else "closed"
                else:
                    self.controllers[cid].apply(True)
                    self.state.applied[cid] = "released"
            except Exception as e:  # noqa: BLE001
                self.state.applied[cid] = f"error: {e}"
                errors.append(f"{cid}: {e}")
            self.state.add_log("manage", f"{cid}={'on' if managed else 'off'}", self.clock())
            state.save(self.state)
        return errors

    def live_status(self) -> dict[str, ControllerStatus]:
        out = {}
        for cid, ctl in self.controllers.items():
            try:
                out[cid] = ctl.status()
            except Exception as e:  # noqa: BLE001
                out[cid] = ControllerStatus(cid, "error", str(e))
        return out

    # -- periodic -----------------------------------------------------------------
    def tick(self) -> None:
        """Called every ~30 s by the background loop."""
        with self._lock:
            if not self.configured or not self.state.is_open:
                return
            now = self.clock()
            s = self.settings
            st = self.state
            if now < st.expires_at:
                if s.reminder_minutes > 0 and now - st.last_reminder_at >= s.reminder_minutes * 60:
                    st.last_reminder_at = now
                    state.save(st)
                    self._notify("n_reminder", "n_reminder_body",
                                 elapsed=self._fmt_elapsed(now - st.opened_at),
                                 until=self._fmt_time(st.expires_at))
                return
            # Expired: warn first, close after the grace period.
            if s.guard_grace_minutes > 0 and not st.guard_warned_at:
                st.guard_warned_at = now
                state.save(st)
                self._notify("n_warning", "n_warning_body", grace=s.guard_grace_minutes)
                return
            if s.guard_grace_minutes > 0 and now - st.guard_warned_at < s.guard_grace_minutes * 60:
                return
        self.close("expired")

    @property
    def configured(self) -> bool:
        """Until the user has set a password the gate touches nothing."""
        return bool(self.settings.password_hash)

    def startup(self) -> None:
        if not self.configured:
            log.info("first run: waiting for setup before touching any protection")
            return
        if self.state.is_open and self.state.expires_at and self.clock() >= self.state.expires_at:
            self.close("startup")
        else:
            self.enforce()

    def run_forever(self, interval: float = 30.0, stop: threading.Event | None = None) -> None:
        stop = stop or threading.Event()
        while not stop.is_set():
            try:
                self.tick()
            except Exception:  # noqa: BLE001
                log.exception("tick failed")
            stop.wait(interval)
