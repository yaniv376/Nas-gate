"""The gate engine: open/close windows, reminders, and the closing guard.

Rules (mirroring the Home Assistant agent gate):
  * Default is closed.
  * Every protection (QuickConnect, SSH, ...) has its own window and timer,
    so one can be open while the others stay closed. "Open the gate" with no
    selection opens every managed protection.
  * The user picks the duration; there is no fixed cap.
  * While a window is open: a reminder every `reminder_minutes`.
  * At expiry: warn first, then close `guard_grace_minutes` later unless the
    window was extended.
  * On startup, windows that have already expired are closed.
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

    def _select(self, cids: list[str] | None) -> list[str]:
        """Resolve a protection selection: None = every managed one."""
        if cids is None:
            return [cid for cid in self.controllers if self._managed(cid)]
        out = []
        for cid in cids:
            if cid not in self.controllers:
                raise KeyError(cid)
            if self._managed(cid):
                out.append(cid)
        return out

    def _names(self, cids: list[str]) -> str:
        lang = self.settings.language
        return ", ".join(t(lang, f"short_{cid}") for cid in cids)

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

    def _notify(self, key: str, body_key: str, cids: list[str] | None = None, **kw) -> None:
        """Send a notification. `cids` lets the notifier attach per-protection buttons."""
        lang = self.settings.language
        event = key if not cids or len(cids) != 1 else f"{key}:{cids[0]}"
        self.notifier(self.settings, t(lang, key, **kw), t(lang, body_key, **kw), event)

    def _apply(self, cids: list[str], open_: bool) -> list[str]:
        """Apply the given controllers; collect errors instead of stopping."""
        errors: list[str] = []
        for cid in cids:
            ctl = self.controllers[cid]
            try:
                ctl.apply(open_)
                self.state.applied[cid] = "open" if open_ else "closed"
            except Exception as e:  # noqa: BLE001
                msg = f"{cid}: {e}"
                log.error("apply failed: %s", msg)
                self.state.applied[cid] = f"error: {e}"
                errors.append(msg)
        return errors

    def _report_errors(self, errors: list[str]) -> None:
        if errors:
            self.notifier(self.settings, t(self.settings.language, "n_error"), "; ".join(errors), "n_error")

    # -- public API -----------------------------------------------------------
    def open(self, minutes: int, cids: list[str] | None = None) -> list[str]:
        """Open the selected protections (default: all managed) for `minutes`.
        A protection that is already open gets the new expiry."""
        if minutes <= 0:
            raise ValueError("minutes must be positive")
        with self._lock:
            now = self.clock()
            sel = self._select(cids)
            if not sel:
                raise ValueError("nothing to open")
            for cid in sel:
                w = self.state.window(cid)
                w.update(opened_at=now, expires_at=now + minutes * 60,
                         last_reminder_at=now, guard_warned_at=0.0)
            errors = self._apply(sel, True)
            self.state.add_log("open", f"{self._names(sel)}: {minutes} min"
                               + (f"; errors: {errors}" if errors else ""), now)
            state.save(self.state)
            until = self._fmt_time(now + minutes * 60)
        self._notify("n_opened", "n_opened_body", self._group(sel, self._select(None)),
                     minutes=minutes, until=until, what=self._names(sel))
        self._report_errors(errors)
        return errors

    def extend(self, minutes: int, cids: list[str] | None = None) -> None:
        """Extend the open windows among the selection (default: every open one)."""
        with self._lock:
            now = self.clock()
            sel = [c for c in (self._select(cids) if cids is not None else self.state.open_ids())
                   if self.state.window_open(c)]
            if not sel:
                raise ValueError("gate is not open")
            for cid in sel:
                w = self.state.window(cid)
                w["expires_at"] = max(w["expires_at"], now) + minutes * 60
                w["guard_warned_at"] = 0.0
            self.state.add_log("extend", f"{self._names(sel)}: +{minutes} min", now)
            state.save(self.state)

    def close(self, reason: str = "manual", cids: list[str] | None = None) -> list[str]:
        """Close the selected protections (default: all managed)."""
        with self._lock:
            now = self.clock()
            sel = self._select(cids)
            was_open = [c for c in sel if self.state.window_open(c)]
            for cid in sel:
                self.state.windows[cid] = state.new_window()
            self.state.last_closed_at = now
            self.state.last_close_reason = reason
            errors = self._apply(sel, False)
            self.state.add_log("close", f"{self._names(sel)}: {reason}"
                               + (f"; errors: {errors}" if errors else ""), now)
            state.save(self.state)
        if was_open:
            self._notify("n_closed", "n_closed_body", self._group(was_open, self._select(None)),
                         what=self._names(was_open),
                         reason=t(self.settings.language, f"r_{reason}")
                         if reason in ("manual", "expired", "startup") else reason)
        self._report_errors(errors)
        return errors

    def enforce(self) -> list[str]:
        """Re-apply every managed protection's current position (startup, settings change)."""
        with self._lock:
            errors: list[str] = []
            for cid in self._select(None):
                errors += self._apply([cid], self.state.window_open(cid))
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
                    open_ = self.state.window_open(cid)
                    self.controllers[cid].apply(open_)
                    self.state.applied[cid] = "open" if open_ else "closed"
                else:
                    self.controllers[cid].apply(True)
                    self.state.applied[cid] = "released"
                    self.state.windows[cid] = state.new_window()
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
        """Called every ~30 s by the background loop. Each window is handled on its own."""
        # Windows opened together share an expiry, so they share one
        # notification (grouped by expires_at) instead of one per protection.
        remind: dict[float, list[str]] = {}
        warn: dict[float, list[str]] = {}
        expired: list[str] = []
        with self._lock:
            if not self.configured:
                return
            now = self.clock()
            s = self.settings
            for cid in self.state.open_ids():
                w = self.state.window(cid)
                if now < w["expires_at"]:
                    if s.reminder_minutes > 0 and now - w["last_reminder_at"] >= s.reminder_minutes * 60:
                        w["last_reminder_at"] = now
                        remind.setdefault(w["expires_at"], []).append(cid)
                    continue
                # Expired: warn first, close after the grace period.
                if s.guard_grace_minutes > 0 and not w["guard_warned_at"]:
                    w["guard_warned_at"] = now
                    warn.setdefault(w["expires_at"], []).append(cid)
                    continue
                if s.guard_grace_minutes > 0 and now - w["guard_warned_at"] < s.guard_grace_minutes * 60:
                    continue
                expired.append(cid)
            if remind or warn:
                state.save(self.state)
            all_open = self._select(None)
        for exp, cids in remind.items():
            w = self.state.window(cids[0])
            self._notify("n_reminder", "n_reminder_body", self._group(cids, all_open),
                         what=self._names(cids), elapsed=self._fmt_elapsed(now - w["opened_at"]),
                         until=self._fmt_time(exp))
        for exp, cids in warn.items():
            self._notify("n_warning", "n_warning_body", self._group(cids, all_open),
                         what=self._names(cids), grace=s.guard_grace_minutes)
        if expired:
            self.close("expired", expired)

    @staticmethod
    def _group(cids: list[str], all_managed: list[str]) -> list[str] | None:
        """None when the group covers every managed protection (generic buttons)."""
        return None if set(cids) >= set(all_managed) else cids

    @property
    def configured(self) -> bool:
        """Until the user has set a password the gate touches nothing."""
        return bool(self.settings.password_hash)

    def startup(self) -> None:
        if not self.configured:
            log.info("first run: waiting for setup before touching any protection")
            return
        now = self.clock()
        stale = [cid for cid in self.state.open_ids() if now >= self.state.window(cid)["expires_at"]]
        if stale:
            self.close("startup", stale)
        self.enforce()

    def run_forever(self, interval: float = 30.0, stop: threading.Event | None = None) -> None:
        stop = stop or threading.Event()
        while not stop.is_set():
            try:
                self.tick()
            except Exception:  # noqa: BLE001
                log.exception("tick failed")
            stop.wait(interval)
