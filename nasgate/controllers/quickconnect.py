"""QuickConnect controller: on while the gate is open, off while closed."""

from __future__ import annotations

import logging

from ..config import Settings
from ..dsm import DSMClient, DSMError
from . import ControllerStatus

log = logging.getLogger("nasgate.quickconnect")


class QuickConnectController:
    id = "quickconnect"

    def __init__(self, settings: Settings):
        self.settings = settings

    def _client(self) -> DSMClient:
        s = self.settings
        if not s.dsm_user or not s.dsm_password:
            raise DSMError("DSM user and password are not set")
        return DSMClient(s.dsm_url, s.dsm_user, s.dsm_password, s.dsm_verify_tls)

    def apply(self, open_: bool) -> None:
        with self._client() as dsm:
            dsm.quickconnect_set(open_)
            after = dsm.quickconnect_get()
        enabled = _enabled(after)
        if enabled is not None and enabled != open_:
            raise DSMError("QuickConnect did not change state; check the DSM user permissions")
        log.info("QuickConnect %s", "enabled" if open_ else "disabled")

    def status(self) -> ControllerStatus:
        try:
            with self._client() as dsm:
                data = dsm.quickconnect_get()
        except DSMError as e:
            return ControllerStatus(self.id, "error", str(e))
        enabled = _enabled(data)
        if enabled is None:
            return ControllerStatus(self.id, "unknown", "no 'enabled' field in reply")
        qc_id = data.get("quickconnect_id") or data.get("server_alias") or ""
        return ControllerStatus(self.id, "open" if enabled else "closed", qc_id)


def _enabled(data: dict) -> bool | None:
    for key in ("enabled", "enable", "is_enabled"):
        if key in data:
            v = data[key]
            if isinstance(v, str):
                return v.lower() == "true"
            return bool(v)
    return None
