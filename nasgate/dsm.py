"""Minimal Synology DSM Web API client.

Only what the gate needs: login, API discovery, and generic requests.
Each call logs in and out so no long-lived DSM session is kept around.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

log = logging.getLogger("nasgate.dsm")


class DSMError(Exception):
    pass


# Common DSM error codes, for friendlier messages.
_ERRORS = {
    100: "Unknown error",
    101: "Invalid parameter",
    102: "API does not exist",
    103: "Method does not exist",
    104: "Version not supported",
    105: "Insufficient privileges (the DSM user must be an administrator)",
    106: "Session timeout",
    107: "Session interrupted (logged in elsewhere)",
    119: "SID not found",
    400: "Invalid account or password",
    401: "Account disabled",
    402: "Permission denied",
    403: "Two-step verification code required (turn it off for the gate user)",
    404: "Two-step verification failed",
}


class DSMClient:
    def __init__(self, url: str, user: str, password: str, verify_tls: bool = False,
                 timeout: float = 15.0):
        self.base = url.rstrip("/")
        self.user = user
        self.password = password
        self.verify = verify_tls
        self.timeout = timeout
        self._client: httpx.Client | None = None
        self._sid: str | None = None
        self._api_info: dict[str, dict] | None = None

    # -- session ---------------------------------------------------------
    def __enter__(self) -> "DSMClient":
        self._client = httpx.Client(verify=self.verify, timeout=self.timeout)
        self._login()
        return self

    def __exit__(self, *exc) -> None:
        try:
            self._logout()
        finally:
            if self._client:
                self._client.close()
                self._client = None

    def _call(self, path: str, params: dict[str, Any]) -> dict:
        assert self._client is not None
        if self._sid:
            params = {**params, "_sid": self._sid}
        try:
            r = self._client.get(f"{self.base}/webapi/{path}", params=params)
            r.raise_for_status()
            data = r.json()
        except httpx.HTTPError as e:
            raise DSMError(f"Cannot reach DSM at {self.base}: {e}") from e
        except ValueError as e:
            raise DSMError("DSM returned a non JSON reply") from e
        if not data.get("success"):
            code = (data.get("error") or {}).get("code", 0)
            raise DSMError(f"DSM error {code}: {_ERRORS.get(code, 'see DSM API docs')}")
        return data.get("data", {}) or {}

    def api_info(self, name: str) -> dict:
        if self._api_info is None:
            self._api_info = self._call("query.cgi", {
                "api": "SYNO.API.Info", "version": 1, "method": "query", "query": "all",
            })
        info = self._api_info.get(name)
        if not info:
            raise DSMError(f"DSM API {name} is not available on this NAS")
        return info

    def _login(self) -> None:
        info = self.api_info("SYNO.API.Auth")
        version = min(int(info.get("maxVersion", 3)), 6)
        data = self._call(info["path"], {
            "api": "SYNO.API.Auth", "version": version, "method": "login",
            "account": self.user, "passwd": self.password,
            "session": "NasGate", "format": "sid",
        })
        self._sid = data.get("sid")
        if not self._sid:
            raise DSMError("DSM login returned no session id")

    def _logout(self) -> None:
        if not self._sid or not self._client:
            return
        try:
            info = self.api_info("SYNO.API.Auth")
            self._call(info["path"], {
                "api": "SYNO.API.Auth", "version": 1, "method": "logout", "session": "NasGate",
            })
        except Exception as e:  # pragma: no cover - best effort
            log.debug("logout failed: %s", e)
        self._sid = None

    # -- generic ---------------------------------------------------------
    def request(self, api: str, method: str, version: int | None = None, **params) -> dict:
        info = self.api_info(api)
        if version is None:
            version = int(info.get("maxVersion", 1))
        else:
            version = min(version, int(info.get("maxVersion", version)))
        return self._call(info["path"], {"api": api, "version": version, "method": method, **params})

    # -- QuickConnect ----------------------------------------------------
    QC_API = "SYNO.Core.QuickConnect"

    def _versions(self, api: str) -> list[int]:
        info = self.api_info(api)
        lo, hi = int(info.get("minVersion", 1)), int(info.get("maxVersion", 1))
        return list(range(hi, lo - 1, -1))

    def _try_versions(self, api: str, method: str, **params) -> dict:
        """Call `method` with the newest version that knows it.

        DSM reports error 103 (method does not exist) or 104 (version not
        supported) when a method is missing from a given version, so we walk
        down from maxVersion until one answers.
        """
        last: DSMError | None = None
        for v in self._versions(api):
            try:
                return self.request(api, method, version=v, **params)
            except DSMError as e:
                last = e
                if "DSM error 103" not in str(e) and "DSM error 104" not in str(e):
                    raise
        raise DSMError(f"{api}.{method}: {last}")

    def quickconnect_get(self) -> dict:
        return self._try_versions(self.QC_API, "get")

    def quickconnect_set(self, enabled: bool) -> dict:
        flag = "true" if enabled else "false"
        errors = []
        # Different DSM builds expose the switch under different method names.
        for method, params in (
            ("set", {"enabled": flag}),
            ("set_server_config", {"enabled": flag}),
            ("set_enable", {"enabled": flag}),
        ):
            try:
                return self._try_versions(self.QC_API, method, **params)
            except DSMError as e:
                errors.append(str(e))
        raise DSMError("no QuickConnect set method worked: " + " | ".join(errors))

    def quickconnect_raw(self) -> dict:
        """Every `get`-style reply per version, for the diagnostics page."""
        out: dict[str, Any] = {}
        for v in self._versions(self.QC_API):
            for method in ("get", "get_misc_config", "get_server_config"):
                try:
                    out[f"{method} v{v}"] = self.request(self.QC_API, method, version=v)
                except DSMError as e:
                    out[f"{method} v{v}"] = str(e)
        return out

    # -- probe (for the settings page "test connection" button) ----------
    def probe(self) -> dict:
        out: dict[str, Any] = {"login": "ok"}
        try:
            info = self.request("SYNO.DSM.Info", "getinfo", version=2)
            out["model"] = info.get("model")
            out["dsm_version"] = info.get("version_string")
        except DSMError as e:
            out["dsm_info"] = str(e)
        for api in ("SYNO.Core.QuickConnect", "SYNO.Core.Terminal", "SYNO.Core.Security.Firewall"):
            try:
                i = self.api_info(api)
                out[api] = f"v{i.get('minVersion')}..{i.get('maxVersion')}"
            except DSMError:
                out[api] = "missing"
        try:
            out["quickconnect"] = self.quickconnect_raw()
        except DSMError as e:
            out["quickconnect"] = str(e)
        return out
