"""Web UI and API (FastAPI).

Auth model:
  * One personal password, set on first run, hashed with scrypt.
  * Session cookie = HMAC(epoch:expiry). Sliding expiry = `ui_lock_minutes`
    of inactivity. "Lock page" bumps the epoch, logging every browser out.
  * `/api/*` also accepts `Authorization: Bearer <api_token>` for Home
    Assistant, so a dashboard card can show state and open/close.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import config, notify
from .dsm import DSMClient, DSMError
from .engine import GateEngine
from .i18n import all_strings, t

log = logging.getLogger("nasgate.web")
HERE = Path(__file__).parent
templates = Jinja2Templates(directory=str(HERE / "templates"))

COOKIE = "nasgate_session"


def create_app(engine: GateEngine) -> FastAPI:
    app = FastAPI(title="NAS Gate", docs_url=None, redoc_url=None)
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")
    settings = engine.settings

    # -- sessions ------------------------------------------------------------------
    def _sign(payload: str) -> str:
        return hmac.new(settings.session_secret.encode(), payload.encode(), hashlib.sha256).hexdigest()

    def _make_cookie() -> str:
        exp = int(time.time() + settings.ui_lock_minutes * 60)
        payload = f"{settings.session_epoch}:{exp}"
        return f"{payload}:{_sign(payload)}"

    def _valid_cookie(value: str | None) -> bool:
        if not value:
            return False
        try:
            epoch, exp, sig = value.split(":")
        except ValueError:
            return False
        payload = f"{epoch}:{exp}"
        if not hmac.compare_digest(sig, _sign(payload)):
            return False
        return int(epoch) == settings.session_epoch and int(exp) > time.time()

    def _authed(request: Request) -> bool:
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer ") and settings.api_token:
            return hmac.compare_digest(auth[7:].strip(), settings.api_token)
        return _valid_cookie(request.cookies.get(COOKIE))

    def require_auth(request: Request) -> None:
        if not settings.password_hash:
            raise HTTPException(status_code=403, detail="setup required")
        if not _authed(request):
            raise HTTPException(status_code=401, detail="unauthorized")

    def _with_session(resp, request: Request | None = None):
        """Sliding expiry: refresh the cookie on user actions and page loads.

        Not on background polling (so idle pages still lock) and never for
        bearer-token requests (Home Assistant must not receive a session).
        """
        if request is not None and not _valid_cookie(request.cookies.get(COOKIE)):
            return resp
        resp.set_cookie(COOKIE, _make_cookie(), httponly=True, samesite="strict",
                        max_age=settings.ui_lock_minutes * 60)
        return resp

    # -- pages ---------------------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        lang = settings.language
        ctx = {"request": request, "s": all_strings(lang), "lang": lang,
               "rtl": lang == "he", "error": request.query_params.get("e", "")}
        if not settings.password_hash:
            return templates.TemplateResponse(request, "setup.html", ctx)
        if not _authed(request):
            return templates.TemplateResponse(request, "login.html", ctx)
        ctx["settings"] = settings.public()
        return _with_session(templates.TemplateResponse(request, "index.html", ctx), request)

    @app.post("/setup")
    def setup(password: str = Form(...), password2: str = Form(...)):
        if settings.password_hash:
            raise HTTPException(status_code=403)
        if len(password) < 8:
            return RedirectResponse("/?e=password_short", status_code=303)
        if password != password2:
            return RedirectResponse("/?e=password_mismatch", status_code=303)
        config.set_password(settings, password)
        engine.enforce()   # first activation: put every managed protection in the closed position
        return _with_session(RedirectResponse("/", status_code=303))

    @app.post("/login")
    def login(password: str = Form(...)):
        time.sleep(0.5)  # slow down guessing
        if not config.verify_password(password, settings.password_hash):
            return RedirectResponse("/?e=wrong_password", status_code=303)
        return _with_session(RedirectResponse("/", status_code=303))

    @app.post("/lock")
    def lock(request: Request, _=Depends(require_auth)):
        settings.session_epoch += 1
        config.save(settings)
        resp = RedirectResponse("/", status_code=303)
        resp.delete_cookie(COOKIE)
        return resp

    @app.post("/password")
    def change_password(request: Request, current: str = Form(...), new: str = Form(...),
                        _=Depends(require_auth)):
        if not config.verify_password(current, settings.password_hash):
            return RedirectResponse("/?e=wrong_password", status_code=303)
        if len(new) < 8:
            return RedirectResponse("/?e=password_short", status_code=303)
        config.set_password(settings, new)
        return _with_session(RedirectResponse("/", status_code=303))

    # -- API ------------------------------------------------------------------------
    def _status_payload(live: bool = False) -> dict:
        st = engine.state
        out = {
            "is_open": st.is_open,
            "opened_at": st.opened_at,
            "expires_at": st.expires_at,
            "remaining_seconds": st.remaining_seconds(),
            "last_close_reason": st.last_close_reason,
            "applied": st.applied,
            "protections": {
                cid: {"managed": bool(getattr(settings, f"manage_{cid}", False))}
                for cid in engine.controllers
            },
            "log": st.log[-15:],
            "now": time.time(),
        }
        if live:
            for cid, cs in engine.live_status().items():
                out["protections"][cid].update({"live": cs.live, "detail": cs.detail})
        return out

    @app.get("/api/status")
    def api_status(request: Request, live: bool = False, _=Depends(require_auth)):
        return JSONResponse(_status_payload(live))

    @app.post("/api/open")
    def api_open(request: Request, minutes: int, _=Depends(require_auth)):
        if minutes < 1 or minutes > 60 * 24 * 30:
            raise HTTPException(status_code=400, detail="minutes out of range")
        errors = engine.open(minutes)
        return _with_session(JSONResponse({**_status_payload(), "errors": errors}), request)

    @app.post("/api/extend")
    def api_extend(request: Request, minutes: int, _=Depends(require_auth)):
        try:
            engine.extend(minutes)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        return _with_session(JSONResponse(_status_payload()), request)

    @app.post("/api/close")
    def api_close(request: Request, _=Depends(require_auth)):
        errors = engine.close("manual")
        return _with_session(JSONResponse({**_status_payload(), "errors": errors}), request)

    @app.post("/api/protections/{cid}")
    def api_protection(request: Request, cid: str, managed: bool, _=Depends(require_auth)):
        try:
            errors = engine.set_managed(cid, managed)
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown protection")
        return _with_session(JSONResponse({**_status_payload(), "errors": errors}), request)

    @app.get("/api/settings")
    def api_get_settings(request: Request, _=Depends(require_auth)):
        return JSONResponse(settings.public())

    @app.post("/api/settings")
    async def api_set_settings(request: Request, _=Depends(require_auth)):
        changes = await request.json()
        config.update(settings, changes)
        errors = engine.enforce()
        return _with_session(JSONResponse({"ok": True, "errors": errors, "settings": settings.public()}), request)

    @app.post("/api/test/dsm")
    def api_test_dsm(request: Request, _=Depends(require_auth)):
        try:
            with DSMClient(settings.dsm_url, settings.dsm_user, settings.dsm_password,
                           settings.dsm_verify_tls) as dsm:
                return _with_session(JSONResponse({"ok": True, "info": dsm.probe()}), request)
        except DSMError as e:
            return _with_session(JSONResponse({"ok": False, "error": str(e)}), request)

    @app.post("/api/test/notify")
    def api_test_notify(request: Request, _=Depends(require_auth)):
        ok = notify.send(settings, t(settings.language, "app"), t(settings.language, "n_test"), "test")
        return _with_session(JSONResponse({"ok": ok}), request)

    @app.get("/api/token")
    def api_token(request: Request, _=Depends(require_auth)):
        # Only cookie sessions may read the token (never the token itself).
        if not _valid_cookie(request.cookies.get(COOKIE)):
            raise HTTPException(status_code=403)
        return JSONResponse({"api_token": settings.api_token})

    @app.get("/health")
    def health():
        return {"ok": True, "is_open": engine.state.is_open}

    return app
