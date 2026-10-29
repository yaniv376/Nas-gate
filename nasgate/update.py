"""Self update: know which build is running, see whether the registry has a
newer image, and ask Watchtower to replace the container.

The gate cannot safely replace its own container, so the actual swap is done
by Watchtower (https://containrrr.dev/watchtower/) through its HTTP API:
    WATCHTOWER_HTTP_API_UPDATE=true, WATCHTOWER_HTTP_API_TOKEN=<token>,
    and its port 8080 published. The gate calls
    POST {watchtower_url}/v1/update?image=<image>  with  Authorization: Bearer <token>
which pulls the newest image and recreates only this container.

"Is there an update?" is answered without Docker access: the CI publishes
every build both as `latest` and as `sha-<git sha>`, and the running build
knows its own sha (baked in at build time). If the registry's digest for
`latest` differs from the digest for `sha-<running>`, there is an update.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import asdict, dataclass

import httpx

from .config import Settings

log = logging.getLogger("nasgate.update")

VERSION = os.environ.get("NASGATE_VERSION", "dev")
BUILD_DATE = os.environ.get("NASGATE_BUILD_DATE", "")

ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])


@dataclass
class UpdateInfo:
    checked_at: float
    running: str
    latest_digest: str = ""
    running_digest: str = ""
    update_available: bool | None = None   # None = could not determine
    error: str = ""


_cache: UpdateInfo | None = None
_lock = threading.Lock()


def _split_image(image: str) -> tuple[str, str]:
    """'ghcr.io/user/repo' -> ('ghcr.io', 'user/repo')."""
    head, _, last = image.rpartition("/")
    if ":" in last:                      # strip a tag such as ':latest'
        image = f"{head}/{last.split(':')[0]}" if head else last.split(":")[0]
    parts = image.split("/", 1)
    if len(parts) == 2 and ("." in parts[0] or ":" in parts[0]):
        return parts[0], parts[1]
    return "registry-1.docker.io", image if "/" in image else f"library/{image}"


def _digest(client: httpx.Client, registry: str, repo: str, tag: str, token: str) -> str:
    r = client.head(f"https://{registry}/v2/{repo}/manifests/{tag}",
                    headers={"Accept": ACCEPT, "Authorization": f"Bearer {token}"})
    if r.status_code == 404:
        return ""
    r.raise_for_status()
    return r.headers.get("docker-content-digest", "")


def check(settings: Settings, timeout: float = 15.0) -> UpdateInfo:
    """Compare the registry's `latest` with the running build. Never raises."""
    global _cache
    info = UpdateInfo(time.time(), VERSION)
    if VERSION == "dev":
        info.error = "development build"
        with _lock:
            _cache = info
        return info
    registry, repo = _split_image(settings.image)
    try:
        with httpx.Client(timeout=timeout) as c:
            # Anonymous pull token (public image). ghcr and Docker Hub both support this.
            auth_url = (f"https://ghcr.io/token?scope=repository:{repo}:pull" if registry == "ghcr.io"
                        else f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull")
            token = c.get(auth_url).json().get("token", "")
            info.latest_digest = _digest(c, registry, repo, "latest", token)
            info.running_digest = _digest(c, registry, repo, f"sha-{VERSION}", token)
        if info.latest_digest and info.running_digest:
            info.update_available = info.latest_digest != info.running_digest
        elif info.latest_digest and not info.running_digest:
            info.error = "running build not found in registry"
    except Exception as e:  # noqa: BLE001
        info.error = str(e)
    with _lock:
        _cache = info
    return info


def cached() -> UpdateInfo | None:
    with _lock:
        return _cache


def apply(settings: Settings) -> dict:
    """Ask Watchtower to update this image. Returns quickly; the container is
    then replaced by Watchtower, which the user sees as a short restart."""
    if not settings.watchtower_url or not settings.watchtower_token:
        return {"ok": False, "error": "Watchtower URL/token not set"}
    url = f"{settings.watchtower_url.rstrip('/')}/v1/update"
    try:
        r = httpx.post(url, params={"image": settings.image}, timeout=20,
                       headers={"Authorization": f"Bearer {settings.watchtower_token}"})
        if r.status_code >= 400:
            return {"ok": False, "error": f"Watchtower answered {r.status_code}: {r.text[:200]}"}
        return {"ok": True, "status": r.status_code}
    except httpx.ReadTimeout:
        # Watchtower keeps the request open while it works; the update is running.
        return {"ok": True, "status": "started"}
    except httpx.HTTPError as e:
        return {"ok": False, "error": f"Cannot reach Watchtower at {settings.watchtower_url}: {e}"}


def as_dict(info: UpdateInfo | None) -> dict | None:
    return asdict(info) if info else None
