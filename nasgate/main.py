"""Entry point: start the engine loop and the web server."""

from __future__ import annotations

import logging
import os
import threading

import uvicorn

from . import config
from .engine import GateEngine
from .web import create_app

logging.basicConfig(level=os.environ.get("NASGATE_LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("nasgate")


def main() -> None:
    settings = config.load()
    engine = GateEngine(settings)
    engine.startup()
    stop = threading.Event()
    threading.Thread(target=engine.run_forever, args=(30.0, stop), daemon=True,
                     name="gate-loop").start()
    app = create_app(engine)
    port = int(os.environ.get("NASGATE_PORT", "8787"))
    log.info("NAS Gate listening on port %s (gate is %s)", port, "OPEN" if settings and engine.state.is_open else "closed")
    try:
        uvicorn.run(app, host=os.environ.get("NASGATE_BIND", "0.0.0.0"), port=port, log_level="warning")
    finally:
        stop.set()


if __name__ == "__main__":
    main()
