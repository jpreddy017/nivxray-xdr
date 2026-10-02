"""E3 PREVIEW-ONLY mount for the read-only /api/e3/trajectory/* router. E1: STRIP or keep OFF.
Enabled only when E3_TRAJECTORY_ROUTER == "1"; touches no auth, ingest or durable-ACK path."""
from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

FLAG = "E3_TRAJECTORY_ROUTER"


def mount_if_enabled(app: Any, get_db: Callable[[], Any]) -> bool:
    if os.environ.get(FLAG) != "1":
        return False
    from .api import build_router

    app.include_router(build_router(get_db), prefix="/api")
    if app.openapi_url != "/api/openapi.json":
        app.add_api_route("/api/openapi.json", lambda: app.openapi(), include_in_schema=False)
    return True
