"""RC5 API test isolation — Motor event-loop safety net.

Problem
-------
`deps.py` exposes `client` / `db` as module-level `_MotorProxy` singletons
that memoise the first `AsyncIOMotorClient` they see (line 165: `if _real
is None: bind()`). Under multi-module serial test execution, module A's
TestClient creates a Motor client bound to *its* event loop, then closes
that loop on `__exit__`. Module B then triggers FastAPI startup again —
`init_database()` sees the proxy is already bound and no-ops. B's first
request then hits Motor over a **closed** loop → `Event loop is closed`.

The failing test fixtures already do `del sys.modules["deps"]` + `del
sys.modules["server"]`, expecting a clean re-import. But every previously
imported router module (routers.*, engine.*, v2.*) still holds a Python
reference to the OLD `deps.client` proxy via its own `from deps import
client` statement. When the fresh `server` re-imports, it uses the
cached router modules — those routers still route DB calls through the
stale proxy on the closed loop.

Fix (test-side, additive, respects RC5 immutability contract)
-------------------------------------------------------------
Before every test module under `tests/rc5/api/`:
  1. Reset the CURRENT `deps.client._real` / `deps.db._real` slots to None
     so any code holding the existing proxy still gets rebound on the
     next `init_database()` call.
  2. Purge cached **router** modules only (not `engine`, not `v2`, not
     `middleware` — those don't create the event-loop race but do carry
     module-level side effects we must not re-trigger). This forces the
     next `from server import app` to freshly re-import every router,
     which rebinds their `from deps import client` local references to
     the freshly-imported `deps` module's fresh proxies.

Nothing in `deps.py`, `server.py`, or any RC5 engine module is touched.
Only test-runtime module cache and proxy state are normalised.
"""
from __future__ import annotations

import sys

import pytest


def _reset_deps_proxies_in_place() -> None:
    """Blank `_real` on the Motor proxies of the currently-cached `deps`.

    This is what unsticks router modules that closed over the OLD proxy —
    those routers keep working through the same object, and the next
    `init_database()` will bind it to a live Motor client on the current
    event loop.
    """
    deps_mod = sys.modules.get("deps")
    if deps_mod is None:
        return
    for proxy_name in ("client", "db"):
        proxy = getattr(deps_mod, proxy_name, None)
        if proxy is None:
            continue
        try:
            object.__setattr__(proxy, "_real", None)
        except (AttributeError, TypeError):
            # Not a _MotorProxy instance — nothing to reset.
            pass
    if hasattr(deps_mod, "_sync_client"):
        setattr(deps_mod, "_sync_client", None)


def _purge_router_modules() -> None:
    """Drop cached router modules so a fresh `server` import re-imports them.

    Routers close over `deps.client` at import time. If a router is
    already in `sys.modules`, a fresh `server` import will reuse it and
    the router will keep its stale proxy reference. Purging routers only
    (NOT engine/v2/middleware) forces fresh binding without disturbing
    global state elsewhere in the app.
    """
    for name in list(sys.modules.keys()):
        if name == "routers" or name.startswith("routers."):
            del sys.modules[name]


@pytest.fixture(autouse=True, scope="module")
def _rc5_api_reset_between_modules():
    """Normalise Motor proxy + router-module state before each API test module.

    After the module finishes we do NOT re-purge: doing so competes with
    the TestClient's own shutdown handler (`client.close()` running on
    the just-closed event loop) and produces the same teardown hang that
    xdist exhibits in CI. Reset is one-way, entry-only.
    """
    _reset_deps_proxies_in_place()
    _purge_router_modules()
    yield
