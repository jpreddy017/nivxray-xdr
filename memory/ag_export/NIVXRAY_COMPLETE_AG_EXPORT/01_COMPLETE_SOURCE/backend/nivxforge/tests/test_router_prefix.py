"""Router prefix invariant — every route lives under /nivxforge.

Even though the router is DORMANT (not mounted in server.py per
Decision A1), we verify its shape here so that when it is eventually
mounted, every route lands at /api/nivxforge/*.
"""

from nivxforge.router import router


def test_all_routes_under_nivxforge_prefix():
    for route in router.routes:
        path = getattr(route, "path", None)
        assert path is not None, f"route has no path attribute: {route!r}"
        assert path.startswith("/nivxforge"), (
            f"Route {path!r} escapes the /nivxforge prefix. "
            "This violates NORTH_STAR §7 (Workspace Protection · API namespace)."
        )


def test_router_has_dormant_health_endpoint():
    paths = [getattr(r, "path", None) for r in router.routes]
    assert "/nivxforge/health" in paths, (
        "Expected the dormant /nivxforge/health probe to be defined."
    )
