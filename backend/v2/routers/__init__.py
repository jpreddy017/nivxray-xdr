"""v2 routers namespace.

Endpoints are ADDITIVE and gated by feature flags. If v2 is deleted
entirely, `server.py` swallows the ImportError and RC5 keeps
running (see `test_v2_isolation.py::test_deleting_v2_would_not_break_rc5`).
"""
from v2.routers.cases import router as cases_router  # noqa: F401
from v2.routers.parse import router as parse_router  # noqa: F401
