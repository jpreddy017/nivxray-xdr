"""v2 routers namespace.

Endpoints are ADDITIVE and gated by feature flags. If v2 is deleted
entirely, `server.py` swallows the ImportError and RC5 keeps
running (see `test_v2_isolation.py::test_deleting_v2_would_not_break_rc5`).
"""
from v2.routers.cases import router as cases_router  # noqa: F401
from v2.routers.parse import router as parse_router  # noqa: F401
from v2.routers.trajectory import router as trajectory_router  # noqa: F401
from v2.routers.mitre_coverage import router as mitre_coverage_router  # noqa: F401
from v2.routers.report import router as report_router  # noqa: F401
from v2.routers.ancestry import router as ancestry_router  # noqa: F401
from v2.routers.ingest import router as ingest_router  # noqa: F401
from v2.routers.artifacts import router as artifacts_router  # noqa: F401
from v2.routers.irg import router as irg_router  # noqa: F401
