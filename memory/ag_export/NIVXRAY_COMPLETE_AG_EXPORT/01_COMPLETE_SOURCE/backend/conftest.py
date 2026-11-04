"""Backend test session · env normalisation.

Loaded by pytest BEFORE any test module imports — this is the single
choke point where the v2 feature-flag state is guaranteed to be set,
regardless of whether CI's job-level `env:` block or the local `.env`
file did (or forgot to do) it.

Historical context
------------------
Every fork-agent handoff has hit the same recurring failure:

    tests/rc5/api/test_v2_ancestry.py::test_ancestry_root_by_binary_name
    FAILED — 503: trajectory engine disabled

…because either
    (a) `v2/flags.py` snapshots env vars at IMPORT time, so a fixture
        that runs later couldn't influence them, or
    (b) a workflow file was updated but the failing CI run predated
        the workflow change, or
    (c) a new test was added without the module-scope fixture and
        picked up the DISABLED default silently.

The permanent fix is a two-layer defence:

  1. `v2/flags.py::get()` now reads `os.environ` on every call — no
     more frozen snapshots (see that module for details).
  2. THIS FILE unconditionally exports `NIVX_FLAG_*` before any test
     module imports anything. Even if a workflow forgets the env
     block, tests still get a coherent flag state.

Everything is scoped strictly to test runs. Production imports do
NOT touch this file; `v2/flags.py` still reads whatever env the real
process was launched with.
"""
from __future__ import annotations
import os

# ─── v2 platform feature flags ───────────────────────────────────────
# Default to SHADOW for tests so the endpoints tests cover actually
# run. Existing env values are respected — a workflow that wants to
# assert DISABLED behaviour can still set the var explicitly.
_TEST_FLAG_DEFAULTS: dict[str, str] = {
    "NIVX_FLAG_TRAJECTORY_ENGINE": "shadow",
    "NIVX_FLAG_CASE_ENGINE":       "shadow",
    "NIVX_FLAG_ADAPTERS":          "shadow",
    "NIVX_FLAG_ARTIFACT_STORE":    "shadow",
}
for _k, _v in _TEST_FLAG_DEFAULTS.items():
    os.environ.setdefault(_k, _v)

# ─── Motor / Mongo defaults for local dev runs ───────────────────────
# CI always sets MONGO_URL; local `pytest` invocations often forget to.
# Setting a sensible default here means `python -m pytest tests/rc5/`
# works out of the box against the pod's local Mongo without every
# developer having to remember the export.
os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
os.environ.setdefault("DB_NAME",   "nivxray_ci_local")

# ─── Admin credentials for endpoint tests ────────────────────────────
os.environ.setdefault("ADMIN_EMAIL",    "admin@nivxray.com")
os.environ.setdefault("ADMIN_PASSWORD", "ci-only-not-a-real-secret")


# ─── Sample1 golden diagnostic case · session-scope seed ─────────────
# The frozen Sample1 case (id 3db79c4a-088b-4df7-b65a-f68b367b7677) is
# the architectural canary for the canonical investigation lifecycle.
# Three tests lock its byte-identical fingerprint against
# GOLDEN_CASE_SAMPLE1.md.  In fresh CI pods / dev environments the
# `nivxray_ci_local` DB starts empty, so seed the golden case from the
# on-disk snapshot before any acceptance test runs.  Idempotent — only
# inserts when workspace_cases lacks the case, and only after the
# snapshot's own fingerprint matches the locked golden value.
def _seed_sample1_if_missing() -> None:
    try:
        import sys
        # Ensure `tools.seed_golden_case` is importable regardless of
        # how pytest was invoked (e.g. from repo root).
        sys.path.insert(0, os.path.dirname(__file__))
        from tools.seed_golden_case import seed_sample1_if_missing
        from pymongo import MongoClient
        client = MongoClient(os.environ["MONGO_URL"],
                                serverSelectionTimeoutMS=2000)
        db = client[os.environ["DB_NAME"]]
        _ = seed_sample1_if_missing(db)
    except Exception:  # noqa: BLE001 — never break test collection
        pass


_seed_sample1_if_missing()
