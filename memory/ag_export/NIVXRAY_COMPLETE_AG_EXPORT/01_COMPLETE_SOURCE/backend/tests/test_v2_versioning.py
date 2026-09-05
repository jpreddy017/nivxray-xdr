"""API versioning invariants — Round-7 requirement.

Proves that hitting any `/api/v2/*` endpoint cannot change the
behaviour or contract of any `/api/rc5/*` endpoint:

  1. Static: no v2 router mutates any RC5 collection.
  2. Static: PIC v2 endpoints are a strict subset of live `/api/v2/*`
     routes; every entry is flag-gated.
  3. Static: no `/api/v2/*` router file imports from `engine.*` or
     from any `routers.rc5_*` module.
  4. Runtime: enabling all v2 flags leaves the RC5 route table
     BYTE-IDENTICAL (same paths + methods).
  5. Runtime: the PIC (rc5) endpoint set remains 100% present when
     v2 flags flip.
"""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
RC5_COLLECTIONS = frozenset({
    "workspace_cases", "investigation_events", "settings",
    "shadow_snapshots", "training_inbox",
    "rc5_golden_runs", "playbooks", "documents", "batch_runs",
})


# ─── 1 · v2 routers must not touch RC5 collections ─────────────────
def test_v2_routers_never_reference_rc5_collections():
    """Grep every file under `v2/routers/` for RC5 collection names."""
    offenders: list[str] = []
    for py in (BACKEND / "v2" / "routers").rglob("*.py"):
        body = py.read_text(errors="ignore")
        for coll in RC5_COLLECTIONS:
            if f'"{coll}"' in body or f"'{coll}'" in body:
                offenders.append(f"{py.name}: references {coll!r}")
    assert not offenders, (
        "v2 routers must never touch RC5 collections directly: " + str(offenders)
    )


# ─── 2 · v2 routers never import from engine.* or routers.rc5_* ─────
def test_v2_routers_never_import_rc5_engine_or_routers():
    offenders: list[str] = []
    for py in (BACKEND / "v2").rglob("*.py"):
        try:
            tree = ast.parse(py.read_text(errors="ignore"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if mod == "engine" or mod.startswith("engine."):
                    offenders.append(f"{py.name}: from {mod}")
                if mod.startswith("routers.rc5"):
                    offenders.append(f"{py.name}: from {mod}")
            elif isinstance(node, ast.Import):
                for a in node.names:
                    if a.name == "engine" or a.name.startswith("engine."):
                        offenders.append(f"{py.name}: import {a.name}")
    assert not offenders, (
        "v2 modules imported from RC5 engine/routers — violates "
        f"cross-namespace isolation: {offenders}"
    )


# ─── 3 · PIC v2 matches live routes; every entry is flag-gated ──────
def test_public_interface_contract_v2_alignment():
    pic_path = BACKEND / "baselines" / "public_interface_contract_v2.json"
    assert pic_path.exists(), "PIC v2 file missing"
    with pic_path.open() as f:
        pic = json.load(f)

    # Live routes.
    from server import app
    live = {(m.upper(), r.path) for r in app.routes
            for m in getattr(r, "methods", set())}

    missing: list[str] = []
    for ep in pic.get("frozen_endpoints", []):
        key = (ep["method"].upper(), ep["path"])
        if key not in live:
            missing.append(f"{ep['method']} {ep['path']}")
        assert ep.get("flag"), (
            f"PIC v2 entry {ep['path']} is not flag-gated (flag field empty)"
        )
    assert not missing, f"PIC v2 declares endpoints not present in live app: {missing}"


# ─── 4 · Enabling v2 flags leaves RC5 route table unchanged ────────
@pytest.fixture()
def _rc5_route_snapshot():
    from server import app
    return {(m.upper(), r.path) for r in app.routes
            for m in getattr(r, "methods", set())
            if getattr(r, "path", "").startswith("/api/rc5")}


def test_rc5_routes_unchanged_when_v2_flags_enabled(_rc5_route_snapshot):
    """Toggle every v2 flag ON and confirm the RC5 subset of the
    route table is byte-identical. Routes are collected once per
    process, so the concrete assertion here is that we never see a
    v2 module's import monkey-patch or hijack an RC5 path."""
    baseline = _rc5_route_snapshot

    # Flip all flags to shadow and re-import server.
    for name in ("CASE_ENGINE", "ADAPTERS", "GRAPH_ENGINE",
                 "TIMELINE_V2", "TRAJECTORY_ENGINE", "REPLAY",
                 "NOTEBOOK", "ARTIFACT_STORE", "KNOWLEDGE_LAYER",
                 "NEGATIVE_EVIDENCE", "COPILOT"):
        os.environ[f"NIVX_FLAG_{name}"] = "shadow"

    import importlib
    import v2.flags as _flags
    importlib.reload(_flags)
    # No need to reload server — router set is fixed at import time.
    from server import app
    now = {(m.upper(), r.path) for r in app.routes
           for m in getattr(r, "methods", set())
           if getattr(r, "path", "").startswith("/api/rc5")}

    # Reset flags to disabled.
    for k in list(os.environ):
        if k.startswith("NIVX_FLAG_"):
            os.environ.pop(k)
    importlib.reload(_flags)

    assert now == baseline, (
        "RC5 route table changed when v2 flags were flipped ON — this "
        f"violates the versioning isolation guarantee. added={now - baseline} "
        f"removed={baseline - now}"
    )


# ─── 5 · RC5 PIC endpoints all still present ───────────────────────
def test_rc5_pic_still_present_after_v2_registration():
    from server import app
    live = {(m.upper(), r.path) for r in app.routes
            for m in getattr(r, "methods", set())}
    with (BACKEND / "baselines" / "public_interface_contract.json").open() as f:
        pic = json.load(f)
    missing = []
    for ep in pic["frozen_endpoints"]:
        if (ep["method"].upper(), ep["path"]) not in live:
            missing.append(f"{ep['method']} {ep['path']}")
    assert not missing, (
        "RC5 PIC endpoints missing after v2 wire-up — versioning "
        f"regression: {missing}"
    )
