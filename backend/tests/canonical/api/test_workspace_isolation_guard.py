"""Phase 5.W permanent fix · P0.3 leg 3 — Workspace ↔ X-Lab isolation
guard (2026-08-11).

Owner directive: "X-Lab / new capability changes must not alter
Workspace behavior/state."

X-Lab in this codebase:
    routers/timeline_lab.py     · /api/v2/timeline/preview,
                                  /api/v2/attack-chain/preview,
                                  /api/v2/correlation/preview,
                                  /api/v2/pipeline/preview
    routers/semantic_lab.py     · /api/v2/semantic/registry,
                                  /api/v2/semantic/preview

Workspace in this codebase:
    routers/die.py, routers/ops.py (upload), routers/decode.py,
    routers/planner.py, routers/analyze.py, routers/v2.py, routers/cases.py

The guard checks both a RUNTIME invariant and a STATIC-IMPORT invariant:

Runtime:
    Any number of X-Lab calls interleaved with Workspace calls MUST
    leave the Workspace response for the SAME input BIT-IDENTICAL.
    (i.e. X-Lab is genuinely observational and cannot leak state
    into the Workspace investigate path.)

Static:
    No production Workspace module (routers/die.py, routers/ops.py,
    routers/cases.py, services/die/*) may import from an X-Lab
    module (routers/timeline_lab.py, routers/semantic_lab.py,
    services/*_lab.py). Enforces one-way dependency direction.
"""
from __future__ import annotations
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pytest
from fastapi.testclient import TestClient


# ─── Workspace / X-Lab boundary definition ──────────────────────
WORKSPACE_MODULES = [
    "routers/die.py",
    "routers/ops.py",
    "routers/cases.py",
    "routers/decode.py",
    "routers/planner.py",
    "routers/analyze.py",
]
WORKSPACE_SERVICE_DIRS = ["services/die"]

XLAB_MODULES = [
    "routers/timeline_lab.py",
    "routers/semantic_lab.py",
]
XLAB_IMPORT_PATTERNS = [
    r"\bfrom\s+routers\.timeline_lab\b",
    r"\bfrom\s+routers\.semantic_lab\b",
    r"\bimport\s+routers\.timeline_lab\b",
    r"\bimport\s+routers\.semantic_lab\b",
    r"\bfrom\s+services\.(\w+_lab)\b",
]


FIXED_INVESTIGATION_INPUT = (
    "During the incident the actor deployed a remote access trojan and "
    "used PowerShell to execute an encoded command. The malware attempted "
    "to disable Windows Defender and moved laterally over SMB."
)


def _response_signature(resp_json: dict) -> str:
    """Deterministic sha256 over the analyst-relevant slice of the response.
    Deliberately excludes fields that legitimately vary run-to-run
    (metadata timestamps, request ids, etc.)."""
    obj = resp_json.get("object") or {}
    n   = obj.get("narrative") or {}
    slim = {
        "mitre_ids":      sorted(t.get("id") for t in (obj.get("mitre") or []) if isinstance(t, dict) and t.get("id")),
        "lolbas":         sorted((l.get("binary") or "").lower() for l in (obj.get("lolbas") or []) if isinstance(l, dict)),
        "chain_len":      len(((obj.get("chain") or {}).get("steps") or [])),
        "exec_summary":   (n.get("executive_summary") or "").strip(),
        "actions_count":  len(n.get("recommended_actions") or []),
        "progression":    [s.get("tactic") for s in (n.get("attack_progression") or []) if isinstance(s, dict)],
        "assessment":     (n.get("overall_assessment") or {}),
    }
    blob = json.dumps(slim, sort_keys=True, default=str, ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()


@pytest.fixture(scope="module")
def client():
    from server import app
    with TestClient(app) as c:
        yield c


# ─────────────────────────────────────────────────────────────────
# P0.3-Iso-1 — Runtime: X-Lab traffic MUST NOT change Workspace output.
# ─────────────────────────────────────────────────────────────────
def test_xlab_traffic_does_not_perturb_workspace(client):
    # Baseline
    r0 = client.post("/api/die/investigation-results",
                     json={"input": FIXED_INVESTIGATION_INPUT})
    assert r0.status_code == 200
    sig_before = _response_signature(r0.json())

    # Interleave X-Lab traffic (best effort — some may return 4xx and
    # that's fine; the guard only cares that a 200 or a benign error
    # doesn't leak state into Workspace).
    xlab_probes = [
        ("POST", "/api/v2/timeline/preview",     {"input": FIXED_INVESTIGATION_INPUT}),
        ("POST", "/api/v2/attack-chain/preview", {"input": FIXED_INVESTIGATION_INPUT}),
        ("POST", "/api/v2/correlation/preview",  {"input": FIXED_INVESTIGATION_INPUT}),
        ("POST", "/api/v2/pipeline/preview",     {"input": FIXED_INVESTIGATION_INPUT}),
        ("GET",  "/api/v2/semantic/registry",    None),
        ("POST", "/api/v2/semantic/preview",     {"input": FIXED_INVESTIGATION_INPUT}),
    ]
    for method, path, body in xlab_probes:
        try:
            if method == "GET":
                client.get(path)
            else:
                client.post(path, json=body)
        except Exception:
            # X-Lab route may 4xx/5xx; that alone is not a workspace
            # isolation failure. What matters is the AFTER signature.
            pass

    # Post-X-Lab Workspace call with the SAME input.
    r1 = client.post("/api/die/investigation-results",
                     json={"input": FIXED_INVESTIGATION_INPUT})
    assert r1.status_code == 200
    sig_after = _response_signature(r1.json())

    assert sig_before == sig_after, (
        f"Workspace investigation output CHANGED after X-Lab traffic:\n"
        f"  before = {sig_before}\n  after  = {sig_after}\n"
        f"X-Lab is intended to be READ-ONLY / observational. Some code "
        f"path is leaking state (shared cache, singleton mutation, DB "
        f"upsert, etc.) from X-Lab into the Workspace investigate lane. "
        f"Locate the writer and remove or isolate it."
    )


# ─────────────────────────────────────────────────────────────────
# P0.3-Iso-2 — Static: no Workspace module imports from X-Lab.
# ─────────────────────────────────────────────────────────────────
def test_no_workspace_module_imports_from_xlab():
    backend_root = Path(__file__).resolve().parents[3]  # /app/backend
    offenders: list[tuple[str, str, str]] = []

    def _scan(path: Path) -> None:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return
        for pattern in XLAB_IMPORT_PATTERNS:
            for m in re.finditer(pattern, text):
                offenders.append((
                    str(path.relative_to(backend_root)),
                    m.group(0),
                    text[max(0, m.start()-40):m.end()+40].replace("\n", " "),
                ))

    for rel in WORKSPACE_MODULES:
        p = backend_root / rel
        if p.exists(): _scan(p)
    for rel in WORKSPACE_SERVICE_DIRS:
        for py in (backend_root / rel).rglob("*.py"):
            _scan(py)

    assert not offenders, (
        "Workspace modules must NOT import from X-Lab modules. Dependency "
        "direction is one-way: X-Lab may observe Workspace, never the "
        "reverse. Offenders:\n" + "\n".join(
            f"  {p} · {m} · …{ctx}…" for p, m, ctx in offenders
        )
    )


# ─────────────────────────────────────────────────────────────────
# P0.3-Iso-3 — X-Lab endpoints must be registered but never invoked
# by the Workspace investigate path. (Sanity check: ensures the
# routes exist so test 1's traffic actually hits them; if a future
# refactor removes them, this test flags it.)
# ─────────────────────────────────────────────────────────────────
def test_xlab_routes_are_registered(client):
    # Any 2xx OR 4xx-with-body counts as "registered". A 404 with
    # no body means the route is gone entirely.
    for path in ("/api/v2/semantic/registry",
                 "/api/v2/timeline/preview"):
        r = client.get(path) if path.endswith("registry") else client.post(path, json={"input": "x"})
        assert r.status_code != 404, (
            f"X-Lab route {path} is not registered anymore. The isolation "
            f"guard depends on X-Lab existing to prove Workspace is not "
            f"perturbed by it. Either restore the route OR remove the guard."
        )
