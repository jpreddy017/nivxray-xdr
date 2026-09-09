"""Phase 5.W permanent fix · P0.3 leg 3 — Workspace ↔ X-Lab isolation
guard (updated 2026-08-11 after X-Lab observational-surface removal).

Owner directive history:
    · 2026-08-11 (session-6): "X-Lab / new capability changes must not
      alter Workspace behavior/state." — enforced as a static-import
      guard + a runtime signature-diff guard.
    · 2026-08-11 (session-7): "GO — remove X-Lab observational surface"
      per ADR-005 X-Lab Removal Impact Audit. The observational surface
      (routers/timeline_lab.py + routers/semantic_lab.py + their 6
      /api/v2/... routes + the Lab2/XLabGraph frontend UI) has been
      deleted.

Post-removal contract this file now locks:

    Static invariant:
        No production Workspace module (routers/die.py, routers/ops.py,
        routers/cases.py, routers/decode.py, routers/planner.py,
        routers/analyze.py, services/die/*) may import from any X-Lab
        module (routers/timeline_lab, routers/semantic_lab, services/*_lab).

    Deletion invariant:
        The removed router files must stay removed. If a future
        contributor re-introduces them, this test fails loudly.

    Route invariant:
        The 6 previously-observational endpoints must return 404.
        Bringing any of them back requires re-opening the audit.

    Workspace-signature invariant:
        The Workspace /api/die/investigation-results response for a
        fixed prose input must be signature-stable across two calls
        (baseline safety even with no X-Lab traffic to interleave).
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

# X-Lab modules that MUST STAY DELETED.
XLAB_REMOVED_MODULES = [
    "routers/timeline_lab.py",
    "routers/semantic_lab.py",
]

# Import patterns that would signal re-introduction of X-Lab
# dependencies inside Workspace code. Failing this test does NOT
# necessarily mean X-Lab came back — it means Workspace picked up an
# import it shouldn't have.
XLAB_IMPORT_PATTERNS = [
    r"\bfrom\s+routers\.timeline_lab\b",
    r"\bfrom\s+routers\.semantic_lab\b",
    r"\bimport\s+routers\.timeline_lab\b",
    r"\bimport\s+routers\.semantic_lab\b",
    r"\bfrom\s+services\.(\w+_lab)\b",
]

# X-Lab observational HTTP surface — must all be 404 post-removal.
XLAB_REMOVED_ROUTES = [
    ("POST", "/api/v2/timeline/preview"),
    ("POST", "/api/v2/attack-chain/preview"),
    ("POST", "/api/v2/correlation/preview"),
    ("POST", "/api/v2/pipeline/preview"),
    ("GET",  "/api/v2/semantic/registry"),
    ("POST", "/api/v2/semantic/preview"),
]


FIXED_INVESTIGATION_INPUT = (
    "During the incident the actor deployed a remote access trojan and "
    "used PowerShell to execute an encoded command. The malware attempted "
    "to disable Windows Defender and moved laterally over SMB."
)


def _response_signature(resp_json: dict) -> str:
    """Deterministic sha256 over the analyst-relevant slice of the response."""
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
    # See test_p02_evidence_chain.py — no `with TestClient(app) as c`
    # to avoid closing the event loop for other modules on the same
    # xdist worker.
    yield TestClient(app)


# ─────────────────────────────────────────────────────────────────
# P0.3-Iso-1 — X-Lab router files must remain deleted.
# ─────────────────────────────────────────────────────────────────
def test_xlab_router_files_removed():
    backend_root = Path(__file__).resolve().parents[3]  # /app/backend
    resurrected = [rel for rel in XLAB_REMOVED_MODULES
                   if (backend_root / rel).exists()]
    assert not resurrected, (
        f"X-Lab router files re-introduced: {resurrected}. The owner "
        f"authorised their removal on 2026-08-11 (see ADR-005 X-Lab "
        f"Removal Impact Audit). If X-Lab is genuinely being revived, "
        f"re-open the audit and update this guard consciously."
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
        "Workspace modules must NOT import from X-Lab modules. Even "
        "post-removal, any re-introduction of these imports would signal "
        "a resurrection of the deleted subsystem. Offenders:\n" +
        "\n".join(f"  {p} · {m} · …{ctx}…" for p, m, ctx in offenders)
    )


# ─────────────────────────────────────────────────────────────────
# P0.3-Iso-3 — X-Lab HTTP routes must return 404.
# ─────────────────────────────────────────────────────────────────
def test_xlab_routes_return_404(client):
    still_alive: list[tuple[str, str, int]] = []
    for method, path in XLAB_REMOVED_ROUTES:
        if method == "GET":
            r = client.get(path)
        else:
            r = client.post(path, json={"input": "x"})
        if r.status_code != 404:
            still_alive.append((method, path, r.status_code))
    assert not still_alive, (
        f"X-Lab routes still reachable after removal: {still_alive}. "
        f"They must return 404 — the audit deleted the router files."
    )


# ─────────────────────────────────────────────────────────────────
# P0.3-Iso-4 — Workspace signature stable across identical calls.
# ─────────────────────────────────────────────────────────────────
def test_workspace_signature_stable(client):
    r0 = client.post("/api/die/investigation-results",
                     json={"input": FIXED_INVESTIGATION_INPUT})
    assert r0.status_code == 200
    r1 = client.post("/api/die/investigation-results",
                     json={"input": FIXED_INVESTIGATION_INPUT})
    assert r1.status_code == 200

    sig0 = _response_signature(r0.json())
    sig1 = _response_signature(r1.json())
    assert sig0 == sig1, (
        f"Workspace investigation output is non-deterministic across two "
        f"identical calls: {sig0} vs {sig1}. Some shared state (cache, "
        f"singleton, DB upsert, clock, random) is leaking into the "
        f"investigate lane."
    )
