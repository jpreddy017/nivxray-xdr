"""T2.7 · Isolation — no existing NivXRay code imports canonical.ssot.

Phase 5.1 (2026-08-10): explicit scoped exemptions for the owner-approved
UIL route migration. These are the ONLY files authorised to bridge from
the legacy tier into `canonical.*`. Every other module must remain
firewall-isolated from `canonical.ssot`.
"""
import os
import subprocess

# ── Phase 5.1 authorised bridge files (owner sign-off 2026-08-10) ──────
PHASE_5_1_ALLOWED = frozenset({
    "/app/backend/services/uil/canonical_entry.py",
    "/app/backend/services/uil/canonical_session.py",
})


def test_no_router_imports_canonical_ssot():
    routers_dir = "/app/backend/routers"
    hits = []
    for root, _dirs, files in os.walk(routers_dir):
        for name in files:
            if not name.endswith(".py"):
                continue
            path = os.path.join(root, name)
            with open(path, encoding="utf-8") as f:
                text = f.read()
            if "canonical.ssot" in text or "from canonical.ssot" in text:
                hits.append(path)
    assert not hits, f"routers must NOT import canonical.ssot in Phase 2: {hits}"


def test_no_service_imports_canonical_ssot():
    for base in ("/app/backend/services", "/app/backend/nivxforge",
                 "/app/backend/v2", "/app/backend/l2_investigation",
                 "/app/backend/l1_evidence"):
        for root, _dirs, files in os.walk(base):
            for name in files:
                if not name.endswith(".py"):
                    continue
                path = os.path.join(root, name)
                # Phase 5.1 authorised bridge — explicit exemption.
                if path in PHASE_5_1_ALLOWED:
                    continue
                with open(path, encoding="utf-8") as f:
                    text = f.read()
                assert "canonical.ssot" not in text, \
                    f"non-canonical module imports canonical.ssot: {path}"


def test_no_route_file_modified_by_phase2():
    """git diff --name-only must not include any file outside the
    approved surface. Phase 5.1 (2026-08-10) adds two explicitly
    approved service files + the UIL router. Everything else must
    remain untouched.
    """
    # Phase 5.1 authorised paths (owner sign-off 2026-08-10).
    PHASE_5_1_PATHS = {
        "backend/routers/uil.py",
        "backend/services/uil/canonical_entry.py",
        "backend/services/uil/canonical_session.py",
        "backend/tests/canonical/test_phase5_1_uil_investigate.py",
        "backend/tools/sample1_sanity_check.py",
    }
    out = subprocess.check_output(
        ["git", "diff", "--name-only"], cwd="/app"
    ).decode()
    lines = [ln for ln in out.splitlines() if ln.strip()]
    non_phase = [
        ln for ln in lines
        if not ln.startswith("backend/canonical/")
        and not ln.startswith("backend/tests/canonical/")
        and not ln.startswith("memory/")
        and ln not in PHASE_5_1_PATHS
    ]
    assert not non_phase, (
        f"unauthorised files touched outside Phase 2 + Phase 5.1 scope: "
        f"{non_phase}"
    )
