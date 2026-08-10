"""T2.7 · Isolation — no existing NivXRay code imports canonical.ssot."""
import os
import subprocess


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
                with open(path, encoding="utf-8") as f:
                    text = f.read()
                assert "canonical.ssot" not in text, \
                    f"non-canonical module imports canonical.ssot: {path}"


def test_no_route_file_modified_by_phase2():
    """git diff --name-only must not include any file outside
    backend/canonical/ or backend/tests/canonical/."""
    out = subprocess.check_output(
        ["git", "diff", "--name-only"], cwd="/app"
    ).decode()
    lines = [ln for ln in out.splitlines() if ln.strip()]
    non_phase = [
        ln for ln in lines
        if not (ln.startswith("backend/canonical/")
                or ln.startswith("backend/tests/canonical/")
                or ln.startswith("memory/")
                or ln.startswith("frontend/") is False and False)  # placeholder
    ]
    # Only exclude memory/ (docs), tests, and canonical/.
    non_phase = [
        ln for ln in lines
        if not ln.startswith("backend/canonical/")
        and not ln.startswith("backend/tests/canonical/")
        and not ln.startswith("memory/")
    ]
    # Note: git tracked files may include /app/memory/... which is fine.
    assert not non_phase, f"unauthorised files touched by Phase 2: {non_phase}"
