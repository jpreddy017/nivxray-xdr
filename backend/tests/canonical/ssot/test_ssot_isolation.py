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
    # Phase 5.W authorised paths (owner sign-off 2026-08-10) — Workspace-priority
    # canonical integration into the existing DIE / upload path.
    PHASE_5_1_PATHS = {
        "backend/routers/uil.py",
        "backend/services/uil/canonical_entry.py",
        "backend/services/uil/canonical_session.py",
        "backend/tests/canonical/test_phase5_1_uil_investigate.py",
        "backend/tools/sample1_sanity_check.py",
        # Phase 5.W
        "backend/routers/die.py",
        "backend/routers/ops.py",
        "backend/services/die/canonical_bridge.py",
        # Phase 5.W · narrative enrichment (2026-08-10 owner sign-off)
        # Fills empty analyst_narrative fields (executive_summary,
        # recommended_actions, behavior_summary, overall_assessment,
        # likely_objective, sigma_hunts, yara_ideas) + synthesises
        # object.chain.steps[] from attack_progression + enriches
        # LOLBAS entries from the registry when they arrive empty.
        "backend/services/die/canonical_narrative_enrichment.py",
        "backend/scripts/backfill_narrative_enrichment.py",
        # Phase 5.W · CSV/EDR tabular log analyzer (2026-08-10)
        # Detects vendor endpoint-security telemetry (SEP, CrowdStrike,
        # Defender, Sentinel) and maps category/action columns → MITRE
        # ATT&CK ids + IOCs + LOLBAS. Fills the tabular-input gap where
        # canonical narrative prose rules matched nothing.
        "backend/services/die/csv_edr_analyzer.py",
        "frontend/src/components/investigation/AnalystNarrativePanel.jsx",
        "frontend/src/components/investigation/AttackChainView.jsx",
        # Phase 5.W.2 · Anti-hang upload path (2026-08-10)
        # - Client-side 2 MB size cap on /api/upload
        # - 25 s abort budget with actionable error
        # - startTransition around setInput / setStatus so downstream
        #   AnalystNarrativePanel / TrajectoryDiagram re-render cascade
        #   yields to user input and paint.
        # - Free heavy state fields (investigationObject / analystNarrative)
        #   BEFORE upload so useIdlePersist has nothing giant to
        #   JSON.stringify during the upload flow.
        # - useIdlePersist bulk-drop guard now includes object size
        #   estimate, so JSON.stringify never blocks the main thread
        #   even when a hydrated investigation is still in state.
        "frontend/src/pages/WorkspacePage.jsx",
        "frontend/src/hooks/useIdlePersist.js",
    }
    out = subprocess.check_output(
        ["git", "diff", "--name-only"], cwd="/app"
    ).decode()
    lines = [ln for ln in out.splitlines() if ln.strip()]
    non_phase = [
        ln for ln in lines
        if not ln.startswith("backend/canonical/")
        and not ln.startswith("backend/tests/canonical/")
        and not ln.startswith("backend/tests/fixtures/")
        and not ln.startswith("memory/")
        and ln not in PHASE_5_1_PATHS
    ]
    assert not non_phase, (
        f"unauthorised files touched outside Phase 2 + Phase 5.1 scope: "
        f"{non_phase}"
    )
