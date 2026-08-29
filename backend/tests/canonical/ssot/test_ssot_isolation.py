"""T2.7 · Isolation — no existing NivXRay code imports canonical.ssot.

Phase 5.1 (2026-08-10): explicit scoped exemptions for the owner-approved
UIL route migration. These are the ONLY files authorised to bridge from
the legacy tier into `canonical.*`. Every other module must remain
firewall-isolated from `canonical.ssot`.
"""
import os
import subprocess

# ── Phase 5.1 authorised bridge files (owner sign-off 2026-08-10) ──────
# Stage-1 IUE authorised bridge (owner sign-off 2026-02-13):
#   The IUE package composes canonical.ssot.models.Provenance so every
#   payload dataclass carries the SAME provenance schema the rest of
#   NivXRay already uses.  This is the deliberate Stage-1 architectural
#   decision — a single Provenance model, no parallel representation.
#   Every IUE .py file that imports it is enumerated here.
PHASE_5_1_ALLOWED = frozenset({
    "/app/backend/services/uil/canonical_entry.py",
    "/app/backend/services/uil/canonical_session.py",
    # IUE facade + lanes + collectors + parsers + normalizers + aggregator
    "/app/backend/services/iue/_prov.py",
    "/app/backend/services/iue/aggregator.py",
    "/app/backend/services/iue/failure.py",
    "/app/backend/services/iue/intake.py",
    "/app/backend/services/iue/collectors/log_collector.py",
    "/app/backend/services/iue/collectors/url_collector.py",
    "/app/backend/services/iue/collectors/file_collector.py",
    "/app/backend/services/iue/parsers/_errors.py",
    "/app/backend/services/iue/parsers/_types.py",
    "/app/backend/services/iue/normalizers/field_map.py",
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
        # Phase 5.W permanent fix · P0.a + P0.b + P0.c (2026-08-11)
        # Payload-shape contract test (allow-list + forbidden-list +
        # 250 KB budget + regression guards for MITRE & exec_summary).
        # Prevents any future contributor from silently reintroducing
        # the "Page Unresponsive" freeze by leaking preprocessor /
        # commands / artifacts / … back onto the wire.
        "backend/tests/canonical/api/__init__.py",
        "backend/tests/canonical/api/test_investigation_results_payload_shape.py",
        # Phase 5.W permanent fix · P0.3 legs 2 & 3 (2026-08-11)
        # Sample1 immutability guard — Workspace API calls MUST NOT
        # mutate the frozen Sample1 case row; static-import invariant
        # forbids DIE modules from hard-coding the Sample1 case id.
        # Workspace ↔ X-Lab isolation guard — X-Lab traffic MUST NOT
        # perturb Workspace output, and no Workspace module may
        # import from X-Lab modules.
        "backend/tests/canonical/api/test_sample1_immutability_guard.py",
        "backend/tests/canonical/api/test_workspace_isolation_guard.py",
        # Panel-level ErrorBoundary — one panel crashing never takes
        # the whole Workspace tab down.
        "frontend/src/components/PanelErrorBoundary.jsx",
        "frontend/src/pages/WorkspacePage.jsx",
        "frontend/src/hooks/useIdlePersist.js",
        # P1.1 · Close-the-bridge (owner sign-off 2026-08-11)
        # /api/upload streams through FileStore first (GridFS + race-safe
        # dedup + 200 MB server-side cap) BEFORE any RAM buffering.
        # Response contract preserved; additive `file_id`/`route`/`dedup`
        # fields only. `init_database()` hardened against post-teardown
        # closed-client reuse. `server.py` wires the retention sweeper
        # start/stop into the FastAPI lifespan.
        "backend/deps.py",
        "backend/server.py",
        "backend/services/files/retention_sweeper.py",
        # Item 1 · Risk-score recalibration (owner sign-off 2026-08-12,
        # ADR-0010e §10 · ADR-0023 §4). LOLBIN + external-IOC boost +
        # known-bad-TTP boost + T1218.* signed-binary-proxy bonus.
        # Backward-compatible: `risk_score(mitre, yara, iocs)` legacy
        # call sites remain valid via `lolbas=None` default.
        "backend/operations.py",
        "backend/routers/analyze.py",
        # Item 2 · Deterministic narrative bridge (owner sign-off
        # 2026-08-12, ADR-0010e §10 · ADR-0023 §4). `/api/die/narrate`
        # now feeds the DIE analyzer's real techniques + LOLBIN-linked
        # MITRE ids into `enrich_narrative`; pure projection, zero
        # inference, zero new data source. `_TECHNIQUE_META` extended
        # with previously-missing tactic/kill_chain rows so the
        # enricher stops silently dropping T1218.005/T1562.004/T1197/
        # T1140/T1047/T1059.005/T1059.007 evidence — this file's
        # header explicitly permits data-catalog completion without
        # projection-logic change.
        "backend/routers/die.py",
        "backend/canonical/projections/attck.py",
        # Item 3 · Recursive decode (owner sign-off 2026-08-12,
        # ADR-0010e §10 · ADR-0023 §4). New module
        # services/die/recursive_decode.py peels nested base64 layers
        # (`-EncodedCommand`, `FromBase64String`, `base64 -d`) with
        # deterministic bounds (MAX_DEPTH=3, MAX_LAYERS=12, SHA-256
        # visit set). services/die/api.py::analyze() calls it after
        # the base envelope is built and merges new evidence via
        # merge_evidence(). Additive-only; cycle-guarded; Cruise-
        # Missile principle honoured (pursues layers but never
        # manufactures verdicts).
        "backend/services/die/recursive_decode.py",
        "backend/services/die/api.py",
        # UI-DEF-01 · Attack Chain panel fix (owner explicit
        # authorisation 2026-08-12, superseding the "no Workspace
        # changes" gate for this specific defect). Three fixes:
        #   1. Tightened T1566.001 spearphishing regex in
        #      operations.py::_MITRE_MAP — a legitimate .ps1 file
        #      reference no longer triggers a false Initial-Access
        #      verdict (the source of the pb-01 divergence).
        #   2. TrajectoryDiagram.jsx: title/legend corrected for the
        #      legacy 6-lane view (it renders artifact categories,
        #      NOT kill-chain phases), + neutral colour for
        #      unclassified phase (was miscoloured cyan =
        #      Reconnaissance), + Rules-of-Hooks fix (useMemo now
        #      runs before the early empty-state return).
        "frontend/src/components/investigation/TrajectoryDiagram.jsx",
        # Item 4 · T1562.004 DIE catalogue signature (owner sign-off
        # 2026-08-12, ADR-0010e §10 · ADR-0023 §4). cmd_ast.py adds
        # a deterministic `netsh advfirewall … state off` (and legacy
        # `netsh firewall set opmode disable`) detection, emitting
        # T1562.004 (Impair Defenses: Disable or Modify System
        # Firewall). Fills the DIE-catalogue gap ADR-0010e §7 Q3
        # identified. Additive-only; no other technique behaviour
        # changed.
        "backend/services/die/cmd_ast.py",
        # Item 5 · Bounded TI-lookup latency (owner sign-off
        # 2026-08-12, ADR-0010e §10 · ADR-0023 §4 · ADR-0010l).
        # `analysis_core.lookup_ti_hits_bounded[_meta]` wraps the
        # existing `lookup_ti_hits` with a strict wall-clock budget
        # (`NIVX_TI_LOOKUP_DEADLINE_MS`, default 500 ms). Timeout /
        # provider exception → `[]` (never fabricate). Wired into
        # the three `/api/analyze` call sites. Preserves verdict /
        # MITRE / risk-score outputs — TI is evidence context, not
        # a verdict driver.
        "backend/analysis_core.py",
        "backend/tests/canonical/api/test_item5_ti_lookup_bounded.py",
        # UI-DEF-02 · MITRE Convergence (owner sign-off 2026-08-12,
        # ADR-0010m · ADR-0023 §3c). `/api/analyze` no longer emits
        # its own regex-based mitre projection — the response `mitre`
        # field is derived from the SAME authoritative surface the
        # Workspace already consumes (services.die.investigation_results
        # → augment_investigation_results → mitre_evidence_chain gate).
        # `mitre_map()` remains available for legacy callers (chain
        # analyzer, layer_360) but is surfaced only as a diagnostic
        # `mitre_provenance.regex_extra` chip on the response.
        # canonical_bridge.py: DIE-catalogue free-text evidence is now
        # wrapped into structured provenance records BEFORE the P0.2
        # gate so the gate no longer silently drops the analyzer's
        # own findings on pure command inputs. Not fabrication —
        # `observed_value` is the exact analyzer-emitted snippet.
        # Frontend TrajectoryDiagram: empty tactic lanes render as
        # structural label + thin divider only (no "· —" suffix, no
        # dimmed fill, no stats/density on empty lanes) per the
        # locked design directive.
        "frontend/src/components/investigation/TrajectoryDiagram.jsx",
        "frontend/src/pages/WorkspacePage.jsx",
        "backend/tests/canonical/api/test_ui_def_02_convergence.py",
        "backend/services/die/canonical_bridge.py",
        # UI-DEF-02 Option B · LOLBAS → technique merge in DIE catalogue
        # (owner sign-off 2026-08-12, ADR-0010p). The `_merge_lolbin_
        # techniques()` helper folds the LOLBAS-registry MITRE ids into
        # every language branch of `_analyze_single` and into
        # `_chain_to_envelope` so the DIE catalogue publishes the
        # LOLBIN-canonical techniques the regex mapper used to cover
        # (T1218.005/010/011, T1047, T1059.003, T1197, …). Evidence
        # anchored to the actual LOLBIN detection — never fabricated.
        "backend/services/die/api.py",
        # P2 Slice-1 · Behavioral evidence ingestion (owner sign-off
        # 2026-08-12, ADR-0023 · ADR-0010q). New telemetry adapter for
        # Sysmon Event 1 (Process Create) → canonical behavioral
        # evidence. Adapter is an EVIDENCE PRODUCER only — no parallel
        # MITRE mapper, no verdict logic, no process-tree engine. The
        # thin router hands the extracted `command_line` to the
        # UI-DEF-02 authoritative surface (services.die.api.analyze).
        "backend/services/behavioral/__init__.py",
        "backend/services/behavioral/sysmon_adapter.py",
        "backend/routers/behavioral.py",
        "backend/server.py",
        "backend/tests/canonical/api/test_p2_sysmon_adapter.py",
        "backend/tests/canonical/api/test_p2_slice1_no_corpus_impact.py",
        # P2 Slice-2 · Sysmon Event 3 network-connect ingestion
        # (owner sign-off 2026-08-12, ADR-0023 · ADR-0010r). Extends
        # the Slice-1 adapter with Event 3 field map + destination
        # classification + ProcessGuid → Event 1 correlation. Still
        # evidence-producer only; the authoritative MITRE surface is
        # driven exclusively by Event 1 command lines.
        "backend/tests/canonical/api/test_p2_slice2_sysmon_event3.py",
        "backend/tests/canonical/api/test_p2_slice2_extended_contract.py",
        # P2 Slice-3 · EVTX binary transport (owner sign-off
        # 2026-08-12, ADR-0023 · ADR-0010s). Transport-only wire-
        # format adapter over the SAME Slice-2 normalizer. No new
        # semantics, no new MITRE mapper. python-evtx parser walks
        # records → concatenates per-record `<Event>` XML into an
        # `<Events>` wrapper → hands to `normalize_sysmon_xml`.
        "backend/services/behavioral/evtx_reader.py",
        "backend/routers/behavioral.py",
        "backend/tests/canonical/api/test_p2_slice3_evtx_transport.py",
        "backend/requirements.txt",
        # P2 UI Slice · Behavioral Evidence Timeline (owner sign-off
        # 2026-08-12, ADR-0010t). Read-only projection component that
        # renders Sysmon Event 1 / Event 3 evidence beneath the
        # existing 14-tactic Attack Chain, with correlation-state
        # chips, dedup badges, and a click-through evidence
        # inspector. NO new MITRE inference · NO new verdict logic
        # · NO IKG persistence · projection only.
        "frontend/src/components/investigation/BehavioralTimeline.jsx",
        # ─── 2026-08-26 · Stage-1 Lane C + Extractor hygiene ──────
        # Owner sign-off: this session's execution order was
        # Threat-Actor De-conflation → Threat-Objective Expansion →
        # (upcoming: Attack-Story Timeline) → Lane C UI polish.  The
        # first two land in these two files.
        #
        # 1) Threat-Actor De-conflation (P2 defect from handoff).
        #    `services.ida.report_extractors._extract_actors` now
        #    filters MITRE ATT&CK tactic ids (TA0001..TA0043 Enterprise
        #    + TA0027..TA0038 Mobile + TA0100..TA0111 ICS) out of the
        #    generic `TA\d{2,4}` regex hits so tactic ids never leak
        #    into investigator-facing threat-actor lists.  Real
        #    Proofpoint TA-numbered actors (TA505 / TA544 / TA577 …)
        #    are preserved because they use 3-digit ids without the
        #    tactic-shape leading zero.  Regression tests locked in
        #    `tests/canonical/ida/test_threat_actor_deconflation.py`.
        "backend/services/ida/report_extractors.py",
        # 2) Threat-Objective Expansion (P1 from handoff).  Adds two
        #    deterministic rules to `services.die.intent`:
        #      · `double_extortion_ransomware` — requires BOTH Impact
        #        AND Exfiltration (modern steal-then-encrypt TTP).
        #      · `multi_stage_intrusion` — broad-coverage fallback
        #        for advisory narratives that walk ≥5 distinct tactics
        #        but do not trigger a specific rule; sits BEFORE the
        #        reconnaissance-only fallback so ransomware-style
        #        reports surface a meaningful objective.  Priority
        #        preserved — every specific rule still wins first.
        #    Regression tests locked in
        #    `tests/canonical/die/test_intent_objective_expansion.py`.
        "backend/services/die/intent.py",
        # Stage-1 Lane C (2026-08-26): additive canonical extraction
        # of file/artifact evidence behind the IUE facade.  Feature-
        # flagged via `IUE_ARTIFACT_LANE`.  Same T2 wire contract as
        # Lane A/B; zero UI structural changes required.  Static
        # analysis only — no execution, no network, no sandbox
        # (locked by test_no_execution_no_network).
        "backend/services/iue/collectors/file_collector.py",
        "backend/services/iue/parsers/artifact_parser.py",
        "backend/services/iue/lanes/file_lane.py",
        "backend/services/iue/normalizers/field_map.py",
        "backend/routers/iue_lane_c.py",
        "backend/server.py",
        "backend/.env",
        "memory/PRD.md",
        # Attack Story Timeline (2026-08-26): pure projection over
        # canonical LogicalEvents from Lane A / Lane B / Lane C.
        # DOES NOT correlate, DOES NOT invent events, DOES NOT
        # cross-lane fuse identical evidence.  Endpoint
        # `POST /api/iue/timeline/fuse` accepts a batch of lane wires
        # and returns one deterministic reconstructed timeline.
        # Tenant firewall enforced at the router — refuses to fuse
        # wires from a different tenant than the caller.
        "backend/services/iue/timeline.py",
        "backend/routers/iue_timeline.py",
        # Clean Baseline Gate (2026-08-26): seed the frozen Sample1
        # golden case (id 3db79c4a-…) from the on-disk snapshot when
        # the DB is empty.  Idempotent seed script + startup hook +
        # pytest session-scope fixture so both the live backend and
        # CI runs converge on the same fingerprint.
        "backend/tools/seed_golden_case.py",
        "backend/tools/__init__.py",
        "backend/conftest.py",
        # Stage-2 Deterministic Verdict Engine (2026-08-26).  Owner-
        # locked decisions #1-#6 · pure rule engine, additive to case
        # (verdict_stage2 sibling), fingerprint excludes generated_at,
        # v3.x contract untouched.  Same canonical inputs → byte-
        # identical output.
        "backend/services/verdict_stage2/__init__.py",
        "backend/services/verdict_stage2/model.py",
        "backend/services/verdict_stage2/rules.py",
        "backend/services/verdict_stage2/fingerprint.py",
        "backend/services/verdict_stage2/inputs.py",
        "backend/services/verdict_stage2/engine.py",
        "backend/routers/verdict_stage2.py",
        # EDR canonical Activity/Evidence model (2026-08-26).  Owner
        # rule #19 · one canonical object drives Left inventory →
        # Trajectory canvas → Right details → Verdict Explainability.
        # Deterministic projection over the Timeline; six entity kinds
        # (System/Processes/Files/Network/Registry/Identity).
        "backend/services/activity/__init__.py",
        "backend/services/activity/model.py",
        "backend/services/activity/projector.py",
        "backend/routers/activity.py",
        # EDR Device Trajectory frontend (2026-08-26).  Owner-locked
        # entity-per-row temporal coordinate system + tri-directional
        # selection sync (inventory ↔ trajectory ↔ details).  Pure
        # projection over `/api/activity/inventory` +
        # `/api/verdict/stage2/compute`.
        "frontend/src/App.js",
        "frontend/src/pages/DeviceTrajectoryPage.jsx",
        "frontend/src/components/edr/EntityInventory.jsx",
        "frontend/src/components/edr/TrajectoryCanvas.jsx",
        "frontend/src/components/edr/ActivityDetails.jsx",
        "frontend/src/components/edr/VerdictExplainabilityCard.jsx",
        # Slice 1 · Canonical Incident shell + NivXRay XDR platform
        # shell (owner spec 2026-08-27 / 2026-08-29).  A navigation
        # layer over existing NivXRay capabilities — never a second
        # implementation of any existing engine.  All entries below
        # are additive and never touch /analyst.
        "backend/routers/incidents.py",
        "frontend/src/components/Header.jsx",
        "frontend/src/lib/incidentsApi.js",
        "frontend/src/constants/incidentTestIds.js",
        "frontend/src/pages/incidents/IncidentsListPage.jsx",
        "frontend/src/pages/incidents/IncidentShellPage.jsx",
        "frontend/src/pages/incidents/xdr.css",
        "frontend/src/components/incidents/IncidentHeader.jsx",
        "frontend/src/components/incidents/LifecycleBar.jsx",
        "frontend/src/components/incidents/tabs/OverviewTab.jsx",
        "frontend/src/components/incidents/tabs/InvestigationTab.jsx",
        "frontend/src/components/incidents/tabs/ActivityTab.jsx",
        "frontend/src/components/incidents/tabs/ResponseTab.jsx",
        "frontend/src/xdr/xdr-console.css",
        "frontend/src/xdr/XdrShell.jsx",
        "frontend/src/xdr/components/IncidentQueue.jsx",
        "frontend/src/xdr/pages/XdrDashboardPage.jsx",
        "frontend/src/xdr/pages/XdrIncidentsPage.jsx",
        "frontend/src/xdr/pages/XdrIncidentDetailPage.jsx",
        # NivXForge EDR Console (owner spec 2026-08-29) — endpoint
        # security console INSIDE NivXRay XDR.  Reuses the existing
        # `/edr/trajectory` implementation; every other tab is an
        # honest reserved page.
        "frontend/src/nivxforge/nivxforge.css",
        "frontend/src/nivxforge/NivXForgeConsole.jsx",
        "frontend/src/nivxforge/pages/EdrOverviewPage.jsx",
        "frontend/src/nivxforge/pages/EdrReservedPages.jsx",
        # Additive edit: incident-context ribbon at the top of the
        # existing Device Trajectory page (owner rule #19 — new-tab
        # context preserved).  Trajectory canvas itself is UNCHANGED.
        "frontend/src/pages/DeviceTrajectoryPage.jsx",
        "backend/server.py",
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
