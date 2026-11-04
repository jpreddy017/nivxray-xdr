#!/usr/bin/env python3
"""P-1 · DOC_PROVENANCE_LEDGER generator.

Owner directive: reconcile every pre-existing /app/memory/*.md so no
previous architecture or design decision is orphaned by the new
authoritative tree.  Nothing is deleted; superseded documents get a
`SUPERSEDED_BY:` pointer.

Classification:
  ADOPTED             content becomes part of an authoritative doc
  SUPERSEDED          replaced by an authoritative doc (pointer added)
  GENERATED           now regenerated from runtime; hand copy is dead
  HISTORICAL_REFERENCE  point-in-time record, retained, never edited
  SPEC_PENDING        the gap it describes is now tracked in the tree
  OPERATIONAL         still live working state (PRD, credentials, learnings)
"""
from __future__ import annotations

import pathlib
import re
from datetime import datetime, timezone

ROOT = pathlib.Path("/app")
MEMORY = ROOT / "memory"
OUT = ROOT / "docs" / "nivxray-xdr" / "01_REFERENCE" / "DOC_PROVENANCE_LEDGER.md"
STAMP = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")

# explicit decisions for significant documents
MAP: dict[str, tuple[str, str, str]] = {
 # file: (class, target, note)
 "ARCHITECTURE.md": ("ADOPTED", "02_ARCHITECTURE/SYSTEM_ARCHITECTURE.md",
   "master architecture v1.1 — folded into the new system architecture"),
 "ARCHITECTURE_v2.md": ("ADOPTED", "02_ARCHITECTURE/SYSTEM_ARCHITECTURE.md",
   "828-line v2 design; the richer source for the target architecture"),
 "ARCHITECTURE.legacy-v1.md": ("HISTORICAL_REFERENCE", "",
   "pre-XDR platform architecture, retained for lineage"),
 "NIVXRAY_ARCHITECTURE_V1.md": ("HISTORICAL_REFERENCE", "",
   "frozen 1186-line investigation architecture; superseded by the "
   "two-product split but load-bearing for IUE lineage"),
 "NivXRay_360_Architecture.md": ("ADOPTED",
   "02_ARCHITECTURE/COMPONENT_ARCHITECTURE.md",
   "current+target component view"),
 "MASTER_OWNERSHIP_AUDIT.md": ("ADOPTED",
   "02_ARCHITECTURE/COMPONENT_ARCHITECTURE.md",
   "1207-line ownership+wiring audit — the primary input for component "
   "ownership"),
 "MASTER_PARITY_MATRIX.md": ("ADOPTED",
   "08_VALIDATION/CISCO_PARITY_MATRIX.md", "matrix 1, capability parity"),
 "MASTER_CISCO_DELTA.md": ("ADOPTED",
   "01_REFERENCE/CISCO_XDR_REFERENCE_MODEL.md",
   "delta mined from the owner's XDR.pptx (76 slides)"),
 "Y0_CISCO_XDR_REFERENCE_INTAKE.md": ("ADOPTED",
   "01_REFERENCE/CISCO_COMPONENT_CATALOG.md",
   "first Cisco reference intake + gap matrices"),
 "AMP_TRAJECTORY_CONFORMANCE.md": ("ADOPTED",
   "08_VALIDATION/CISCO_PARITY_MATRIX.md",
   "Secure Endpoint device-trajectory conformance study"),
 "XDR_EDR_PARITY_AUDIT.md": ("ADOPTED",
   "00_PRODUCT/PRODUCT_BOUNDARIES.md", "two-product parity audit"),
 "XDR_SEPARATION_HANDOFF.md": ("ADOPTED",
   "00_PRODUCT/PRODUCT_BOUNDARIES.md", "application-separation directive"),
 "CAPABILITY_REGISTRY.md": ("SUPERSEDED",
   "08_VALIDATION/GENERATED_CAPABILITY_MATRIX.md",
   "hand-maintained registry replaced by generation from the runtime "
   "inventory — this is exactly the drift the gate now prevents"),
 "CAPABILITIES_HLD_LLD.md": ("ADOPTED",
   "00_PRODUCT/CAPABILITY_CATALOG.md", "514-line HLD/LLD"),
 "CAPABILITIES_SKELETON.md": ("SUPERSEDED",
   "00_PRODUCT/CAPABILITY_CATALOG.md", "earlier skeleton of the same"),
 "GA_BLOCKERS.md": ("ADOPTED", "08_VALIDATION/GA_READINESS_MATRIX.md",
   "P0 GA blocker list; must be reconciled against the reality baseline"),
 "MATURITY_ASSESSMENT_2026-09-02.md": ("ADOPTED",
   "00_PRODUCT/MATURITY_MODEL.md", "444-line maturity assessment"),
 "GOVERNANCE_RULES.md": ("ADOPTED",
   "04_DEVELOPMENT/CONTRIBUTION_RULES.md",
   "1039-line ARB rules — the largest single input to contribution rules"),
 "GOVERNANCE.md": ("ADOPTED", "04_DEVELOPMENT/CONTRIBUTION_RULES.md",
   "RC5 preservation + platform governance directive"),
 "MASTER_GATE.md": ("ADOPTED", "04_DEVELOPMENT/CONTRIBUTION_RULES.md",
   "binding master gate, read-first rules"),
 "CORPUS_VERSIONING.md": ("ADOPTED", "04_DEVELOPMENT/TESTING_GUIDE.md",
   "evidence benchmark discipline"),
 "evaluation_rubric.md": ("ADOPTED", "04_DEVELOPMENT/TESTING_GUIDE.md",
   "permanent payload evaluation rubric"),
 "DEVELOPING_V2.md": ("ADOPTED", "04_DEVELOPMENT/DEVELOPMENT_GUIDE.md",
   "contributor onboarding for v2"),
 "NIVXRAY_VISUAL_GRAMMAR.md": ("ADOPTED", "03_DESIGN/DESIGN_SYSTEM.md",
   "617-line locked visual grammar"),
 "VISUAL_LANGUAGE.md": ("ADOPTED", "03_DESIGN/DESIGN_SYSTEM.md",
   "514-line visual language system — must be reconciled with the "
   "visual grammar; two design authorities cannot both survive"),
 "NIVXRAY_ENTERPRISE_UX_GAP_ANALYSIS.md": ("ADOPTED",
   "03_DESIGN/INFORMATION_ARCHITECTURE.md", "enterprise UX gap analysis"),
 "ANALYST_WORKSPACE_BLUEPRINT.md": ("ADOPTED",
   "02_ARCHITECTURE/INVESTIGATION_ARCHITECTURE.md", "workspace blueprint"),
 "ANALYST_OPERATIONS_ARCHITECTURE.md": ("ADOPTED",
   "02_ARCHITECTURE/INCIDENT_ARCHITECTURE.md",
   "analyst operations phase-0 architecture"),
 "ANALYST_OPERATIONS_MANDATE.md": ("ADOPTED",
   "02_ARCHITECTURE/INCIDENT_ARCHITECTURE.md", "locked build mandate"),
 "WORKSPACE_USER_JOURNEY.md": ("ADOPTED",
   "06_USER_GUIDES/SOC_ANALYST_GUIDE.md", "workspace user journey"),
 "WORKSPACE_ARCHITECTURE_RULES.md": ("SUPERSEDED",
   "02_ARCHITECTURE/INVESTIGATION_ARCHITECTURE.md",
   "already self-declared superseded inside the file"),
 "WORKSPACE_VALIDATION_MATRIX.md": ("ADOPTED",
   "08_VALIDATION/E2E_ACCEPTANCE_MATRIX.md", "workspace validation package"),
 "IUE_ARCHITECTURE_V2.md": ("ADOPTED",
   "02_ARCHITECTURE/INVESTIGATION_ARCHITECTURE.md", "frozen IUE v2"),
 "IUE_ARCHITECTURE_TRACE.md": ("HISTORICAL_REFERENCE", "",
   "read-only track-A trace"),
 "IUE_INVESTIGATION_SSOT_RECONCILIATION.md": ("ADOPTED",
   "02_ARCHITECTURE/INVESTIGATION_ARCHITECTURE.md",
   "unresolved IUE/investigation SSOT authority question — carried "
   "forward as an open question, NOT silently closed"),
 "IVE_ARCHITECTURE.md": ("ADOPTED",
   "02_ARCHITECTURE/INVESTIGATION_ARCHITECTURE.md", "frozen IVE"),
 "BEE_ARCHITECTURE.md": ("ADOPTED",
   "02_ARCHITECTURE/SECURITY_STATE_CAUSAL_ARCHITECTURE.md",
   "frozen behaviour explanation engine"),
 "IDA_ARCHITECTURE.md": ("ADOPTED",
   "02_ARCHITECTURE/EVIDENCE_ARCHITECTURE.md",
   "frozen intelligent document analyzer"),
 "ARCHITECTURAL_DIRECTION_IEDDE.md": ("ADOPTED",
   "02_ARCHITECTURE/EVIDENCE_ARCHITECTURE.md", "ratified ARB direction"),
 "RC5_SEMANTIC_ENGINE_SPEC.md": ("ADOPTED",
   "02_ARCHITECTURE/DETECTION_ARCHITECTURE.md",
   "709-line semantic execution engine spec"),
 "RC5_PLUGIN_API.md": ("ADOPTED",
   "04_DEVELOPMENT/INTEGRATION_SDK_GUIDE.md", "frozen plugin API"),
 "RC5_EVIDENCE_GRAPH_ROADMAP.md": ("ADOPTED",
   "02_ARCHITECTURE/INVESTIGATION_ARCHITECTURE.md", "IKG roadmap"),
 "IR_REPORT_CONTRACT.md": ("ADOPTED",
   "02_ARCHITECTURE/INCIDENT_ARCHITECTURE.md", "frozen report contract"),
 "L1_INVESTIGATION_API_PLAYBOOK.md": ("ADOPTED",
   "04_DEVELOPMENT/API_GUIDE.md", "L1 investigation API playbook"),
 "lab-2.0-api-contract.md": ("ADOPTED", "04_DEVELOPMENT/API_GUIDE.md",
   "Lab 2.0 API governance artefact"),
 "lab-2.0-design-specification.md": ("ADOPTED",
   "03_DESIGN/PAGE_TEMPLATES.md", "541-line workspace design spec"),
 "MIGRATION_DEPENDENCIES.md": ("ADOPTED",
   "02_ARCHITECTURE/INTEGRATION_ARCHITECTURE.md",
   "what XDR must eventually own itself"),
 "REFERENCE_ADAPTATION.md": ("ADOPTED",
   "01_REFERENCE/CISCO_TO_NIVXRAY_MAPPING.md",
   "commercial EDR/XDR capabilities to adopt, not copy"),
 "NIVXFORGE_EDR_ROADMAP.md": ("ADOPTED", "09_RELEASE/LAB_VALIDATION_PLAN.md",
   "EDR-only track roadmap"),
 "NIVXFORGE_PLATFORM_VISION.md": ("ADOPTED",
   "00_PRODUCT/PRODUCT_VISION.md", "frozen platform vision"),
 "NORTH_STAR.md": ("ADOPTED", "00_PRODUCT/PRODUCT_VISION.md",
   "aspirational north star — explicitly not a roadmap"),
 "NORTH_STAR_PRODUCT_GOAL.md": ("ADOPTED", "00_PRODUCT/PRODUCT_VISION.md",
   "adopted product goal"),
 "PRODUCT_CHARTER.md": ("ADOPTED", "00_PRODUCT/PRODUCT_VISION.md",
   "product charter + v1.6.0 roadmap"),
 "PLATFORM_POSITIONING.md": ("ADOPTED", "00_PRODUCT/PRODUCT_BOUNDARIES.md",
   "NivXForge vs Workspace positioning"),
 "NivXRay_Strategic_Master_Positioning.md": ("ADOPTED",
   "00_PRODUCT/PRODUCT_VISION.md", "1164-line locked positioning"),
 "VISION_ENTERPRISE_INTEGRATION.md": ("ADOPTED",
   "02_ARCHITECTURE/INTEGRATION_ARCHITECTURE.md",
   "enterprise integration vision and scope"),
 "REASONING_ENGINE_VISION.md": ("ADOPTED",
   "02_ARCHITECTURE/SECURITY_STATE_CAUSAL_ARCHITECTURE.md",
   "analyst reasoning vision"),
 "AUTONOMOUS_INVESTIGATION.md": ("ADOPTED",
   "02_ARCHITECTURE/INVESTIGATION_ARCHITECTURE.md",
   "autonomous investigation operating model"),
 "PHASE4_ORCHESTRATION_SPEC.md": ("ADOPTED",
   "02_ARCHITECTURE/AUTOMATION_ARCHITECTURE.md",
   "auto-investigation orchestration preview spec"),
 "OPERATIONAL_LOOP.md": ("ADOPTED", "05_OPERATIONS/OBSERVABILITY_GUIDE.md",
   "standing operational feedback loop"),
 "OFFLINE_LLM_DEPLOYMENT.md": ("ADOPTED",
   "05_OPERATIONS/DEPLOYMENT_GUIDE.md", "offline LLM deployment"),
 "DEPLOYMENT_EVIDENCE.md": ("HISTORICAL_REFERENCE", "",
   "RC2.0 deployment evidence pack"),
 "P0_2C_ALIAS_SITE_SWEEP.md": ("ADOPTED",
   "02_ARCHITECTURE/EVIDENCE_ARCHITECTURE.md",
   "the endpoint-identity invariant — the reference pattern for every "
   "future platform invariant"),
 "P0_2_EDR_RESPONSE_SURFACE.md": ("ADOPTED",
   "02_ARCHITECTURE/RESPONSE_ARCHITECTURE.md", "EDR response surface"),
 "STEP2_RESPONSE_SERVICE_DEPLOY.md": ("ADOPTED",
   "02_ARCHITECTURE/RESPONSE_ARCHITECTURE.md", "response service deploy"),
 "STEP1_WORKLOG_ADOPTION_CHECK.md": ("ADOPTED",
   "02_ARCHITECTURE/INCIDENT_ARCHITECTURE.md",
   "worklog SSOT decision: incident_state_history is the only worklog"),
 "UNIVERSAL_DECODER_COVERAGE_MATRIX.md": ("ADOPTED",
   "04_DEVELOPMENT/DETECTION_CONTENT_GUIDE.md", "decoder coverage"),
 "UNIVERSAL_DECODER_LICENSE_MATRIX.md": ("ADOPTED",
   "04_DEVELOPMENT/DETECTION_CONTENT_GUIDE.md", "decoder licensing"),
 "UNIVERSAL_DECODER_SOURCE_INVENTORY.md": ("ADOPTED",
   "04_DEVELOPMENT/DETECTION_CONTENT_GUIDE.md", "decoder sources"),
 "P0_1B_SCOPE.md": ("ADOPTED",
   "04_DEVELOPMENT/DETECTION_CONTENT_GUIDE.md", "deobfuscation scope"),
 "NIVXRAY_CURRENT_STATE_TRUTH.md": ("SUPERSEDED",
   "08_VALIDATION/REALITY_MATRIX.md",
   "hand-written current-state truth audit — now generated, so it can "
   "no longer drift"),
 "CURRENT_STATE_AUDIT.md": ("SUPERSEDED",
   "08_VALIDATION/REALITY_MATRIX.md", "605-line hand audit (2026-02)"),
 "CURRENT_STATE_AUDIT_RECONCILIATION.md": ("SUPERSEDED",
   "08_VALIDATION/REALITY_MATRIX.md", "audit reconciliation (2026-08)"),
 "NIVXRAY_XDR_360_AUDIT.md": ("SUPERSEDED",
   "08_VALIDATION/REALITY_MATRIX.md", "360 production-readiness audit"),
 "NivXRay_360_Evidence_Matrix.md": ("SUPERSEDED",
   "08_VALIDATION/REQUIREMENTS_TRACEABILITY_MATRIX.md",
   "flat citation table of capability evidence"),
 "NIVXRAY_CT_SCAN_REVIEW.md": ("HISTORICAL_REFERENCE", "",
   "honest CT-scan review, v1.3.0-preview"),
 "NivXRay_360_Audit_Spec.md": ("HISTORICAL_REFERENCE", "",
   "audit execution brief"),
 "RC4.5_ARCHITECTURE_AUDIT.md": ("HISTORICAL_REFERENCE", "",
   "729-line RC4.5 architecture + capability audit"),
 "ENGINES_UI_PERF.md": ("ADOPTED",
   "08_VALIDATION/PERFORMANCE_MATRIX.md", "engines/UI/perf/security notes"),
 "V1_6_0_BASELINE_METRICS.md": ("ADOPTED",
   "08_VALIDATION/PERFORMANCE_MATRIX.md", "captured baseline metrics"),
 "RC4.6_PIPELINE_PERF_INVESTIGATION.md": ("ADOPTED",
   "08_VALIDATION/PERFORMANCE_MATRIX.md", "pipeline perf investigation"),
 "ROADMAP.md": ("OPERATIONAL", "09_RELEASE/LAB_VALIDATION_PLAN.md",
   "1462-line live roadmap — stays live until the release plans absorb it"),
 "IMPLEMENTATION_ROADMAP.md": ("OPERATIONAL",
   "09_RELEASE/LAB_VALIDATION_PLAN.md", "active NivXForge roadmap"),
 "BACKLOG.md": ("OPERATIONAL", "", "post-v1.5.7 backlog"),
 "REMINDERS.md": ("OPERATIONAL", "", "durable pending-work ledger"),
 "DECISION_LOG.md": ("OPERATIONAL", "", "chronological decision index — "
   "remains the index of record"),
 "PRD.md": ("OPERATIONAL", "", "12209-line master requirements + progress "
   "log; the live working document for this programme"),
 "CHANGELOG.md": ("OPERATIONAL", "", "7292-line release history"),
 "test_credentials.md": ("OPERATIONAL", "", "live test credentials"),
 "agent_learnings.md": ("OPERATIONAL", "", "agent learnings"),
 "REAL_WORLD_LOG.md": ("OPERATIONAL", "", "real SOC case log"),
 "RESEARCH_REFERENCES.md": ("ADOPTED", "01_REFERENCE/SOURCE_REGISTER.md",
   "saved research sources"),
 "MASTER_GATE.md.": ("HISTORICAL_REFERENCE", "", ""),
 "FUNDRAISING_PACK.md": ("HISTORICAL_REFERENCE", "",
   "commercial, out of scope for the engineering tree"),
 "LAUNCH_CONTENT_PACK.md": ("HISTORICAL_REFERENCE", "", "marketing copy"),
 "NivXRay_Investor_Due_Diligence.md": ("HISTORICAL_REFERENCE", "",
   "self-declared superseded"),
 "NivXRay_360_Product_Market_Posture.md": ("HISTORICAL_REFERENCE", "",
   "1171-line market posture, commercial"),
 "NIVXMACHINES_REDIRECT_FIX_HANDOFF.md": ("HISTORICAL_REFERENCE", "",
   "unrelated website SEO task"),
 "WAKE_UP_REMINDER.md": ("HISTORICAL_REFERENCE", "", "session note"),
 "DEMO_PAYLOAD_BATTERY.md": ("ADOPTED", "04_DEVELOPMENT/TESTING_GUIDE.md",
   "demo payload battery — TEST-ONLY, must never seed the operational "
   "environment"),
 "GOLDEN_CASE_SAMPLE1.md": ("ADOPTED", "04_DEVELOPMENT/TESTING_GUIDE.md",
   "golden diagnostic case"),
 "LLM_TRAINING_SCHEMA.md": ("HISTORICAL_REFERENCE", "",
   "LLM fine-tune schema"),
 "DESIGN_NIVXFORGE_ANALYST_PLATFORM.md": ("ADOPTED",
   "00_PRODUCT/PRODUCT_BOUNDARIES.md", "design memo, awaiting decision"),
 "SPRINT_1_CHECKPOINT.md": ("HISTORICAL_REFERENCE", "", "sprint checkpoint"),
 "PHASE0_COMPLETION.md": ("HISTORICAL_REFERENCE", "",
   "permanent audit record, do not edit"),
 "P0_MISSION.md": ("HISTORICAL_REFERENCE", "", "locked X-LAB P0 mission"),
 "P0_P1_BUG_BASELINE.md": ("HISTORICAL_REFERENCE", "",
   "pre-migration bug baseline"),
 "xlab_parity_audit.md": ("HISTORICAL_REFERENCE", "",
   "X-Lab capability parity audit"),
 "COCKPIT_AUDIT_R44.md": ("ADOPTED",
   "03_DESIGN/INFORMATION_ARCHITECTURE.md", "incident cockpit UX audit"),
 "LAYER2_QUEUE_REBUILD_MANDATE.md": ("ADOPTED",
   "03_DESIGN/INFORMATION_ARCHITECTURE.md", "incident queue rebuild mandate"),
 "LAYER2_FINAL_EXECUTION_CONTRACT.md": ("HISTORICAL_REFERENCE", "",
   "layer 2 execution contract"),
 "Y1_STATUS_REPORT.md": ("ADOPTED", "03_DESIGN/NAVIGATION_SPEC.md",
   "product separation + rail information architecture — the origin of "
   "the shipped 8-primary rail"),
 "EVIDENCE_INVENTORY_2026-02-28.md": ("HISTORICAL_REFERENCE", "",
   "point-in-time evidence inventory"),
 "PR_2_1_2_DIRECTIVE.md": ("HISTORICAL_REFERENCE", "", "ARB directive"),
 "phase-0-parity-guard-report.md": ("HISTORICAL_REFERENCE", "",
   "parity guard completion"),
 "_archive_ARCHITECTURAL_DIRECTION_ICUE_superseded.md":
   ("HISTORICAL_REFERENCE", "", "already archived and self-superseded"),
}

# rule-based classification for the remainder
RULES = [
 (re.compile(r"^RC\d|^RELEASE_NOTES|^CHECKPOINT|_COMPLIANCE\.md$|"
             r"^STEP\d.*REPORT|^DIAGNOSTIC_|^DOCX_|^V1_6_0_PLANNING|"
             r"^v1\.\d|^NivXRay_Stage1_"),
  "HISTORICAL_REFERENCE", "",
  "point-in-time release/phase/diagnostic record — retained unedited"),
]


def classify(name: str):
    if name in MAP:
        return MAP[name]
    for rx, cls, tgt, note in RULES:
        if rx.search(name):
            return (cls, tgt, note)
    return ("HISTORICAL_REFERENCE", "",
            "not yet individually reviewed — retained; raise if it holds a "
            "live decision")


def main() -> None:
    files = sorted(p.name for p in MEMORY.glob("*.md"))
    rows = [(f, *classify(f)) for f in files]
    counts: dict[str, int] = {}
    for _, c, _, _ in rows:
        counts[c] = counts.get(c, 0) + 1

    L = [f"""<!-- NIVX-DOC
layer: HISTORICAL_RECORD
status: GENERATED
generated_by: scripts/docs_provenance.py
generated_at: {STAMP}
-->

# DOC PROVENANCE LEDGER

Every pre-existing document under `/app/memory/` reconciled against the
authoritative tree at `/app/docs/nivxray-xdr/`. **{len(files)} documents.**

**Nothing is deleted.** A `SUPERSEDED` document keeps its content and
gains a `SUPERSEDED_BY:` pointer. An `ADOPTED` document's decisions are
carried into the named authoritative document; the original is retained
as the provenance record of *when and why* the decision was made.

> Why this matters: `/app/memory/CAPABILITY_REGISTRY.md` was a
> hand-maintained capability list that had drifted from the runtime
> inventory. That is precisely the failure mode the generated matrix plus
> the reconciliation gate now make impossible. The ledger exists so that
> replacing it does not lose the reasoning that produced it.

## Classification

| Class | Count | Meaning |
|---|---:|---|
| `ADOPTED` | {counts.get('ADOPTED', 0)} | content becomes part of an authoritative document |
| `SUPERSEDED` | {counts.get('SUPERSEDED', 0)} | replaced — usually by a GENERATED document that cannot drift |
| `OPERATIONAL` | {counts.get('OPERATIONAL', 0)} | still live working state; not documentation |
| `HISTORICAL_REFERENCE` | {counts.get('HISTORICAL_REFERENCE', 0)} | point-in-time record, retained, never edited |

## Ledger

| Legacy document | Class | Absorbed into | Note |
|---|---|---|---|"""]
    for f, cls, tgt, note in rows:
        L.append(f"| `memory/{f}` | `{cls}` | "
                 f"{'`' + tgt + '`' if tgt else '—'} | {note} |")
    L += ["", "## Open reconciliation risks", "",
          "1. **Two design authorities.** `NIVXRAY_VISUAL_GRAMMAR.md` (617 "
          "lines) and `VISUAL_LANGUAGE.md` (514 lines) are both ADOPTED "
          "into `03_DESIGN/DESIGN_SYSTEM.md`. They have never been "
          "diffed. One must become authoritative.",
          "2. **Three architecture documents.** `ARCHITECTURE.md`, "
          "`ARCHITECTURE_v2.md` and `NIVXRAY_ARCHITECTURE_V1.md` describe "
          "overlapping but different systems. v2 is the richest source; "
          "V1 is frozen and still load-bearing for IUE lineage.",
          "3. **Three governance documents.** `GOVERNANCE_RULES.md`, "
          "`GOVERNANCE.md` and `MASTER_GATE.md` all assert binding rules.",
          "4. **An unresolved SSOT question is carried forward, not "
          "closed.** `IUE_INVESTIGATION_SSOT_RECONCILIATION.md` leaves the "
          "investigation authority question open; it is now recorded as an "
          "explicit unresolved question in "
          "`02_ARCHITECTURE/INVESTIGATION_ARCHITECTURE.md` rather than "
          "quietly dropped.",
          "5. **Two live roadmaps.** `ROADMAP.md` (1462 lines) and "
          "`IMPLEMENTATION_ROADMAP.md` both claim to be active. Both stay "
          "OPERATIONAL until `09_RELEASE/` absorbs them.",
          "6. **Test-only corpora must never leak.** "
          "`DEMO_PAYLOAD_BATTERY.md` and `GOLDEN_CASE_SAMPLE1.md` are "
          "adopted into the testing guide explicitly as TEST-ONLY. The "
          "operational environment defaults to real evidence only.", ""]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(L))
    print(f"ledger written · {len(files)} documents · {counts}")

    # stamp SUPERSEDED_BY pointers into the legacy files (non-destructive)
    n = 0
    for f, cls, tgt, _ in rows:
        if cls != "SUPERSEDED" or not tgt:
            continue
        p = MEMORY / f
        txt = p.read_text()
        if "SUPERSEDED_BY:" in txt:
            continue
        p.write_text(f"> **SUPERSEDED_BY:** `docs/nivxray-xdr/{tgt}` "
                     f"(P-1 documentation reconciliation, {STAMP}). "
                     f"Retained for provenance; do not edit.\n\n" + txt)
        n += 1
    print(f"SUPERSEDED_BY pointers added: {n}")


if __name__ == "__main__":
    main()
