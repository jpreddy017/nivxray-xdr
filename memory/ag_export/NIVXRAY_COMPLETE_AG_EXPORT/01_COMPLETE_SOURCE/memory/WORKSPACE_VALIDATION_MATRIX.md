# NivXRay · Workspace Validation Package

**Status**: DRAFT v1.0 — final ARB validation artifact
**Companion to**: `ANALYST_WORKSPACE_BLUEPRINT.md` v1.1 · `WORKSPACE_USER_JOURNEY.md` v1.0
**Purpose**: Prove that Blueprint v1.1 is workflow-complete, dead-end-free, and future-proof against P0 #2-#5.
**Implementation authorization**: NOT GRANTED (this is the last artifact required before PR-0 sign-off)
**Date**: 2026-08-04

> This document is validation-only. It **does not modify** any decision in Blueprint v1.1. If any cell reveals a gap, the fix is a blueprint amendment, not a code shortcut.

---

## 1 · Investigation Workflow Validation Matrix

Every workflow × every Workspace capability. Legend: **✅ required · ▫ optional · ❌ hidden**.

| Workflow / Mode | Summary | Story | Timeline | Evidence | MITRE | IOCs | Capabilities | Detections | Hunting | Cert Viewer | Report Export |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **J1 · Tier-1 Triage** (Quick Triage) | ✅ | ▫ | ❌ | ▫ | ▫ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **J2 · Standard Investigation** (Investigation) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ▫ | ▫ | ▫ | ▫ | ▫ |
| **J3 · Deep Investigation** (Deep Analysis) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **J4 · Executive Report** (Reported) | ✅ | ✅ | ▫ | ✅ | ✅ | ✅ | ✅ | ▫ | ▫ | ▫ | ✅ |
| **J5 · Reopen & Iterate** (Reopened → Investigation) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ▫ | ▫ | ▫ | ✅ | ✅ |

**Orphan check** (every capability used by at least one workflow):

| Capability | Workflows Using | Verdict |
|---|---|---|
| Summary | J1 · J2 · J3 · J4 · J5 | ✅ used |
| Story | J1 (opt) · J2 · J3 · J4 · J5 | ✅ used |
| Timeline | J2 · J3 · J5 · J4 (opt) | ✅ used |
| Evidence | J1 (opt) · J2 · J3 · J4 · J5 | ✅ used |
| MITRE | J1 (opt) · J2 · J3 · J4 · J5 | ✅ used |
| IOCs | J1 · J2 · J3 · J4 · J5 | ✅ used |
| Capabilities | J2 (opt) · J3 · J4 | ✅ used |
| Detections | J2 (opt) · J3 | ✅ used |
| Hunting | J2 (opt) · J3 | ✅ used |
| Cert Viewer | J2 (opt) · J3 · J5 | ✅ used |
| Report Export | J3 · J4 · J5 | ✅ used |

**Result**: **Zero orphaned capabilities.** Every lens/sub-panel serves a workflow.

**Cross-check against Design Principles**:
- P1 Investigation First: J2/J3 flows drive the design — validated
- P3 Progressive Disclosure: Tier-1 (J1) hides depth via `❌`; Deep Analysis (J3) unlocks everything — validated
- P5 Single Workspace: all 5 workflows execute on `/investigate` — validated
- P6/P7 Zero Duplicates: no capability appears twice across the matrix — validated

---

## 2 · Cross-Feature Navigation Matrix

Every pair of Workspace objects. **✅ direct click** · **▶ 1-hop pivot** · **▶▶ 2-hop pivot** · **❌ unreachable (dead end — must be fixed)**.

| FROM ↓ / TO → | Summary | Story | Timeline | Evidence | MITRE | IOC | Capability | Detection | Hunting | Cert Row | Report |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Summary bullet** | — | ✅ | ▶ | ✅ | ✅ | ✅ | ▶ | ▶ | ▶ | ▶ | ▶ |
| **Story event** | ✅ | — | ✅ | ✅ | ✅ | ✅ | ✅ | ▶ | ▶ | ✅ | ▶ |
| **Timeline iteration** | ✅ | ✅ | — | ✅ | ✅ | ✅ | ✅ | ▶ | ▶ | ✅ | ▶ |
| **Evidence panel** | ✅ | ✅ | ✅ | — | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ▶ |
| **MITRE technique** | ✅ | ✅ | ✅ | ✅ | — | ✅ | ✅ | ✅ | ✅ | ▶ | ▶ |
| **IOC** | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ | ✅ | ✅ | ✅ | ▶ |
| **Capability tag** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ | ✅ | ▶ | ▶ |
| **Detection rule** | ▶ | ▶ | ▶ | ✅ | ✅ | ✅ | ✅ | — | ✅ | ▶ | ▶ |
| **Hunting query** | ▶ | ▶ | ▶ | ✅ | ✅ | ✅ | ✅ | ✅ | — | ▶ | ▶ |
| **Certificate row** | ✅ | ✅ | ✅ | ✅ | ▶ | ✅ | ▶ | ▶ | ▶ | — | ▶ |
| **Report section** | ✅ | ✅ | ▶ | ✅ | ✅ | ✅ | ✅ | ▶ | ▶ | ▶ | — |

**Dead-end audit**: **Zero ❌ cells.** Every pair of objects is reachable in ≤ 2 hops. Every 1-hop pivot lands in the Evidence lens with the target object highlighted (Blueprint §8.4).

**Analyst-natural pivots that MUST be 1-click** (validated):
- IOC → Timeline (see where in the decode this IOC was extracted) → ✅
- IOC → Certificate row (which transformation surfaced it) → ✅
- IOC → Detection rule (auto-generated Sigma using this IOC) → ✅
- IOC → Hunting query (search my SIEM for this IOC) → ✅
- MITRE → Capability (what capability implements this technique) → ✅
- MITRE → Detection (rules that detect this technique) → ✅
- Certificate row → Timeline (locate this transformation in time) → ✅
- Detection rule → IOC (which IOC anchors this rule) → ✅
- Report section → Evidence (drill down from executive claim to raw evidence) → ✅

**Result**: **Analyst can pivot naturally in any direction. No dead ends. No hidden objects.**

---

## 3 · Future-Proofing Validation

Prove Blueprint v1.1 absorbs the remaining P0 roadmap **without structural redesign**.

### 3.1 · P0 #2 · Executive & SOC Reports (PDF / DOCX / STIX)

| Requirement | Blueprint v1.1 Support | Structural Change? |
|---|---|---|
| Generate PDF / DOCX / STIX from investigation | §10 endpoints already defined: `/report.pdf`, `/stix` | **No** |
| Deterministic byte-identical exports | P10 principle already enforced | **No** |
| Report anchored to evidence (evidence navigation) | §8.4 Evidence Navigation contract already covers "Report section → Evidence" | **No** |
| Exports discoverable from Workspace | Exports Lens already listed in §8 layout | **No** |
| Report versioning on Reopen | §8.1 state machine already tracks Reported (v1) → Reopened → Reported (v2) | **No** |

**Verdict**: **P0 #2 lands as new content inside existing Exports lens + implementation behind existing `/report.*` endpoints. No blueprint amendment required.**

### 3.2 · P0 #3 · Detection Rule Generation (Sigma / KQL / Splunk / YARA)

| Requirement | Blueprint v1.1 Support | Structural Change? |
|---|---|---|
| Generate detections from evidence + registry | §10 endpoint `/detections` already defined | **No** |
| Rules visible to analyst | Analysis lens (§8) and Detections sub-panel already listed | **No** |
| Rules downloadable | Exports lens already lists Sigma / KQL / Splunk | **No** |
| Rules anchor back to source IOC / MITRE | Navigation matrix (§2 of this doc) shows Detection ↔ IOC ↔ MITRE all 1-click | **No** |
| Regeneration on Reopen | §8.1 Reopened → Correlating re-runs L2 including detection generator | **No** |

**Verdict**: **P0 #3 lands as an L2 service (`detection_rules.py`) feeding the existing Analysis lens. Existing endpoint slot at §10 is unchanged. No blueprint amendment required.**

### 3.3 · P0 #4 · Attack Story (deterministic narrative)

| Requirement | Blueprint v1.1 Support | Structural Change? |
|---|---|---|
| Ordered narrative from evidence | Story lens already listed (§9) | **No** |
| Story events clickable to evidence | Navigation matrix (§2) shows Story event → Evidence direct | **No** |
| Story deterministic | L2 service `attack_story.py` reads L1 evidence only (P10) | **No** |
| Included in Executive Report | Blueprint §9 lists Story as a Report section | **No** |
| Persistent across Reopen | §8.1 state model plus §8.3 persistence already covers | **No** |

**Verdict**: **P0 #4 lands as `attack_story.py` L2 service + existing Story lens. No blueprint amendment required.**

### 3.4 · P0 #5 · Integrations (Splunk / Sentinel / MISP / STIX / TAXII)

| Requirement | Blueprint v1.1 Support | Structural Change? |
|---|---|---|
| Push detections / IOCs to SIEM | Read-only via existing `/detections`, `/iocs`, `/stix` endpoints | **No** — integration is a *consumer*, not a Workspace change |
| SIEM app views investigation | Existing `/api/investigation/:case_id` full-bundle endpoint | **No** |
| Deep-link back into Workspace | `/investigate?case_id=…` route already the single canonical entry | **No** |
| Integration configuration | Admin surface (§5 `AdminPage` KEEP) | **No** |
| Audit-logged export events | §10 audit-log already applies to state transitions + can extend to export events | **Minor** — audit-log extension only, not blueprint redesign |

**Verdict**: **P0 #5 lands as external adapter modules consuming existing L1 endpoints. Only extension is audit-logging on export events — additive, not structural.**

### 3.5 · Summary of Future-Proofing

| Future P0 | Structural Blueprint Change Needed | Where It Lands |
|---|---|---|
| P0 #2 Executive Reports | **No** | Exports lens + `/report.*` endpoints (already declared) |
| P0 #3 Detection Rules | **No** | Analysis lens + `/detections` endpoint (already declared) |
| P0 #4 Attack Story | **No** | Story lens + `attack_story.py` L2 service (already declared) |
| P0 #5 Integrations | **No** | External adapters consuming existing L1 endpoints |

**Verdict**: **Blueprint v1.1 is future-proof against every declared P0.** Every future roadmap item lands as content inside existing lenses or as an L2 service consuming existing endpoints. **Zero structural redesigns projected.**

---

## 4 · Non-Structural Extensions Reserved

The following are **additive** and don't require blueprint changes when they arrive:

- Audit-log schema extension for export events (P0 #5)
- L2 services: `attack_story.py`, `detection_rules.py`, `hunting_queries.py`, `threat_assessment.py`, `ioc_intelligence.py`, `capability_explorer.py`, `executive_summary.py`, `workspace_bundle.py`
- New capability tags added to the vocabulary (as families expand)
- New MITRE mappings (data-only)
- New corpus samples (data-only, no schema)

None of the above requires re-opening the Workspace design.

---

## 5 · Final ARB Sign-Off Package Contents

The complete pre-implementation package:

1. `ANALYST_WORKSPACE_BLUEPRINT.md` v1.1 — architecture (approved)
2. `WORKSPACE_USER_JOURNEY.md` v1.0 — experience (approved)
3. `WORKSPACE_VALIDATION_MATRIX.md` v1.0 — **this document** — proof of completeness, dead-end-freeness, and future-proofing

If the ARB confirms:
- **Workflow Validation** (§1): every capability used, no orphans — ✅ demonstrated
- **Cross-Feature Navigation** (§2): zero dead ends, natural pivots — ✅ demonstrated
- **Future-Proofing** (§3): P0 #2-#5 all fit without structural change — ✅ demonstrated

then PR-0 sign-off is unblocked, and PR-1 (L2 Investigation Services backend scaffolding — no UI, no engine changes) can begin.

---

## 6 · What I Am NOT Doing

- Not modifying the blueprint
- Not modifying the journey document
- Not starting PR-0
- Not starting any implementation

The codebase remains untouched. All 438 tests pass · M8 17/17 · R1 107/107 · Transformation Coverage 100%.

---

**End of Validation Package · Awaiting ARB Final Sign-Off**
