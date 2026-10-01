# NivXRay XDR · Master Architecture Conformance Audit — Addendum · Owner Correction

> **Basis:** Owner correction to §7 of `NIVXRAY_XDR_MASTER_ARCHITECTURE_CONFORMANCE_AUDIT.md`.
> **Mode:** STRICT READ-ONLY.  No code / test / config / UI / Mongo mutation.
> **Product:** NivXRay XDR.

---

## 1 · Correction to §7 (single-gap framing was over-optimistic)

The audit's §7 stated:

> "The gap is NOT architectural. It is a runtime-pipeline instantiation gap. Once the closed loop is proven for one source, the same architecture handles the rest."

This is **partially correct but too optimistic.** The audit itself surfaces evidence of **three distinct gaps**, not one:

### Gap A · Core reasoning pipeline proof
```
Source → Parser → Normalizer → Canonical Evidence → IUE → ICE → IKG → VEEE
                                                                     → Security State
                                                                     → Investigation SSOT
                                                                     → Attack Story / ATT&CK
```
Closed by a canonical-evidence smoke test with full traceability across the chain.

### Gap B · Real XDR source integrations
```
MDE · CrowdStrike · SentinelOne · Cisco SEP · NDR · Email ·
Identity · Cloud · SaaS · DNS · Proxy · Firewall · SIEM · Sandbox
```
These 14 sources are `TARGET` or `SCAFFOLD` in the coverage matrix. **NOT closed by any single smoke test.** Each requires its own connector/collector/parser/normalizer path even though they all consume the same canonical evidence contract downstream.

### Gap C · Behavioral / XDR-UBAE runtime
```
Entity → Behavior → Baseline → Anomaly → Abuse → Compromise
```
- `behaviors` = 0, `behavior_baselines` = 0, no `/api/ubae/*` router surface
- Classification: `TARGET` — NOT closed by proving the reasoning pipeline

## 2 · Corrected §7 wording (this addendum supersedes the audit's §7)

> **NivXRay XDR IS still becoming the complete unified XDR we designed. The architecture is intact. But the audit reveals THREE separate gaps that must each be closed with distinct proof:**
>
> **Gap A · Core reasoning pipeline** — closed by end-to-end canonical-evidence smoke test with full chain traceability (source → parser → normalizer → canonical_evidence → IUE → ICE → IKG → VEEE → Security State → Investigation SSOT → Attack Story → ATT&CK). Prove using entity/evidence-ID traceability across every stage.
>
> **Gap B · Real XDR source integrations** — closed only by instantiating and proving each vendor/telemetry connector (MDE, CrowdStrike, SentinelOne, Cisco SEP, NDR, Email, Identity/ITDR, Cloud AWS/Azure/GCP, SaaS M365, DNS, Proxy, Firewall, SIEM, Sandbox).
>
> **Gap C · Behavioral / UBAE runtime** — closed only by populating `behaviors` and `behavior_baselines` from real evidence, exposing the `BASELINE → ANOMALY → ABUSE → COMPROMISE` FSM, and integrating with IKG + Security State + Reachability + Verdict.
>
> One Sysmon smoke test proves Gap A. It does **NOT** prove NivXRay XDR is a fully integrated enterprise XDR. That distinction is what separates "a very good investigation engine" from "an XDR."

## 3 · Revised acceptance test for the canonical-evidence smoke test

Replace the audit's §8.1 proposal with this stronger version:

```
1. Real Sysmon event ingested via /api/xdr/collector/connectors (kind=sysmon_wef)
2. Parser produces a normalized event with entity_ids, timestamps, provenance
3. Normalizer emits at least one canonical_evidence document
   → verify canonical_evidence.count() > 0
4. IUE processes the evidence
   → verify IUE output records reference the same evidence_id
5. ICE correlates the evidence
   → verify ICE output records reference the same evidence_id + entity_ids
6. IKG populates at least one node + one edge
   → verify ikg_nodes.count() >= 1 AND ikg_edges.count() >= 1
   → verify the node.id / edge.src / edge.dst reference the same entity_ids
7. VEEE / Verdict engine produces a stage2 verdict
   → verify workspace_cases.verdict_stage2.evidence contains the same evidence_id
8. Security State evaluates the case
   → verify /api/v2/security-state/{case_id} returns state
   → verify the state.entity_refs reference the same entity_ids
9. Investigation SSOT is written
   → verify investigation_ssot document exists for the case
10. Attack Story projection includes the ATT&CK technique
    → verify /api/incidents/{case_id}/attack-story references the same technique
11. UI /xdr/investigations/{case_id} 8-tab shows real state on every tab
    → Attack Story, Device Trajectory, Process Ancestry, Evidence Graph, Security State, Extracted Artifacts, Deterministic Verdict, MITRE ATT&CK

ACCEPTANCE: The same evidence_id / entity_ids / relationships remain
            traceable end-to-end without silent loss.
```

## 4 · Then Source #2 (proves source-independence)

After the Sysmon smoke test passes:

```
Source #2 candidate: file_ingest (artifact) OR windows_security_events

Prove:
   Source A ──┐
              ├──> Same canonical_evidence schema
              ├──> Same IUE/ICE/IKG/VEEE downstream
              ├──> Same Security State / Investigation / Response flow
   Source B ──┘

This proves canonical evidence is source-independent, which is the
architectural invariant of the model.
```

## 5 · Revised execution order (supersedes audit §8)

The audit listed 4 next moves. Per owner correction the ordered execution should be:

1. **Save to GitHub** (Step 1) — immutable checkpoint of alignment branch + all audit artifacts + Stage 3 evidence + honest-state repairs, BEFORE touching any code that could break something.
2. **Fix `/api/v2/cases` ObjectId serialization** (Step 2) — one-line stringify, unblocks 29 real docs. Must happen BEFORE canonical smoke test so that we don't confuse API-500 with EVIDENCE-absence during interpretation.
3. **Canonical Evidence Smoke Test (Sysmon)** with the strengthened acceptance criteria from §3 above (Step 3).
4. **Source #2 (file_ingest or windows_security_events)** — proves source-independence (Step 4).
5. **XDR Source Integration Matrix build-out** — MDE, CrowdStrike, SentinelOne, Cisco SEP, NDR, Email, Identity, Cloud, SaaS, DNS, Proxy, Firewall, SIEM connectors, each following the same CONNECTOR → COLLECTOR → PARSER → NORMALIZER → CANONICAL EVIDENCE contract (Step 5).
6. **UBAE first-class promotion** — ONLY after the pipeline is proven populating `behaviors` and `behavior_baselines`. Otherwise we risk building an API surface around an unpopulated data model (Step 6).
7. **Sandbox runtime plane** — differentiator ADD-01 §1, once infrastructure available; interface + orchestration + evidence contracts land regardless (Step 7).

## 6 · Updated conformance stance per gap

| Gap | Status | Closes when |
| :--: | ------ | ----------- |
| A · Core reasoning pipeline | 🟠 Un-proven live | Sysmon smoke test with full chain traceability passes |
| B · Real XDR source integrations | 🔴 12 declared / 0 instantiated / 4 vendors TARGET | Each connector proves the same canonical-evidence path (5-10 vendors) |
| C · Behavioral / UBAE runtime | 🔴 TARGET | Behaviors + baselines populated from real evidence; UBAE FSM exposed and integrated |

**All three gaps are runtime-instantiation gaps, not architectural gaps.** No architectural rework is required. What is required is disciplined pipeline activation.

## 7 · Intelligence-layer clarification

Owner also emphasized: OSINT + LOLBAS + MITRE + YARA + IOC are NOT standalone menu items. They must **enrich the evidence/intelligence layer** and become usable during investigation, per the original NivXRay concept.

Current audit read shows:
- MITRE: `IMPLEMENTED_AND_PROVEN` — Emergent authoritative store; techniques observed on real R-numbered cases.
- OSINT: `IMPLEMENTED_NOT_FULLY_PROVEN` — 5 live paths, providers wired.
- LOLBAS: `IMPLEMENTED_NOT_FULLY_PROVEN` — 18 live paths.
- YARA: `PARTIAL` — 1 live path (case-scoped); no `yara_rules` corpus loaded.
- IOC: `IMPLEMENTED_NOT_FULLY_PROVEN` — 8 live paths.

The gap is not their existence — it's whether they surface as **enrichment during investigation**, i.e. whether the 8-tab workspace shows LOLBAS matches, OSINT enrichments, YARA hits, IOC hits alongside the analyst's evidence view. That is a Step-3 UI-wiring outcome once the canonical-evidence pipeline provides them.

## 8 · Invariants respected (this addendum)

- ✅ No code / test / config / UI / Mongo modified.
- ✅ Preservation tag `preserve-pre-alignment-2026-09-05` intact.
- ✅ Truth Contract v1/v2/v3 unamended. Master audit and this addendum are new immutable artifacts.
- ✅ `mal-20` untouched.
- ✅ Product name **NivXRay XDR** used consistently.
- ✅ No architectural rework proposed. The design stands.

## END · Owner-correction addendum · read-only · awaiting authorization for the revised Step 1–7 sequence
