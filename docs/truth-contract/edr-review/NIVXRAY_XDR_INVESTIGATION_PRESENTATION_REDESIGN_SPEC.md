# NivXRay XDR · INVESTIGATION PRESENTATION REDESIGN · SPECIFICATION

> **STATUS: SPECIFICATION ONLY. No production UI modified. No engine, IKG, correlation, canonical evidence, 615-content corpus, decoder, Security State or backfill touched.**
> Owner rejected the current Activity Graph / Attack Chain presentation (2026-09-05). This is a **UX-layer redesign**; the underlying capability stays exactly where it is.
> **STOP for owner review before any production UI change.**

---

## 1 · Accepted diagnosis

| Defect | Why it matters |
|---|---|
| Reads as a graph-engine/debug view, not an investigation experience | `INC/USR/EVT/PRC/SIG/CMD/HST` are internal IKG node classes leaking into the analyst surface |
| Glowing arrows imply confirmed causality while the caption says correlation never implies causality | **The most serious defect: the visual language contradicts the product's own epistemic contract** |
| Empty right inspector | Selection produces nothing — the single biggest wasted surface |
| Graph diagnostics lead the view (`9/28 nodes`, `7.1% completeness`, `correlation strength 0%`) | Answers questions no analyst asked |
| "Attack Chain" vs "Evidence Graph" compete | No hierarchy between narrative, progression and exploration |

**Root cause:** the graph is presented as the *primary* artefact. Every benchmarked vendor treats progressive disclosure as primary and the graph as secondary.

## 2 · Information architecture (target)

```
INCIDENT
 ├── Summary
 ├── Attack Story            ← DEFAULT
 ├── Evidence Graph          ← secondary exploration
 ├── Device Trajectory       ← endpoint forensic timeline
 ├── Process Ancestry
 ├── Security State
 ├── Artifacts & Hashes
 ├── Verdict & Explainability
 └── ATT&CK
```

Persistent right-hand **Evidence Inspector** spans all modes; it is the constant, the mode is the variable.

## 3 · Relationship semantics — LOCKED GRAMMAR

This replaces the current undifferentiated arrow and is **non-negotiable**. It extends the Phase 1-a epistemic tokens; it must never be reused for anything else.

| Relationship | Line | Marker | Meaning | Required backing |
|---|---|---|---|---|
| **OBSERVED** | solid, 1px | none | both endpoints exist in canonical evidence and the edge was recorded | `xdr_evidence_graph_edges` row |
| **SUPPORTED** | solid, 2px | ◆ on the edge | observed **and** corroborated by ≥1 additional independent source | edge + ≥2 distinct `event_ids` |
| **INFERRED** | dashed | ◇ | derived by a rule/engine, not directly observed | engine id + rule id must be citable |
| **POSSIBLE** | dotted | ? | candidate relationship, not asserted | must be labelled `candidate` |
| **UNKNOWN / GAP** | broken neutral segment | ? | a stage exists in the model with no evidence either way | rendered as an explicit gap node |
| **CONTRADICTED** | solid with strike | ⊘ | negative evidence exists | `NEGATIVE_EVIDENCE` correlation operator |

**Hard rules**
1. Only `OBSERVED` and `SUPPORTED` may render as a continuous directional arrow.
2. `INFERRED`/`POSSIBLE` must never be visually continuous with observed edges.
3. Direction may only be drawn where the backing evidence carries an ordering fact (timestamp or parent→child). Otherwise the edge is **undirected**.
4. Every edge exposes `relationship_class` + provenance on hover. **No edge without a citation.**
5. The banner changes from a disclaimer to a **legend** — the grammar carries the caveat, so the caveat stops being a caption nobody reads.

## 4 · Mode ① Attack Story (DEFAULT)

Vertical, chronological, stage-numbered. Each stage: ATT&CK tactic name · primary entity · epistemic badge · 3-5 facts only (user, host, PID, timestamp) · ATT&CK technique. Everything else lives in the Inspector.

- Stages come from `/api/incidents/{id}/attack-story`; evidence from `/attack-evidence`; findings from `/investigation/findings`.
- **Gaps are rendered, not hidden.** A tactic with no evidence appears as a `? UNKNOWN` stage. That is a first-class finding and the honest inverse of a fabricated chain.
- Header carries verdict + score + confidence from the now-backfilled `verdict_stage2`, with the arithmetic available (`weight_contribution` per row, `score_cap_applied`).
- Stage click → Inspector. Stage expand → inline evidence rows. **No modal.**

## 5 · Mode ② Evidence Graph (secondary)

- Entity-typed nodes with **human labels** (`powershell.exe`, `WKS-R43`, `ivy@…`) — never `PRC`/`HST`/`USR`.
- Semantic edge labels (`authenticated`, `executed`, `spawned`, `resolved`, `connected to`) using the §3 grammar.
- Disposition colour from severity tokens; **epistemic state from the epistemic tokens**. The two scales stay separate — a node can be `malicious` *and* `inferred`.
- Aggregates use a dashed outline (industry-conventional for grouped nodes).
- **Render only relationships that exist.** With `xdr_evidence_graph_edges` currently at 10 rows, the honest default for most incidents is a small graph or an explicit empty state — **not a padded canvas**.
- Layout choice (hierarchical / radial / temporal) is analyst-selectable, never auto-inflated.

## 6 · Mode ③ Device Trajectory

Horizontal time axis with swimlanes: SYSTEM · PROCESS · FILE · NETWORK · REGISTRY · AUTHENTICATION (the last enabled by the new 4624/4625 coverage). Backed by `/api/edr/device-trajectory`, `/api/edr/process-tree`, `/api/v2/cases/{id}/trajectory/device`. Empty lanes render as labelled `◇ NO EVIDENCE` lanes — **an empty lane is a finding, not blank space**.

## 7 · Evidence Inspector (the highest-value change)

Backed by the **already-existing** `/api/incidents/{id}/inspector/{kind}/{ref_id}` — no new endpoint required.

Sections, each omitted entirely when unbacked (never shown with a placeholder): Identity · Process (PID/parent/user/host) · Command Line (verbatim + decoder trace when present) · Detection (rule + engine) · MITRE · **Evidence** (one ◆ row per canonical artefact with event ids) · **Verdict Contribution** (`+45 detection`, `+15 iue.severity_hint` …) · **Pivots** (Process Tree · Device Trajectory · Command Intelligence · MITRE · Related Incidents; a pivot whose plane does not exist renders `⊘ CAPABILITY UNAVAILABLE` — e.g. Hunting, per CAT-09).

## 8 · Diagnostics drawer (demoted, not deleted)

`nodes 9/28 · edges 9/15 · 1 obs · 0 sup · 3 gaps · completeness 7.1% · correlation strength 0% · unknown coverage 38%` move into a collapsed **Graph Diagnostics** drawer for advanced analysts. They are legitimate engine telemetry and must remain reachable — they simply must not lead.

## 9 · Traceability requirement

Every Attack Story stage, every graph edge and every Inspector row must carry a resolvable reference to canonical evidence / IKG (`event_id`, `iue_id`, `match_id`, `rule_id`, `trace_id`). **A UI element that cannot cite its source must not render.** No fabricated relationships, evidence, causality, ordering or completeness percentages.

## 10 · Phased build order (for owner approval)

| Phase | Scope | Risk |
|---|---|---|
| **A** | Relationship-semantics tokens + legend; demote diagnostics to the drawer | **LOW** — tokens + one collapse, no data change |
| **B** | Evidence Inspector wired to the existing inspector endpoint | LOW-MED — highest value per unit of risk |
| **C** | Attack Story as the default mode; existing graph becomes mode ② | MED — changes the default tab |
| **D** | Evidence Graph relabel/relayout (human labels, semantic edges) | MED |
| **E** | Device Trajectory swimlanes incl. the new AUTHENTICATION lane | MED |

Recommended start: **A + B**. They fix the two defects the owner called most serious (false causality implication; empty inspector) without altering any default view.

## 11 · Explicit non-goals

No new investigation engine · no second reasoning path · no IKG writer · no engine/corpus/decoder/Security State/backfill change · no vendor visual identity, layout, component styling, icons, typography or proprietative interaction copied — Microsoft/Cisco/CrowdStrike/Cortex/SentinelOne/Trellix/Splunk inform **interaction principles only**.

## 12 · Known data constraint the redesign must survive honestly

`xdr_evidence_graph_edges` holds **10 rows** and the canonical pipeline has **no IKG write path** (master audit DEV-4). The redesign therefore must look correct and deliberate on a *sparse* graph. It must not be designed for a dense graph that does not yet exist — otherwise the UI will silently start implying relationships to fill space, which is the exact failure being corrected here.

## END · Specification · awaiting owner review · no production UI changed
