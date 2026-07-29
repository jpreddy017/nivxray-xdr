# ADR-0009 — Canonical Investigation View Model

- **Status:** Proposed (2026-02-28 · implementation PARKED behind Track A completion)
- **Deciders:** Operator (product owner) · Emergent (proposer)
- **Threshold met:** 3 independent real-world observations of P-VERDICT-DUAL-SURFACE (Cases 0006, 0013, 0002) · plus supporting defects P-SHELLCODE-PRESENTATION-GAP (Case 0002) and P-MITRE-DEDUP-MISS (Case 0002).
- **Sequencing:** MUST NOT enter implementation until ADR-0008 and ADR-0007 are Active, Corpus v1 parity validation is green, and Phase 2 evidence collection is under way.

## 1 · Problem

Case 0002 exposed that a single investigation is currently rendered from **multiple independent representations** on the same page:

- Investigation Summary block · Analyst Report · TI Shield · Output · Semantic Intent · Evidence Graph

Each surface computes or formats verdict / confidence / MITRE / decoded payload independently, producing the observable defects:

- **A** — SOC Verdict card shows `Malicious 70%`; Investigation Summary block shows `Malicious 90%` for the same case.
- **B** — Analyst Report MITRE row renders `T1055 · T1055` (deduplication miss).
- **C** — L-FINAL DECODED PAYLOAD panel dumps raw shellcode bytes as text; Workspace correctly detects the same bytes as x86 shellcode, switches to HEX + Capstone disassembly, and extracts C2 IP + Meterpreter UA. Both surfaces receive the same backend output — the divergence is presentation-only.

## 2 · Decision

Introduce a **single canonical investigation object** — a normalised, immutable view model computed once per case — from which every UI section renders. No section performs its own verdict math, MITRE deduplication, layer selection, or IOC extraction.

### 2.1 Canonical fields (single source of truth)

- `verdict` — one label · one confidence · one severity
- `mitre` — deduplicated, ordered set of techniques with per-technique evidence links
- `iocs` — one collection (post ADR-0008 validation) grouped by kind
- `layers` — ordered decode chain; each layer carries `kind` (text · pe · shellcode · gzip · b64 · …), `bytes`, `preferred_view` (text · hex · disassembly)
- `final_payload` — pointer to the *analyst-meaningful* final layer (may differ from the last layer by index when the last is binary/shellcode)
- `evidence` — indicators, each with `evidence_class` (per ADR-0007)
- `explanation` — per-finding rationale strings

### 2.2 UI rendering rule

Every card / panel / summary block renders **from the canonical object only**. UI components accept the canonical object as a prop and MAY NOT re-compute derived fields (confidence, dedup, layer selection). Verdict / MITRE / IOC counts MUST be identical across every surface on the same page — this is a merge-gate assertion, not a convention.

### 2.3 Shellcode / binary layer rendering (Defect C)

The canonical object's `layers[*].preferred_view` field drives which viewer (text · hex · disassembly) NivXForge presents. Reuse the Workspace shellcode-detection + Capstone disassembly path via a shared component — not by copying the UI. Same detection logic on both surfaces → same rendering on both surfaces.

## 3 · Amendments the operator directed

- Renamed from "Verdict Surface Consistency" → **Canonical Investigation View Model** to capture the broader scope.
- Scope explicitly includes: single verdict, single confidence, single MITRE list, single final payload, single evidence collection, single IOC collection.
- The single object also provides a natural place to address Defects B and C when Track B returns.

## 4 · Non-goals

- No changes to analytical logic. Backend produces the same fields; this ADR normalises how those fields are rendered.
- No changes to `/api/decode/smart` or `/api/v2/auto-investigate` response shapes.
- No changes to Workspace pages.

## 5 · Sequencing (locked by operator)

- Draft: 2026-02-28 (this document)
- Accepted / Implementation: **NOT before** ADR-0008 Active · ADR-0007 Active · Corpus v1 parity green · Phase 2 evidence collection under way.
- Rationale: Track A is locked. Interrupting it to fix Case 0002's presentation defects would dilute the sequential-implementation discipline. Case 0002 has already served its purpose — it produced evidence and updated the pattern register.

## 6 · Exit Criteria (mandatory when implementation is later authorised)

1. Every rendered `verdict.confidence` on every NivXForge surface for a given case is identical (Case 0002 rendering shows same value across SOC Verdict card and Investigation Summary block).
2. Every rendered MITRE list is deduplicated (Case 0002 `T1055 · T1055` becomes `T1055`).
3. Case 0002 L-FINAL panel renders shellcode via HEX + Capstone disassembly with the "SHELLCODE DECODED" banner and C2-IP + UA extraction (identical to Workspace).
4. Full Workspace regression suite green.
5. Full NivXForge regression suite green.
6. Parity contract test (`nivxforge/tests/test_parity_endpoints.py`) green.
7. No new backend routes; response shapes unchanged.
8. A new regression test asserts, at the frontend integration layer, that all verdict/MITRE/IOC counts match across every rendered surface on the same page for at least three corpus cases (0002, 0006, 0013).

## 7 · Related patterns

- P-VERDICT-DUAL-SURFACE (this ADR's threshold-crossing pattern)
- P-SHELLCODE-PRESENTATION-GAP (addressed by §2.3)
- P-MITRE-DEDUP-MISS (addressed by §2.1 canonical mitre field)
- P-VERDICT-STRUCTURAL (ADR-0007, independent)
- P-IOC-VALIDATION (ADR-0008, independent)

## 8 · Registry impact

`CAPABILITY_REGISTRY.md` gains a new row on Accepted:

| Capability | ADR | Status | Evidence | Corpus | Regression | Non-regression | Component | Introduced In | Superseded By |
|---|---|---|---|---|---|---|---|---|---|
| Canonical Investigation View Model | ADR-0009 | Proposed (impl parked) | 0006, 0013, 0002 | v1 | see ADR §6 | Cases 0003, 0009, 0018–0020 unchanged | NivXForge frontend rendering | pending | — |
