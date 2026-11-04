# NivXRay Investigation Workspace — Lab 2.0 API Contract

> **Status**: Governance artefact — binding for all Lab 2.0 frontend work
> **Corresponds to**: ADR-0014 (Canonical Investigation Object) · Slice-A/B/C/D
> **Purpose**: Immutable contract between the backend investigation engine and every UI surface (Story · Source · Behavior · Timeline · ATT&CK · Entity · Report · Knowledge lenses)
> **Rule (ADR-0014 §1.1.9)**: The frontend NEVER composes prose, verdicts, or reasoning. Every field below is produced by the backend and read as-is.

---

## 1 · Root object

Endpoints producing this object today:

| Endpoint | Producer | Status |
|---|---|---|
| `POST /api/decode/smart` | `routers/ops.py` → `nivxforge/investigation/builder.py` | Live |
| `POST /api/v2/auto-investigate` | `routers/auto_investigate.py` → same builder | Live |

Additive top-level field on the response:

```
response.cio  →  CIO object (see §2)
response.investigation  →  legacy ADR-0009 CIM (kept byte-identical §1.1.6)
response.investigation_report  →  legacy Workspace report (kept byte-identical)
response.output / mitre / iocs / ...  →  legacy fields (byte-identical)
```

---

## 2 · CIO object (`response.cio`) — field-by-field contract

| Field | Type | Producer | Consumer (lens) | Required | Stability | Notes |
|---|---|---|---|---|---|---|
| `schema_version` | `Literal["0.1"]` | `investigation/models.py` | All | Yes | 🔒 pinned | Bump requires ADR |
| `cio_id` | `str` (deterministic `CIO-<hex12>`) | `investigation/builder.py::_short_hash` | Case Spine, Report | Yes | 🔒 stable | Identical input → identical cio_id |
| `created_at` | ISO-8601 datetime | builder | Timeline, Report | Yes | 🔒 stable | Deterministic (epoch + step offset) |
| `source.surface` | `str` (`lab` \| `workspace` \| `api`) | builder | Case Spine | Yes | 🔒 stable | — |
| `source.endpoint` | `str` | builder | Provenance banner | Optional | 🔒 stable | — |
| `input_text` | `str` | Route handler | Source lens (raw view) | Yes | 🔒 stable | Post-ingress-gate canonical text when vendor JSON detected |
| `input_kind` | `str` | Route handler | Story lens (opening) | Yes | 🔒 stable | `powershell` \| `cmd` \| `bash` \| `raw_log` \| `json` \| `text` |
| `decode_chain` | `List[dict]` | builder | Source lens (Decode Ladder) | Yes | 🔒 stable | Each layer: `idx / op / input_kind / output_kind / preview / node_id` |
| `evidence_graph.nodes` | `List[Node]` | builder | Behavior · Timeline · Entity lenses | Yes | 🔒 stable | See §3 |
| `evidence_graph.edges` | `List[Edge]` | builder | Behavior lens | Yes | 🔒 stable | See §3 |
| `reasoning_steps` | `List[ReasoningStep]` | builder | Timeline lens (scrubber) | Yes | 🔒 stable | See §4 |
| `confidence` | `float` [0..1] | verdict_engine | Verdict Ribbon | Yes | 🔒 stable | Equals `verdict.confidence` |
| `verdict` | `VerdictNode` object | verdict_engine | Verdict Ribbon · Story · "Why this verdict?" | Yes | 🔒 stable | See §5 |
| `timeline` | `List[dict]` | builder | Timeline lens | Yes | 🔒 stable | View over `reasoning_steps` |
| `summary` | `Summary` object | summary_composer | Story · Report · Executive · SOC · DFIR views | Yes | 🔒 stable | See §6 (the biggest section) |
| `recommendations` | `List[Recommendation]` | summary_composer | Findings panel | Yes | 🔒 stable | Mirror of `summary.recommendations` |
| `reports` | `dict` | (future Slice-E/F) | Report lens | Optional | 🚧 planned | STIX / Navigator / MDR export |
| `metadata.slice` | `str` (`A`\|`B`\|`C`\|`D`) | builder | Debug badge | Yes | 🔒 stable | Ships with current shipped slice |
| `metadata.normalised_via` | `str` | routers | "Normalised By" badge | Optional | 🔒 stable | Present iff ingress gate fired |
| `metadata.node_count` / `edge_count` / `reasoning_step_count` / `verdict_engine` | `int` / `str` | builder | Story footer strip | Yes | 🔒 stable | — |

**Legend**: 🔒 stable = additive-only changes require ADR · 🚧 planned = not yet emitted.

---

## 3 · Evidence Graph nodes and edges

### 3.1 · Node

| Field | Type | Notes |
|---|---|---|
| `id` | `str` (`N-<3digit>`) | Unique within CIO; dense monotonic |
| `kind` | enum | `artifact` \| `decoded_fragment` \| `ioc` \| `mitre_technique` \| `lolbin` \| `family_match` \| `behaviour` \| `reasoning_step` \| `verdict` |
| `label` | `str` | Analyst-facing short label |
| `value` | `Optional[str]` | Canonical value (IOC value, technique id, lolbin name) |
| `confidence` | `float [0..1]` | |
| `provenance` | `str` | Producer tag (`decoder:base64`, `extractor:ioc`, `engine:unified-verdict`) |
| `attrs` | `dict` | Kind-specific small dict |

### 3.2 · Edge

| Field | Type |
|---|---|
| `source` / `target` | Node id references (validated non-dangling by G2 gate) |
| `kind` | `produces` \| `contributes_to` \| `contradicts` \| `supports` \| `derived_from` \| `references` \| `escalates_to` |
| `weight` | `float [0..1]` |

**Guarantee (G2 · ADR-0014 §7.1)**: No dangling edges. Every non-artifact node reachable from artifact via directed edges.

---

## 4 · ReasoningStep

| Field | Type | Notes |
|---|---|---|
| `step_id` | `str` (`RS-<3digit>`) | Dense monotonic |
| `timestamp` | ISO-8601 datetime | Deterministic (epoch + step offset) |
| `rule` | `str` | Internal rule id (`input.ingest`, `decoder.<op>`, `ioc.<kind>.extract`, `mitre.map.<tid>`, `lolbin.detect.<name>`, `ti.family.<provider>`, `behaviour.observe`, `verdict.compute`) |
| `input_nodes` | `List[str]` | Node ids consumed |
| `output_nodes` | `List[str]` | Node ids produced |
| `confidence_before` / `confidence_after` | `float [0..1]` | |
| `explanation` | `str` | Analyst-facing prose, evidence-first |

**Consumer contract**: Story lens's inline evidence tokens are `explanation` clauses; clicking a token surfaces `output_nodes` in the Evidence Bar.

---

## 5 · VerdictNode

| Field | Type | Notes |
|---|---|---|
| `label` | enum | `Malicious` \| `Suspicious` \| `Runtime Dependent` \| `Informational` \| `Undetermined` |
| `confidence` | `float [0..1]` | |
| `confidence_pct` | `int [0..100]` | Rounded percentile |
| `reason` | `str` | One-sentence rationale citing top contributor |
| `contributors` | `List[VerdictContribution]` | Sorted desc by (weight, confidence) |
| `not_counted` | `List[VerdictContribution]` | Nodes observed but weight 0 (§1.1.16 vendor / CA infra) — explainability by design |
| `engine` | `str` | `unified-verdict-engine-v1` (§1.1.3 · single engine) |

**VerdictContribution**: `{ node_id, kind, weight [0..10], confidence [0..1], category, label }`

---

## 6 · Summary (Slice-D · the Story-lens contract)

The Story · Report · Executive · SOC · DFIR views ALL read from this object. Frontend never composes prose.

| Field | Type | Producer | Consumer | Ordering (§1.1.18) |
|---|---|---|---|---|
| `executive` | `str` (1-2 sentences) | summary_composer | Executive View · Report header · Notifications | Verdict → top driver → coverage |
| `analyst` | `str` (2-4 paragraphs) | summary_composer | Story lens (body) | Event → Chain → Host/User → Timeline → Evidence → Scope → Impact → Actions |
| `technical` | `str` (deep bullet list) | summary_composer | Source lens sidebar · Report technical section | Decode layers · findings · ATT&CK |
| `attack_story` | `str` | summary_composer | Behavior lens footer · Report kill-chain section | `1. → 2. → ...` ordered chain |
| `key_findings` | `List[KeyFinding]` | summary_composer | Findings panel · Verdict Ledger | Sorted by weight desc |
| `unknowns` | `List[Unknown]` | summary_composer | Unknowns lens · Findings panel | `id / category / description / confidence_impact` |
| `recommendations` | `List[Recommendation]` | summary_composer | Findings panel · Report actions | Priority (`critical`\|`high`\|`medium`\|`low`\|`informational`) |
| `confidence` | `float [0..1]` | summary_composer | Verdict Ribbon fallback | Mirrors `verdict.confidence` |
| `evidence_digest.total_nodes` / `contributors` / `not_counted` / `by_kind` | int / dict | summary_composer | Story footer strip | — |
| `attack_chain` | `List[AttackChainStep]` | summary_composer | Behavior lens (auto-highlight) · Report kill chain | Decoded → Behaviour → Verdict |
| `entities_digest.hosts` / `users` / `hashes` / `external_domains` / `external_ips` / `lolbins` | `List[str]` | summary_composer | Entity lens · Story lens (hosts/users) | Sorted; deduped; vendor/CA infra filtered out |
| `mitre_digest.techniques` / `tactics` / `coverage` | list/list/int | summary_composer | ATT&CK lens · Story lens | Observed-only |
| `timeline_digest.steps` / `verdict_step_id` | int / str | summary_composer | Timeline lens (scrubber cursor) | — |
| `report_sections.what_happened` / `what_we_found` / `what_we_dont_know` / `what_to_do` | 4×str | summary_composer | Report lens (4 columns) | §1.1.18 canonical ordering |
| `composer_version` | `str` | summary_composer | Debug badge | `slice-d-v1` currently |

### 6.1 · KeyFinding

`{ id (kf-NNN), label, weight [0..10], confidence [0..1], evidence_node_ids: [] }`

### 6.2 · Unknown

`{ id (uk-NNN), category, description, confidence_impact [-1..0] }`

### 6.3 · Recommendation

`{ id (rc-NNN), priority (critical|high|medium|low|informational), action, rationale, evidence_node_ids: [] }`

### 6.4 · AttackChainStep

`{ order (1..N), label, node_id, tactic }`

---

## 7 · Versioning policy

1. **Additive changes** — new fields, new sub-objects, new enum values — allowed without ADR, provided all existing consumers keep working.
2. **Breaking changes** — removing a field, changing a type, tightening an enum — require a superseding ADR and a `schema_version` bump (`0.1` → `0.2`).
3. **Deprecation before removal** — a deprecated field remains in the payload for one release cycle with `x-deprecated: true` companion field.
4. **Stability marker** — every field carries a stability level in this document. 🔒 fields are frontend-safe to hard-depend on.

---

## 8 · Test coverage guarantees

Every field in this contract is protected by at least one pytest regression:

| Area | Test file | Assertions |
|---|---|---|
| CIO shape + gates | `test_adr0014_cio.py` | 30 tests · G1/G2/G3 gates · input-agnostic |
| Evidence graph | `test_adr0014_graph.py` | node uniqueness · edge integrity · determinism |
| ReasoningStep | `test_adr0014_reasoning_steps.py` | dense ids · monotonic confidence · timeline view |
| Verdict | `test_adr0014_verdict_engine.py` | label logic · vendor-infra downweight · determinism |
| IOC classifier | `test_adr0014_ioc_classifier.py` | 6-category boundaries · pollution corpus |
| Evidence priority | `test_adr0014_evidence_priority.py` | weight bounds · classification-never-upweights |
| Ingress gate | `test_adr0014_ingress_gate.py` | per-vendor detection · pollution regression |
| Summary composer | `test_adr0014_summary_composer.py` | 14-field presence · event-first ordering · determinism |

**Grand total**: 200+ pytest guarantees against this contract.

---

## 9 · Frontend consumption rules

1. **Read-only.** The frontend NEVER mutates CIO fields. Local UI state (selection, expand/collapse) lives outside the CIO.
2. **No composition.** No client-side prose synthesis. No client-side verdict computation. No client-side confidence calculation.
3. **Selectors, not scans.** Every lens gets a dedicated selector hook (`useVerdict()`, `useSummary()`, `useGraph()`, `useTimeline()`, `useEntity(id)`).
4. **Optional fields render empty states.** If `summary.entities_digest.hosts === []`, render "No hosts recorded" — not "Loading…" and not silently hide.
5. **Missing fields are bugs, not features.** Any lens that would need a field not in this contract MUST first raise an ADR to extend the contract.

---

## 10 · Open extension points (planned, not yet emitted)

| Field | Purpose | Slice |
|---|---|---|
| `cio.reports.stix21` | STIX 2.1 export | Slice-E |
| `cio.reports.attack_navigator` | Navigator layer JSON | Slice-E |
| `cio.knowledge.similar_cases` | Similar-case fingerprint hits | Slice-F |
| `cio.knowledge.campaign_correlation` | Campaign-graph edges | Slice-F |
| `cio.summary.llm_overlay` | Optional AI narrative overlay (never consulted by verdict / weights / classification per §1.1.5) | Slice-G |
| `cio.streaming.reasoning_step_offset` | Live-mode cursor for SSE | Phase-D |
| `cio.provenance.confidence_certificate_url` | Signed downloadable manifest | Phase-E |

---

*End of contract v1 · Slice-D. Amendments require superseding ADR.*
