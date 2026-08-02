# NivXRay — Architectural Vision

*Effective 2026-08-01 · Revised 2026-02-XX (Owner Amendments) · North-star document · Do not overwrite existing PRDs.*

---

## 1 · Mission

NivXRay is an **Autonomous Security Investigation Platform**.

It accepts arbitrary security telemetry, alerts, scripts, command lines,
logs, and forensic artefacts from any source. It automatically:

1. Understands the input format and schema,
2. Recursively decodes embedded content,
3. Extracts evidence and indicators,
4. Builds a canonical investigation graph,
5. Correlates events,
6. Interprets attacker behaviour,
7. Enriches intelligence, and
8. Produces a deterministic investigation report with full evidence
   provenance.

Vendor-specific knowledge **enhances** investigations but never
**limits** them. Unknown telemetry must still be understood using
schema inference, semantic analysis, and evidence extraction. Every
analytical conclusion must be traceable to observed evidence rather
than assumptions.

**Design north star (owner amendment):** *Do not optimize for the
current telemetry corpus. Optimize for telemetry we have never seen
before.* Every design decision must improve NivXRay's ability to
understand previously unseen security telemetry without requiring a
new vendor-specific implementation.

---

## 2 · Design Principles

1. **Vendor is enrichment, not a gate.** The platform must work when
   presented with previously unseen telemetry.
2. **Schema is understanding.** Format detection is not vendor
   detection.
3. **Semantics is normalisation.** Concept-level unification of fields
   (`DeviceName` / `Computer` / `HostName` → `Host`) is independent of
   any product.
4. **Investigation is evidence-driven.** Every conclusion in the
   narrative traces to a graph node with `evidence_refs`.
5. **Decode is a first-class subsystem.** It never runs inside the
   investigation engine; it produces artefacts the graph consumes.
6. **The Investigation Graph is the single source of truth.** Every
   downstream stage (Timeline, Attack Chain, Correlation, Reasoning,
   Narrative) reads only from the graph.
7. **The narrative never describes the tool.** Subject = incident,
   endpoint, user, malware, attacker — enforced by lexicon gate and
   contract tests.
8. **The Canonical Event Model is the SSOT for *what happened*.**
   Vendor identity, when known, is *metadata about who reported it*.
   The two concerns are separated by design (§5, §6).

---

## 3 · Canonical Processing Pipeline (locked)

```
                     Raw Input
                         │
                         ▼
                Input Understanding             ← Stage 1 (built)
                         │
                         ▼
                       Parser                    ← Stage 2a (built)
                         │
                         ▼
                Schema Understanding             ← Stage 2b (NEW · built)
                         │
                         ▼
             Semantic Field Mapping              ← Stage 3 (planned)
                         │
                         ▼
        Canonical Event Model (SSOT)             ← Stage 4 (built)
                         │
      ┌──────────────────┼──────────────────┐
      │                  │                  │
      ▼                  ▼                  ▼
Vendor Enrichment   Artifact          Evidence
(optional metadata) Discovery         Extraction
                         │                  │
                         ▼                  ▼
                    Decode Engine       (feeds graph)
                         │
                         ▼
                Investigation Graph              ← Stage 8 (SSOT · built)
                         │
                         ▼
                Entity Resolution                ← Stage 9 (built)
                         │
                         ▼
                     Timeline                    ← Stage 10 (planned)
                         │
                         ▼
                   Attack Chain                  ← Stage 11 (planned)
                         │
                         ▼
                   Correlation                   ← Stage 12 (planned)
                         │
                         ▼
                    Reasoning                    ← Stage 13 (planned)
                         │
                         ▼
                    Narrative                    ← Stage 14 (built)
```

**Critical amendment:** Vendor Enrichment is a **sibling consumer** of
the Canonical Event Model — it is *never* upstream of the CEM.
Vendor metadata attaches to the CEM as decoration:

```
cem.metadata.vendor       = "Microsoft Defender"   # optional
cem.metadata.product      = "MDE"                   # optional
cem.metadata.schema       = "ecs"                   # optional
cem.metadata.confidence   = 0.91                    # optional
```

Downstream investigation engines (Timeline, Attack Chain, Correlation,
Reasoning, Narrative) **must not read** `cem.metadata.vendor` to make
decisions. Vendor is descriptive, not prescriptive.

---

## 4 · Subsystem Responsibilities

### Decode Engine (independent subsystem)

Handles embedded technical content: PowerShell, CMD, Bash, Python, JS,
Base64, UTF-16LE, gzip, RC4, AES, XOR, nested encodings, registry
blobs, XML, JSON, URLs, scripts, macros. Recursively decodes until
nothing remains. Emits `DecodedLayer` records with provenance.

### Investigation Engine (independent subsystem)

Investigates everything else — alerts, endpoints, users, hostnames,
devices, severities, processes, network, registry, files, parent /
child processes, event history, vendor metadata, timestamps, alerts,
hashes, domains, emails, URLs. Builds the story from the
Investigation Graph.

### Schema Understanding

Detects **structural format** and **schema family** without vendor
knowledge. Answers: ECS / OpenTelemetry / Windows Event XML / CEF /
LEEF / generic_json / generic_ndjson / generic_csv / generic_xml /
generic_kv / generic_yaml / generic_ini / command_line /
unknown_structured / unknown_unstructured / empty. Produces a
`SchemaFingerprint(schema_family, schema_version, schema_confidence,
candidate_fields, parser_features, reasons, diagnostics,
registry_version)`. **Never performs semantic mapping.**

### Semantic Field Mapper

Owns concept resolution — never parsing, decoding, investigation,
timeline, ATT&CK reasoning, or IOC enrichment. Frozen contract:

  · Consumes `SchemaFingerprint` + `ParsedInput` + `semantic_alias_registry_v1`
  · Emits `SemanticMappingResult(mappings, unmapped_fields,
    ambiguous_fields, semantic_confidence, evidence, diagnostics,
    registry_version)`
  · Every `FieldMapping` is explainable via `confidence_provenance`
    — an itemised ledger of `SignalContribution(signal, delta,
    detail)` records whose deltas sum to the final confidence.
  · Ambiguity band: two concepts within
    `SEMANTIC_AMBIGUITY_THRESHOLD` (default 0.15, single constant)
    are surfaced as `ambiguous_fields` — never silently resolved.
  · Signals: registry alias match + value-shape boosts (via
    `value_shape.py` — full boundary detection: IPv4/IPv6/MAC/ASN/
    hashes/URL/email/SID/GUID/JWT/paths/registry/MITRE&CVE/
    Windows Event/AWS ARN/Azure Resource/K8s object/container
    IDs/OCI digest/DNS RR types) + sibling concept co-occurrence +
    dotted-namespace context.
  · Zero vendor knowledge. Enforced by contract test.

Maps concept-level entities from field-name aliases using the
**Semantic Alias Registry** (see §5):
- `DeviceName`, `Computer`, `HostName`, `endpoint`, `machine`,
  `asset` → **Host**
- `UserName`, `Account`, `user`, `principal`, `login`, `actor` → **User**
- `src_ip`, `SourceIp`, `client_ip`, `RemoteAddress` → **IP**
- Similar mappings for Process, File, Hash, URL, Domain, Registry.

Driven by semantic aliases + structural context. Never branches on
vendor names.

### Vendor Enrichment (optional metadata)

An optional sibling consumer of the CEM. When high-confidence vendor
identity can be inferred (e.g., a `provider` field says
`Microsoft-Windows-Sysmon`, a document declares `agent.type: mde`),
it attaches metadata to the CEM — never mutating the canonical
event shape. If the vendor is unknown, the CEM is complete without
it.

### Commandline Analysis Engine

Dedicated analytical subsystem. Given a commandline or decoded script,
answers: language, behaviour, capabilities, ATT&CK techniques,
persistence, network activity, file operations, registry operations,
credential targets, analyst explanation, risk, recommendations.

### IOC Engine

Extracts IPs, URLs, domains, hashes, emails, registry paths, mutexes,
services, scheduled tasks, CLSIDs, named pipes. Enriches with TI,
reputation, defanging.

### Reasoning Engine

Confidence + Hypothesis + Root Cause + Visibility Gap. Every
conclusion returns a confidence score and a list of supporting /
contradicting evidence node ids.

### Narrative Engine

Renders analyst-style prose from the Investigation Graph. Never
describes the tool. Lexicon-gated. Contract-tested across every
telemetry archetype.

---

## 5 · Semantic Alias Registry (governed asset)

The Semantic Alias Registry is a **governed architectural asset**,
not a dictionary. Located at
`/app/backend/nivxforge/investigation/pipeline/semantic_alias_registry.py`.

### 5.1 · Canonical Concepts First

The registry maps **surface field names → canonical concepts** —
never to vendors.

Correct:

    DeviceName · Computer · HostName    →   Host

Incorrect:

    DeviceName                          →   "Microsoft Defender"

The registry has **zero vendor knowledge**. Its integrity is
enforced by regression tests
(`tests/investigation/test_semantic_alias_registry.py`).

### 5.2 · Registry Versioning

The registry is versioned. Current version:
`semantic_alias_registry_v1`. Future releases (`v2`, `v3`, …) are
explicit and traceable. Downstream stages that consume a mapping
must record the `registry_version` they read for provenance.

### 5.3 · Confidence per alias

Every declared alias carries a confidence score in `[0.0, 1.0]`.
v1 alias confidences are conservative (0.80 – 1.00); low-confidence
fuzzy matches are the Semantic Field Mapper's responsibility, not
the registry's.

### 5.4 · Registry Governance

Every addition must satisfy:

  · Backed by real telemetry,
  · Regression tested,
  · Does not create ambiguity (a normalized surface must map to
    exactly one concept),
  · Improves semantic understanding.

The registry is intentionally curated and foundational, not
exhaustive. It grows deliberately.

### 5.5 · Foundational concepts (v1)

```
Host · User · Process · Command · File · Directory · Hash · IP
Domain · URL · Email · Registry · Service · ScheduledTask
Certificate · NetworkConnection · Port · Protocol · NamedPipe
Mutex · Detection · Alert · MITRE
```

---

## 6 · Architectural Constraints

- Every stage after **Investigation Graph** consumes ONLY the graph.
- Vendor normalisers are optional enrichments; the pipeline must
  produce a well-formed investigation for previously unseen telemetry.
- Every conclusion returned to a user must cite graph node ids.
- Deterministic outputs. No LLM-hallucination-based conclusions
  outside explicitly LLM-annotated subsystems.
- Test contracts are permanent guardrails; broken contracts block
  merge.

### 6.1 · No downstream subsystem may branch on vendor

> **Rule:** No downstream subsystem may branch on vendor unless there
> is a documented capability that cannot be achieved through semantic
> understanding alone.
>
> If vendor-specific logic is introduced, the implementation MUST
> document:
> 1. Why semantic mapping was insufficient,
> 2. What additional capability the vendor provides,
> 3. Why the capability cannot be generalized.
>
> Undocumented vendor branches are architectural defects and must be
> removed. This rule prevents the architecture from silently drifting
> back into vendor-centric design.

### 6.2 · Every stage must degrade gracefully

> **Rule:** Every stage must degrade gracefully.
>
> If a stage cannot confidently classify or enrich the input, it MUST
> produce the best possible partial result and allow the pipeline to
> continue. **Unknown schema, unknown vendor, unknown entities, and
> missing fields are supported states — not errors.** Explicit
> supported-unknown states:
>
> · `schema_family = unknown_structured` (records exist, family
>   unclear)
> · `schema_family = unknown_unstructured` (no structure detected)
> · `vendor = unknown` (no vendor identified — pipeline still runs)
> · `entity concept = <no match>` (registry lookup returned empty)
>
> Every stage returns a first-class result object, never `None`,
> never a raised exception outside of programmer errors.

---

## 7 · Engineering Rule (mandatory)

Every proposed feature must answer these before implementation:

1. Which subsystem owns this capability?
2. Does it belong in Decode, Investigation, Schema, Semantic Mapping,
   or Reasoning?
3. Does it strengthen the canonical pipeline or bypass it?
4. Can it operate on previously unseen telemetry?
5. Does every conclusion remain evidence-backed?
6. **Does it branch on vendor?** If yes, does it satisfy the §6.1
   documented-exception rule?
7. **Does it degrade gracefully?** What is the explicit
   supported-unknown return path?

If any answer is "no" (or unsatisfied), the design is revisited
before code is written.

---

## 8 · Future Roadmap (informative — subject to phase gates)

| Phase | Milestone | Status |
|---|---|---|
| 1 | Phase 1 pipeline · CEM · Graph · Narrative · Entity Resolution | ✅ Frozen (148/148 tests, Suricata defect closed) |
| 2a | **Schema Understanding** + Semantic Alias Registry v1 | ✅ Built (frozen contract) |
| 2b | **Semantic Field Mapping** (Stage 3) + Value Shape library + Alien Corpus | ✅ Built (frozen contract) |
| 2c | **Additive CEM sibling wiring** + Parity Comparator | ✅ Built (additive; cut-over pending owner review of parity report) |
| 2d | Cut-over: Semantic Field Mapping → CEM (default path) | 🔴 Blocked on parity thresholds (see REGISTRY_GOVERNANCE.md) |
| 2e | Timeline · Attack Chain · Correlation | 🔴 Not started (sequenced after cut-over) |
| 3 | Reasoning · Confidence · Hypothesis · Root Cause · Visibility · Threat Family · TI Interface | 🔴 Not started |
| 4 | Recommendation Engine · Structured Report Ownership migration | 🔴 Not started |
| 5 | Commandline Analysis Engine · Rich Narrative expansion | 🔴 Not started |

---

## 9 · Mindset (owner statement)

> The Canonical Event Model represents *what happened*.
> Vendor enrichment represents *who reported it*.
> Keeping those concerns separate makes NivXRay far more extensible
> as new telemetry sources emerge.

---

*This document is the architectural north star. Amendments require
owner approval.*
