# NivXRay — Architectural Vision

*Effective 2026-08-01 · North-star document · Do not overwrite existing PRDs.*

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

---

## 3 · Canonical Processing Pipeline (locked)

```
        Input
          │
          ▼
   Input Understanding          ← Stage 1 (built)
          │
          ▼
   Schema Understanding         ← Stage 2 (NEW · next milestone)
          │
          ▼
   Semantic Field Mapping       ← Stage 3 (planned)
          │
          ▼
   Canonical Event Model        ← Stage 4 (built)
          │
          ▼
   Artifact Discovery           ← Stage 5 (built)
          │
          ▼
   Decode Engine                ← Stage 6 (built)
          │
          ▼
   Evidence Extraction          ← Stage 7 (built)
          │
          ▼
   Investigation Graph          ← Stage 8 (built · SSOT)
          │
          ▼
   Entity Resolution            ← Stage 9 (built)
          │
          ▼
   Timeline                     ← Stage 10 (planned)
          │
          ▼
   Attack Chain                 ← Stage 11 (planned)
          │
          ▼
   Correlation                  ← Stage 12 (planned)
          │
          ▼
   Reasoning                    ← Stage 13 (planned · Confidence +
          │                       Hypothesis + Root Cause)
          ▼
   Narrative                    ← Stage 14 (built)
```

**Vendor Normalisers** remain, but are relegated to an *enrichment
plug-in* invoked between Semantic Field Mapping and CEM when
vendor-specific field mappings materially improve extraction. They
are never on the critical path.

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
knowledge. Answers: JSON / NDJSON / CEF / LEEF / CSV / XML / KV /
Elastic ECS / OpenTelemetry / Sysmon XML / Windows XML / Custom /
Unknown. Identifies nested structures, delimiters, object shapes.

### Semantic Field Mapper

Maps concept-level entities from field-name aliases:
- `DeviceName`, `Computer`, `HostName`, `endpoint`, `machine`, `asset`,
  `computer_name` → **Host**
- `UserName`, `Account`, `user`, `principal`, `login`, `actor` → **User**
- `src_ip`, `SourceIp`, `client_ip`, `RemoteAddress` → **IP**
- Similar mappings for Process, File, Hash, URL, Domain, Registry.

Driven by semantic aliases and structural context — not vendor names.

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

## 5 · Architectural Constraints

- Every stage after **Investigation Graph** consumes ONLY the graph.
- Vendor normalisers are optional enrichments; the pipeline must
  produce a well-formed investigation for previously unseen telemetry.
- Every conclusion returned to a user must cite graph node ids.
- Deterministic outputs. No LLM-hallucination-based conclusions
  outside explicitly LLM-annotated subsystems.
- Test contracts are permanent guardrails; broken contracts block
  merge.

---

## 6 · Engineering Rule (mandatory)

Every proposed feature must answer these before implementation:

1. Which subsystem owns this capability?
2. Does it belong in Decode, Investigation, Schema, Semantic Mapping,
   or Reasoning?
3. Does it strengthen the canonical pipeline or bypass it?
4. Can it operate on previously unseen telemetry?
5. Does every conclusion remain evidence-backed?

If any answer is "no", the design is revisited before code is written.

---

## 7 · Future Roadmap (informative — subject to phase gates)

| Phase | Milestone | Status |
|---|---|---|
| 1 | Phase 1 pipeline · CEM · Graph · Narrative · Entity Resolution | ✅ Frozen (148/148 tests, Suricata defect closed) |
| 2 | **Schema Understanding** (next) · Semantic Field Mapper · Timeline · Attack Chain · Correlation | 🔴 Not started |
| 3 | Reasoning · Confidence · Hypothesis · Root Cause · Visibility · Threat Family · TI Interface | 🔴 Not started |
| 4 | Recommendation Engine · Structured Report Ownership migration | 🔴 Not started |
| 5 | Commandline Analysis Engine · Rich Narrative expansion | 🔴 Not started |

---

*This document is the architectural north star. Amendments require
owner approval.*
