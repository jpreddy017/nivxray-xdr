# ADR-2026-08-01 · X-Lab Investigation Engine Architecture

_Locked by operator. Supersedes every previous roadmap. Do not deviate._

## Guiding Principle (measurement of success)

> Do not measure success by how good the report sounds. Measure success
> by whether the investigation itself would allow an experienced SOC
> analyst to independently arrive at the same conclusions. The report
> is only a rendering of the investigation graph — not the investigation
> itself.

## Investigation Pipeline (canonical order — no shortcuts)

```
INPUT
 → Parser
 → Normalizer
 → Artifact Discovery
 → Recursive Decoder
 → Evidence Extractor
 → Entity Resolver
 → Correlation Engine
 → Timeline Builder
 → Attack Chain Builder
 → Threat Intelligence
 → Threat Family Resolver
 → Mechanism Interpreter
 → Root Cause Engine
 → Confidence Engine
 → Hypothesis Engine
 → Recommendation Engine
 → Narrative Engine
```

Until every stage exists, downstream stages are dependent stubs. Knowledge
bases (LOLBIN / ATT&CK / family / mechanism) are SUPPORTING DATA — they
are consumed by pipeline stages, they are not stages themselves.

## Canonical Event Model (CEM)

Every vendor input passes through a per-vendor adapter that emits CEM.
Downstream stages **only** consume CEM — never vendor JSON.

    Cisco Secure Endpoint / Cisco XDR / Defender / CrowdStrike / Sysmon
    / QRadar / Elastic / Splunk / Suricata / Zeek / cloud logs
        →  CEM
        →  Pipeline

## Investigation Graph (single source of truth)

Not documents. Not lists. A graph.

    Host → User → Process → Command → Decoded Payload → File → Registry
      → Network → DNS → Threat Intel → ATT&CK → Malware Family
      → Recommendation

Every conclusion cites the graph nodes it depends on. Every sentence in
the eventual narrative traces to a subgraph.

## Threat Family Resolution (multi-signal, confidence-scored)

Never `Detection == Family`. Family recognition combines:

    Detection Name + Behaviour + Command Pattern + Process Chain
    + Registry + Network + Mutex + URLs + Hashes + ATT&CK
        →  Family Confidence (0..1)

## Mechanism Library (bigger than LOLBIN KB)

Each entry:

    Mechanism
      → Purpose
      → Typical ATT&CK
      → Common Malware
      → Analyst Explanation
      → Risk
      → Customer Explanation

Example: `IEX` → loads script directly into memory → why attackers use
it → ATT&CK → detection guidance → SOC explanation → customer
explanation.

## Rule-Driven Recommendations (no static playbook)

    Threat Family + Containment State + Attack Stage + Malware
    + Host + User + Visibility Gaps
        →  Playbook
        →  Recommendations

Never `if malware then run AV`.

## Narrative Engine consumes the Investigation

    Investigation (facts + interpretation + correlation + root cause
                    + confidence + recommendations)
        →  Narrative

The narrative is a **render** of the investigation graph. Facts come
from the graph, phrasing is deterministic templating that walks the
graph. If a claim can't be cited to a graph subgraph, it doesn't ship.

## Evidence Citation (every sentence)

Every sentence in every persona-specific render carries an internal
citation list of the graph nodes it depends on. The Citation Engine
that verifies this becomes trivial once the graph is authoritative.

## Multi-Persona Rendering

Same investigation. Different narrative.

    Investigation
      → Customer Report
      → SOC Report
      → Threat Hunter Report
      → DFIR Report
      → Management Report
      → Executive Report

The investigation is invariant. Renderers select which graph subgraphs
and which mechanism explanations to include.

## Hypothesis Engine (the missing module)

The MDR analyst's core differentiator. Given the current evidence set:

    Evidence
      → Possible explanations
      → Evidence FOR each hypothesis
      → Evidence AGAINST each hypothesis
      → Most likely explanation
      → Confidence + Alternatives

Explicit enumeration of alternatives is what separates a real analyst
from a decoder.

## Phased Roadmap (strict order)

### Phase 1 — Foundation
- Canonical Event Model
- Vendor Normalizers (per-vendor adapters emitting CEM)
- Recursive Decoder (existing, wired into pipeline)
- Artifact Discovery (existing RADE, wired into pipeline)

### Phase 2 — Correlation
- Investigation Graph
- Timeline Builder
- Correlation Engine
- ATT&CK Mapper (deterministic, single pass — closes BUG-P4-02)

### Phase 3 — Enrichment
- Threat Family Resolver
- Mechanism Knowledge Base
- Threat Intelligence
- Root Cause Engine
- Confidence Engine

### Phase 4 — Analyst Intelligence
- Recommendation Engine
- Playbook Engine
- Visibility Analysis
- **Hypothesis Engine**

### Phase 5 — Rendering
- Narrative Engine
- Customer Report renderer
- SOC Report renderer
- DFIR Report renderer
- Threat Hunting Report renderer

### Phase 6 — Long-horizon
- Learning Engine (rebuilt on graph, not summaries)
- Golden Corpus (analyst-approved investigations only)
- Incident Correlation
- Campaign Correlation

## Freeze scope (unchanged)

All UI, dashboards, personas beyond CEM-driven renderers, LLM polish,
correlation dashboards, cosmetic improvements remain frozen until each
phase acceptance criterion is signed off.

## Acceptance signal per phase

Each phase ends with an operator-visible artifact:
- Phase 1: a raw vendor payload → CEM → recovered artifacts, printable.
- Phase 2: an investigation graph render + timeline + attack chain.
- Phase 3: family + mechanism explanations with citations.
- Phase 4: recommendation + hypothesis output with FOR/AGAINST evidence.
- Phase 5: multi-persona narratives from the same investigation.
- Phase 6: cross-investigation campaign linkage.

## Blocking asks for next session

1. Four gold-standard analyst investigations pasted into
   `/app/memory/P0_MISSION.md` under the placeholders so the pipeline
   can be validated end-to-end against real analyst methodology.
2. Operator confirmation that Phase 1 (CEM + Vendor Normalizers +
   pipeline stubs wired) is the correct first deliverable.
