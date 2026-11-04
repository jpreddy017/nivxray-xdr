# Platform Positioning · NivXForge vs Workspace

**Status:** Long-horizon architectural direction (adopted 2026-02-28)
**Classification:** Vision — NOT a build order
**Enforcement:** Every future ADR that adds capability to NivXForge or Workspace MUST be
consistent with the division of responsibilities below.

---

## 1 · The intended future state

NivXForge Investigate is the **primary analyst investigation console**.
Workspace is the **case-management and operational-workflow system of record**.

This is not "Workspace + governance" or "Workspace++". These are two different
products sharing the same analytical backend. Analysts naturally open NivXForge
first because it provides deeper *understanding*. They open Workspace when they
need to *manage cases, alerts, and workflow*.

---

## 2 · Division of responsibilities

### Workspace owns
- Case management (create / assign / close / archive)
- Alerts & alert triage queues
- Incident tracking & lifecycle
- Analyst workflow (states, transitions, SLAs)
- Assignments (who owns which case)
- Collaboration surfaces (comments, tickets, hand-off)

### NivXForge owns
- Investigation (deep artifact analysis)
- Analysis (decode chain, evidence extraction)
- Reasoning (Investigation Brain)
- Threat intelligence integration
- Reporting (analyst-facing narratives)
- Analyst assistance (conversational, evidence-cited)
- Knowledge generation (patterns across investigations)

### Shared backend (unchanged from ADR-0006)
- `/api/decode/smart`, `/api/v2/auto-investigate/*`, `/api/iocs/*`, report-writer, etc.
- One source of truth. Both surfaces call the same endpoints.

---

## 3 · What NivXForge Investigate should produce on every case

Aspirational — each capability lands only when justified by ≥3 real cases per the
operational loop.

| Layer                 | Content                                                                                            |
| --------------------- | -------------------------------------------------------------------------------------------------- |
| Decode Engine         | Multi-stage deterministic decoding · full chain · per-stage confidence · layer visualisation       |
| Investigation Brain   | What was found · why it matters · confidence — with tier separation (Observable / Inference / Hypothesis) |
| Threat Intelligence   | IOC enrichment · infrastructure history · family indicators · MITRE mapping · historical occurrence in NivXForge corpus |
| Attack Story          | Chronological narrative · evidence-per-step · missing-evidence flags                              |
| Evidence Explorer     | Strings · APIs · URLs · Domains · IPs · Registry · Filesystem · Processes · Network · Shellcode · PowerShell · Certificates · Macros |
| Interactive Layer     | Evidence-cited answers to "why is this malicious?", "why T1105?", "show only network evidence", "what lowers confidence?", "what's missing?", "generate SOC report" |
| Intelligence Layer    | Correlation across previous investigations · similar commands / infra / families / TTPs — always evidence-backed |

---

## 4 · Non-negotiable governance rules

The deterministic pipeline is the source of truth. The conversational / reasoning
layer MUST:

1. **Never invent evidence.**
2. **Never override deterministic results.**
3. **Never fabricate attribution.**
4. **Clearly state uncertainty when evidence is insufficient.**
5. **Cite supporting evidence for every conclusion.**

These rules extend `REASONING_ENGINE_VISION.md` §3 and are equally binding.

---

## 5 · Sequencing (how this doc changes ADR flow)

This document does NOT authorise construction of any layer above.

- ADR-0006 (Accepted, Phase 1 shipped) — analyst-parity surface using existing components.
- Every subsequent layer (Investigation Brain, Attack Story, Evidence Explorer,
  Interactive Layer, Intelligence Layer) requires:
  1. ≥3 real cases in `REAL_WORLD_LOG.md` where the missing layer is the recorded gap.
  2. A dedicated ADR (ADR-0007, 0008, …) drafted from that evidence.
  3. Operator approval.

No layer is built on the strength of this vision alone.

---

## 6 · How Workspace evolves

Workspace remains fully supported. Under this positioning:

- Workspace UI **is not deprecated**.
- Workspace investigation views **may be simplified** over time as analysts migrate
  to NivXForge Investigate for the deep analytical work — but only under an
  authorised Workspace change ADR.
- Workspace-owned functions (case management, alerts, workflow, assignments) **are
  not moved into NivXForge** unless a dedicated ADR authorises it.

---

## 7 · The observable analyst behaviour that would prove this positioning is working

If, after 6-12 months of operation, we observe:

- Analysts open `/nivxforge/investigate` first when a new artifact arrives.
- Analysts open `/analyze` (Workspace) primarily to manage the case, not to investigate.
- The `REAL_WORLD_LOG.md` records more NivXForge-sourced investigations than Workspace-sourced ones.
- Analyst corrections trend downward as NivXForge's Investigation Brain matures.

…then this positioning has succeeded. If we don't see that shift, the positioning
needs to be revisited — evidence, not aspiration, decides.
