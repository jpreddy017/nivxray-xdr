# NivXForge Platform Vision · The Analyst-Visible Roadmap

**Status:** Vision FROZEN 2026-02-28 · no further vision documents authorised
**Classification:** Long-horizon roadmap — NOT a build order
**Sequencing:** Activates ONLY after ADR-0007 and ADR-0008 are Active and Phase 2
evidence collection is complete.

> ### 🔒 Vision docs frozen 2026-02-28
>
> No further vision or roadmap documents are authorised. The next meaningful
> milestone is not another design discussion — it is an analyst opening
> Investigate, analysing a real PowerShell sample, understanding the attack
> from a single screen, and generating a report without switching tools.
>
> **The single evaluation metric for every future capability:**
> *Does this reduce the time it takes an analyst to understand and explain an investigation?*
>
> If yes → belongs in Investigate.
> If no  → belongs elsewhere, or not at all.
>
> Governance / engineering diagnostics stay in Governance — they are not
> part of the analyst workflow.

---

## 1 · The honest gap this document names

Two things are simultaneously true:

- The engine work (ADR-0001, 0004, 0005, 0006 Phase 1, 0007, 0008) is
  necessary. Without it, no analyst-visible feature would be trustworthy.
- The analyst-visible surface today is **one page**. Input + Decode + Auto
  Investigate + IOCs + Verdict. Structurally similar to Workspace. The value
  differentiation lives in the backend; the analyst doesn't see it.

Engine improvements make outputs *correct*. This roadmap is about making
NivXForge *feel* like a flagship analyst platform.

---

## 2 · Where the analyst-visible surface should land

```
NivXForge
│
├── Dashboard              ← landing page; investigation metrics, quick access
│   ├── Recent Investigations
│   ├── Investigation Statistics
│   ├── Top Threats
│   ├── Recent Malware Families
│   ├── IOC Trends
│   ├── MITRE Coverage
│   └── System Health
│
├── Investigate            ← current page, expanded
│   ├── Decode              ✓ (Phase 1 · Active)
│   ├── Investigation Brain
│   ├── Attack Story
│   ├── Evidence Explorer
│   ├── Threat Intelligence
│   ├── MITRE
│   └── Reports
│
├── Threat Intelligence
│   ├── IOC Lookup
│   ├── IP / Domain / URL / Hash Intelligence
│   ├── Malware Families
│   └── Infrastructure History
│
├── Threat Hunting
│   ├── IOC / Command / YARA / ATT&CK Search
│   └── Similar Investigations
│
├── Knowledge Base
│   ├── Malware Families
│   ├── LOLBAS
│   ├── ATT&CK
│   ├── Detection Rules
│   └── Playbooks
│
├── Reports
│   └── Executive · SOC · IR · Markdown · PDF
│
├── History
│   ├── Previous Investigations
│   ├── Saved Cases
│   ├── Search
│   └── Compare
│
└── Governance             ← moved from top-nav to submenu
    ├── Capability Registry
    ├── ADRs
    ├── Quality Baseline
    ├── Corpus
    └── Scorecard
```

Governance content is not the analyst's primary workflow. It moves to a
sub-tree of NivXForge, not the front door.

---

## 3 · Division of responsibilities (refines PLATFORM_POSITIONING.md)

### Workspace
- Alert management
- Case queue
- Incident assignment
- Workflow / SLA / assignments
- Collaboration
- Customer operations

### NivXForge
- Investigation
- Malware analysis
- Command decoding
- Threat intelligence lookup + enrichment
- Threat hunting
- Knowledge base
- Reporting
- Analyst assistant

Analysts open Workspace to **manage** cases. They open NivXForge to
**understand** artifacts.

---

## 4 · Priority order for building the platform surface

(applies *after* ADR-0007/0008 are Active and Phase 2 evidence collection is
complete)

1. **Dashboard** — the landing surface. Read-only aggregation of existing state
   (investigations, IOC trends, MITRE coverage). No new backend logic.
2. **Investigate — expanded** — Investigation Brain · Attack Story · Evidence
   Explorer. This is the "Wow, I can understand this entire attack from one
   screen" moment.
3. **Threat Intelligence** — IOC lookup, enrichment, infrastructure history.
4. **History** — searchable previous investigations, comparisons.
5. **Reports** — one-click SOC / IR / Executive / PDF export.
6. **Governance sub-tree** — move existing governance content under NivXForge.

Threat Hunting and Knowledge Base are Phase-N (further out).

---

## 4a · Section-level design intent (operator notes 2026-02-28 · reference only)

These are guiding intents for each section when its evidence-backed ADR is
eventually drafted. **Not build orders.** Every capability inside still
requires the operational loop's evidence gate.

### Dashboard — evolve beyond platform-health
Beyond the current 6 metric cards, the mature Dashboard should surface:
- Recent investigations · recent malware families · most common ATT&CK techniques
- Recent decoded artifacts · IOC trends · investigation success rate · latest reports
- **Quick actions**: New Investigation · Upload Sample · IOC Lookup · Threat Hunt

The Dashboard is what analysts see every day — it should be usable, not just informational.

### Investigate — the centerpiece
This is where analysts should spend most of their time. Mature Investigate contains:
- Investigation Brain (why · confidence · missing evidence)
- Decode Chain (per-layer, per-stage confidence)
- Attack Story (chronological narrative with evidence-per-step)
- Evidence Explorer (network · processes · registry · PowerShell · shellcode · strings · files · certs)
- Threat Intelligence (inline enrichment)
- MITRE ATT&CK (coverage, evidence, navigator)
- Reports (SOC · IR · executive · markdown · PDF)
- **Ask NivXForge** (evidence-cited conversational layer — see `REASONING_ENGINE_VISION.md` §9)

The reason an analyst chooses NivXForge over Workspace for deep analysis lives in this section.

### Threat Intelligence — deep lookup
IP · Domain · URL · Hash lookup · ASN · WHOIS · Malware families · Infrastructure history.

### Threat Hunting — search across the corpus
By IOC · Hash · Command · PowerShell fragment · MITRE technique · Malware family · Similar investigations.

### History — the corpus as a queryable asset
Example queries that should be trivially answerable:
> "Show every investigation involving 149.28.81.19."
> "Show all PowerShell AMSI bypass investigations."

This is more valuable than scrolling through old cases and turns operational history into a hunting asset.

### Architectural navigation refinement (long-horizon)
When analyst-workflow evidence justifies it, consider promoting Investigation to a top-level nav group with sub-items:
```
Investigations
   ├── New Investigation
   ├── History
   └── Compare
```
That mirrors how SOC analysts actually work: **start → investigate → pivot to TI → hunt → report**.

---

## 5 · Governance rules that still apply

This vision does **not** bypass the frozen governance model.

- Each major section (Dashboard, Investigation Brain, Attack Story, Evidence
  Explorer, TI, Threat Hunting, KB, Reports, History) requires its **own ADR**
  when its turn comes.
- Each ADR must be justified by real cases from `REAL_WORLD_LOG.md` (Corpus v2
  or later) — not by this vision alone.
- Each ADR must define Exit Criteria (`OPERATIONAL_LOOP.md` §Rule 1).
- Each ADR is implemented under the Mandatory Verification Pipeline.
- Each ADR must preserve the Workspace ↔ NivXForge parity contract on the
  analytical layer — new UI surfaces are permitted; new analytical
  duplication is not.

This vision is the target. The governance model is the mechanism. Neither
overrides the other.

---

## 6 · What this vision is NOT

- Not authorisation to start building any of the above.
- Not a change to the current execution contract (ADR-0008 → ADR-0007 → Phase 2).
- Not a rebuttal to the analyst-parity Phase-1 work — Phase 1 is what makes
  everything above possible.
- Not a promise of a delivery date — each capability lands when evidence
  justifies it.

---

## 7 · What to do with this document

- After ADR-0007 and ADR-0008 are Active and their `Introduced In` fields are
  populated in the Capability Registry, and Phase 2 evidence collection has
  produced ≥1 recurring pattern relevant to an analyst-visible capability
  above, draft the first platform-surface ADR.
- Do not draft platform-surface ADRs speculatively — the evidence-first rule
  from `REASONING_ENGINE_VISION.md` §5 and `OPERATIONAL_LOOP.md` still
  applies to every capability, analyst-visible included.

The vision names the destination. The governance model names how each step is
earned.
