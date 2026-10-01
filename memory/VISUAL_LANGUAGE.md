# NivXRay XDR Visual Language System · v1.0

> **Status**: Foundation artifact · established 2026-09-01
> **Owner rating gate**: The Incident record is the flagship implementation
> of v1.0. Every subsequent analyst surface (Alerts, Cases, MITRE,
> Evidence, Entities, TI, Response, Endpoint, Investigation Graph,
> Reports) MUST inherit this language without inventing its own.
>
> **Sits alongside**: `ARCHITECTURE.md` (Evidence Plane, Investigation
> Graph, Verdict Engine, Integration Fabric). This document is the
> equivalent PLATFORM-LEVEL contract for the analyst experience.

---

## 0 · Non-negotiables

1. **NivXRay XDR is a white/light enterprise SOC console.**
   No product-wide dark theme. Dark navy is permissible only as a
   high-impact accent within a component, never as a page background.
2. **No fabricated telemetry, no fabricated evidence, no fabricated
   MITRE coverage.** Absence is a first-class visual state, not a
   fallback to "0".
3. **Icons are information, not decoration.** Custom NivXRay XDR
   glyphs express security ontology. Lucide is a utility base only.
4. **Composition is a language.** New surfaces express workflows
   (Incident → Vitals → Attack Story → Graph → Evidence → MITRE →
   Response), not free-form card grids.
5. **Never expose implementation terminology as an analyst-facing
   heading**: `Truth State`, `Provenance`, `Relationship`, `Entity`,
   `EvidenceState`, `Action` are internal primitives. Their
   analyst-facing equivalents are `Verdict / Confidence / Status`,
   `Evidence lineage`, `Investigation graph`, `Security entity`,
   `Verdict indicator`, and `Response`.

---

## 1 · Tokens

### 1.1 Typography
| Role                     | Face          | Size · Weight        | Use                                          |
|--------------------------|---------------|----------------------|----------------------------------------------|
| Command title            | UI sans       | 24/1.15 · 800        | Incident name, page hero identity            |
| Section title            | UI sans       | 15/1.3 · 700         | "Attack Story", "Evidence-backed techniques" |
| Body                     | UI sans       | 13/1.5 · 400         | Prose, descriptions                          |
| Meta / machine ID        | Mono          | 11/1.4 · 500         | INC-…, hashes, T1059.003                     |
| Label eyebrow            | UI sans       | 9.5/1.0 · 800 upper  | "EVIDENCE", "ATTACK STORY"                   |
| Metric value             | UI sans       | 28/1.05 · 700        | KPI numerals when populated                  |
| Metric value (absent)    | UI sans       | 20/1.05 · 500 italic | `—` when no evidence                         |

### 1.2 Spacing scale (density-first)
`2 · 4 · 6 · 8 · 12 · 14 · 18 · 24 · 32 · 48`. Analyst screens use
**8 / 12 / 14** as the primary rhythm. `24+` only for section joins.

### 1.3 Surface / border
- Canvas: `--nx-surf-page` (warm-neutral) · Primary surface:
  `--nx-surf-primary` · Inset: `--nx-surf-inset`.
- Hairlines: `1px solid --nx-divider` (never 2px unless it carries
  security meaning).
- Radius: `3–4px`. No 8/12/16px rounded cards.
- Elevation: subtle 0/1/2 · never decorative drop-shadows.

### 1.4 Semantic colour (state, not decoration)
| Token                | Hex     | Meaning                              |
|----------------------|---------|--------------------------------------|
| `--nx-sev-p1`        | #DC2626 | Critical / P1 / Malicious            |
| `--nx-sev-p2`        | #EA580C | High / P2                            |
| `--nx-sev-p3`        | #CA8A04 | Medium / P3 / Pending                |
| `--nx-sev-p4`        | #6B7280 | Low / P4                             |
| `--nx-sev-p5`        | #9CA3AF | Info / P5 / Suppressed               |
| `--nx-ev-observed`   | #059669 | Evidence observed                    |
| `--nx-ev-supported`  | #2563EB | Evidence supported                   |
| `--nx-ev-missing`    | #CA8A04 | Evidence missing / partial           |
| `--nx-ev-unavailable`| #B91C1C | Explicitly absent (NOT_OBSERVED)     |
| `--nx-ev-actioned`   | #6D28D9 | Analyst / responder took action      |

**Purple** is reserved for the primary command action (Respond) and the
`actioned` evidence state. Purple gradients are banned.

### 1.5 Interaction states
- Hover: `background: var(--nx-surf-hover)` + hairline weight bump.
- Focus: 2px inset ring, colour-matched to state.
- Disabled: opacity 55% + `data-reason="…"` visible as machine-face
  micro-text (never a silent grey button).

---

## 2 · Security-Ontology Glyph Vocabulary

Fifteen native NivXRay XDR SVG glyphs form the security-ontology
alphabet. Every glyph is drawn on a 24×24 grid with 1.5px stroke,
renders correctly at 12/16/24/32px, and carries one meaning only.

| Concept       | Glyph shape rationale                                   |
|---------------|---------------------------------------------------------|
| Incident      | Notched shield · warning corner cut                     |
| Alert         | Shield with siren dot                                   |
| Detection     | Crosshair inside square                                 |
| Host          | Server chassis · two horizontal slots                   |
| User          | Bust silhouette · hexagonal head                        |
| Process       | Cog with square teeth · centred dot                     |
| File          | Document · corner fold · hash line                      |
| Network       | Three linked nodes                                      |
| Domain        | Globe · single meridian                                 |
| IP address    | Square with `.` separators                              |
| Evidence      | Stacked layered plates                                  |
| Technique     | Tag shape with anchor hole                              |
| Tactic        | Chevron / progress marker                               |
| Response      | Bolt inside shield                                      |
| Verdict       | Diamond with check or slash                             |
| Provenance    | Three linked breadcrumb dots                            |

Reference implementation: `apps/nivxray-xdr/src/xdr/design/glyphs.jsx`.
Adding a new security concept REQUIRES a new glyph — Lucide is not
acceptable for ontology-level concepts. Lucide remains permitted for
utility (chevrons, close, refresh, external-link, more).

---

## 3 · Component language

Each component is a *speaker* of the language. Reusable components
(defined once in `xdr/design/`) are:

- **Command Band** — incident/case/alert identity with severity anchor.
- **Vitals Rail** — glyph-led metric row (Evidence · Hosts · Users …).
- **Attack Story Node** — one step in an evidence-derived progression.
- **Investigation Graph Node** — entity node in the correlation graph.
- **Evidence Card / Drawer** — expandable evidence body.
- **Entity Card** — host/user/process/file/network summary.
- **Technique Row** — MITRE technique with tactic & confidence.
- **Verdict Indicator** — closed enum, glyph + text.
- **Severity Indicator** — priority glyph + label + accent rail.
- **Confidence Indicator** — 4-state (observed/supported/missing/absent).
- **Provenance Chain** — glyph-led telemetry lineage.
- **Response Action** — capability-gated button with reason.
- **Recommendation Card** — impact + rationale + link to response.

Components MUST expose `data-testid` and respect the state tokens.
They MUST NOT hardcode colours outside of the state tokens.

---

## 4 · Composition rules

Analyst surfaces compose components in **narrative order**, never
free-form grid layouts.

### 4.1 Incident record
```
[Command Band]
       ↓
[Vitals Rail]
       ↓
[Attack Story]
       ↓
[Investigation Graph]
       ↓
[Evidence] · [Entities] · [MITRE] · [Recommendations]
       ↓
[Response]
```

### 4.2 Alert record
```
[Detection identity]
       ↓
[Evidence]
       ↓
[Entity]
       ↓
[Correlation]
       ↓
[Investigation]
```

### 4.3 Threat Intelligence record
```
[Indicator identity]
       ↓
[Provenance / Feed lineage]
       ↓
[Enrichment]
       ↓
[Related Incidents]
```

Rules:
- A composition MUST be justified by an analyst decision it enables.
- Never insert a section without an evidence-driven purpose.
- Sections collapse (not disappear) when their data is absent — the
  reader still sees the shape of the investigation.

---

## 5 · Honest-state visual grammar

Nine states, expressed identically across every surface:

| Token           | Visual                                    | Analyst meaning                          |
|-----------------|-------------------------------------------|------------------------------------------|
| PRESENT         | glyph solid · numeric bold                | Data observed and available              |
| PARTIAL         | glyph half-fill · italic value            | Partial / insufficient evidence           |
| NOT_PRESENT     | glyph outline · `—` muted italic          | Layer not populated                       |
| NOT_RUN         | glyph outline · "pending" dot-chip amber  | Verdict/analysis not executed             |
| PENDING         | glyph outline · dot-chip blue             | Queued / in progress                     |
| FAILED          | glyph outline red · reason inline         | Executed but errored                     |
| NOT_SUPPORTED   | glyph outline grey · reason inline        | Vendor / capability gap                  |
| ACTIONED        | glyph purple fill                         | Analyst / responder acted                 |
| SUPPRESSED      | glyph outline · struck through            | Hypothesis not substantiated              |

Never render a fabricated numeric zero styled like a real value. `0`
without evidence is `—` in muted italic.

---

## 6 · Data-visualisation grammar

- **Attack progression** — horizontal tactic chevrons + timeline
  markers. Evidence-derived, honest gaps.
- **Evidence density** — inline sparkline (never a decorative
  chart-js pie).
- **Entity relationships** — force-directed graph with glyph nodes
  and confidence-coloured edges.
- **MITRE coverage** — 14-tactic strip with observed-count fills.
- **Timeline** — one row per correlated event, source-provenance
  chip left-aligned.
- **Confidence** — 4-band vertical bar (observed / supported /
  missing / absent).
- **Response state** — capability strip: `cap-full · cap-standby ·
  cap-unavailable`, glyph-led.

Visualisations MUST express security meaning. A bar chart that shows
"7" is not preferred over a glyph strip that shows the seven
techniques by tactic.

---

## 7 · VEEE — Visual Expression / Evaluation Engine

VEEE is the language's **enforcement layer**. It answers:

> Does this rendered surface look, behave and communicate like
> NivXRay XDR?

### 7.1 Inputs
- Rendered screenshot (post-hydrate)
- DOM tree with `data-testid` attributes
- Composition manifest (which sections rendered, in what order)

### 7.2 Evaluations (v1)
- **Hierarchy**: is the analyst's eye pulled to Severity → Identity
  → Verdict → Evidence → Response, in that order?
- **Density**: no section wastes >30% vertical space to an absent
  data category.
- **Consistency**: every security concept uses its declared glyph.
- **State grammar**: absent values render as `—` italic muted, never
  as `0` styled like a populated metric.
- **Composition**: sections follow a declared narrative order for
  the surface type.
- **Semantic tone**: purple only on Respond + `actioned` state; red
  only on critical/malicious; no gradients.
- **Empty-state efficiency**: with zero evidence, the surface still
  reads as a complete investigation shell in < 400px vertical.

### 7.3 Failure modes → auto-report
VEEE returns a JSON verdict `{score, findings[]}` per surface. A
score below the "flagship" threshold blocks a Round from shipping
until fixed. Every finding cites a v1.0 rule number.

### 7.4 Roadmap
- v1.0 (this artifact): rulebook + manual gate.
- v1.1: automated screenshot capture + rule scoring in CI.
- v1.2: composition manifest → v1.0 conformance test.

---

## 8 · Iteration loop (mandatory for flagship surfaces)

```
Design compose  →  Render  →  Screenshot  →  VEEE evaluate
      ↑                                          │
      └──────── redesign (cite rule #) ──────────┘
```

Never declare a flagship surface shipped on the first pass. The
Incident record specifically must pass three evaluation cycles
before it can be considered v1.0-conformant.

---

## 9 · Rollout order

1. **Flagship**: Incident record (`Command Band` + `Vitals Rail` +
   `MITRE Table` + `Attack Story` + `Investigation Graph` +
   `Evidence` + `Recommendations` + `Response`). Round 29 delivered
   the first two; the remaining sections are the next rounds.
2. **Alerts**: reuse `Command Band` + `Evidence` + `Entity Card` +
   `Correlation`.
3. **Cases**: aggregate view of related Incidents.
4. **MITRE / Coverage** page: 14-tactic strip promoted to a
   dedicated navigator surface.
5. **Threat Intelligence**: indicator identity + Provenance +
   Enrichment.
6. **Response / Playbooks**: capability + Recommendation cards.
7. **Reports**: exports must also speak the language — PDF and JSON
   render with the same glyph-led hierarchy.

---

## 10 · Governance

- Any pull request touching an analyst surface MUST cite the v1.0
  rules it satisfies.
- Introducing a new colour, new radius, or new elevation requires a
  v1.x amendment to this document.
- Icons that are neither a declared glyph nor a permitted Lucide
  utility are blocked.

---

## 11 · Anti-patterns (rejected v1.0)

- Dark navy page background as the product theme.
- Purple gradient hero banners.
- Rounded 12px+ cards for operational data.
- Emoji or coloured Lucide icons as ontology.
- Metadata sections named after implementation primitives
  (`Truth State`, `Provenance`, `Relationships`).
- KPI cells that render `0` styled the same as `42`.
- Any section whose only job is to prove a primitive is present.

---

_This document is a platform contract. Discussions of "which colour
should this button be" are out of scope — the answer is always
"whatever the token says". Discussions of "which glyph should this
concept use" are in scope; add the glyph to §2 and to
`glyphs.jsx`._

---

# NivXRay XDR Visual Language · v1.1 — Composition Language
> _Established 2026-09-01, immediately after v1.0._
> v1.0 gave the vocabulary. v1.1 is how the vocabulary composes into an
> XDR investigation workspace. Components are speakers of the language;
> **compositions are sentences**.

## 12 · Composition primitives (not cards)

Cards are one composition primitive. NivXRay XDR uses a mixture:

| Primitive             | When                                                     |
|-----------------------|----------------------------------------------------------|
| **Command Band**      | Identity + severity + verdict + status + response        |
| **Vitals Rail**       | Glyph-led metrics: Evidence · Alerts · Hosts · Users …   |
| **Attack Story band** | Evidence-derived attack progression (chevron timeline)   |
| **Graph mini**        | Entity flow: Host → User → Process → File → Network       |
| **Entity cluster**    | Group of same-kind entities with count + top instances   |
| **Timeline**          | Correlated events, source-provenance chip left-aligned   |
| **Compact list**      | 3-line evidence/recommendation preview + "see all N"     |
| **Evidence drawer**   | Expandable evidence body, docked to a row                |
| **Contextual panel**  | Right-side rail with metadata + provenance               |
| **Inline state chip** | Confidence / verdict / severity dot-chip                  |
| **Relationship line** | Two entities + verb + state colour                       |

**Rule**: a page MUST use ≥3 different primitives from this list.
Composing an entire surface out of stacked cards fails VEEE §7.2.

---

## 13 · The flagship — Incident Overview composition blueprint

The Incident record is the composition laboratory. All other analyst
surfaces inherit from this pattern.

### 13.1 Analyst scan path (first viewport, ≤5s)

```
    ┌─ Q1 What happened? ─────────────────────────┐
    │                                              │
Q3 What is affected? ─── Q2 How severe? ─── Q7 What can I do?
    │                                              │
    └─ Q4 Evidence?  Q5 Progression?  Q6 MITRE? ──┘
```

Concretely — every question maps to a fixed viewport position so an
analyst learns "the answer to Qn lives here" once and forever.

### 13.2 Wireframe (empty-evidence state)

```
← Incidents / INC-FE3DD9
┌──────────────────────────────────────────────────────────────────┐
│ 🛡  Suspicious PowerShell Activity            P1 · CRITICAL      │
│    INC-FE3DD9              ● IN PROGRESS      ● VERDICT PENDING  │
│    First seen …   Last activity …   Owner …   Tenant …           │
│    ─────────────────────────────────────────────────────────────  │
│    Ⓔ Evidence — · Ⓐ Alerts — · Ⓗ Hosts — · Ⓤ Users —            │
│    Ⓕ Files — · Ⓣ MITRE — · Ⓒ Correlation —      [ Respond ] [⋯] │
└──────────────────────────────────────────────────────────────────┘

──  no telemetry-backed investigation available. ──
     Attack Story · Investigation Graph · Evidence · Entities ·
     MITRE · Recommendations will render as evidence is ingested.
```

Absent state collapses to a **single** compact hint line — NOT six
"NOT PRESENT" cards. This is the honest-state rule at composition
level (VEEE §7.2 empty-state efficiency).

### 13.3 Wireframe (populated state)

```
← Incidents / INC-7A21C9
┌──────────────────────────────────────────────────────────────────┐
│ 🛡  Ransomware Impact · MedTech-01           P1 · CRITICAL       │
│    INC-7A21C9              ● ACTIVE           ● MALICIOUS         │
│    First seen …   Last activity …   Owner …   Tenant …           │
│    ─────────────────────────────────────────────────────────────  │
│    Ⓔ 42  Ⓐ 24  Ⓗ 3  Ⓤ 2  Ⓕ 7  Ⓣ 7  Ⓒ 17        [ Respond ] [⋯]  │
└──────────────────────────────────────────────────────────────────┘

ATTACK STORY  ─── evidence-derived progression ────────────────────
[TA0001]───[TA0002]───[TA0003]───[TA0005]───[TA0011]───[TA0040]
Init.Access  Exec     Persist   Def.Evasion    C2         Impact
02:14        02:16     02:17     02:19        02:22       02:26

INVESTIGATION GRAPH  ── Host → User → Process → File → Network ────
   [Host medtech-01] ─owns─ [User svc-adm] ─spawned─ [Process pwsh.exe]
       │                                              │
       │                              executed ──── [File a1b2c3.ps1]
       │
   contacted ──── [Domain c2.evil.tld] ── [IP 185.10.5.7]

╔ EVIDENCE (42) ═════╦ ENTITIES (12) ═╦ MITRE (7) ═════╦ RECOMMENDATIONS (5) ═╗
║ 24 EDR events      ║ Ⓗ 3 hosts      ║ TA0002 · T1059 ║ Isolate host          ║
║ 12 file hashes     ║ Ⓤ 2 users      ║ TA0005 · T1055 ║ Reset user creds      ║
║  4 network conn.   ║ Ⓟ 5 processes  ║ TA0011 · T1071 ║ Block C2 domain       ║
║  2 canonical corr. ║ Ⓕ 7 files      ║ …              ║ …                     ║
║ see all 42 →       ║ see all 12 →   ║ see all 7 →    ║ see all 5 →           ║
╚════════════════════╩═════════════════╩════════════════╩═══════════════════════╝

PROVENANCE  Ⓟ Ⓟ Ⓟ Ⓟ  Telemetry ── Canonical ── Correlation ── MITRE
```

Notes:
- **Bottom row** is four **compact lists** (not cards). Each list
  answers one question and links to the deep-dive tab.
- **PROVENANCE** is a compact contextual footer, never a section.
- **Attack Story** and **Investigation Graph** are the visually
  loudest elements — they answer Q5 and Q3 simultaneously.

### 13.4 Composition rules (locked)

C1. **Command Band is one card.** Not a card + a KPI card + a chip
   card + an actions card. One card with an internal rule between
   identity and vitals rail.

C2. **Empty state compresses.** If the incident has no evidence, the
   Attack Story / Graph / bottom row all collapse into a single
   hint line. Never 4+ empty cards.

C3. **Vitals rail lives inside the Command Band** as the last row.
   It is not a separate strip below the band. (This fixes the
   "band → giant KPI card → buttons" waste flagged 2026-09-01.)

C4. **Bottom row is a 4-column module cluster**, each column
   rendered as a compact list (3-6 rows + `see all N →`). No
   duplicate `See details` links.

C5. **Attack Story chevrons are chronological** and evidence-
   anchored (timestamp comes from an actual observed event).

C6. **Investigation Graph mini** shows at most one path per line;
   the full graph lives on the Related tab.

C7. **PROVENANCE** never becomes a headline section on the Overview.
   It renders as a compact footer strip, one line only.

C8. **Analyst-facing headings only.** `TRUTH STATE`, `RELATIONSHIPS`,
   `PROVENANCE` (as a section title) are forbidden on the Overview.
   Use `Vitals`, `Attack Story`, `Investigation Graph`, `Evidence`,
   `Entities`, `MITRE`, `Recommendations`, `Response`.

### 13.5 VEEE composition-level checks (v1.1 additions)

Beyond v1.0 §7.2, VEEE v1.1 also fails a surface when:

- V-COMP-1: fewer than 3 distinct composition primitives are used.
- V-COMP-2: absent-state renders more than one card of "NOT PRESENT".
- V-COMP-3: the KPI rail is rendered outside the Command Band.
- V-COMP-4: the Overview surface duplicates content from deep-dive
  tabs (e.g. re-listing every evidence item instead of a 3-row
  preview + `see all`).
- V-COMP-5: the analyst scan path (§13.1) is broken — e.g. Response
  is below Q4 Evidence.
- V-COMP-6: `PROVENANCE`, `TRUTH STATE`, or `RELATIONSHIPS` appears
  as a section heading.

---

## 14 · Rollout order for v1.1

1. Incident Overview (flagship — this delivery).
2. Attack Story tab v2 — inherits the Attack Story band.
3. Investigation Graph tab v2 — inherits the Graph mini.
4. Alerts detail — reuse Command Band + Vitals rail with narrower
   set (Evidence · Host · User · MITRE).
5. Cases — aggregate of Incident overviews with an additional
   "related incidents" cluster.
6. TI record — Command Band + Provenance + Enrichment cluster.
7. Response console — the bottom row's `Recommendations` cluster
   promoted to a first-class surface.

