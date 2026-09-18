# E2E-UX0 · NIVXRAY XDR ENTERPRISE UX FOUNDATION — BLUEPRINT

Status: **AWAITING OWNER VISUAL APPROVAL**
Gate: no E2E-1…E2E-10 propagation until this blueprint *and* the clickable
prototype are approved.
Prototype route: **`/xdr/_ux0-preview`** (additive, non-destructive, no
production route altered, no production page replaced).

Owner rejection this blueprint answers:
> the current Investigation / Attack Story / Evidence / Command Intelligence
> surfaces read as an **engineering debug console** — vertical logs, raw JSON,
> uniform card rhythm, no answer to "what happened / what is affected / what
> proves it".

---

## 0 · The one rule that was being broken

**API-first does not mean API-response-shaped UI.**

The failure mode was structural, not cosmetic: backend response keys were
mapped 1:1 onto React cards in response order. That produces a console that
*reports fields*. An analyst console must *answer questions*, in a fixed order,
with the engine's internals available but demoted.

Every surface in NivXRay XDR is therefore built on a four-band answer stack:

| band | question | content | placement |
|---|---|---|---|
| **A · Verdict** | What is this and how bad? | severity · verdict · confidence · one-sentence assessment | persistent header |
| **B · Impact** | What is affected? | assets · identities · observables · blast radius | above the fold |
| **C · Narrative** | What happened, in order? | attack story · execution flow · timeline | primary tab |
| **D · Proof** | What proves it? | evidence rows · decoded artifacts · provenance | drill-down + flyout |
| **E · Engine** | How did the product decide? | raw JSON · AST · decoder chain · rule internals | collapsed "Technical details", last |

Band E is never removed — NivXRay's differentiator is that it is *auditable* —
but it is never band A either.

---

## 1 · Live industry research

Sources read for this blueprint (2026-06):

- **Microsoft Defender XDR** — `learn.microsoft.com/defender-xdr/investigate-incidents`,
  `/manage-incidents`, and the Attack Story announcement on techcommunity.
- **Palo Alto Cortex XDR 3.x/5.x** — `cortex-docs.paloaltonetworks.com`
  detailed case view, key assets & artifacts, causality view, forensics
  highlights; Cortex XSIAM custom incident layouts.
- **Cisco XDR** — `docs.xdr.security.cisco.com` incident-detail,
  incident-overview, incident-detection, relations-graph, AI analysis view,
  ribbon incidents app.
- **SOC console craft** — Cisco Security blog *"From frustration to clarity:
  embracing progressive disclosure in security design"*; OpenSOAR engineering
  design-decisions; Elastic EUI; dashboard-density writing.

### 1.1 Observed patterns and the NivXRay decision

| # | Pattern observed | Where | Decision | Rationale |
|---|---|---|---|---|
| 1 | Incident detail = **persistent header + tab set**, processed left→right | Defender (Attack story · Alerts · Assets · Investigations · Evidence and Response · Activities), Cisco (Overview · Detection · Response · Evidence · Worklog · Report) | **ADOPT** | Two of three majors converge. Tabs preserve one URL per incident and stop the infinite vertical scroll we were rejected for. |
| 2 | **Attack story as the centre of gravity**, not a chart | Defender | **ADOPT** | Our detections already carry stage + evidence; the story is the product. |
| 3 | **Metric cards that are drawers** ("View all" → filterable list) | Cisco incident overview | **ADOPT** | Gives band B above the fold and band D one click away without a page hop. |
| 4 | **Right-side flyout for entity/event detail, layered, with breadcrumb + "open full page"** | Cisco event drawer, Defender asset side pane, SOC-craft "investigation rail" | **ADOPT** — we already have `NxFlyout`; make it the only detail mechanism | Preserves investigation context. This is the single biggest fix to our "page hop" problem. |
| 5 | **Key Assets & Artifacts** as a first-class consolidated object list | Cortex | **ADOPT** as the `Entities` tab | Matches our IKG; artifact = our decoded-artifact classes. |
| 6 | **Causality / process-chain view with a group owner on the left** | Cortex causality view | **ADAPT** | We keep the left-to-right chain, but render it as a *narrated* chain (stage → claim → evidence count), not a raw process graph, until the graph has real edge provenance. |
| 7 | **Raw JSON inside the event drawer** for technical inspection | Cisco | **ADAPT** | Keep raw JSON, but only inside the drawer's last section, collapsed, labelled *Technical details*. Never a top-level page body. |
| 8 | **Verdict/disposition on every evidence row** (Malicious / Suspicious / Clean + remediation status) | Defender Evidence and Response | **ADOPT** | One verdict grammar (`NxVerdict`) everywhere. |
| 9 | **Worklog / Activities** — every manual and automated action, for postmortem | Defender Activities, Cisco Worklog | **ADOPT** | We already persist an audit trail; it had no surface. |
| 10 | **AI narrative panel that classifies TP/FP with reasoning** | Cisco AI analysis view | **REJECT (for now)** | We will not ship a confident narrative we cannot evidence. Our equivalent is the *Assessment* band, which is deterministic and cites its basis. Revisit only with per-claim citations. |
| 11 | **Per-tenant / per-analyst custom incident layouts** | Cortex XSIAM 2.3, XSOAR | **REJECT (for now)** | Layout customisation before a good default layout multiplies the problem we were just rejected for. Backlog. |
| 12 | **Dark theme as the only default** | SOC-craft writing | **REJECT as an absolute** | Cisco XDR ships Light default with Auto/Light/Dark; our tokens already support both. Both themes are first-class and both are screenshot-gated. |
| 13 | **"Avoid tabs for alert details — single scrollable view"** | OpenSOAR design-decisions | **REJECT at incident scope, ADOPT at alert scope** | A *detection* is small enough to scroll in a flyout. An *incident* is not: it is a container of alerts, assets, evidence and response. Tabs at incident scope, scroll inside flyouts. |
| 14 | 12-column grid; Rule of 6 per widget group; saturated colour reserved for the top severity; hover-revealed bulk select; row-click navigation | SOC-craft writing | **ADOPT** | Directly fixes the "uniform card grid" complaint. |
| 15 | Node unification in the attack graph (collapse nodes sharing strong identifiers) | Cisco | **ADOPT** as an IKG rule | We already have strong-identifier resolution; use it to reduce graph noise. |

### 1.2 NIVX-DIFFERENTIATORs (patterns we ship that the majors do not)

| # | Differentiator | Why it is ours |
|---|---|---|
| **D-A** | **Epistemic banding on every fact.** Observed / Reconstructed / Decoded / Inferred / Unresolved, rendered as a provenance chip (`NxProvenance`). | None of the three majors tell you whether a displayed value was *seen* or *derived*. We already compute it; it is our trust surface. |
| **D-B** | **Honest decode status as a first-class UI object.** `NOT_REQUIRED / DETECTED / PARTIALLY_RECOVERED / RECOVERED / AMBIGUOUS / UNSUPPORTED / LIMIT_REACHED / FAILED` with the unresolved constructs listed by name. | Competitors show "decoded" or nothing. Showing *what we could not evaluate* is the feature. |
| **D-C** | **"Unavailable" is a designed state, not an empty div.** Every empty state states the reason, the data source responsible, and the one action that would fix it. | Our `NxEmpty` already carries reason + hint; nothing else surfaces *why* a panel is blank. |
| **D-D** | **Evidence-backed ATT&CK only.** A technique chip is unclickable unless it can cite the artifact that justified it. | Removes the industry's favourite hallucination. |
| **D-E** | **Permission-adapted, never role-hardcoded.** Every action, tab and column is gated by effective permission scopes from `/api/xdr/rbac/me/effective`; the UI contains no `isAdmin` literal. | RBAC-0 finding; carried into the prototype. |

---

## 2 · Information architecture

### 2.1 Navigation depth — hard limit of four
```
L1  primary rail (locked, unchanged)
L2  page tabs                      ← incident workspace lives here
L3  flyout (layered, breadcrumbed) ← entity / evidence / artifact detail
L4  full page                      ← only when the object owns a URL
```
A page never grows a second permanent navigation column. A flyout never
becomes a modal that blocks the workspace.

### 2.2 Incident workspace tab set (locked)

| tab | answers | primary object |
|---|---|---|
| **Overview** | verdict, impact, priority, correlation basis | the incident |
| **Attack Story** | what happened, in stage order | narrated chain |
| **Timeline** | when, precisely | events |
| **Evidence** | what proves it | artifacts with verdicts |
| **Entities** | what is affected | assets · identities · observables |
| **Response** | what we did / can do | actions & approvals |
| **Activity** | who did what, when, and on what basis | worklog |

`Command Intelligence` is **not** a tab: it is a *composition* that appears
(a) as a flyout when an analyst opens a command artifact from Evidence,
Attack Story or Timeline, and (b) as a standalone page at
`/xdr/intelligence/command` for ad-hoc analysis. The composition is identical
in both; only the container changes. The prototype shows it in both containers.

---

## 3 · Wireframes

### 3.1 Persistent incident header (sticky, always band A + B)
```
┌───────────────────────────────────────────────────────────────────────────────┐
│ Incidents ›  INC-2291                                        [Light|Dark]     │  breadcrumb row (12px)
│                                                                               │
│ ██ CRITICAL   Credential theft via obfuscated PowerShell on FIN-WS-014        │  h1, 24/28, display font
│ ▸ MALICIOUS · confidence 0.91 · correlated from 4 detections                  │  assessment line, one sentence
│                                                                               │
│ Status      Assignee     SLA          First seen        Assets  Observables   │  fact strip — mono values,
│ In progress a.rahman     02:14 left   14 Jun 09:22 UTC  3       17            │  labels 10px caps
│                                                                               │
│                        [ Assign ▾ ] [ Manage incident ▾ ] [ Take action ▾ ]   │  right-aligned, permission-gated
├───────────────────────────────────────────────────────────────────────────────┤
│ Overview │ Attack Story │ Timeline │ Evidence │ Entities │ Response │ Activity │  sticky tab bar
└───────────────────────────────────────────────────────────────────────────────┘
```
Rules: header height ≤ 168px expanded, collapses to a 56px condensed bar
(severity dot · id · title · actions) after 120px of scroll. The tab bar never
scrolls away. Title wraps to two lines max, then ellipsis with title attr.

### 3.2 Overview — 12-column, asymmetric 8/4
```
┌─ 8 cols ──────────────────────────────────────────┐ ┌─ 4 cols ───────────────┐
│ ASSESSMENT                                        │ │ PRIORITY & SLA         │
│ Obfuscated PowerShell reconstructed a network-     │ │ P1 · breach in 02:14   │
│ reset payload and executed it in memory on one     │ │ ▓▓▓▓▓▓░░░░ 68%         │
│ finance workstation. No exfiltration observed.     │ ├────────────────────────┤
│ [observed] [reconstructed] [decoded]  basis: 4 det │ │ ASSIGNMENT             │
├────────────────────────────────────────────────────┤ │ a.rahman · Tier 2      │
│ ATTACK CHAIN                                       │ │ queue: FIN-EMEA        │
│  Initial access → Execution → Defense evasion →    │ ├────────────────────────┤
│  Discovery → Impact          (stage chips, active) │ │ CORRELATION BASIS      │
├──────────────┬──────────────┬──────────────────────┤ │ 4 detections · 2 rules │
│ ASSETS  3    │ OBSERVABLES  │ INDICATORS  6        │ │ identity pivot: strong │
│ 1 malicious  │ 17 · 4 mal   │ 2 malicious          │ ├────────────────────────┤
│ View all →   │ View all →   │ View all →           │ │ CONTRIBUTING SOURCES   │
├──────────────┴──────────────┴──────────────────────┤ │ Sysmon · EDR · DNS     │
│ DETECTIONS (4)                    compact table    │ │ (3 of 5 connected)     │
│ ▸ sev  rule                 asset      seen        │ └────────────────────────┘
└────────────────────────────────────────────────────┘
```
"View all →" opens a **flyout**, never a new page. Metric cards obey the Rule
of 6: at most six in any one group.

### 3.3 Attack Story — narrated stage rail (not a vertical log)
```
 STAGE RAIL (horizontal, 5 stages, active stage filled)
 ●────────●────────●────────○────────○
 Initial   Exec     Defense  Disc.    Impact
 access             evasion

┌ STAGE 2 · EXECUTION ─────────────────────────────── 3 evidence ─ [Show ▾] ─┐
│ CLAIM    powershell.exe launched with -ExecutionPolicy bypass and          │
│          reconstructed its payload from string fragments at runtime.       │
│ BASIS    Sysmon EventID 1 · process 7412 · FIN-WS-014                      │
│ PROOF    [command artifact ▸]  [process tree ▸]  [parent: outlook.exe ▸]   │
└────────────────────────────────────────────────────────────────────────────┘
```
One card per stage. Card = **claim (prose) · basis (source) · proof (chips
that open flyouts)**. Collapsed by default except the highest-severity stage.
There is no JSON on this tab, at any depth.

### 3.4 Evidence — one table grammar
```
 [ verdict ▾ ] [ type ▾ ] [ source ▾ ]  17 rows      [density] [columns] [export]
 ┌──┬─────────┬───────────────────────┬────────┬───────────┬──────────────┐
 │▢ │ VERDICT │ ENTITY                │ TYPE   │ FIRST SEEN│ REMEDIATION  │
 ├──┼─────────┼───────────────────────┼────────┼───────────┼──────────────┤
 │  │ ● Malic.│ powershell.exe -enc … │ command│ 09:22:14  │ not required │  ← row click → flyout
 │  │ ● Susp. │ 185.199.x.x           │ ip     │ 09:22:51  │ blocked      │
 └──┴─────────┴───────────────────────┴────────┴───────────┴──────────────┘
```
Checkbox column is hidden until row hover or an active selection. Row click
opens the flyout (Fitts's law); interactive sub-elements stop propagation.
Long values truncate mid-string, never wrap the row height.

### 3.5 Flyout — layered, breadcrumbed, escapable
```
                         ┌─ ← Incident INC-2291 ────────────────── ↗ full page ─ ✕ ┐
                         │ COMMAND ARTIFACT                                        │
                         │ powershell.exe -ExecutionPolicy bypass -c "$EbaYA; …"   │
                         ├─────────────────────────────────────────────────────────┤
                         │ SUMMARY      one sentence + verdict + provenance chips  │
                         │ RELATIONS    process ▸ parent ▸ asset ▸ identity        │
                         │ WHY FLAGGED  rule + matched condition + evidence ref    │
                         │ ⌄ TECHNICAL DETAILS            (collapsed, raw JSON)    │
                         └─────────────────────────────────────────────────────────┘
```
Width 560px (evidence) / 720px (command intelligence). Scrim dims but does not
block the header. A second flyout layers with `← back` breadcrumb.

### 3.6 Command Intelligence composition (replaces the JSON dump)
```
┌ ASSESSMENT ───────────────────────────────────────────────────────────────┐
│ ⬤ MALICIOUS   PARTIALLY RECOVERED   powershell · windows-argv            │
│ Obfuscated PowerShell assembles a Base64 payload from string fragments at │
│ runtime, decodes it in memory and executes it via ScriptBlock::Create.    │
│ 9 constructs could not be evaluated statically — the canonical payload is │
│ NOT promoted.                                                             │
└───────────────────────────────────────────────────────────────────────────┘
┌ EXECUTION FLOW ───────────────────────────────────────────────────────────┐
│ 1 OBSERVED       C:\Windows\…\powershell.exe -ExecutionPolicy bypass -c   │ [observed]
│ 2 CONSTRUCTED    $BnWKB assembled from 3 literals + 2 non-string operands │ [partial]
│ 3 DECODED        Base64 → UTF-8                                           │ [decoded]
│ 4 EXECUTED       Invoke-Command ← ScriptBlock::Create($EbaYA)             │ [inferred]
└───────────────────────────────────────────────────────────────────────────┘
┌ WHAT IT DOES ─────────────┐ ┌ NOT EVALUATED (9) ──────────────────────────┐
│ • resets network stack     │ │ non-string-concat-operand  'ZWxlYXN' + 9    │
│ • releases/renews DHCP     │ │ unbound-variable           $EbaYA           │
│ • sleeps 5s between steps  │ │ dynamic-scriptblock        [ScriptBlock]::… │
└────────────────────────────┘ └─────────────────────────────────────────────┘
┌ DECODED ARTIFACT ── class: DECODED_ARTIFACT · NOT promoted as canonical ──┐
│ (mono, line-numbered, copy button, 12 lines then "show all")              │
└───────────────────────────────────────────────────────────────────────────┘
┌ INDICATORS ─────────────┐ ┌ ATT&CK (evidence-backed only) ────────────────┐
│ ip · domain · path rows │ │ T1059.001 ▸ cited by: command artifact         │
└─────────────────────────┘ └───────────────────────────────────────────────┘
⌄ DECODER CHAIN        (per-step: op · reason · complete? · in → out)
⌄ TECHNICAL DETAILS    (raw analyser JSON — last, collapsed, copyable)
```
Hard rules for this composition:
1. Raw JSON is **only** inside `TECHNICAL DETAILS`.
2. `DECODED ARTIFACT` renders the *canonical* artifact when
   `canonical_decoded_artifact.promoted === true`; otherwise it renders the
   candidate with a `NOT promoted` banner and the reason string. Never silently.
3. `NOT EVALUATED` is rendered whenever `unresolved_expressions[]` is
   non-empty — it is the honesty surface, not an error state.
4. ATT&CK chips without a citation are not rendered at all.

### 3.7 Empty / unavailable states — three distinct designs
| state | shape | copy contract |
|---|---|---|
| **No data yet** | outlined well, no icon | "No evidence has been attached to this incident yet." |
| **Source not connected** | well + one action | "DNS telemetry is not connected. 2 of 5 sources contributing." → `Connect source` |
| **Not authorized** | well + basis | "Your effective permissions do not include `incident.respond`. Authorization basis: …" |

A blank panel with a spinner that never resolves is a defect, not a state.

---

## 4 · Component contracts

Everything below already exists in `src/xdr/nx/` or is added by UX0. No page
may hand-roll an equivalent.

| component | contract | status |
|---|---|---|
| `NxIncidentHeader` | `{ id, title, severity, verdict, confidence, assessment, facts[], actions[], condensed }` — sticky, collapses on scroll, actions permission-gated | **NEW (UX0)** |
| `NxTabs` | `{ tabs:[{key,label,count}], active, onChange }` — page-level only | exists |
| `NxDataTable` | `{ columns, rows, onRowClick, density, selectable }` — hover-revealed select, mid-truncation, row-click | exists · extend |
| `NxFlyout` | `{ open, title, eyebrow, onBack, backLabel, fullPageHref, width }` | exists |
| `NxMetricDrawerCard` | `{ label, value, breakdown[], onViewAll }` — the Cisco "card is a drawer" pattern | **NEW (UX0)** |
| `NxStageRail` | `{ stages:[{key,label,state}], active, onSelect }` | **NEW (UX0)** |
| `NxClaimCard` | `{ claim, basis, proof[], severity, defaultOpen }` — the anti-JSON unit | **NEW (UX0)** |
| `NxVerdict` / `NxLifecycle` / `NxPriority` / `NxConfidence` | one severity grammar | exists |
| `NxProvenance` | epistemic band chip: observed · reconstructed · decoded · inferred · unresolved | exists |
| `NxTechnicalDetails` | `{ title, json, defaultOpen=false }` — the ONLY place raw JSON may render | **NEW (UX0)** |
| `NxEmpty` | `{ title, hint, action }` — three variants per §3.7 | exists · extend |

### 4.1 Typography and density (locked)
```
h1 page/incident title   24/28  display 700
h2 panel title           13/18  body 700, +0.3px tracking, sentence case
label / eyebrow          10/12  body 700, uppercase, +0.4px, muted
body                     13/20  body 400
machine fact             12/18  MONO 500      ← every hash, path, id, command
table row (comfortable)  32px · (compact) 26px · (dense) 22px
panel padding            14px · section gap 20px · card gap 12px
```
Colour: saturated red is reserved for `critical`. One accent (amber ink) for
selection and focus. No gradient on any surface. No purple-on-white gradient.

### 4.2 Theme
Both themes are first-class, driven entirely by tokens in `nx-theme.css`
(`.xdr-console` = dark, `[data-nx-theme="light"]` = light). A component that
hard-codes a hex value fails review. Every UX0 screenshot is produced in both.

### 4.3 Permission adaptation (RBAC-0 carry-through)
```js
const { canAny } = useAccess();
// three-valued: false denies, true/null allows (a transient read must not lock out)
{canAny(["incident.respond"]) !== false && <TakeActionMenu/>}
```
No role-name literals. No `isAdmin`. Hidden-vs-disabled rule: an action the
operator could plausibly earn is **disabled with reason**; an entire surface
they cannot hold is **hidden**.

---

## 5 · The prototype

`/xdr/_ux0-preview` · additive route, `Protected`, no permission requirement
beyond authentication, marked with a persistent design-state banner.

Demonstrates, in one place:
shell → persistent incident header (expanded + condensed) → tab set →
Overview (8/4 grid, metric-drawer cards) → Attack Story (stage rail + claim
cards) → Evidence (table grammar → flyout) → Entities → Activity (worklog) →
Command Intelligence composition → layered flyout → all three empty states →
light + dark.

Data honesty in the prototype:
- **Command Intelligence** calls the **real** `POST /api/analyze/command` and
  renders the real contract, including `decode_status`,
  `unresolved_expressions[]` and `canonical_decoded_artifact` from Lane B.
- Every other panel uses **explicitly labelled design-state fixtures**
  (`ux0Fixtures.js`), badged `DESIGN-STATE` in the UI. No fixture is written to
  a database, no production route is altered, no production page is replaced.

---

## 6 · Acceptance checklist for the owner

- [ ] Incident header carries verdict + impact and survives scroll
- [ ] Tab set matches §2.2 and processes left→right
- [ ] Overview answers "how bad / what is affected" above the fold
- [ ] Attack Story is narrated claims, not a vertical log; zero JSON
- [ ] Evidence is one table grammar; row click opens a flyout, not a page
- [ ] Flyouts layer with breadcrumb and an "open full page" escape
- [ ] Command Intelligence shows assessment → flow → behaviour → artifact →
      indicators → ATT&CK, with JSON demoted to Technical details
- [ ] `PARTIALLY_RECOVERED` and `NOT EVALUATED` are visible, not hidden
- [ ] Three distinct empty/unavailable states, each stating the reason
- [ ] Light and dark both legible at density = compact
- [ ] No role literals anywhere in the prototype

## 7 · Out of scope for UX0 (do not start)
E2E-1…E2E-10 propagation · deleting or replacing any production page ·
RBAC-1+ · W1 · W2-1 · decoder semantics (Lane B owns those) ·
per-tenant layout customisation · AI narrative panel.

## 8 · STOP
Blueprint + prototype delivered for **visual** approval. No destructive
migration until the owner approves the prototype screenshots.
