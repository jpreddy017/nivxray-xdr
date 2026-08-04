# NivXRay · Roadmap · Product Hardening Phase
_Baseline: M2 Hero build (approved). New capability development frozen._

## Rule of the road
> Perfect one workflow → observe analyst → improve workflow → only then add capability.

No feature moves to the next phase until the phase it lives in is production-quality.

---

## Phase 3 · Artifact Intelligence Layer — CLOSED (Feb 2026)

- ✅ **Cycle A** — PE Static Analyzer (`pefile`)
- ✅ **Cycle B** — PDF + Office OOXML Analyzers + `ThreatSummaryCard`
- ✅ **Cycle C** — **ELF Analyzer** (2026-02-15, iteration_61 · 33/33 backend · 100% frontend · zero regressions)

Phase 3 delivered a full artifact-first architecture: PE · PDF · Office · ELF are
routed deterministically through the Artifact Intelligence Layer, verdict/risk
surfaces via `ThreatSummaryCard`, and every analyzer degrades gracefully when
its dependency is absent.

---

## Phase 4 · Investigation Intelligence — CURRENT PHASE (owner directive · 2026-02-15)

> **Architectural pivot:** Stop adding more parsers. Start connecting analyzed
> artifacts into a single investigation. NivXRay evolves from *collection of
> analyzers* → *artifact-first investigation platform*.

### P1 · Cross-Artifact Correlation (⏭️ next up)
Correlate related artifacts into **one deterministic investigation**, not four
independent reports.

**Architectural rule (owner directive · 2026-02-15):**
> **An Investigation is a first-class entity, not a collection of linked cases.**
> Cases remain atomic records; the Investigation becomes the analyst's primary
> working object with its own timeline, evidence graph, threat summary, attack
> story, artifacts, cases, and relationships.

**Owner-locked design (2026-02-15):**
- **1c + 1d — Correlation trigger:** Auto-chain child artifacts within the same
  decode/session (recursive inline chaining, ALWAYS auto), PLUS auto-suggest
  cross-case correlations from deterministic shared evidence (hashes, URLs,
  C2, IOC overlap, MITRE overlap) for analyst confirm/dismiss.
- **2c — Data model:** Hybrid — new `investigations` collection + each case
  carries `investigation_id` back-reference. Cases stay atomic; investigations
  evolve independently.
- **3c — Visualization:** Chain View (default, top-to-bottom attack progression)
  + Graph View (deep-dive force-directed evidence graph) with a toggle.
- **4c — UI placement:** New top-level **INVESTIGATIONS** tab peer to HISTORY.
  HISTORY continues to show all cases; member cases display an
  "Investigation: <name>" badge with click-through to the investigation.
- **5d — Scope (Full P1):** Manual linking · auto suggestions · evidence graph ·
  unified timeline · provenance back-links · **recursive inline chaining**
  (NOT deferred — foundational to preserving provenance at capture time).

Example chain:
```
Email (.eml) → Office Document → PowerShell → PE Payload → Persistence
```

Deliverables:
- Unified attack chain with artifact-to-artifact edges + edge provenance
- Shared evidence graph (nodes = artifacts + IOCs; edges = relationships)
- Unified timeline across all artifacts in the investigation
- Consolidated `InvestigationThreatSummaryCard` at investigation level
- Deterministic MITRE aggregation (union with evidence back-links)
- Recursive inline chaining wired into `recipe_planner` — when a decode
  surfaces child artifacts, they auto-attach to the same investigation with
  `source=inline_recursive`.
- Cross-case correlator: deterministic evidence matcher emitting confidence-
  scored suggestions the analyst approves/dismisses.
- New INVESTIGATIONS tab + investigation-detail page (Chain / Graph / Timeline).
- Ships as a complete feature, not a preview.

### P2 · Compare Cases (⏸️ queued)
Side-by-side diff of two cases across:
Interpreter · MITRE · LOLBAS · IOCs · Hashes · Threat Summary · Canonical Output · Attack Story
plus a **deterministic similarity score** for malware clustering (e.g. "91%,
shared: T1105 T1059 Net.WebClient · different: persistence, C2").

### P3 · Saved Collections (⏸️ queued)
Analyst-facing tagging/grouping on the History page — APT29 · QakBot ·
Customer A · Incident 104 · Campaign July. Collections organize investigations
without changing analysis results. MSSP-friendly.

### P4 · Mach-O Analyzer (⏸️ queued)
Fifth first-class artifact type, same artifact-first UX as PE/PDF/Office/ELF.
Same graceful-degradation contract. Reframed from "add another parser" → the
macOS wing of the Artifact Intelligence Layer.

### Deferred
- **YARA Auto-Match** — HOLD until `yara-python` is verified in the environment.
  Do NOT implement placeholder UI. When available: rules, matching, severity,
  tags, integration into `ThreatSummaryCard`, generic (not PE-only) scanner.
- **Archive Analyzer** (ZIP / 7z / RAR / ISO / CAB / IMG) — deferred until after
  Mach-O. Pairs naturally with Cross-Artifact Correlation because archives
  expand into linked artifacts that must preserve provenance.

---

## Phase 5 · Semantic Provenance Engine (SPE) — architectural direction (queued)

Begins **only after** Phase 4 is production complete. Not another analyzer, not
a sandbox, not an emulator — a **deterministic semantic analysis layer** sitting
after the Recursive Transformation Engine. Explains *how* malicious behavior is
constructed.

Capabilities:
- Variable provenance
- Expression graphs
- Data-flow graphs
- String reconstruction
- API resolution
- Behavioral pattern detection
- Evidence graphs

Integrates with the existing Workspace, `ThreatSummaryCard`, and Investigation
Knowledge Graph. Must preserve the **shared deterministic convergence
architecture** — single certified model across components, no divergent
behavioral implementations.

---

## Non-negotiable architectural principles (all phases)

1. Artifact-first workflow
2. Deterministic-first analysis (AI-optional, never in decode path)
3. Graceful degradation for every optional capability
4. Evidence-backed findings (severity + code + title + detail + back-link)
5. Single analyzer per artifact type
6. Stable certification + regression gates before phase close
7. **Shared deterministic convergence architecture** — one certified model,
   never divergent implementations

---

## P0 — Complete Investigation Experience (in-flight)
Hard block on any new capability until every box below is checked. Verified against
the six analyst tasks in `USABILITY_REVIEW.md`.

- [ ] Root process immediately identifiable on landing
- [ ] Parent-child ancestry rendered from real adapter data (blocked by P1)
- [ ] Process lifetimes render as accurate spans (start → end)
- [ ] Event density comparable to enterprise EDR (30+ rows in 900 px)
- [ ] Evidence panel synchronization is instantaneous on click
- [ ] Hover and selection states polished (no flicker, no lag, no dropped tooltips)
- [ ] Keyboard navigation complete (↑ ↓ ← → F H L Esc ⌘K ⌘\ ⌘D ?)
- [ ] Smooth pan, zoom, focus (60 fps sustained)
- [ ] Investigation workflow requires minimal scrolling (fit-to-content default)
- [ ] Every major analyst task completes naturally (see usability review)

## P1 — Adapter Ancestry (backend, engineering-priority)
Every emitted event must include: `entity.iid`, `parent.iid`, `root.iid`,
`process_start` (epoch ms), `process_end` (epoch ms).
Contract change lives in `/app/backend/v2/adapters/` and the shadow observation
schema. Without this, canvas ancestry is a heuristic. **Blocks P0 items 2 and 3.**

## P2 — Report Export
PDF · Markdown · JSON · STIX 2.1 · Evidence Package. Unlocks direct customer
value the moment P0 + P1 ship.

## P3 — Phase 2 (deferred)
- Analyst Playback
- Case Comparison


## Milestone Ordering (2026-08-02 · owner directive)

> The project has now crossed from **decoder stabilisation** into
> **capability expansion**. Engineering effort moves upward in the
> stack. This is the authoritative priority order for the next
> milestones.

### Priority 1 — Real Sanitised Telemetry ⭐⭐⭐⭐⭐
The highest-value activity because it strengthens every downstream
capability: parser validation, deterministic decoding, Investigation
Graph, Timeline, Attack Chain, Correlation, future semantic work.
Rather than optimising against synthetic samples, validate against
telemetry users actually investigate.

**Sources to onboard** (owner priority order):
- CrowdStrike Falcon EDR event stream
- SentinelOne Deep Visibility
- IBM QRadar / LEEF
- Splunk CIM-normalised feeds

Deliverable: sanitised samples land under a versioned corpus with
provenance notes and rehydration-safety metadata.

### Priority 2 — Deterministic Decoding Corpus ⭐⭐⭐⭐
A permanent, versioned corpus for the decoder:
- Enterprise administration scripts
- LOLBins / living-off-the-land PowerShell
- Bash administration pipelines
- CMD installers
- Malware families
- Mixed-obfuscation chains

Rule: every future bug fix contributes another permanent regression
sample.

### Priority 3 — Timeline / Attack Chain ⭐⭐⭐⭐
Starts only after the evidence layer is mature. The Timeline
**consumes validated Investigation Graph evidence** — it must not
introduce new inference into the parser.

**Update 2026-02-XX** — Timeline Builder (Stage 9) landed as a
deterministic renderer over the Investigation Graph. Contract enforced
via 19 tests: no invention, actor never in own targets, phantom-node
guard, empty-CEM → empty timeline, byte-identical determinism.
Wired ONLY into `POST /api/v2/timeline/preview` (X-Lab / read-only).
Next: Attack Chain Builder on top of the Timeline, then Correlation.


## P1 — Interpreter Ownership Coverage (measurable Workspace quality signal)
_Filed 2026-08-02 by owner as part of the Workspace stabilisation phase._

Introduce a persistent, corpus-driven metric that lives alongside the unit
regression suite. Purpose: give Workspace a measurable quality indicator
beyond "395/395 tests pass" so interpreter-routing stability can be tracked
as the corpus grows.

**Deliverable** — a JSON summary at
`/app/backend/tests/investigation/interpreter_ownership_coverage.json`,
regenerated on every pytest run of a new
`test_interpreter_ownership_coverage.py`:

```
{
  "generated_at": "2026-08-XX…",
  "git_sha": "…",
  "corpus_size": N,
  "by_interpreter": {
    "bash":       { "samples": …, "correctly_routed": …, "rate": … },
    "cmd":        { "samples": …, "correctly_routed": …, "rate": … },
    "powershell": { "samples": …, "correctly_routed": …, "rate": … },
    "mixed_launcher": { "samples": …, "correctly_routed": …, "known_limitations": … }
  },
  "regressions_since_last_run": [ … ]
}
```

**Corpus sources** (growable, real-world first — no synthetic special-casing):

- Bash: real malicious shell command lines (sanitised)
- CMD: real Windows batch / cmd invocations (sanitised)
- PowerShell: real enterprise PowerShell command lines (sanitised)
- Mixed launcher: real cases where a non-PS launcher wraps a PS payload
  (documented as *known limitations*, not as production regressions)

**Acceptance:**

- Report regenerates on every test run and never raises
- Never gates cut-over or deploy — this is a health signal, not a criterion
- Mixed-launcher rows carry an explicit `known_limitations` field so
  currently-under-decoded nested cases stay visible without being flagged
  as regressions
- Corpus grows over time; new samples arrive with sanitisation notes

Not a hotfix. Awaits the current P0 hero-build work.


## P2 — Nested Interpreter Detection (Workspace decoder, future capability)
_Filed 2026-08-02 by owner as follow-up to the PowerShell Interpreter Gate hotfix._

Treat this as a **new feature**, not a bug. The Interpreter Gate that shipped in
`routers/ops.py` is a subtractive heuristic: any leading token in
`{eval, sh, bash, dash, zsh, ksh, openssl, tr, sed, awk, xxd, rev, curl, wget,
python, python3, perl, ruby, node, cmd, cmd.exe}` (plus shebangs, `$(...)`,
leading backtick substitution) skips all PowerShell-specific normalization
stages. This is deliberately conservative — the worst case is that a *nested*
PowerShell invocation such as `cmd /c powershell -enc …` or
`bash -c 'powershell …'` reaches the analyst un-decoded, which is far safer
than the alternative of rewriting Bash text as PowerShell.

**Do not close this backlog item by expanding the blocklist / allowlist.**
Owner directive: chasing launcher patterns (sh -c powershell, dash -c pwsh,
env bash -c powershell, sudo powershell, python subprocess.run([...powershell]),
Start-Process powershell, CreateProcess → powershell, …) is a losing game.

**Correct architectural solution** — a generic **Launcher Detector**:

```
Raw input
    │
    ▼
Interpreter classification (CMD / Bash / Python / …)
    │
    ▼
Launcher analysis  ← NEW
    │
    ▼
Effective interpreter (may differ from launcher)
    │
    ▼
Interpreter-specific decoder
```

Examples the Launcher Detector must handle correctly:

- `cmd /c powershell -enc …`  → launcher=CMD, payload=PowerShell
- `bash -c 'powershell Get-Process'` → launcher=Bash, payload=PowerShell
- `sh -c pwsh …` → launcher=sh, payload=PowerShell
- `python -c "subprocess.run(['powershell', ...])"` → launcher=Python, payload=PowerShell
- `sudo powershell` → launcher=sudo, payload=PowerShell
- `Start-Process powershell -ArgumentList …` → launcher=PowerShell, payload=PowerShell (nested)

Acceptance: the decoder correctly routes a **nested PowerShell payload**
through PowerShell normalization even when the outermost interpreter is
non-PowerShell. Regression tests cover every launcher shape above plus at
least one adversarial case where the payload only *mentions* PowerShell in a
string literal (must NOT be treated as a nested PS invocation).

**Priority**: P2. Not a hotfix. Waits until the current P0 + P1 hero-build
work is complete.

Not blockers. Do not start until P0 + P1 + P2 are complete.

---

## Milestone-closing template (all future milestones must follow this)
Each milestone ends with exactly four lines:
1. What was completed.
2. Screenshot or short video of the result.
3. Any blockers (if any).
4. The single next priority.

No feature suggestions, no roadmap speculation, no "next action items" list.



---

## Post-Workspace P0 Capability Backlog (2026-02 · ARB)

> Captured **after ARB re-affirmed roadmap discipline**. These items are NOT
> authorised until the approved Workspace milestones (PR-4 → PR-8) ship.
> Rule 20 / 21 remain binding.

### P0-C1 · PowerShell Invocation Simplifier (deferred to post-PR-8)

**Status**: Backlog · **Type**: New interpreter capability (Rule 19) · **Not a bug fix**.

**Motivation**: Payload
`powershell.exe -NoProfile -Command "&(('Get-' + 'Process') 'lsass')"`
currently folds the string concatenation but leaves the `&(...)` invocation
unresolved. The canonical output should be `Get-Process lsass`.

**Scope**: Deterministic AST simplification of provably-deterministic PS
invocation forms **only**. Interpreter-owned (Rule 19). No runtime execution.

Examples that MUST be handled:
- `&('Get-Process') 'lsass'` → `Get-Process lsass`
- `&('who' + 'ami')` → `whoami`  (after string-fold)
- `&($cmd)` where `$cmd` deterministically resolves to a string literal
  earlier in the same script → `<resolved cmdlet>`

Examples that MUST NOT be handled by this simplifier (out of scope,
non-deterministic):
- `&($cmd)` where `$cmd` comes from a network read, env lookup, or any
  non-literal source.
- Any invocation whose target requires runtime state.

**Placement in roadmap**: After PR-8 (Workspace Persistence) and before P1
Corpus Expansion. It is a P0 capability because analysts hit it on real
LSASS-dump precursors, but sequencing goes through the Workspace milestones
first per ARB.

**Rule alignment**: Rule 17 (canonical consumer) · Rule 19 (interpreter
ownership) · Rule 22 (generic primitive, not sample fix) · Rule 23
(stability gate is what tells this simplifier when to run and when to stop).

**Blockers**: None technical. Blocked purely by roadmap discipline (Rule 20).

---

### P0-C2 · ACDE — Autonomous Canonical Decoding Engine (post-P1, architectural)

**Status**: Post-P1 architectural evolution · **Not authorised before**:
1. All P0 Workspace milestones ship (PR-4 → PR-8), AND
2. P1 Corpus Expansion is under way (or complete).

**Vision**: Evolve NivXRay from a plugin-driven decoder chain into a
deterministic planning engine that asks *"what am I looking at, what
deterministic transformations are present, and what is the next provably
correct step toward canonical?"* — never *"which decoder should I run?"*.

**Phased architecture** (all phases governed by Rule 20 sequencing and
Rule 23 stability principle):

| Phase | Name | Purpose |
|---|---|---|
| ACDE Phase 1 | **Input Intelligence** | Interpreter identification + confidence scoring before any decoder runs. |
| ACDE Phase 2 | **Capability Registry** | Small reusable deterministic capabilities (Base64, Hex, XOR, GZip, AES, RC4, UTF16, string+, char[], env, invocation, alias, AST fold, pipeline, …), each shared across interpreters. |
| ACDE Phase 3 | **Planner** | Builds a deterministic execution graph automatically; no hard-coded decoder chains. |
| ACDE Phase 4 | **Stage Evaluation** | Progress scoring (entropy, printable ratio, AST complexity, wrapper reduction, new IOC recovered, canonicality score). |
| ACDE Phase 5 | **Deterministic Self-Healing** | Only when progress is provable. Never guesses, never invents outputs, never calls an LLM to fabricate a decode. |
| ACDE Phase 6 | **Evidence Verification Engine** | Verifies external documentation / claims against deterministic execution reality. |

**Non-goals of ACDE (permanent)**:
- ACDE will never eliminate the need for adding new capabilities when a
  genuinely new obfuscation primitive appears. The goal is that *new
  combinations of known techniques* need zero new code; only *new primitives*
  require new code (Rule 22 remains binding).
- ACDE will never introduce non-deterministic reasoning into L0.

**Roadmap position**: Explicitly deferred until after P0 Workspace + P1
Corpus Expansion. Any earlier attempt to implement ACDE violates Rules
20 / 21 / 23.

**Design ownership**: Captured here as an architectural preservation record
so the vision isn't lost between milestones. Full HLD/LLD to be drafted
when ACDE Phase 1 is authorised.

---

### Sequencing (authoritative, 2026-02 · ARB)

```
PR-4  Executive Summary + Attack Story           ← current PR
PR-5  MITRE + IOC + Capability cards
PR-6  Certificate + Raw Decode cards
PR-7  Page consolidations & route redirects
PR-8  Export bar wiring + Workspace Persistence
───── (Workspace P0 complete) ─────
P0-C1 PowerShell Invocation Simplifier            ← queued
P1    Corpus Expansion
───── (P1 in-flight or complete) ─────
Phase B Stage Quality Gates                       ← Rule 23 implementation window opens
Phase C Deterministic Self-Healing
───── (Post-P1) ─────
P0-C2 ACDE Phase 1 → Phase 6                      ← incremental architectural evolution
```

**No item may jump the queue.** Rule 20 anchors this sequence.
