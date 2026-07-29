# NivXRay — Product Charter & v1.6.0 Roadmap

_Established 2026-02-28. Ratified by SME. This document supersedes any
loose priorities in PRD.md or historical planning docs. It is the
non-negotiable definition of what NivXRay is and how the next major
release must be shaped._

---

## 1 · Identity

> **NivXRay is a deterministic malware investigation assistant that
> explains command lines, scripts, shellcode, and attack behavior in
> analyst language while showing the evidence behind every
> conclusion.**

This is the strongest differentiator vs "another decoder." Every new
capability must strengthen this identity or it does not ship.

---

## 2 · Mission (v1.6.0)

> **Improve analyst trust and investigation quality. Every conclusion
> should be explainable, evidence-backed, and deterministic where
> possible.**

Feature count is not the metric. Analyst trust is.

---

## 3 · Engineering Principles (LOCKED · non-negotiable)

Every PR touching investigation output must uphold these. Reviewers
reject anything that violates them, no exceptions.

### Rule 1 — No unsupported conclusions

Do not emit:

* "This is Zoom"
* "This is legitimate"
* "No SOC action required"

…unless there is evidence supporting the conclusion.

### Rule 2 — Separate facts from inference

Every report and every UI panel distinguishes:

```
Observed  · direct evidence in the sample
Likely    · inference chained from ≥2 observed facts
Unknown   · no supporting evidence — DO NOT guess
```

### Rule 3 — Every verdict needs evidence

Bad:
```
MSFVenom
```

Good:
```
Evidence
  ✓ PEB traversal
  ✓ WinInet resolver
  ✓ Embedded User-Agent
  ✓ HTTP bootstrap
       ↓
Conclusion
  Network stager
```

### Rule 4 — Unknown is acceptable

Prefer `Executable unknown` over `Likely Zoom`. An honest gap builds
more trust than a confident guess.

### Rule 5 — Deterministic first

AI may enhance explanations. AI must never replace deterministic
analysis. If a claim exists in the AI layer only, it must be labelled
as such and must be revocable without touching the deterministic
pipeline.

### Rule 6 — Explainability by default

Every conclusion must answer "Why?" via a linked Evidence chain.
Analysts click a verdict, see the reasoning, see the source bytes.

### Rule 7 — Performance transparency

Every investigation displays end-to-end time and per-stage timing.
Slow paths are visible to the analyst.

---

## 4 · v1.6.0 Roadmap — Ship in this Order

### Phase 1 · Semantic Command Understanding (P0)
_Explain command lines like an experienced SOC analyst._

Deliverables:
- Detect command type: PowerShell, CMD, Bash, Application CLI, Shellcode, etc.
- Explain each argument in plain English
- Classify behaviour: configuration, downloader, installer, persistence, network, etc.
- Separate Facts / Likely / Unknown (Rule 2)
- Zero unsupported conclusions (Rule 1)
- Semantic def-use analysis per `/app/memory/V1_6_0_PLANNING.md`

#### Phase 1a · Plain-Text Command-Line Investigation (P0 — added Feb-2026 SME)

_Command lines are FIRST-CLASS investigation artifacts, not just wrappers
around encoded payloads. When the analyst pastes a plain-text CLI (e.g.
Zoom `--haszoomim=1`, MSI installer flags, ffmpeg args, application
`--useroption*` bundles), the engine must produce a real analyst
narrative — never a generic "no encoding detected" fall-through._

**Required investigation output** for any plain-text CLI artifact:

1. **Command Classification** — PowerShell / CMD / Bash / Application CLI /
   Installer / Service / Scheduled task / Python / Java / etc.
2. **Argument Analysis** — every meaningful argument explained in
   analyst-friendly language. Numeric configuration values that cannot
   be interpreted MUST be labelled `Unknown` per Rule 2, never guessed.
3. **Investigation Summary** — plain-English narrative describing what
   the command WOULD do, based only on observed evidence.
4. **Evidence** — enumerated `Observed ✓` list (PS syntax present /
   absent, base64 present / absent, URLs, IPs, file ops, registry ops,
   execution primitives, network ops).
5. **Unknowns** — explicit `Unknown` block for what CANNOT be concluded
   (executable name, vendor, digital signature, parent process, runtime
   behaviour, etc.).
6. **Verdict + Confidence + Reason** — three-tier confidence per Rule 2.
   `Reason` cites the limiting factor (e.g. "only command-line arguments
   provided without associated executable or execution context").

**Explicit non-goals for Phase 1a:**
- Do NOT invent vendor identity from a single flag (Rule 4: `--haszoomim`
  is INSUFFICIENT evidence for "Zoom").
- Do NOT emit "No malicious behavior" without evidence — say
  "No malicious indicators observed FROM THE SUPPLIED command line
  alone" and enumerate what would be needed to conclude further.
- Do NOT produce empty / generic / boilerplate output for CLIs the
  engine has no signature for. Always fall through to the Argument
  Analysis + Unknowns narrative structure.

This is a strict superset of the existing `command_analyzer.py` —
audit its current behaviour against these rules before writing new
code and only extend where the current implementation violates a
Rule 1-4 principle.

##### First objective of Phase 1a (SME-ratified, Feb-2026)

**REFACTOR before EXTEND.** Do not add new capabilities to
`command_analyzer.py` before removing the pre-Charter heuristics
that violate Rules 1 & 4. Concretely, the following inferences must
be DELETED from the analyzer:

- Any path that emits `"benign"` from *absence* of malicious indicators
- Any path that emits `"legitimate"` / `"legitimate application"`
- Any single-flag vendor identification (e.g. `--haszoomim` → "Zoom")
- Any `"no action required"` recommendation without positive
  corroborating evidence

Then introduce a **tri-state verdict model** — this replaces the
current binary MALICIOUS/BENIGN:

| State                     | When to use                                                  |
|---------------------------|--------------------------------------------------------------|
| `Malicious`               | Positive evidence of malicious behaviour                     |
| `Suspicious`              | Mixed or incomplete evidence                                 |
| `Unknown` / Indeterminate | Insufficient evidence to classify (default for plain-text CLIs without executable context) |

`Benign` is intentionally OMITTED as a default state. Benign requires
**positive evidence of legitimate behaviour** (signed executable,
known-good hash, canonical vendor CLI pattern, etc.) — never the
mere absence of malicious signals.

##### Phase 1a mandatory success criteria (release gate)

- ❌ NEVER infer a vendor from a single flag
- ❌ NEVER infer legitimacy from missing malicious indicators
- ❌ NEVER recommend "no action required" without corroborating evidence
- ✅ ALWAYS emit `Classification:` (explicit section header)
- ✅ ALWAYS separate Observed / Unknown / Conclusion (Rule 2)
- ✅ ALWAYS explain the confidence level with a `Reason:` line
- ✅ Every conclusion cites supporting evidence (Rule 3)

Ship Phase 1a only when the SME acceptance sample
(`--runaszvideo=TRUE ... --haszoomim=1`) produces a report with:
- `Verdict: Unknown` (not Benign)
- No `"Zoom"` vendor identification
- No `"legitimate application"` phrase
- Explicit `Classification: Application CLI (unknown vendor)` header
- Explicit `Unknowns:` block listing what cannot be concluded

##### Phase 1a Definition-of-Done — gold-standard report

The plain-text CLI acceptance sample MUST produce output structurally
equivalent to this reference (SME-ratified 2026-02-28). Wording may
vary; structure and omissions may NOT.

```
Classification
  Application Command Line

Summary
  This artifact contains application-style command-line arguments.
  No scripting constructs, encoded payloads, execution primitives,
  network indicators, or persistence mechanisms were identified.
  The available evidence is insufficient to determine the associated
  software or its runtime behavior.

Observed
  ✓ Plain-text arguments
  ✓ Configuration-style flags
  ✓ Numeric option values

Unknowns
  • Executable
  • Vendor
  • Runtime context
  • Parent process
  • Actual behavior

Verdict
  Unknown

Confidence
  Medium
```

**Omissions matter as much as inclusions.** The following MUST NOT
appear anywhere in the report:
- `Zoom` (any form — "Zoom", "Zoom-related", "likely Zoom")
- `Legitimate application` (or `legitimate` in a conclusion)
- `Benign` (as a verdict for insufficient-evidence cases)
- `No action required` (any phrasing)

##### The universal quality gate

Every investigation feature added from v1.6.0 onward MUST satisfy
this single test:

> **If an experienced SOC analyst asks "Why did the engine conclude
> that?", the report should already contain the answer.**

If the answer isn't in the report, the feature isn't done. This
supersedes any other acceptance criterion and applies to Semantic
Command Understanding, Evidence-backed Reasoning, Application
Recognition, and every panel in the Workspace.

### Phase 2 · Evidence-backed Reasoning (P0)
_Every conclusion must be traceable to evidence._

Deliverables:
- New "Evidence → Conclusion" section in the UI (Rule 3)
- Every IOC linked to the source bytes / strings / command tokens
- Every verdict includes supporting evidence + confidence score
- Explicit `evidence_refs: [{stream, offset, length, token}]` on every
  intent + verdict object
- Hover-to-highlight: click a conclusion → source spans in input /
  decoded panels light up

### Phase 3 · Application & Vendor Recognition (P1)
_Identify software only when justified._

Deliverables:
- Vendor CLI signature database
- Recognition requires ≥2 corroborating indicators from: executable
  name, code-signing publisher, known CLI pattern, PE metadata,
  path convention
- Ban single-flag inferences (Rule 4)
- Emit explicit `unknown application (single weak signal: --haszoomim)`
  when evidence is insufficient

### Phase 4 · Performance Profiler (P1)
_Show analysts how efficiently NivXRay processed the sample._

Deliverables:
- End-to-end analysis time (headline metric)
- Per-stage timings, collapsed by default:
  ```
  ⚡ Analysis Performance
  Analysis completed in 18.4 ms
  ▼ View Details
    Input Classification    0.4 ms
    Parser                  0.8 ms
    Decoder                 6.1 ms
    Semantic Engine         3.2 ms
    IOC Extraction          0.9 ms
    ATT&CK Mapping          0.6 ms
    Threat Scoring          0.5 ms
    Report Generation       2.4 ms
    ─────────────────────────────
    Total Analysis Time    14.9 ms
  ```
- Input size + decoded size
- **Benchmark Mode**: run against a fixed corpus and report Avg / P50 /
  P90 / P95 / Max + decode success rate. Enables comparison against:
  - Manual analyst workflow baseline
  - CyberChef-assisted workflow
  - Previous NivXRay releases
- Piggybacks on the v1.5.6 offload infrastructure — timings already
  exist in the executor, this phase just surfaces them.

### Phase 5 · Golden Analyst Corpus (P1)
_Prevent regressions, drive trust._

Deliverables:
- Curated real-world SOC samples (categorized: Malware / Benign /
  Ambiguous / Decoder-family)
- Each sample carries the expected: Explanation · Behaviour · ATT&CK
  · IOCs · Verdict · Confidence
- CI validation against the corpus on every release
- Fed by `/app/memory/REAL_WORLD_LOG.md` — real SOC cases drive the
  next batch of corpus additions

---

## 4.5 · Validation Mode (active — Feb-2026 → next decision point)

_Between Phase 1a shipping and Phase 1b starting, NivXRay is
intentionally frozen. The engine has just undergone an
architecture-level change (tri-state verdict, benign-by-absence
removed) and must be validated against real analyst experience
before more heuristics are layered on top._

### Operating principles (LOCKED for this phase)

**P-A · Every real case is an asset.**
A correct verdict earns a free regression test. A wrong verdict
earns a concrete, prioritized improvement request. Neither
outcome is wasted — both go into `/app/memory/REAL_WORLD_LOG.md`.

**P-B · A justified `Unknown` is a success.**
Pre-Phase-1a, the engine could confidently emit `Benign` without
evidence. It can now honestly emit `Unknown`. In incident
response, an honest gap builds more trust than a confident
guess. `Unknown` is only a failure when the evidence WAS present
and the engine failed to use it.

**P-C · Build from repeated patterns, never isolated examples.**
One case needing vendor recognition does NOT justify a new
subsystem. ~20 similar cases probably do. The data determines
the roadmap; the roadmap does not determine the data.

### The single validation metric

Maintain a running Missing-Evidence tally inside
`/app/memory/REAL_WORLD_LOG.md`. Example shape:

| Missing Evidence | Cases | Priority |
|------------------|-------|----------|
| Executable name  | 12    | High     |
| Digital signature| 9     | High     |
| Parent process   | 4     | Medium   |
| Network context  | 3     | Medium   |
| Registry         | 1     | Low      |

Phase 1b scope is derived from this table, not from intuition.

### Unfreeze ritual (mandatory before Phase 1b coding begins)

When the log reaches ~20–30 real cases, do NOT open an editor.
Instead run one review session that answers only three questions:

1. Which evidence type appears most often across the log?
2. Which single improvement would have flipped the most
   `Unknown` verdicts to a higher-confidence, correct call?
3. Which single improvement would have raised analyst
   confidence the most, even where the verdict was already
   correct?

The answers to these three questions define Phase 1b's scope.
Anything not required by the answers is deferred.

### Project Health Scorecard (updated after every review session)

_This is the objective go / no-go signal. Do not open Phase 1b
until "Phase 1b justified?" reads `Yes`._

| Metric                    | Current |
|---------------------------|---------|
| Real SOC cases reviewed   | 0       |
| `Unknown` verdicts        | 0       |
| Incorrect verdicts        | 0       |
| Top missing evidence      | —       |
| Phase 1b justified?       | No      |

Update rules:
- **Real SOC cases reviewed** — count of entries in `REAL_WORLD_LOG.md`.
- **`Unknown` verdicts** — subset where the engine emitted `Unknown`.
- **Incorrect verdicts** — verdict did not match the analyst's expected conclusion (any band).
- **Top missing evidence** — highest-count row from the Missing-Evidence tally.
- **Phase 1b justified?** — `Yes` only when the top missing-evidence
  bucket both (a) accounts for ≥30% of incorrect-or-`Unknown` cases
  and (b) has ≥20 supporting cases logged.

### Handoff instruction (mandatory first read for any new engineer / agent)

> **Do not write Phase 1b code until the Validation Mode exit
> criteria in this section are satisfied.** Read the scorecard
> above. If `Phase 1b justified?` is `No`, the correct next
> action is to help the analyst investigate and log real cases —
> not to write new heuristics.

---

## 5 · Post-v1.6.0 backlog (deferred)

- UI cleanup: delete `DashboardPage.jsx`, verify tree-shaking, remove
  stale docs (per `/app/memory/BACKLOG.md`)
- BATCH / HEATMAP promotion to ADMIN — only if real-world log
  confirms low daily usage
- Static Control Flow Simulation (Phase 4.5, from historical planning)
- Behavior Correlation (Phase 6, from historical planning)
- Analyst PDF Export

---

## 6 · Non-goals (v1.6.0)

These are explicitly OUT of scope for v1.6.0 so the mission stays focused:

- New top-level UI tabs
- New decoder families
- AI-only features (must always sit ON TOP OF deterministic evidence)
- Real-time collaboration / multi-analyst features
- Any capability that cannot cite its evidence source

---

_When starting any v1.6.0 work: read this file first. If the proposed
change conflicts with any Rule 1-7 or the mission, redesign the change,
do not weaken the rule._
