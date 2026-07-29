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
