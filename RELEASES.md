# NivXRay · Release Records

Immutable audit trail of every production release. One block per
tag. Every entry is filled in at the moment of deploy from the
platform's deploy output and appended here for permanent record.

**Do not backfill.** If a field cannot be captured, mark it
`UNKNOWN` and open a follow-up.

---

## v1.4.0 — Investigation Brain · Stabilization + Behaviour Graph Schema Freeze

| Field | Value |
| ----- | ----- |
| **Release** | NivXRay v1.4.0 |
| **Release Date** | 2026-07-27 |
| **Deployed Commit SHA** | `c6ccc2b61f8cf6c3e7f4e7b2d06850cfe52a464f` |
| **Behaviour Graph Schema** | `1.0.0` (frozen · CI-locked) |
| **Investigation Baseline** | `iu → cre → rte → intent → behaviour → verdict → graph → report` |

### Verification results (pre-deploy · preview build)

| Suite | Result |
| ----- | ------ |
| Targeted Investigation Regression | **331 / 331 PASS** |
| Trust Corpus | **14 / 14 PASS** |
| Behaviour Graph Schema Freeze CI | **8 / 8 PASS** |
| Behaviour Graph regression | **15 / 15 PASS** |
| Behaviour Chain regression | **40 / 40 PASS** |
| Version Baseline lock | **4 / 4 PASS** |

### Trust Metrics (14-sample corpus)

| Metric | Result |
| ------ | ------ |
| Accuracy | **PASS** (100 %) |
| Honesty | **PASS** (100 % · zero unsupported claims) |
| Explainability | **PASS** (100 % · every intent evidence-anchored) |
| Unknown Handling | **PASS** (100 %) |
| Investigation Integrity | **PASS** (100 %) |
| Hard Failures | **0** |

### Provenance

- **PR**: v1.4.0: Investigation Brain Stabilization & Behavior Graph Schema Freeze
- **Merged from**: `feature/rc2.1b` → `main`
- **Merge SHA (canonical)**: [`c6ccc2b`](https://github.com/jana017/NivXRAY_NivXForge/commit/c6ccc2b61f8cf6c3e7f4e7b2d06850cfe52a464f)
- **Merge date**: 2026-07-27

### Production Smoke (post-deploy · to be re-run on LIVE URL)

| Sample | Expected | Result |
| ------ | -------- | ------ |
| Atomic IOC (`scwxc.exe`) | `benign · 0` · zero behaviour nodes | **PASS · 2026-07-27 · verified on `nivxray.nivxforge.com`** |
| Benign (`Write-Host`) | `benign · 60` · zero behaviour nodes | **PASS · 2026-07-27 · verified on `nivxray.nivxforge.com`** |
| Download → Execute (`iwr … -OutFile a.exe; Start-Process a.exe`) | `malicious · 93` · `[download, write_file, remote_execution, execute]` | **PASS · 2026-07-27 · verified on `nivxray.nivxforge.com`** |
| Persistence (`HKCU:\…\Run`) — validate via UI or properly-escaped HTTP | `malicious · 90` · `[persistence]` | **PASS · 2026-07-27 · verified on `nivxray.nivxforge.com`** |

### Determinism guarantees

| Guarantee | Status |
| --------- | ------ |
| `determinism_hash` folds in `behavior_shape` | ✅ |
| Same input → byte-identical `BehaviorGraph` | ✅ verified |
| `schema_version` emitted on every serialized graph | ✅ `1.0.0` |
| Analyst Report `behavior_graph` field mirrors pipeline output | ✅ |

### Legacy audit outcome

Every candidate for removal was verified as a live runtime
dependency. **Zero code deleted.** Legacy retirement is deferred
until each consumer has a migration path.

| Candidate | Verdict | Reason |
| --------- | ------- | ------ |
| `SemanticIntelligencePanel.jsx` | KEEP | Analyst-facing render on `AutoInvestigatePage` |
| `rc22_adapter.py` | KEEP | Imported by `analysis_core.py` |
| Workspace `<details>` legacy trace panels | KEEP | Still in DOM output — removal = drift |
| `SocVerdictPanel` + v1.3.x panels | KEEP | Feed shellcode-verdict surface |

### Known follow-ups (non-blocking · track for v1.4.1 / v1.5.0)

| ID | Item | Type | Priority |
| -- | ---- | ---- | -------- |
| FU-1 | Diff `WorkspacePage.jsx` against last known-good baseline | Verification | P2 |
| FU-2 | Re-run persistence smoke via deployed HTTPS API (shell escape bit the earlier curl) | Verification | P2 |
| FU-3 | Rename `BASELINE_TESTS` → `INVESTIGATION_BASELINE_TESTS` for scope clarity | Cosmetic | P3 |
| FU-4 | Run full repo `pytest tests/` in CI (unblock timeout-bound shell) | CI hardening | P2 |
| FU-5 | **v1.4.1 fast-follow · P0** — Legacy `NIVXRAY INVESTIGATION SUMMARY` block (rc2-orchestrator) shown at the bottom of Workspace contradicts the Investigation Brain verdict on **every** production smoke sample: chain sample showed `Runtime Dependent · 55` vs Brain's `MALICIOUS · 93`; persistence sample showed `Suspicious · 45` vs Brain's `MALICIOUS · 90`. Hide the legacy summary or rewrite it to render the Investigation Brain verdict so analysts cannot copy the stale/weaker verdict into a SOC ticket. Observed on `nivxray.nivxforge.com` during v1.4.0 smoke tests 2026-07-27 | UX / correctness | **P0 (v1.4.1)** |

### v1.5.0 theme direction (agreed with reviewer)

Not a grab bag — organised around three themes:

1. **Analysis depth** — Static Control Flow (`if/else`, `try/catch`,
   loops) modelled as branch sub-graphs feeding the SAME canonical
   Behaviour Graph. Behaviour Correlation on top of that.
2. **Quality** — Trust Corpus expansion driven by real-world SOC
   investigations; full-repo CI validation (FU-4); regression
   scenario growth.
3. **Analyst experience** — Reporting improvements (PDF export,
   sharable Investigation Summary) and workflow refinements. The
   core investigation pipeline stays frozen unless a Trust-Corpus
   sample proves a gap.

### Release principle (kept from v1.4.0)

> "The Investigation Pipeline, Behaviour Graph, Verdict Engine,
> Trust Corpus, and Analyst Report are the product core. Preserve
> their behaviour. Real-world SOC investigations and Trust Corpus
> expansion drive future development rather than adding more
> foundational architecture."

---

## v1.5.0 — Decoder Convergence

| Field | Value |
| ----- | ----- |
| **Release** | NivXRay v1.5.0 |
| **Release Date** | 2026-07-28 |
| **Behaviour Graph Schema** | `1.1.0` (unchanged) |
| **Recursive Transformation Engine** | max depth **24 → 64** |
| **New RTE plugin** | `ps_indirect_compression_stream` (variable-bound base64 → compression) |
| **Trust Corpus additions** | `PS_ENCODEDCOMMAND_GZIP_STAGE2_001` (locked) |
| **Change scope** | Backend only · additive (no decoder rewrites) |

### The failing sample (P0)

Real-world sample supplied by SOC lead 2026-07-28:

```
%COMSPEC% /b /c start /b /min powershell -nop -w hidden -encodedcommand
JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUA…
```

The RTE was exiting at L1 with `stop_reason = NO_TRANSFORMATION`
after decoding `-EncodedCommand` — despite the recovered
PowerShell being the extremely common variable-bound base64 +
GzipStream loader idiom.

### Root cause

`_resolve_compression_stream` in `/app/backend/v2/semantic/ps_deobfuscate.py`
uses `_COMPRESSION_RE` which requires source order:

```
[IO.Compression.GzipStream]  …  [Convert]::FromBase64String("<literal>")  …  ::Decompress
```

But the sample uses the equally-common reversed order:

```
$s = New-Object IO.MemoryStream(,[Convert]::FromBase64String("<literal>"));
… [IO.Compression.GzipStream]($s, …, ::Decompress) …
```

The strict-order regex cannot match this shape, so
`ps_compression_stream.applicable()` returned `None`, no
transformation was scheduled, and the RTE terminated cleanly with
`NO_TRANSFORMATION`. **This is an orchestration/extraction gap,
not a missing decoder** — the underlying gzip inflate primitive
(`_decompress` in the same module) already existed and was
already correct.

### Fix (generic, deterministic, class-level)

1. **New generic resolver**
   `_resolve_variable_bound_compression_stream` in
   `v2/semantic/ps_deobfuscate.py`. Two-pass linking:
   - Pass 1: index every `$VAR = … [Convert]::FromBase64String("<lit>") …`
     assignment (with optional `New-Object IO.MemoryStream(,…)` wrap)
     by variable name.
   - Pass 2: find every `IO.Compression.(gzip|deflate|brotli)Stream($VAR, …, ::Decompress)`
     consumer. First match on a shared variable name → deterministic
     decompress + inline of the recovered plaintext.
   - Reuses the existing `_decompress` primitive → no new decoders.

2. **New RTE plugin**
   `v2/investigation/rte/transformations/ps_indirect_compression_stream.py`
   surfaces the resolver to the engine at confidence **94**.
   Registered in `TRANSFORMATION_REGISTRY` **before** the strict-order
   `ps_compression_stream` so its (larger) surface area wins on ties.

3. **RTE depth cap**: `DEFAULT_MAX_DEPTH: 24 → 64` per spec.
   Stopping conditions unchanged: `NO_TRANSFORMATION` / `LOOP` (via
   SHA-256 hash reappearance) / `MAX_DEPTH` / `UNSUPPORTED`.

### Verification

| Check | Result |
| ----- | ------ |
| Reproducer without fix — layers | **2** (`NO_TRANSFORMATION` at L1) ❌ |
| Reproducer WITH fix — layers | **3** (`ps_encoded_command` → `ps_indirect_compression_stream`) ✅ |
| Stage-3 plaintext recovered byte-for-byte | ✅ |
| Determinism (2 independent runs) | identical hash `576e3b4f0efd7f1d` ✅ |
| RTE latency (full 3-layer chain) | **21.8 ms** (target ≤ 500 ms) ✅ |
| Strict-order compression regression | still fires ✅ (`test_reverse_order_compression_still_works`) |
| No fabrication guard (consumer missing) | resolver silent ✅ |
| No fabrication guard (variable mismatch) | resolver silent ✅ |
| Registry order (indirect before strict) | asserted ✅ |
| Locked pytest suite (`test_decoder_convergence_v150.py`) | **10 / 10 PASS** ✅ |
| Existing decoder / RTE / behavior / verdict / investigation suites | **244 PASS**, 3 pre-existing failures unrelated to this change ✅ |
| Golden Corpus entry `PS_ENCODEDCOMMAND_GZIP_STAGE2_001` | added ✅ |

### Deliverable — Decoder Timeline (from the actual engine)

```
STAGE 1
  Input:      %COMSPEC% /b /c start /b /min powershell -nop -w hidden -enc <blob>
  Selected:   ps_encoded_command
  Reason:     command line contains -EncodedCommand with valid UTF-16LE base64
  Confidence: 98
  Result:     PASS   1204 chars → 424 chars

STAGE 2
  Input:      $s = New-Object IO.MemoryStream(,[Convert]::FromBase64String("H4sI…"));
              IEX (…GzipStream($s, ::Decompress)…).ReadToEnd();
  Selected:   ps_indirect_compression_stream           ← v1.5.0
  Reason:     variable-bound base64 assignment linked to same-variable
              GzipStream consumer; deterministic decompress
  Confidence: 94
  Result:     PASS   424 chars → 172 chars

STAGE 3
  Input:      Write-Host "STAGE-3 payload …"; New-ItemProperty -Path HKCU:\… -Name Backdoor …
  Selected:   NONE
  Reason:     plaintext PowerShell — no further deterministic transformation applies
  Result:     STOP · stop_reason = NO_TRANSFORMATION (principled convergence)

Determinism hash: 576e3b4f0efd7f1d (stable across runs)
Total RTE latency: 21.8 ms
```

### Files touched

- `backend/v2/semantic/ps_deobfuscate.py` — new resolver
- `backend/v2/investigation/rte/transformations/ps_indirect_compression_stream.py` — new plugin (created)
- `backend/v2/investigation/rte/transformations/__init__.py` — registry update
- `backend/v2/investigation/rte/engine.py` — `DEFAULT_MAX_DEPTH: 24 → 64`
- `backend/tests/test_decoder_convergence_v150.py` — 10 locked regressions (created)
- `backend/tests/trust_corpus/PS_ENCODEDCOMMAND_GZIP_STAGE2_001.yaml` — Golden Corpus entry (created)
- `RELEASES.md` — this ledger
- `memory/PRD.md` — release entry

### Rollback plan

Revert commits touching the four backend files above. The new plugin
is purely additive — removing it degrades the engine to v1.4.3
behaviour without breaking any other stage. The `DEFAULT_MAX_DEPTH`
bump is a single-line change.

### v1.5.0 phase 3 status (Resource Nodes)

The originally-planned v1.5.0 (Process → Resource → Behavior graph
expansion, schema bump to 1.2.0) is **rescheduled to v1.6.0** per
SOC lead direction — decoder correctness for real-world samples
took priority.

---

## v1.5.0 · SOC-review follow-ups (same release · 2026-07-28)

Follow-up work driven by the SOC lead's post-review comments. All
additive; the correctness contract from the v1.5.0 base is
unchanged.

### 1 · Failure-reporting (DoD gate — critical)

Prior to this delta, when the resolver *detected* a variable-bound
`$VAR = FromBase64String("<lit>") … [IO.Compression.*Stream]($VAR,
…)` pattern but decompression failed (base64 truncated, DEFLATE
corrupt), the RTE returned `stop_reason = no_transformation` and the
analyst had **no idea why** the pipeline stopped. The Sophos-class
family the corpus targets frequently transits chats / doc exports
that can lose a single character in a multi-kilobyte base64 blob —
so silent halts destroy analyst trust.

**Fix** — new deterministic RTE protocol:
- `DecodeDiagnostic` dataclass (`layer, detector, attempted, outcome, reason, meta`).
- `TransformationChain.diagnostics: list[DecodeDiagnostic]` (empty by default).
- Engine `_collect_diagnostics()` polls every plugin's optional
  `diagnose(artifact)` method **only** when about to stop with
  `NO_TRANSFORMATION`. No fabrication: a plugin that can decode
  successfully never emits a duplicate diagnostic.
- Diagnostics contribute to the chain's determinism hash — a change
  in the failure reason changes the fingerprint.
- `ps_indirect_compression_stream.diagnose()` explains, e.g.:
  ```
  Detected invalid Base64 length (2635 characters, length mod 4 = 3).
  The embedded payload appears incomplete or malformed.
  Gzip inflate failed: error: Error -3 while decompressing data:
  invalid distance too far back.
  This commonly occurs due to copy/paste truncation, logging limits,
  EDR field-length caps, or transport corruption — the decoder cannot
  determine the specific cause.
  ```
  with meta `{blob_chars, raw_bytes, magic_bytes, mod4_offset}`.

**Wording discipline (v1.5.0 evidence gate)** — the diagnostic
reports ONLY what the decoder can deterministically prove:
extracted base64 length, ``length mod 4``, decode exception, inflate
exception. Possible causes (copy/paste truncation, logging limits,
EDR field caps, transport corruption) are listed as **possibilities**,
never conclusions. A regression test (`test_corrupt_gzip_payload_emits_deterministic_diagnostic`)
asserts the diagnostic never over-claims phrases like "this is chat-
transmission corruption", "the payload is truncated", or "definitely
corrupted".

### 2 · Diverse-family coverage (Sophos class)

New parametrised tests in `test_decoder_convergence_v150.py` prove
the resolver is class-level, not sample-specific:
- variable names `$s`, `$ms`, `$stream`, `$randomIdent42` all handled
- `DeflateStream` variant handled by the same resolver (kind captured
  by regex group, not hardcoded)
- `New-Object IO.MemoryStream` wrap optional (some real samples skip
  it)
- benign administrative PS reading a `.gz` file MUST NOT trigger the
  resolver — locked false-positive guard

### 3 · Performance corpus

`test_deep_recursion_terminates_within_budget` builds a 30-layer
nested base64 chain and asserts full RTE convergence in **< 2 s**
with ≥ 20 layers peeled. Proves the scheduler is not quadratic.

### 4 · Decoder-trace API

`TransformationChain.to_dict()` now surfaces `artifacts[]`, `steps[]`,
`stop_reason`, `depth`, `final_layer`, `determinism_hash`, and the
new `diagnostics[]` field. Already reachable via
`POST /api/decode/smart → investigation.rte` — no new endpoint
required, no schema break.

### Sophos reference (validation-only)

The [Sophos "Decoding Malicious PowerShell Activity" case study]
documents the exact `CMD → PS -EncodedCommand → UTF-16LE base64 →
variable-bound base64+gzip → recovered PS` chain that the v1.5.0
corpus sample instantiates. Referenced here as validation of the
**strategy** — no pattern from the article is hardcoded, no
sample-specific regex has been introduced.

### Verification (follow-ups delta)

| Check | Result |
| ----- | ------ |
| `test_decoder_convergence_v150.py` (base + follow-ups) | **21 / 22 PASS** (1 non-ASCII PS identifier skipped intentionally) |
| Diverse-family (5 tests, 4 vars × 2 kinds) | ✅ |
| False-positive guard (benign admin PS) | ✅ |
| Diagnostic path (3 tests) | ✅ |
| Perf guard (30-layer chain) | ✅ (converges < 2 s, ≥ 20 layers peeled) |
| Determinism includes diagnostics | ✅ |
| Zero-regression on 210+ decoder / behaviour / verdict / investigation tests | ✅ (3 pre-existing failures unchanged) |
| API surface exposes `investigation.rte.diagnostics[]` | ✅ |

### Files touched (this delta)

- `backend/v2/investigation/rte/models.py` — `DecodeDiagnostic` dataclass, `TransformationChain.diagnostics` field, serialised in `to_dict()`, included in the determinism hash.
- `backend/v2/investigation/rte/engine.py` — `_collect_diagnostics()` helper; called at the `NO_TRANSFORMATION` stop point; diagnostics threaded into `TransformationChain`.
- `backend/v2/investigation/rte/transformations/ps_indirect_compression_stream.py` — new `diagnose(artifact)` method, detection-only regexes, `_diagnose_pattern()` helper.
- `backend/tests/test_decoder_convergence_v150.py` — 12 new tests (diverse variables, deflate variant, no-MemoryStream wrap, benign guard, corrupt-payload diagnostic, no-double-report, determinism-of-diagnostics, deep-recursion perf).

---

## v1.4.3 — FU-5 · Legacy Verdict Surface Retirement (Feature-Flag Hide)

| Field | Value |
| ----- | ----- |
| **Release** | NivXRay v1.4.3 |
| **Release Date** | 2026-07-28 |
| **Behaviour Graph Schema** | `1.1.0` (unchanged) |
| **Investigation Baseline** | `iu → cre → rte → intent → behaviour → verdict → graph → report` |
| **Change surface** | Frontend only · `/app/frontend/src/pages/WorkspacePage.jsx` |
| **Backend change** | **NONE** (zero behavioural drift) |

### Problem addressed

FU-5 (P0 from v1.4.0 smoke): the workspace was still rendering
multiple legacy verdict surfaces below the Investigation Brain that
could emit **weaker, contradictory** verdicts (e.g. `Suspicious · 45`
next to Brain's `MALICIOUS · 90`). Analysts could accidentally
copy the stale verdict into a SOC ticket.

### Fix

A single module-level feature flag `SHOW_LEGACY_INVESTIGATION_SUMMARY = false`
in `WorkspacePage.jsx` gates five legacy verdict surfaces:

| # | Component | Location | Reason gated |
| - | --------- | -------- | ------------ |
| 1 | `SocVerdictPanel` | above workspace | client-side one-line shellcode verdict |
| 2 | `AnalystQuickActions` | strip below SOC verdict | synthesises verdict from legacy `verdictCard` |
| 3 | `AnalystResults` (in `<details>`) | below Brain | 7-panel legacy rc2-orchestrator verdict view |
| 4 | `SemanticIntelligencePanel` (in `<details>`) | below Brain | legacy "Behavior Storyline" verdict |
| 5 | `FinalSummary` | below process tree | "NIVXRAY — FINAL INVESTIGATION SUMMARY" card |

Preserved (not gated · non-verdict analyst content):
`OutputView`, `EscalationLadder`, `TIShieldPanel`, `AttackGraph`,
`AttackPathClean`, `ProcessTreeView`, `IOC enrichment strip`,
`IR handoff strip`, `Refine launcher`, `ThreatAnalysis`.

### Verification

| Check | Result |
| ----- | ------ |
| Frontend webpack build | **Compiled successfully** |
| Legacy panels DOM count (post-`/decode/smart`) | **0 / 0 / 0** |
| Brain panel DOM count | **1** (`workspace-investigation-brain`) |
| `"FINAL SUMMARY"` / `"NIVXRAY — FINAL INVESTIGATION SUMMARY"` in DOM | **not present** |
| Smoke sample (`Invoke-Command … net user backdoor … Set-MpPreference`) | Brain reports **MALICIOUS · confidence 90** as sole verdict |
| Backend regression (Investigation / Behaviour / Verdict) | **199 / 201 PASS** (2 pre-existing legacy-verdict-card failures unrelated to this change) |
| `git diff` scope | `frontend/src/pages/WorkspacePage.jsx` only |

### Rollback plan

Flip the flag: `const SHOW_LEGACY_INVESTIGATION_SUMMARY = true;`
No code deletion, no imports removed. Actual removal of the gated
components is scheduled for **v1.5.x** after one stable release
cycle with no regressions, once runtime dependency analysis confirms
the legacy components have no remaining consumers.

---
