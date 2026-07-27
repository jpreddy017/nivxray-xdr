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
