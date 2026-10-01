# NivXRay v1.6.0 · Baseline Metrics (P0.5)

- **Captured**: `2026-07-28T11:29:13Z`
- **Commit (approx)**: `8d9c1c387a44`
- **Corpus size**: 17 samples
- **Runs per sample**: 5

## Aggregate

| Metric | Value |
| --- | --- |
| Latency P50 min / mean / max (ms) | 0.13 / 1.03 / 10.48 |
| Latency P95 max (ms) | 10.54 |
| Latency max observed (ms) | 10.55 |
| RTE depth min / max | 0 / 2 |
| RTE steps max | 2 |
| Peak RSS across corpus (KB) | 29,144 |
| Corpus pass rate | **94.1 %** (16/17) |
| False-positive rate (benign → mal/susp) | **0.00 %** (0) |
| Determinism hash stable across all samples | **True** |

## Known Limitations · locked exceptions

Per SME steer: any sample that does NOT match its expected
verdict is documented here as an explicit known limitation —
never silently normalised as "acceptable". Every entry must
carry an exit criterion tied to a specific release milestone.

| sample_id | expected | actual | root cause | exit criterion |
| --- | --- | --- | --- | --- |
| `PS_ENCODEDCOMMAND_GZIP_STAGE2_001` | malicious | benign | DX1002,DX2002 | **v1.6.0 GA**: either fires `must_fire_intents` on the L1 partial recovery (moving pass_rate to 100 %), OR relocated to `unsupported_patterns/` corpus with `unsupported_pattern: true` and an explicit rationale (corrupt-inner-b64 mod-4=3 is an unrecoverable class; verdict `benign` is the honest static conclusion — this may be the correct classification). |

### v1.6.0 corpus exit criterion

**Corpus pass rate MUST reach 100 % on the maintained Golden
Corpus at v1.6.0 GA — OR — every remaining exception MUST be
moved to a dedicated `unsupported_patterns/` corpus subdirectory
with an explicit `unsupported_pattern: true` YAML flag and a
public rationale for why the pattern is out of scope.**

This prevents "known gap" entries from quietly persisting.

## Complexity Budget · pre-resolver baseline

Metrics measurable today (v1.5.2, no def-use resolver yet).
Every future PR must ALSO run against this budget so a more
sophisticated resolver never silently increases algorithmic
complexity beyond the declared ceilings.

| Metric | Today (v1.5.2 max) | v1.6.0 GA ceiling | Rationale |
| --- | ---: | ---: | --- |
| Input bytes | 7,624 | 65,536 | Reject inputs > 64 KB with `DX4001 · OVERSIZED_INPUT`. |
| RTE recursion depth | 2 | 32 | Existing RTE cap — unchanged. |
| RTE steps count | 2 | 64 | Existing RTE cap — unchanged. |
| Diagnostics per decode | 2 | 32 | Existing cap — unchanged. |
| Peak RSS (KB) | 29,144 | 65,536 (~64 MB) | 2× headroom over today's peak. |
| Latency P95 (ms) | 10.5 | 12.1 | 15 % ceiling — hard fail above. |

### Post-resolver ceilings (targets for P1.1 onwards)

These are BUDGETS, not measurements. Each metric is instrumented
by the resolver itself when it lands and reported per decode via
the new `resolver_trace` block in the investigation JSON.

| Metric | Ceiling | If exceeded |
| --- | ---: | --- |
| Max AST nodes / decode | 8,192 | `DX3005 · AST_BUDGET_EXCEEDED` → resolver aborts, plugin falls back to Unresolved(reason=budget). |
| Max symbol count / decode | 512 | `DX3006 · SYMBOL_BUDGET_EXCEEDED` → same behaviour. |
| Max definition edges / decode | 2,048 | `DX3007 · DEFS_BUDGET_EXCEEDED` → same behaviour. |
| Max use edges / decode | 4,096 | `DX3008 · USES_BUDGET_EXCEEDED` → same behaviour. |
| Max resolver iterations / call | 32 | `DX3009 · RESOLVER_ITER_EXCEEDED` → returns `Unresolved(reason=depth_exceeded)`. |
| Per-decode wall time in resolver | 250 ms | `DX3010 · RESOLVER_TIME_EXCEEDED` → same behaviour. |

Adding a new sample that hits a ceiling is a **signal**, not a
bug: it means the corpus has grown a new complexity class that
must be classified before we bump the ceiling.

## Per-sample

| sample_id | bytes | depth | steps | stop | P50 ms | P95 ms | verdict | expected | ✓ | DX |
| --- | ---: | ---: | ---: | --- | ---: | ---: | --- | --- | :---: | --- |
| `PS_ENCODEDCOMMAND_GZIP_REFLECTIVE_LOADER_002` | 7624 | 2 | 2 | no_transformation | 10.5 | 10.5 | malicious | malicious | ✅ | DX2002 |
| `PS_ENCODEDCOMMAND_GZIP_STAGE2_001` | 688 | 1 | 1 | no_transformation | 0.9 | 1.0 | benign | malicious | ❌ | DX1002,DX2002 |
| `T01_benign_write_host` | 25 | 0 | 0 | no_transformation | 0.2 | 0.2 | benign | benign | ✅ | DX2002 |
| `T02_benign_get_process` | 66 | 0 | 0 | no_transformation | 0.2 | 0.2 | benign | benign | ✅ | DX2002 |
| `T03_download_and_run_cradle` | 83 | 0 | 0 | no_transformation | 0.4 | 0.4 | malicious | malicious | ✅ | DX2002 |
| `T04_registry_run_persistence` | 155 | 0 | 0 | no_transformation | 0.4 | 0.4 | malicious | malicious | ✅ | DX2002 |
| `T05_lsass_dump_lolbas` | 81 | 0 | 0 | no_transformation | 0.3 | 0.3 | malicious | malicious | ✅ | DX2002 |
| `T06_amsi_bypass_reflective` | 132 | 0 | 0 | no_transformation | 0.4 | 0.4 | malicious | malicious | ✅ | DX2002 |
| `T07_runtime_dependent_reflection` | 62 | 0 | 0 | no_transformation | 0.3 | 0.3 | runtime_dependent | runtime_dependent | ✅ | DX2002 |
| `T08_ad_discovery_powerview` | 72 | 0 | 0 | no_transformation | 0.3 | 0.3 | suspicious | suspicious | ✅ | DX2002 |
| `T09_wmic_encodedcommand_cradle` | 276 | 0 | 0 | no_transformation | 0.6 | 0.6 | malicious | malicious | ✅ | DX2002 |
| `T10_benign_iwr_windows_update` | 92 | 0 | 0 | no_transformation | 0.4 | 0.5 | suspicious | suspicious | ✅ | DX2002 |
| `T11_bits_download_and_execute` | 335 | 0 | 0 | no_transformation | 0.8 | 0.8 | malicious | malicious | ✅ | DX2002 |
| `T12_atomic_ioc_bare_filename` | 9 | 0 | 0 | empty_input | 0.1 | 0.1 | benign | benign | ✅ | — |
| `T13_iwr_outfile_startprocess` | 83 | 0 | 0 | no_transformation | 0.4 | 0.5 | malicious | malicious | ✅ | DX2002 |
| `T14_certutil_start_chain` | 115 | 0 | 0 | no_transformation | 0.5 | 0.5 | malicious | malicious | ✅ | DX2002 |
| `T15_psexec_winrm_lateral_admin` | 327 | 0 | 0 | no_transformation | 0.8 | 0.8 | malicious | malicious | ✅ | DX2002 |

## How to use this file

Every v1.6.0 PR that touches the decode pipeline MUST attach a
**delta table** against these numbers, produced by re-running
`python -m scripts.v160_baseline_metrics --json` on the PR branch.
Regressions:

- P95 latency ↑ > 15 %  → **HARD FAIL** (requires SME sign-off).
- Any sample flips from ✅ to ❌  → **HARD FAIL**.
- Any determinism hash becomes unstable  → **HARD FAIL**.
- False-positive rate ↑ from 0  → **HARD FAIL**.
- Any complexity-budget ceiling exceeded → **HARD FAIL**.
- Peak RSS ↑ > 25 %  → soft fail (review, may be legitimate).

_This file is generated. Do NOT edit by hand — re-run the
script to refresh._