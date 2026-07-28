# NivXRay v1.6.0 · Baseline Metrics (P0.5)

- **Captured**: `2026-07-28T11:24:16Z`
- **Commit (approx)**: `ae0198d21f29`
- **Corpus size**: 17 samples
- **Runs per sample**: 5

## Aggregate

| Metric | Value |
| --- | --- |
| Latency P50 min / mean / max (ms) | 0.12 / 1.03 / 10.39 |
| Latency P95 max (ms) | 10.41 |
| Latency max observed (ms) | 10.52 |
| RTE depth min / max | 0 / 2 |
| RTE steps max | 2 |
| Peak RSS across corpus (KB) | 29,200 |
| Corpus pass rate | **94.1 %** (16/17) |
| False-positive rate (benign → mal/susp) | **0.00 %** (0) |
| Determinism hash stable across all samples | **True** |

## Per-sample

| sample_id | bytes | depth | steps | stop | P50 ms | P95 ms | verdict | expected | ✓ | DX |
| --- | ---: | ---: | ---: | --- | ---: | ---: | --- | --- | :---: | --- |
| `PS_ENCODEDCOMMAND_GZIP_REFLECTIVE_LOADER_002` | 7624 | 2 | 2 | no_transformation | 10.4 | 10.4 | malicious | malicious | ✅ | DX2002 |
| `PS_ENCODEDCOMMAND_GZIP_STAGE2_001` | 688 | 1 | 1 | no_transformation | 1.0 | 1.0 | benign | malicious | ❌ | DX1002,DX2002 |
| `T01_benign_write_host` | 25 | 0 | 0 | no_transformation | 0.2 | 0.2 | benign | benign | ✅ | DX2002 |
| `T02_benign_get_process` | 66 | 0 | 0 | no_transformation | 0.2 | 0.2 | benign | benign | ✅ | DX2002 |
| `T03_download_and_run_cradle` | 83 | 0 | 0 | no_transformation | 0.4 | 0.4 | malicious | malicious | ✅ | DX2002 |
| `T04_registry_run_persistence` | 155 | 0 | 0 | no_transformation | 0.4 | 0.4 | malicious | malicious | ✅ | DX2002 |
| `T05_lsass_dump_lolbas` | 81 | 0 | 0 | no_transformation | 0.3 | 0.3 | malicious | malicious | ✅ | DX2002 |
| `T06_amsi_bypass_reflective` | 132 | 0 | 0 | no_transformation | 0.4 | 0.4 | malicious | malicious | ✅ | DX2002 |
| `T07_runtime_dependent_reflection` | 62 | 0 | 0 | no_transformation | 0.3 | 0.3 | runtime_dependent | runtime_dependent | ✅ | DX2002 |
| `T08_ad_discovery_powerview` | 72 | 0 | 0 | no_transformation | 0.3 | 0.3 | suspicious | suspicious | ✅ | DX2002 |
| `T09_wmic_encodedcommand_cradle` | 276 | 0 | 0 | no_transformation | 0.6 | 0.6 | malicious | malicious | ✅ | DX2002 |
| `T10_benign_iwr_windows_update` | 92 | 0 | 0 | no_transformation | 0.4 | 0.4 | suspicious | suspicious | ✅ | DX2002 |
| `T11_bits_download_and_execute` | 335 | 0 | 0 | no_transformation | 0.8 | 0.8 | malicious | malicious | ✅ | DX2002 |
| `T12_atomic_ioc_bare_filename` | 9 | 0 | 0 | empty_input | 0.1 | 0.1 | benign | benign | ✅ | — |
| `T13_iwr_outfile_startprocess` | 83 | 0 | 0 | no_transformation | 0.5 | 0.5 | malicious | malicious | ✅ | DX2002 |
| `T14_certutil_start_chain` | 115 | 0 | 0 | no_transformation | 0.5 | 0.5 | malicious | malicious | ✅ | DX2002 |
| `T15_psexec_winrm_lateral_admin` | 327 | 0 | 0 | no_transformation | 0.8 | 0.9 | malicious | malicious | ✅ | DX2002 |

## How to use this file

Every v1.6.0 PR that touches the decode pipeline MUST attach a
**delta table** against these numbers, produced by re-running
`python -m scripts.v160_baseline_metrics --json` on the PR branch.
Regressions:

- P95 latency ↑ > 15 %  → **HARD FAIL** (requires SME sign-off).
- Any sample flips from ✅ to ❌  → **HARD FAIL**.
- Any determinism hash becomes unstable  → **HARD FAIL**.
- False-positive rate ↑ from 0  → **HARD FAIL**.
- Peak RSS ↑ > 25 %  → soft fail (review, may be legitimate).

_This file is generated. Do NOT edit by hand — re-run the
script to refresh._