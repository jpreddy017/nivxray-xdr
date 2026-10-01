# EVTX Test Fixtures — NOTICE

This directory contains real Sysmon `.evtx` binary files used **as test data only** for exercising the actual `python-evtx` binary parser through `services/behavioral/evtx_reader.py` and the Sysmon normalizer (`services/behavioral/sysmon_adapter.py`). They are NOT shipped in production build artifacts and are NOT executed on end-user machines. They exist solely under `backend/tests/fixtures/evtx/` for CI regression.

## Files

| File | SHA-256 | Bytes | Source | Sysmon Event IDs |
|---|---|---:|---|---|
| `sysmon_e1_only.evtx` | `08ce1feab22e30eb12a5a5b1ba4ac0aa552ff988b762d08de3a4d75ee1636abd` | 69 632 | `sbousseaden/EVTX-ATTACK-SAMPLES` — `Execution/revshell_cmd_svchost_sysmon_1.evtx` | 4 × Event 1 (Process Create) |
| `sysmon_e3_only.evtx` | `d7e75b35f9db32c91dc0d066ee935b382253fb56659f19c05833c964f8217469` | 69 632 | `sbousseaden/EVTX-ATTACK-SAMPLES` — `Command and Control/tunna_iis_rdp_smb_tunneling_sysmon_3.evtx` | 12 × Event 3 (Network Connect) |

## Upstream provenance

Both files originate from the publicly-published `sbousseaden/EVTX-ATTACK-SAMPLES` corpus by Samir Bousseaden:

- Repository: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- License: **GPL-3.0** (SPDX-License-Identifier: GPL-3.0-only)
- Copyright: © Samir Bousseaden and contributors

## License note

The bundled `.evtx` files are covered by the upstream **GPL-3.0** license. They are included in this repository as unmodified **test data only** for the purpose of running the CI regression suite. Their inclusion does NOT re-license the surrounding NivXRay source tree.

**Rules of use:**

1. Do not modify the byte content of these files. Test-time behavior must depend on the exact upstream bytes so that the SHA-256 hashes in the table above remain the acceptance witnesses.
2. Do not ship these files in production build artifacts. They live only under `backend/tests/fixtures/evtx/` and are excluded from the deploy tarball.
3. If further Sysmon fixtures are needed and must be redistributed inside a non-GPL-compatible artifact, generate them synthetically (a minimal EVTX writer) rather than adding more GPL data here.

## Why bundled rather than downloaded at test time

CI runs on air-gapped pods; downloading during test setup is unreliable and would introduce non-determinism into the test corpus. Bundling the exact bytes (locked by SHA-256) is the only way to guarantee "same test on every run".

## Rationale for TWO fixtures (E1-only + E3-only) instead of one mixed file

The Sysmon Slice-2 normalizer (per `ADR-0010r`) is intentionally strict: it accepts only Event IDs 1 and 3. It **fail-loud rejects** any other Event ID (10, 11, 13, 22, …) with `SysmonAdapterError("unsupported_event_id", ...)`. Every real-world Sysmon capture in the wild contains additional event types (10, 11, 13 …). Rather than modify the Slice-2 boundary to accept a mixed real capture (which would violate the Task-2 "no new behavioral semantics" rule), we ship two focused single-event-type files. Together they cover the full E1+E3 owner requirement.

The mixed rejection behavior is also exercised in the same test module — see `test_evtx_reader_rejects_mixed_real_capture` — using a third file that is downloaded transiently at test runtime.
