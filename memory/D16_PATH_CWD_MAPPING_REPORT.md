# D16 — auditd PATH / CWD → CANONICAL FILE & DIRECTORY EVIDENCE

Date: 2026-09-15 · **PREVIEW ONLY — no production deployment, no merge.**

```
cd /app/backend && python -m pytest tests/test_d16_path_cwd_mapping.py -q
cd /app          && python scripts/p0_d16_path_cwd_mapping_live_proof.py
```

## RESULT: **PASS**

| Proof | Result |
|---|---|
| `tests/test_d16_path_cwd_mapping.py` | **26 passed** |
| `scripts/p0_d16_path_cwd_mapping_live_proof.py` (real HTTP, preview) | **PASS** — 30/30 checks |
| Regression (auditd + pipeline + D8–D15 suites, 12 files) | **358 passed**, only the 4 known pre-existing `test_xdr_detection_consolidation` failures |

## WHAT WAS ACTUALLY MISSING

auditd had always delivered this and NivX had always discarded it:

```
type=CWD  msg=audit(…): cwd="/home/deploy"
type=PATH msg=audit(…): item=0 name="/usr/bin/bash"      nametype=NORMAL
type=PATH msg=audit(…): item=1 name="scripts/payload.sh" nametype=CREATE
type=PATH msg=audit(…): item=2 name="scripts"            nametype=PARENT
```

The D4 stitcher already grouped these records and already declared
`working_directory -> CWD` and `file.path -> PATH` in `FIELD_AUTHORITY` — but
the normalizer never read them, so **the canonical `file` entity was empty
for every auditd event in the platform**. No detection rule could cite a file
path that the source had genuinely observed.

## CHANGED

| File | Δ | What |
|---|---|---|
| `linux_auditd_dsm.py` | +185 | `_path_records()`, `_entry()`, `_project_paths()`; the canonical `file` entity; `additional_fields.path_mapping` + `working_directory`; `supports()` now claims CWD/PATH records; standalone PATH/CWD get their own honest event types |
| `auditd_stitcher.py` | +11 | `kv_fields()` — public read of ONE verbatim record, so later PATH records can be re-read unmerged |
| `tests/test_d16_path_cwd_mapping.py` | **NEW**, 26 tests | |
| `scripts/p0_d16_path_cwd_mapping_live_proof.py` | **NEW** | 30/30 PASS over real HTTP |

## THREE REFUSALS THAT MAKE THE MAPPING TRUSTWORTHY

1. **No path is invented.** An absolute name is `VERBATIM_ABSOLUTE`. A
   relative name plus an observed CWD becomes `DERIVED_FROM_OBSERVED_CWD`
   with `absolute_path_resolved_from` naming both halves. A relative name
   with **no** CWD record stays `NOT_RESOLVABLE` and says why. The filesystem
   is never consulted — no `realpath`, no symlink resolution, no `stat`.
   A missing CWD is `NOT_OBSERVED`, never `/`.
2. **PATH records are never collapsed.** The stitcher merges only the FIRST
   record of each type, so items 1..n are re-read from their own preserved
   verbatim lines. Every item keeps `item`, `nametype`, `inode`, `dev`,
   `mode`, `ouid`, `ogid` and a `record_ref` back to the exact auditd record.
   The canonical `file` entity names ONLY the primary item, with its basis
   declared (`LOWEST_PATH_ITEM_EXCLUDING_PARENT` / `SINGLE_PATH_OBJECT`).
3. **The object kind is not guessed.** auditd does not say whether a NORMAL
   path is a file or a directory, so the kind stays
   `OBJECT_KIND_NOT_OBSERVED`. Only `nametype=PARENT` is recorded as a
   directory — that is what auditd means by it. `file.action` is mapped only
   from `nametype=CREATE`/`DELETE`; NORMAL yields `NOT_OBSERVED`, never a
   plausible-looking "read".

## ONE REAL GAP CLOSED ALONG THE WAY

`LinuxAuditdDSM.supports()` did not recognise `type=CWD` or `type=PATH`, so a
CWD or PATH record delivered on its own was refused as "not auditd" — and
after D15 it would have been blocked as `SOURCE_FORMAT_MISMATCH`. Real
forwarders do split batches. Those records are now accepted and labelled for
exactly what they are:

```
event_type     = auditd_path_record | auditd_cwd_record
fragment_state = STANDALONE_RECORD_NO_PROCESS_CONTEXT
identity_state = NOT_OBSERVED        (absent, NOT unprivileged)
```

D10 identity is preserved: a lone PATH and a lone CWD of the same audit event
stay distinct canonical events, and the same record delivered twice is one.

## INVARIANTS RE-VERIFIED

* paths are evidence, never identity material — the same execution with and
  without PATH/CWD records is still **one** canonical event (`event_id`
  unchanged);
* D4 stitch provenance, D2 host/identity honesty, D11/D12 temporal basis and
  D14 tenant authority are all unchanged on the same events;
* the live proof re-delivers the six records through the D15 declared path:
  1 REASONED + 5 STITCHED_INTO, one canonical event.

**TEST/SYNTHETIC auditd records. No real host connected. Nothing deployed.**
