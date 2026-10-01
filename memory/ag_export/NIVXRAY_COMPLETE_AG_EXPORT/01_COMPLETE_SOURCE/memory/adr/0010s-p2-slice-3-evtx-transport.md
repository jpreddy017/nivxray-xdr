# ADR-0010s · P2 · Slice-3 · EVTX Binary Transport — 🟢 GREEN

**Status**: 🟢 PASS · Slice-3 shipped (2026-08-12 · Session-19)
**Scope**: EVTX binary wire-format adapter. **Transport only.** No new semantics, no new MITRE mapping, no new verdict logic.
**Companion**: ADR-0010q (Slice-1) · ADR-0010r (Slice-2) · ADR-0023 (P2 direction).

---

## 1. Objective

> "Add native `.evtx` ingestion using python-evtx as a TRANSPORT LAYER over the existing Sysmon XML normalizers. If a Sysmon-XML normalizer already consumes a given field, EVTX delivers it exactly the same way."

## 2. Files touched

```
backend/services/behavioral/evtx_reader.py                       (new · transport-only reader)
backend/routers/behavioral.py                                    (new endpoint POST /api/behavioral/sysmon/evtx)
backend/requirements.txt                                          (+ python-evtx==0.8.1, hexdump==3.3)
backend/tests/canonical/api/test_p2_slice3_evtx_transport.py     (new · 10 focused tests)
backend/tests/canonical/ssot/test_ssot_isolation.py               (allow-list entries)
memory/adr/0010s-p2-slice-3-evtx-transport.md                     (this file)
memory/experiments/rip/results.p2_slice3_run.json                 (post-Slice-3 harness snapshot)
```

**Zero files modified in `services.die.*`, `analysis_core`, `operations`, `routers/analyze.py`, `services/behavioral/sysmon_adapter.py`, or the frontend.** The transport layer is strictly additive.

## 3. Architecture (locked)

```
EVTX binary bytes (base64 in request body)
   ↓
services.behavioral.evtx_reader.decode_evtx_to_sysmon_xml()
   · magic check      (`ElfFile\x00` prefix required)
   · size cap         (`NIVX_EVTX_MAX_BYTES`, default 16 MiB)
   · record cap       (`NIVX_EVTX_MAX_RECORDS`, default 10 000)
   · python-evtx walks records in on-disk order (deterministic)
   · per-record XML declaration stripped
   · concatenated into `<Events>…</Events>` wrapper
   ↓
services.behavioral.sysmon_adapter.normalize_sysmon_xml()   ← SAME Slice-2 normalizer
   ↓
existing canonical evidence + correlation + authoritative MITRE surface
```

The transport layer **never touches** correlation, dedup, IP canonicalization, evidence provenance, MITRE resolution, or verdict scoring. It is a pure wire-format shim.

## 4. Parser used

`python-evtx==0.8.1` (pure-Python, no native dependencies, no network side effects). Its `Evtx.records()` iterator is deterministic — same input bytes always produce records in the same order.

## 5. Endpoint

`POST /api/behavioral/sysmon/evtx` (auth-gated)
Body: `{"evtx_base64": "<base64 of raw .evtx bytes>"}`

Response shape is identical to `POST /api/behavioral/sysmon` (same envelope), plus one additive `transport` chip:

```json
"transport": {
  "transport":   "sysmon.slice3.evtx@1.0",
  "record_count": 2,
  "raw_bytes":   1024,
  "resource_limits": { "max_bytes": 16777216, "max_records": 10000 }
}
```

## 6. Error codes & HTTP status mapping

| Machine code | HTTP | Cause |
|---|---|---|
| `evtx_bad_base64`          | 400 | base64 decode failure |
| `empty_input`              | 400 | empty payload OR empty XML wrapper |
| `evtx_bad_magic`           | 400 | first 8 bytes != `ElfFile\x00` |
| `evtx_no_records`          | 400 | valid header but 0 records rendered |
| `evtx_record_parse_error`  | 400 | a single record refused to render |
| `evtx_walk_error`          | 400 | chunk-walk exception |
| `evtx_payload_too_large`   | 413 | > `NIVX_EVTX_MAX_BYTES` |
| `evtx_record_cap_exceeded` | 413 | > `NIVX_EVTX_MAX_RECORDS` |
| Slice-1/2 codes            | as before | forwarded from the normalizer |

**No silent truncation. Every failure mode surfaces a machine-readable code.**

## 7. Security controls

| Control | Enforcement |
|---|---|
| Authentication            | `Depends(get_current_user)` — same as Slice-1/2 |
| Resource cap              | `NIVX_EVTX_MAX_BYTES` (default 16 MiB) — enforced BEFORE parsing |
| Record cap                | `NIVX_EVTX_MAX_RECORDS` (default 10 000) — fail-loud |
| Zero outbound lookups     | Locked by `test_slice3_no_outbound_calls_at_import` (static grep for `socket.gethostbyname`, `requests.get`, `aiohttp`, `urllib.request`, `dnspython`, `resolver.resolve`) |
| No arbitrary code exec    | python-evtx is a pure-Python parser; no ctypes/subprocess/eval; base64 decode uses `validate=True` |
| Deterministic output      | On-disk record order preserved; canonical evidence identical across replays |
| Slice-1/2 XML security preserved | The unwrapped `<Events>` string flows through the identical `normalize_sysmon_xml` gate — defusedxml XXE-safe, size cap, Event-ID whitelist {1, 3} |

## 8. Test results

| Test | Result |
|---|---|
| `test_bad_base64` (400 `evtx_bad_base64`) | PASS |
| `test_empty_payload` (400 `empty_input`) | PASS |
| `test_bad_magic` (400 `evtx_bad_magic`) | PASS |
| `test_oversized_payload` (413 `evtx_payload_too_large`) | PASS |
| `test_record_cap_fails_loud` (413 `evtx_record_cap_exceeded`) | PASS |
| `test_walk_error_on_corrupt_body` (400 walk/no_records) | PASS |
| `test_evtx_round_trip_matches_xml_path` (canonical equivalence) | PASS |
| `test_evtx_determinism` (2 replays → identical `evidence_ref`) | PASS |
| `test_transport_only_no_new_mitre` (static grep) | PASS |
| `test_slice3_no_outbound_calls_at_import` (static grep) | PASS |

**10/10 Slice-3 tests PASS.**

**Full combined regression: 104 PASS · 2 skip · 0 FAIL** across Slice-1 + Slice-2 base + Slice-2 extended + Slice-3 + UI-DEF-02 + Item-5 + P0.2 + workspace-isolation + SSOT-isolation.

## 9. Frozen 12-case corpus

- Two back-to-back harness replays against Slice-3 build.
- Compared against Slice-2 snapshot (`results.p2_slice2_run.json`).
- **0 deltas** across all 12 cases (verdict / risk_score_bucket / mitre_ids / lolbas_bins / ioc_counts / language).

## 10. Canonical equivalence proof

Test `test_evtx_round_trip_matches_xml_path` mocks `python-evtx`'s record iterator with two hand-crafted Sysmon events (Event 1 certutil + Event 3 network to 198.51.100.20) and asserts the response is byte-identical (across `mitre_technique_ids`, `event_counts_by_id`, `network_evidence.connections[0].correlation_state`, canonical `destination_ip`) to the response from posting the equivalent XML to `/api/behavioral/sysmon`. The only additive difference is the `transport` meta chip on the EVTX response.

## 11. What Slice-3 does NOT do (owner-scoped)

- No new canonical fields.
- No new MITRE mapper / no new ATT&CK rules.
- No new verdict logic.
- No IKG persistence.
- No Event 11 / Event 22 / other Sysmon EIDs.
- No Workspace UI changes.
- No modification of Slice-1/Slice-2 normalization behaviour.

## 12. Uncovered limitations (deferred)

- **No real-EVTX round-trip corpus** — the pod has no `.evtx` sample files, so the equivalence test relies on `unittest.mock.patch("Evtx.Evtx.Evtx", …)`. A future slice should include a small hand-crafted or vendor-supplied `.evtx` fixture for genuine binary round-trip validation.
- **No streaming** — the whole EVTX is decoded in-memory, capped at 16 MiB / 10 000 records. Streaming ingestion is a future concern.
- **No multi-channel EVTX** — Sysmon channel only; System / Security / Application EVTX files will parse but their non-Sysmon EIDs will hit the whitelist and 422.

## 13. Standing down

Slice-3 closed. Locked sequence remaining:

```
P2 Slice-1 Event 1        ✅
P2 Slice-2 Event 3        ✅
P2 Slice-3 EVTX transport ✅  (this ADR)
       ↓ (await owner)
Slice-4 Event 22 DNS      ⏸
Slice-5 Event 11 File     ⏸
IKG persistence           ⏸
Workspace timeline        ⏸
```

**Do NOT proceed to any further slice, IKG persistence, or Workspace change without explicit owner authorisation.**
