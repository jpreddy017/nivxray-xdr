# ADR-0010w · P2 Slice-3 · Real EVTX Fixture (Task 2 Stabilization)

**Status**: 🟢 SHIPPED (2026-02-15, Session-20).
**Task**: Owner-approved Task 2 — Real EVTX Fixture.
**Scope**: Replace the mocked primary EVTX round-trip test with a committed, minimal, real Sysmon-generated `.evtx` fixture. Exercise the actual `python-evtx` binary parser in CI. Zero changes to the Sysmon Slice-2 normalizer, the transport layer, the MITRE surface, the verdict engine, or any UI.

## Owner's exact acceptance criteria (verbatim, ticked)

1. ✅ Add the real `.evtx` fixture(s) to the canonical test fixtures.
2. ✅ Exercise the actual `python-evtx` parser in CI.
3. ✅ Remove `patch("Evtx.Evtx.Evtx", ...)` from the primary round-trip test.
4. ✅ Pass the fixture through the existing `evtx_reader` without changing its contract.
5. ✅ Pass parsed events through the existing Sysmon normalizer.
6. ✅ Assert canonical evidence is produced for E1 and E3.
7. ✅ Assert existing correlation-state semantics remain intact.
8. ✅ Assert existing size / magic / malformed-input protections remain intact.
9. ✅ Do NOT add MITRE mappings, verdict logic, IKG behavior, new adapters, or Workspace routing.
10. ✅ Run focused EVTX tests plus complete existing P2 regression suite.
11. ✅ Report exactly what was changed, test counts, and whether any existing behavior changed.

## Files changed

| File | Kind | Purpose |
|---|---|---|
| `backend/tests/fixtures/evtx/sysmon_e1_only.evtx` | NEW · TEST DATA | Real Sysmon capture · 4 × Event 1 (Process Create) · SHA-256 `08ce1fe…6abd` · 69 632 bytes |
| `backend/tests/fixtures/evtx/sysmon_e3_only.evtx` | NEW · TEST DATA | Real Sysmon capture · 12 × Event 3 (Network Connect) · SHA-256 `d7e75b3…7469` · 69 632 bytes |
| `backend/tests/fixtures/evtx/NOTICE.md` | NEW · legal | GPL-3.0 attribution to `sbousseaden/EVTX-ATTACK-SAMPLES` upstream + test-data-only rules |
| `backend/tests/canonical/api/test_p2_slice3_evtx_transport.py` | MODIFIED | Primary tests G, H rewired to real fixtures. New K + L tests. E-only mock retained with explicit justification. |

Nothing else changed. **`backend/services/behavioral/evtx_reader.py`, `sysmon_adapter.py`, and `routers/behavioral.py` are byte-identical to pre-Task-2.**

## Two fixtures — rationale (documented for the record)

Owner said "**containing at least Event ID 1 and Event ID 3**". The Slice-2 normalizer intentionally fail-loud rejects any other Event ID (per ADR-0010r). Every real-world Sysmon capture contains at least a few E10/E11/E13 records alongside E1/E3 — a single mixed real capture would trip the strict adapter. Rather than relax Slice-2 (which would violate Task 2's "no new behavioral semantics"), the fixture set is split:

- `sysmon_e1_only.evtx` — 4 real Event-1 records (revshell captured from a Windows host)
- `sysmon_e3_only.evtx` — 12 real Event-3 records (RDP/SMB tunneling capture)

Together they cover the E1 + E3 requirement without weakening the adapter's strictness.

## Test delta

**Before**: 10 tests in the module. Tests G + H used `patch("Evtx.Evtx.Evtx", return_value=_FakeEvtxLog(...))` — the actual `python-evtx` binary parser was never exercised in CI.

**After**: 12 tests in the module.

| # | Test | Status | Real parser exercised? |
|---|---|---|---|
| A | `test_bad_base64_returns_400` | preserved | boundary before parser (checks bad-base64 detect) |
| B | `test_empty_input_returns_400` | preserved | boundary before parser |
| C | `test_bad_magic_returns_400` | preserved | boundary before parser |
| D | `test_oversized_payload_returns_413` | preserved | boundary before parser |
| E | `test_record_cap_fails_loud` | preserved · **mock retained (justified)** | mock scoped to `Evtx.Evtx.Evtx` only; cap defence requires >10k records which can't be committed as bytes |
| F | `test_walk_error_returns_400` | preserved | real parser walks malformed body |
| **G** | `test_real_evtx_e1_fixture_round_trip` | **rewritten · REAL fixture** | ✅ real `python-evtx` parser end-to-end |
| **H** | `test_real_evtx_determinism` | **rewritten · REAL fixture** | ✅ |
| I | `test_evtx_transport_emits_no_own_technique` | preserved | static grep of the reader source |
| J | `test_slice3_zero_outbound_lookups` | preserved | static grep of the reader source |
| **K** | `test_real_evtx_e3_fixture_network_evidence` | **NEW · REAL E3 fixture** | ✅ · locks evidence-producer constraint (E3 → 0 MITRE) |
| **L** | `test_real_evtx_parity_with_xml_path` | **NEW · REAL fixture** | ✅ · proves EVTX transport is transport-only, not a shadow analyzer |

**All 12 pass. Net +2 tests. One remaining mock in the module (test E), scoped narrowly, documented.**

## Fixture integrity guardrail

Both real `.evtx` files are SHA-256-pinned inside the test module:

```python
_E1_SHA256 = "08ce1feab22e30eb12a5a5b1ba4ac0aa552ff988b762d08de3a4d75ee1636abd"
_E3_SHA256 = "d7e75b35f9db32c91dc0d066ee935b382253fb56659f19c05833c964f8217469"
```

If any future edit mutates the fixture bytes, `_read_fixture()` fails immediately with a clear message pointing to `NOTICE.md`. This prevents silent drift.

## Regression results

- **Focused EVTX tests**: 12 / 12 PASS.
- **Full P2 + UI-DEF-02 regression**: **67 / 67 PASS · 0 drift** (previous baseline was 65 / 65; the delta of +2 is exactly the new K + L tests).
- **No existing behaviour changed** — the byte-identical adapter/reader/router code confirms this; the regression suite confirms the observable behaviour.

## Real-fixture round-trip — what actually happens now

```
sysmon_e1_only.evtx  (69 632 real bytes, GPL-3 upstream, SHA-256 locked)
        │
        ▼
_read_fixture()  ─→  bytes  ─→  base64.encode  ─→  POST /api/behavioral/sysmon/evtx
                                                             │
                                                             ▼
                            backend/services/behavioral/evtx_reader.py
                            decode_evtx_to_sysmon_xml(bytes, …)
                                • magic check (ElfFile\x00)
                                • size gate (≤ 16 MiB)
                                • REAL python-evtx binary parser via Evtx.Evtx.Evtx(io.BytesIO(bytes))
                                • record iteration through Evtx.records() — REAL
                                • record cap (≤ 10 000)
                                • rec.xml() → wrapped <Events>…</Events>
                                             │
                                             ▼
                            backend/services/behavioral/sysmon_adapter.py
                            normalize_sysmon_xml(wrapped_xml)
                                • defusedxml parse (XXE-safe)
                                • per-Data evidence records with evidence_ref
                                • parent-child pair corroboration
                                • per-event MITRE via _authoritative_techniques
                                             │
                                             ▼
                            _build_response(meta, events, transport=evtx_meta)
                                             │
                                             ▼
                            HTTP 200 with canonical envelope
                            (transport.transport = 'sysmon.slice3.evtx@1.0',
                             transport.record_count = 4,
                             transport.raw_bytes = 69632,
                             event_counts_by_id = {"eid1": 4, "eid3": 0},
                             evidence = [ ... real Sysmon fields ... ],
                             parent_child_evidence.pairs = 4,
                             per_event_mitre = 4 entries with real command lines)
```

The mocked `_FakeEvtxLog` / `_FakeRecord` classes still exist in the module but are only referenced by test E's record-cap boundary check.

## What was NOT changed (locks confirmed intact)

- ❌ No new MITRE mappings (owner directive).
- ❌ No new verdict logic (owner directive).
- ❌ No Verdict Engine v3 promotion (owner directive).
- ❌ No IKG promotion (owner directive).
- ❌ No Workspace reroute (owner directive).
- ❌ No new adapters (owner directive).
- ❌ No Sysmon Event 11 work (owner directive · Slice-5 LOCKED).
- ❌ No Sysmon Event 22 work (owner directive · Slice-4 LOCKED).
- ❌ No correlation redesign (owner directive).
- ❌ No UI redesign (owner directive).
- ❌ No X-Lab changes (owner directive).
- ❌ No Sysmon Event 3 "improvement" (owner explicitly forbade — E3 remains evidence-producer-only per ADR-0010q; test K locks the zero-MITRE-from-E3 invariant permanently).
- ❌ `services/behavioral/evtx_reader.py`, `sysmon_adapter.py`, `routers/behavioral.py` — byte-identical to pre-Task-2.

## Provenance / legal note

Real fixtures come from the public `sbousseaden/EVTX-ATTACK-SAMPLES` corpus (GPL-3.0) authored by Samir Bousseaden. Bundled here as **test data only** under `backend/tests/fixtures/evtx/` with `NOTICE.md` recording upstream, SHA-256 pins, and rules of use. Not shipped in production build artifacts. This mirrors standard practice for security-test corpora in mainstream security tools (Volatility, YARA, Suricata, etc.).

If a future policy shift requires eliminating GPL data entirely, the replacement path is a synthetic minimal EVTX writer (600–800 LoC) — deliberately out of scope for Task 2, which explicitly forbids expansion.

## Next-checkpoint boundary

Task 2 done. Per owner directive: **STOP** and hand results back before starting any other task. Task 3 (auto-scroll) and Task 4 (source-agnostic audit) remain queued but LOCKED at this checkpoint.
