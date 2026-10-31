# Gate 2D-B3.1 · Plane-A Codec Migration · CHECKPOINT REPORT

**Status:** ALL 7 CODEC FAMILIES MIGRATED — FROZEN-FIXTURE OUTPUT PARITY — STOPPED FOR OWNER ACCEPTANCE
**Owner directive:** option (a) — B3 absorbs BOTH decoder runtime surfaces.
**mal-20:** untouched (still the sole intentional failing test).

---

## Migration principle applied uniformly across all 7 families

Each family follows the exact same 5-step surgical pattern:

1. Create authoritative implementation in `services/decoder/base/*` (or `services/analyzers/*` for analyzers — Gate 2D-B3.2 territory).
2. Extract shared helpers into `services/decoder/base/_shared.py`.
3. Convert the legacy location into a **thin re-export shim**:
   `from services.decoder.base.<module> import <fn> as <legacy_name>  # noqa: F401`
   `<legacy_name> is <fn>` returns `True` — legacy callers get the exact same function object.
4. Re-run BOTH parity snapshots — content signatures must be byte-identical.
5. Re-run decoder_harness + corpus regression suite.

The result: `services/decoder/base/*` is now the **single authoritative source location** for all 7 codec implementations. `recursive_decoder.py`, `decoders/crypto_symmetric.py`, and `decoders/xor_brute.py` remain in place as **legacy/reference wrappers** — they contain zero unique codec logic post-migration.

---

## Per-family migration ledger

| # | Family | Legacy origin | New home | Parity |
|--:|---|---|---|---|
| 1 | GZIP | `recursive_decoder._decode_gzip_bytes` | `services/decoder/base/compression.decode_gzip_bytes` | ✓ Snap #1 identical |
| 2 | Zlib / Deflate | `recursive_decoder._decode_zlib_bytes` | `services/decoder/base/compression.decode_zlib_bytes` | ✓ Snap #1 identical |
| 3 | XOR (byte-array loop, single-byte) | `recursive_decoder._decode_byte_array_xor_loop` | `services/decoder/base/transform.decode_byte_array_xor_loop` | ✓ Snap #1 identical |
| 4 | Repeating-key XOR (brute-force) | `decoders/xor_brute.XorBruteDecoder` | `services/decoder/base/xor_brute.XorBruteDecoder` | ✓ Snap #2 identical |
| 5 | RC4 | `decoders/crypto_symmetric.Rc4Decoder` | `services/decoder/base/crypto.Rc4Decoder` | ✓ Snap #2 identical |
| 6 | AES-CBC (+ ECB) | `decoders/crypto_symmetric.AesCbcDecoder` | `services/decoder/base/crypto.AesCbcDecoder` | ✓ Snap #2 identical |
| 7 | UTF-16LE (via PS-EncodedCommand) | `recursive_decoder._decode_ps_encoded_command` + `_utf16le_realign` | `services/decoder/base/powershell_encoded_command.py` | ✓ Snap #1 identical |

**Shared helpers moved to `services/decoder/base/_shared.py`:**
`_RAWBYTES_RE`, `_extract_rawbytes`, `_mostly_printable`, `_IP_RE`, `_URL_RE`, `_DOM_RE`, `_shellcode_string_scan`.

---

## Byte-identical parity proof (frozen-fixture output parity)

Frozen-fixture output parity verified cryptographically; no
observed behavioral regression within the migration parity corpus.
SHA-256 identity of the captured signatures proves parity of the
frozen observed outputs, not universal behavioural equivalence for
every possible input.

```
Snapshot #1 (peel_recursively surface)
  frozen at B3.0     : 12378d118ffdc7fd68cbad72547af81b3fe716abe61682652c36b58982308bac
  post-migration     : 12378d118ffdc7fd68cbad72547af81b3fe716abe61682652c36b58982308bac
  MATCH: OK

Snapshot #2 (crypto + xor-brute + PE + shellcode surface)
  frozen at B3.0     : 6427903eae774599f1c8e710223fb6d603276e5fae1a1fad1f8ecd453b297897
  post-migration     : 6427903eae774599f1c8e710223fb6d603276e5fae1a1fad1f8ecd453b297897
  MATCH: OK
```

Content signatures are computed over decode observables only
(fixture_id, ok, exception, final_sha256, final_bytes_len,
layer_sequence, layer_count, layers_detail, provenance,
peeled_any). Any behavioural drift — output byte change, layer
ordering change, provenance flag change, exception class change —
would flip the SHA-256. Neither did.

---

## Regression gate

| Suite | Result |
|---|---|
| `tests/decoder_harness/` | 32 / 32 pass |
| `tests/corpus/` (excl. mal-20) | 76 / 76 pass |
| `tests/corpus/test_corpus.py::test_scenario[mal-20]` | fail (intentional, honestly deferred) |
| `tests/test_decoder_bridge.py`, `test_intelligence_policy.py`, `test_phase2_final_gate.py` | 32 / 32 pass |

UAIE plugin adapter smoke test:
```
services.uaie.plugins.{crypto_rc4, crypto_aes_cbc, xor_brute,
                       pe_analyzer, shellcode_analyzer}  → LOAD OK
identity check: legacy import IS new import
```

---

## Latency budget

**Snapshot #2 (100s of ms · statistically meaningful):**
```
p50: baseline 0.0200  post 0.0197  Δ  −1.4%   OK
p95: baseline 380.64  post 379.48  Δ  −0.3%   OK
p99: baseline 471.60  post 471.24  Δ  −0.1%   OK
```

**Snapshot #1 (7–90 µs · single-run variance dominates):**
```
p50 post 0.0075  Δ vs single-shot baseline +7.7%
p95 post 0.0416  Δ vs single-shot baseline +1.4%
p99 post 0.0750  Δ vs single-shot baseline −13.8%
```

At sub-100 µs scale the B3.0 baseline was captured from ONE run
and the natural run-to-run variance measured across 5 subsequent
runs is ±20 % on p50 and ±90 % on p99. Post-migration medians sit
inside the baseline noise envelope. **No real regression** — the
migration is a pure import-redirect (`legacy_name is new_name`
returns True; the function object is literally the same).

Honest reporting: had we required strict-median ≤5%, we would
re-run Snapshot #1 at least 10× and compare medians — that
methodology is proposed for B3.4 (final validation) and not
adopted here to avoid inflating the harness cost.

---

## Architectural invariants (this checkpoint)

- `static_only=True · execution=False · network_access=False · attck_promotion=False` — preserved on every migrated codec (structurally identical to legacy; the function object is the same).
- No new codec capabilities introduced.
- No verdict / IOC / ATT&CK / narration change.
- No DDO semantic change.
- Fixtures + `.expected.txt` sidecars untouched.
- `tests/corpus/baseline_p0_1.json` untouched.
- mal-20 untouched.

**Interim architectural state (before B3.2):**
- `services/decoder/base/*` is the SOURCE-OF-TRUTH implementation location for all 7 codecs.
- `services/die/preprocessor/recursive_decoder.py` and `decoders/{xor_brute,crypto_symmetric}.py` are import shims (zero unique codec logic).
- `services/decoder/` still has **zero** runtime import of `recursive_decoder` (unchanged from B3.0).
- Legacy callers of `recursive_decoder` (`analysis_core.py`, `services/decoder_bridge/`, `pipeline.py`, `investigation_results.py`) transitively route to `services/decoder/base/*` via the shim — one authoritative implementation, backwards-compatible entry points.

---

## Explicit deferrals to B3.2 / B3.3

- **PE analyzer** → `services/analyzers/pe/` (B3.2 · Gate authorisation says "PE and shellcode functionality into services/analyzers/").
- **Shellcode analyzer** → `services/analyzers/shellcode/` (B3.2).
- **DDO signature-based dispatch of migrated codecs** — the DDO in `services/decoder/orchestrator.py` currently signature-dispatches only the 7 new text-encoding codecs from B1. Wiring the 7 migrated Plane-A codecs (which operate on `@@RAWBYTES@@`-sentinel-embedded text, a different input contract) into DDO dispatch is scheduled for **B3.2 tail-end** so the analyzer separation and DDO integration land together.
- **Zero-runtime-dependency proof** (CI import-graph audit test + runtime audit) — B3.3.
- **Full validation gate** (both harnesses + full pytest + latency ≤5% median-based) — B3.4.

---

## STOPPED for owner acceptance of B3.1 before B3.2 (PE + shellcode analyzer separation + DDO codec wiring) begins.
