# Gate 2D-B3.2 · Analyzer Separation + DDO Codec Wiring · CHECKPOINT REPORT

**Status:** COMPLETE (B3.2 + B3.2-A completion correction applied) — STOPPED FOR OWNER ACCEPTANCE
**Owner scope note:** B3.2 is a migration/separation gate, not feature-expansion.
**Wording adopted:** Frozen-fixture output parity verified using SHA-256 content signatures. (Not "cryptographically proving universal zero behavioural change.")
**mal-20:** untouched.

---

## Change ledger (B3.2 initial + B3.2-A correction)

### B3.2 initial delivery
1. **PE analyzer** moved (byte-identical) → `services/analyzers/pe.py`. Legacy `services/pe_analyzer.py` = re-export shim. Identity check: `legacy is new` = True.
2. **Shellcode analyzer** moved (byte-identical) → `services/analyzers/shellcode.py`. Legacy `shellcode_analyzer.py` = re-export shim. Identity check: True.
3. **`services/analyzers/__init__.py`** exposes `ANALYZER_INVARIANTS` contract.
4. **DDO** signature-dispatches 4 of the 7 migrated Plane-A codecs via `services/decoder/base/_ddo_adapter.py`.

### B3.2-A completion correction (owner-directed)
5. Added DDO adapters for the remaining 3 migrated families:
   - `ddo_xor_brute` → `services.decoder.base.xor_brute.XorBruteDecoder`
   - `ddo_rc4`       → `services.decoder.base.crypto.Rc4Decoder`
   - `ddo_aes_cbc`   → `services.decoder.base.crypto.AesCbcDecoder`
6. Signatures added to `_SIGNATURES` for `base.xor_brute` / `base.rc4` / `base.aes_cbc`.
7. **All 7 migrated families now DDO-reachable.**
8. **`tests/decoder_harness/test_ddo_dispatch_matrix.py`** freezes the 7/7 dispatch invariant so any future regression fails a fast test.

---

## Final DDO dispatch matrix (7/7 Plane-A + 7 encoding = 14 total)

| # | Signature name | Adapter callable | Authoritative implementation |
|--:|---|---|---|
| 1 | `base.gzip`                | `ddo_gzip`                | `services.decoder.base.compression.decode_gzip_bytes` |
| 2 | `base.zlib`                | `ddo_zlib`                | `services.decoder.base.compression.decode_zlib_bytes` |
| 3 | `base.byte_array_xor_loop` | `ddo_byte_array_xor_loop` | `services.decoder.base.transform.decode_byte_array_xor_loop` |
| 4 | `base.xor_brute`           | `ddo_xor_brute`           | `services.decoder.base.xor_brute.XorBruteDecoder` |
| 5 | `base.rc4`                 | `ddo_rc4`                 | `services.decoder.base.crypto.Rc4Decoder` |
| 6 | `base.aes_cbc`             | `ddo_aes_cbc`             | `services.decoder.base.crypto.AesCbcDecoder` |
| 7 | `base.ps_encodedcommand`   | `ddo_ps_encoded_command`  | `services.decoder.base.powershell_encoded_command.decode_ps_encoded_command` |

Plus 7 pre-existing encoding codecs (url / unicode / html / base32 / base85 / octal / decimal ASCII) — all wired via `services.decoder.base.encoding`.

### Adapter contract (thin invocation-shape bridge)

For text-in / text-out codecs (families 1, 2, 3, 7):
```
adapter(text) = _text_or_none(codec_fn(text))   # drops the meta dict
```

For plugin-shape codecs (families 4, 5, 6 — B3.2-A):
```
adapter(text):
    ensure_shims()                              # module-level lazy init
    fp = _fp_for(text)                          # deterministic Fingerprint
    det = plugin.detect(text, fp, ctx)          # authoritative detect()
    if det.confidence < 0.30: return None       # same floor as legacy
    res = plugin.decode(text, det.args, ctx)    # authoritative decode()
    return res.output or None                   # DDO's Optional[str]
```

Zero new capability. Zero new heuristics. The confidence floor
`0.30` mirrors the legacy plugin-registry acceptance floor
verbatim. The Fingerprint contains only what the plugins read
(`input_len`, `entropy`, `printable_ratio`).

---

## Signature discipline

Signatures are intentionally strict — they require BOTH the
algorithm token AND a base64/hex blob of sufficient length in the
same window:

```
base.xor_brute  → \b(?:xor|bxor)\b.{0,240}(?:[b64]{40+}|[hex]{80+})
base.rc4        → \b(?:rc4|arc4)\b.{0,240}(?:[b64]{40+}|[hex]{80+})
base.aes_cbc    → \baes(?:-|_)?(?:cbc|ecb|128|192|256)?\b.{0,240}(?:[b64]{40+}|[hex]{80+})
```

`test_adapter_never_fires_on_benign_ascii` proves the adapters
return `None` on plain English, benign PowerShell (`Get-Service |
Where-Object Status -eq Running`), and SQL. On genuinely
crypto-shaped input the plugin's own `.detect()` gates the actual
decode.

---

## Frozen-fixture parity proof (SHA-256 content signatures)

```
Snapshot #1  frozen at B3.0    : 12378d118ffdc7fd68cbad72547af81b3fe716abe61682652c36b58982308bac
Snapshot #1  post-B3.2-A       : 12378d118ffdc7fd68cbad72547af81b3fe716abe61682652c36b58982308bac  MATCH

Snapshot #2  frozen at B3.0    : 6427903eae774599f1c8e710223fb6d603276e5fae1a1fad1f8ecd453b297897
Snapshot #2  post-B3.2-A       : 6427903eae774599f1c8e710223fb6d603276e5fae1a1fad1f8ecd453b297897  MATCH
```

Frozen-fixture output parity verified using SHA-256 content
signatures. SHA-256 identity proves parity of the frozen captured
outputs, not universal behavioural equivalence for every possible
input.

---

## Regression gate

| Suite | Result |
|---|---|
| `tests/decoder_harness/` (incl. new `test_ddo_dispatch_matrix.py` +10) | 42 / 42 pass |
| `tests/corpus/` (excl. mal-20) | 76 / 76 pass |
| `tests/corpus/test_corpus.py::test_scenario[mal-20]` | fail (intentional) |
| `tests/test_decoder_bridge.py` + `test_intelligence_policy.py` + `test_phase2_final_gate.py` | 32 / 32 pass |
| **Combined** | **150 / 150 pass** (excl. mal-20) |

New invariant test file: `tests/decoder_harness/test_ddo_dispatch_matrix.py`

- `test_ddo_signature_table_contains_all_7_migrated_families` ✓
- `test_ddo_dispatch_fns_wired_to_authoritative_adapter`      ✓ (identity check via `is`)
- `test_ddo_invariants_intact`                                ✓
- `test_adapter_never_fires_on_benign_ascii` (×7 parametrised) ✓

---

## Architectural state after B3.2 + B3.2-A

- `services/decoder/base/*`  — 7 authoritative Plane-A codec implementations.
- `services/analyzers/{pe,shellcode}.py` — 2 authoritative artifact analyzers.
- `services/decoder/orchestrator.py` — DDO signature-dispatches **all 7 migrated Plane-A codecs** + 7 encoding codecs = **14/14 total**.
- Legacy paths (`recursive_decoder.py`, `decoders/{crypto_symmetric,xor_brute}.py`, `services/pe_analyzer.py`, `shellcode_analyzer.py`) — thin re-export shims, zero unique logic.
- UAIE plugin adapters (`crypto_rc4`, `crypto_aes_cbc`, `xor_brute`, `pe_analyzer`, `shellcode_analyzer`) — still functional via shims; they now reach the SAME authoritative implementations the DDO reaches.

**Invariants preserved end-to-end:**
- `static_only=True · execution=False · network_access=False · attck_promotion=False · provenance_required=True`
- No new codec / analyzer capability introduced.
- No verdict / IOC / ATT&CK / narration change.
- Fixtures + `.expected.txt` sidecars untouched.
- `tests/corpus/baseline_p0_1.json` untouched.
- mal-20 untouched.

---

## Explicit deferrals

- **B3.3** — static import-graph + runtime dependency audit (CI-enforced test that fails if `services/decoder/*` or `services/analyzers/*` import a legacy module in production paths).
- **B3.4** — final validation gate (both harnesses + full pytest + median-based latency ≤5%).
- **Gate 2F** — real positive-fixture corpus for RC4 / AES-CBC / PE / shellcode (not part of B3).

---

## STOPPED for owner acceptance of B3.2 (+B3.2-A) before B3.3 begins.
