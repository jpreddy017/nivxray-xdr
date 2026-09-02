# Gate 2D-B3.0 · Pre-Migration Parity Snapshot · CHECKPOINT REPORT

**Status:** SNAPSHOT COMPLETE — STOPPED FOR OWNER ACCEPTANCE
**Date:** 2026-02 (fork continuation)
**Gate scope:** B3.0 only — NO codec migration, NO runtime edits.
**mal-20:** untouched (intentional single failure preserved).

---

## What B3.0 delivered

Reusable, deterministic parity harness + frozen baseline for the
authoritative pre-migration reference decoder runtime,
`services.die.preprocessor.recursive_decoder.peel_recursively`.

### Files added (all under `/app/backend/tests/decoder_migration/`)

| File | Purpose |
|---|---|
| `__init__.py` | package marker + scope note |
| `parity_harness.py` | reusable harness: fixture enumeration, snapshot capture, mismatch comparator, report I/O |
| `capture_pre_migration_snapshot.py` | one-shot executable; freezes the pre-migration baseline |
| `pre_migration_manifest.json` | 257-fixture inventory: path, size, `input_sha256`, codec hints, expected sidecar hash |
| `fixture_codec_map.json` | codec-capability → fixture-id map + counts + unhinted list |
| `pre_migration_results.json` | reference decode snapshot: per-fixture layer sequence, final SHA-256, layer counts, provenance, latency + a single **content_signature_sha256** that is byte-identical across re-runs |

### Determinism check (run twice, hashes compared)
```
sig1 = 12378d118ffdc7fd68cbad72547af81b3fe716abe61682652c36b58982308bac
sig2 = 12378d118ffdc7fd68cbad72547af81b3fe716abe61682652c36b58982308bac
→ DECODE-CONTENT-DETERMINISTIC-OK
```
Timestamps + wall-clock latency are excluded from `content_signature_sha256`
by design — only decode observables (fixture_id, ok, exception,
final_sha256, final_bytes_len, layer_sequence, layer_count,
layers_detail, provenance, peeled_any) contribute.

---

## Fixture inventory (frozen baseline)

Total `.txt` fixtures under `tests/fixtures/`: **257**
(`.expected.txt` sidecars excluded; jsonl/evtx/plugin_regression/
regression_baseline/mixed_investigation_input excluded.)

- peeled by reference `peel_recursively` : **25 / 257**
- exceptions raised                     : **0**
- latency p50 / p95 / p99               : **0.007 / 0.041 / 0.087 ms**

### Codec-capability × fixture map

| Capability | Hinted fixtures | Peeled by reference |
|---|---:|---:|
| gzip                 | 6  | **6/6**  |
| zlib_deflate         | 5  | **5/5**  ¹ |
| utf16le              | 5  | **5/5**  (via `ps_encodedcommand`) |
| xor                  | 12 | **1/12** ² |
| repeating_key_xor    | 6  | **0/6**  ³ |
| rc4                  | 5  | **0/5**  ³ |
| aes_cbc              | 5  | **0/5**  ³ |
| pe *(analyzer)*      | 5  | **0/5**  ⁴ |
| shellcode *(analyzer)* | 5  | **0/5**  ⁴ |

Notes:
- ¹ Deflate fixtures actually decode via the `gzip` codec inside
  `peel_recursively` (either the fixture blobs are gzip-framed or
  `_decode_gzip_bytes` accepts both — parity requires the migrated
  codec to reproduce **the same** observable path, not a
  "theoretically-more-correct" one).
- ² Only the byte-array XOR-loop pattern is decoded by
  `peel_recursively` (via `_decode_byte_array_xor_loop`). The other
  11 XOR fixtures rely on the separate `xor_brute` UAIE plugin
  runtime surface.
- ³ **RC4 / AES-CBC / repeating-key-XOR are NOT part of
  `peel_recursively`.** They live in `decoders/crypto_symmetric.py`
  and are only reachable through the UAIE plugin registry. A
  faithful B3 migration therefore has *two* codec source-of-truth
  surfaces to reconcile — see "Honest gap" below.
- ⁴ PE + shellcode analyzers are UAIE plugins, not codecs; they
  never fire inside `peel_recursively`.

### Distinct layer sequences observed (in the 25 peeled fixtures)
```
 10x  ps_encodedcommand
  5x  from_base64_string
  5x  from_base64_string → gzip
  4x  bare_base64
  1x  from_base64_string → gzip → byte_array_xor_loop
```

---

## Honest gap surfaced by B3.0

The scope note in the B3 authorisation lists **7 codec capabilities**
(GZIP · Zlib/Deflate · XOR · repeating-key XOR · RC4 · AES-CBC · UTF-16LE)
plus **2 analyzers** (PE · shellcode).

The B3.0 snapshot proves that **only 3 of the 7 codecs (GZIP, Zlib,
UTF-16LE) and part of the 4th (XOR — byte-array-loop variant only)
are actually present inside `recursive_decoder.peel_recursively`.**

The remaining 3 codecs (RC4, AES-CBC, repeating-key XOR) and both
analyzers (PE, shellcode) live in a *different* runtime surface:

- `decoders/crypto_symmetric.py`   (AES-CBC, RC4)
- `decoders/xor_variants*` /  `xor_brute` UAIE plugin (repeating XOR)
- `services/uaie/plugins/pe_analyzer/…`      (PE)
- `services/uaie/plugins/shellcode_analyzer/…` (shellcode)

**Consequence for B3.1 (codec migration):**
The migration must reconcile **two** parity surfaces:

1. `peel_recursively` orchestrator (already snapshotted here).
2. UAIE-plugin invocation of `decoders/crypto_symmetric.py`,
   `decoders/xor_variants*`, PE and shellcode analyzers.

Before starting B3.1 we must decide whether B3 will absorb both
surfaces or defer surface #2 to a later gate. Choosing to defer
surface #2 is defensible (RC4/AES/PE/shellcode plugins currently
enter incident evidence via a separate wire — not via the
`peel_recursively` runtime path we're migrating), but it must be
**explicit**, not implicit.

**Not decided in this checkpoint.** Reported honestly for owner
adjudication.

---

## Architectural invariants preserved (this checkpoint)

- Zero runtime code changed.
- `services/decoder/` unchanged; still no runtime import of
  `recursive_decoder` from within it (the existing entry point in
  `canonicalize()` is preserved).
- No fixture modified; no `.expected.txt` sidecar modified.
- Immutable P0-1 baseline (`tests/corpus/baseline_p0_1.json`)
  untouched.
- No verdict / IOC / ATT&CK / narration change.
- Provenance envelope on every reference snapshot:
  `static_only=True, execution=False, network_access=False,
  attck_promotion=False`.
- mal-20 not touched.

---

## Ready for B3.1 · Codec migration (order — one family at a time)

Per the B3 authorisation, migration proceeds:

```
GZIP → Zlib/Deflate → XOR → repeating-key XOR → RC4 → AES-CBC → UTF-16LE
```

Each family, after code migration into `services/decoder/base/…`,
must re-run the harness (candidate implementation this time) and
compare against the frozen pre-migration baseline. Any divergence
in `layer_sequence`, `final_sha256`, `provenance`, or
exception/success shape blocks acceptance for that family.

**Awaiting owner acceptance of B3.0 before B3.1 begins, plus a
decision on the surface #2 question above.**
