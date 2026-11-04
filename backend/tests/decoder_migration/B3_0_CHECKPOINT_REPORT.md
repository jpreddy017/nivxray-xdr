# Gate 2D-B3.0 · Pre-Migration Parity Snapshot · CHECKPOINT REPORT (both surfaces)

**Status:** BOTH SNAPSHOTS COMPLETE — STOPPED FOR OWNER ACCEPTANCE
**Owner decision:** (a) B3 absorbs BOTH decoder runtime surfaces.
**Gate scope:** B3.0 only — NO codec migration, NO runtime edits.
**mal-20:** untouched.

---

## Files added (all under `/app/backend/tests/decoder_migration/`)

| File | Purpose |
|---|---|
| `__init__.py` | package marker + scope note |
| `parity_harness.py` | reusable harness: enumerate, snapshot, compare, report I/O |
| `capture_pre_migration_snapshot.py` | Snapshot #1 driver (`peel_recursively` surface) |
| `capture_pre_migration_snapshot_2.py` | Snapshot #2 driver (crypto + xor-brute + PE + shellcode surface) |
| `pre_migration_manifest.json` | 257-fixture inventory + SHA-256 |
| `fixture_codec_map.json` | codec-capability → fixture-id map |
| `pre_migration_results.json` | Snapshot #1 reference results |
| `pre_migration_snapshot_2.json` | Snapshot #2 reference results |
| `B3_0_CHECKPOINT_REPORT.md` | this document |

---

## Snapshot #1 · `recursive_decoder.peel_recursively` surface

Frozen behaviour of the primary orchestration path. Determinism
verified across two consecutive runs.

- `content_signature_sha256 = 12378d118ffdc7fd68cbad72547af81b3fe716abe61682652c36b58982308bac`
- 257 fixtures probed · 25 peeled · 0 exceptions
- latency p50 / p95 / p99 = 0.007 / 0.041 / 0.087 ms

Codec-capability coverage:

| Capability | Hinted fixtures | Peeled by reference |
|---|---:|---:|
| gzip | 6 | 6/6 |
| zlib_deflate | 5 | 5/5 (¹ path canonicalises to gzip) |
| utf16le | 5 | 5/5 (via `ps_encodedcommand`) |
| xor (byte-array-loop only) | 12 | 1/12 |
| repeating_key_xor | 6 | 0/6 |
| rc4 | 5 | 0/5 |
| aes_cbc | 5 | 0/5 |
| pe *(analyzer)* | 5 | 0/5 |
| shellcode *(analyzer)* | 5 | 0/5 |

Distinct layer sequences observed on the 25 peeled fixtures:
```
 10x  ps_encodedcommand
  5x  from_base64_string
  5x  from_base64_string → gzip
  4x  bare_base64
  1x  from_base64_string → gzip → byte_array_xor_loop
```

---

## Snapshot #2 · Second runtime surface

References:
- `decoders.crypto_symmetric.Rc4Decoder`
- `decoders.crypto_symmetric.AesCbcDecoder`
- `decoders.xor_brute.XorBruteDecoder`
- `services.pe_analyzer.analyze_pe`
- `shellcode_analyzer.analyze`

Availability check on the pod: all 5 references import and load
cleanly (`pefile`, `capstone`, `cryptography` present).

- `content_signature_sha256 = 6427903eae774599f1c8e710223fb6d603276e5fae1a1fad1f8ecd453b297897`
- 38 applicable fixtures probed · 0 exceptions
- latency p50 / p95 / p99 = 0.020 / 380.6 / 471.6 ms
  *(xor-brute multi-key search is the p95/p99 driver — expected.)*

Per-capability fire rate:

| Capability | Probed | Detect ≥ 0.30 | Decoded output | Analyzer applicable |
|---|---:|---:|---:|---:|
| rc4        | 5  | 0 | 0 | — |
| aes_cbc    | 5  | 0 | 0 | — |
| xor_brute  | 18 | 5 | 5 | — |
| pe         | 5  | — | — | 0 |
| shellcode  | 5  | — | — | 0 |

---

## Honest finding — the surface #2 corpus barely exercises surface #2

The 20 fixtures hinting at RC4 / AES-CBC / PE / shellcode do **NOT
carry** recoverable ciphertext or an embedded PE/shellcode blob:

- `corpus_rc4_analyst_00[1-5]` / `corpus_aes_cbc_analyst_00[1-5]`
  contain PowerShell/CMD scaffolding that *references* RC4/AES
  idioms but no key candidate is discoverable inside the artifact
  (they were authored as *analyst-prompt* fixtures, meant to
  surface a `KEY REQUIRED` UI flag — not to end-to-end decrypt).
- `corpus_reflection_assembly_00[1-5]` do **not** embed a real
  MZ-header PE blob; they simulate a reflective-loader shape.
- `corpus_shellcode_virtualalloc_00[1-5]` do **not** embed real
  shellcode bytes either — they demonstrate the VirtualAlloc /
  RWX loader tradecraft in text form.

Only `xor_brute` (5/18 decodes) provides a genuine
positive-parity anchor on the fixture set.

**Consequence for B3.1 codec parity:**
The parity harness will primarily prove *NO REGRESSION* for
RC4 / AES-CBC / PE / shellcode — i.e. the migrated code must
**not newly fire** on the same fixtures, which is exactly the
"false reconstruction" guard the DDO already enforces on Snapshot
#1's 7 new codecs. Positive-parity validation for RC4/AES/PE/
shellcode against real ciphertexts and real embedded binaries
requires **new fixtures** — that is a separate deliverable (Gate
2F offline corpus generation), NOT part of B3.

Owner acknowledged this exit path in the B3 authorisation:
> "If a legacy capability cannot be migrated with parity, STOP
>  and report the exact blocker rather than silently changing
>  behavior."

**Reporting it now — before touching any migration code.**

---

## Both snapshots — combined determinism proof

```
Snapshot #1 signature :  12378d118ffdc7fd68cbad72547af81b3fe716abe61682652c36b58982308bac
Snapshot #2 signature :  6427903eae774599f1c8e710223fb6d603276e5fae1a1fad1f8ecd453b297897
Snapshot #1 re-run    :  IDENTICAL
Snapshot #2 re-run    :  IDENTICAL
```

Both content signatures are computed over decode observables only
(fixture_id, hints, detect confidence, output SHA-256, output
length, tradecraft flag set, MITRE hint set, analyzer report
fields) — timestamps and wall-clock latency are excluded by
design so any drift in the *decode surface* is instantly visible.

---

## Baseline regression (proof that B3.0 changed nothing at runtime)

```
tests/decoder_harness  : 32/32 passed
tests/corpus           : 76 passed · 1 failed (mal-20 · intentional, deferred)
```

No new tests were added to the runtime suite. Snapshot capture
runs are **read-only** with respect to production code.

---

## Architectural invariants (this checkpoint)

- Zero runtime code changed.
- `services/decoder/` still has zero runtime import of
  `recursive_decoder`.
- Fixtures and `.expected.txt` sidecars untouched.
- `tests/corpus/baseline_p0_1.json` untouched.
- No verdict / IOC / ATT&CK / narration change.
- Static-only invariants preserved (snapshot only reads bytes;
  never runs a decoded payload).
- mal-20 not touched.

---

## Migration order for B3.1 (per owner authorisation)

```
GZIP → Zlib/Deflate → XOR → repeating-key XOR → RC4 → AES-CBC → UTF-16LE
```

After each family:
1. Migrate implementation into `services/decoder/base/…`.
2. Wire it via the DDO signature registry (no new orchestration path).
3. Re-run `capture_pre_migration_snapshot*` in *candidate* mode
   (harness supports it via the same `snapshot_reference()` call
   with the migrated function passed as `peel_fn` / plugin class).
4. Byte-compare `content_signature_sha256` against the frozen
   baseline. Any divergence → STOP + report.
5. Analyzer migration (PE, shellcode) into `services/analyzers/`
   follows codec migration, gated by the same content signatures.

Latency budget: **≤5% per-fixture regression** measured against
the p50/p95/p99 numbers frozen above.

Zero-runtime-dependency proof (dependency-audit test) to be added
in **B3.3** as required by the authorisation.

---

## STOPPED for owner acceptance of Snapshots #1 + #2 before B3.1 begins.
