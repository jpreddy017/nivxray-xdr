# RC2.2 · Deterministic Decoder Expansion — Release Notes

**Version:** `v1.0.0-RC2.2`
**Ship date:** 2026-07-20
**Branch:** `feature/rc2`
**Tests:** 147/147 engine green (16 new · zero regressions)
**Type:** additive · backward-compatible · no schema break

---

## Why

Production analysts reported that 4 out of 5 test payloads submitted after the
RC2.1a rollout were failing to decode. Reproducing locally against the
deterministic engine surfaced three distinct root causes and a family of
adjacent gaps in the L0-L3 pipeline. RC2.2 closes them.

## What ships

### New plugins (7)

| ID                    | Category       | Purpose                                                       |
|-----------------------|----------------|---------------------------------------------------------------|
| `utf16-decode`        | encoding       | Decode UTF-16LE/BE bytes (with BOM or heuristic)              |
| `ps-reconstruct`      | reconstruct    | `[char]NN`, `[char[]](…)-join`, `'a'+'b'+'c'`, PS backticks   |
| `data-uri-extract`    | reconstruct    | RFC 2397 `data:*;base64,` and percent-encoded body unwrap     |
| `ioc-extractor`       | intelligence   | Harvest URLs / IPs / domains / emails / hashes / BTC / paths  |
| `base58-decode`       | encoding       | Bitcoin / Solana / IPFS alphabet                              |
| `jwt-decode`          | encoding       | JWT header + payload → pretty JSON (terminal-marking output)  |
| `reverse-string`      | reconstruct    | Reverse-string obfuscation (`llehsrewop`, `:sptth`)           |

### Engine tweaks

- `extract_wrapper._normalize()` now strips both CMD `^` **and** PowerShell
  backtick escapes before wrapper regex matching.
- `base64-decode` defers to `base58-decode` when the payload looks like a
  Bitcoin/Solana wallet address (starts with `1`/`3`, len 25-44,
  no `0OIl+/=`).
- `base91-decode` rejects inputs that contain multiple whitespace-separated
  tokens (JSON, prose, wrapped output).
- `xor-brute` skips high-printable structured text (JSON, prose, wrapped
  script output) and short binary blobs (< 32 bytes).
- `fingerprint_util._COMMON_EN` gained JSON claim names (`alg`, `sub`, `iat`,
  `typ`, `header`, `payload`, `signature`, ...) plus common web/short tokens
  so JWT and other structured decodes hit terminal-English quickly.

## Verified end-to-end recoveries

| Payload class                                     | Before          | After                                                          |
|---------------------------------------------------|-----------------|----------------------------------------------------------------|
| `powershell.exe -enc <UTF-16LE-B64>`              | Garbage output  | `extract-wrapper → base64 → utf16 → extract-wrapper` → clean URL |
| `p\`ow\`ers\`h\`ell -e <B64>`                     | No match        | Same clean chain                                                |
| `data:text/html;base64,<B64>`                     | No candidate    | `data-uri-extract → base64 → ioc-extractor`                     |
| `<reversed IEX/DownloadString>`                    | Skipped         | `reverse-string → extract-wrapper → ioc-extractor`              |
| JWT `<header>.<payload>.<sig>`                     | Garbage (XOR)   | `jwt-decode` (terminal, JSON output)                            |
| Base58 wallet `1BvBMS…`                            | b64 misfire     | `base58-decode` (no XOR mangling)                               |
| `[char]0x49+[char]0x45+[char]0x58 …`               | Left literal    | `ps-reconstruct` collapses chained `[char]NN` into `'IEX'`     |

## No breaking changes

- All plugin IDs above are **new**. Existing decoders keep their contracts.
- `AnalystReport` schema unchanged — new signals arrive via existing fields
  (`iocs`, `mitre_hints`, `tradecraft`).
- Family plugin registry count is unchanged (still 9 `family-*`). The
  `test_family_plugins.py` assertion was tightened to filter by the
  `family-` prefix so new intelligence plugins don't trip it.

## Test evidence

- `backend/tests/test_rc22_decoder_pack.py` — 16 tests, all pass.
- Full engine regression: `pytest tests/test_engine_phase_*.py
  tests/test_family_plugins.py tests/test_base32_ascii_decimal.py
  tests/test_regression_lock.py tests/test_rc22_decoder_pack.py`
  → **147 passed** in ~1.7s.
- Preview API smoke: `POST /api/v2/analyze` with
  `powershell.exe -enc SQBFAFgA…` → `output: "http://evil.com/x.ps1"`,
  `trace: [extract-wrapper, base64-decode, utf16-decode, extract-wrapper]`,
  `iocs.urls: ["http://evil.com/x.ps1"]`.

## Rollback

Revert commit range on `feature/rc2` covering the RC2.2 files:

```
backend/decoders/base58.py         (new)
backend/decoders/data_uri.py       (new)
backend/decoders/ioc_extractor.py  (new)
backend/decoders/jwt.py            (new)
backend/decoders/ps_reconstruct.py (new)
backend/decoders/reverse_string.py (new)
backend/decoders/utf16.py          (new)
backend/decoders/base64.py         (modified — base58 defer branch)
backend/decoders/base91.py         (modified — reject structured text)
backend/decoders/extract_wrapper.py (modified — PS backtick strip)
backend/decoders/xor_brute.py      (modified — structured-text guard)
backend/engine/fingerprint_util.py (modified — expanded English list)
backend/tests/test_family_plugins.py (modified — filter by `family-` prefix)
backend/tests/test_rc22_decoder_pack.py (new)
memory/PRD.md                      (modified — RC2.2 section)
```

No DB migrations, no env-var changes.

## Known remaining gaps (deferred to RC2.3/2.4)

- Base58 → downstream decode of the raw wallet bytes still yields opaque
  bytes (this is by design — a wallet address IS the payload).
- Brotli / LZMA / xz compression decoders (targeted for RC2.2 batch 2).
- Homoglyph normalization (Cyrillic → Latin) and case-normalization.
- Advanced CMD reconstruction (`%var%`, `!DELAYED!`, `for /f`).
