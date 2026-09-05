# NivXRay v1.5.0 — Release Metrics Snapshot

**Release date:** 2026-07-28
**Status:** ✅ Feature-frozen, ready for staging → production
**Branch policy:** No new features on `v1.5.x`. All new engineering
effort routes to `v1.6.0`.

> These numbers are *measured*, not asserted. Re-run
> `scripts/v1_5_0_release_metrics.py` on any commit of the branch to
> reproduce them.

---

## Quality dashboard

| Metric | Value | Source |
| ------ | ----- | ------ |
| Golden Corpus pass rate | **100 %** on the v1.5.0 locked set | `tests/test_decoder_convergence_v150.py` |
| Total decoder-convergence tests | **33 passed · 1 skipped** (34 total) | pytest |
| Broader adjacent regression (decoder + behaviour + verdict + investigation) | **209 passed** · 3 unrelated pre-existing failures held baseline | pytest |
| Median decode latency (typical) | **0.71 ms** (synthetic clean 3-stage) | probe · 50 runs |
| Median decode latency (corrupt real sample) | **3.90 ms** | probe · 50 runs |
| Median decode latency (plain PS · no transforms) | **0.04 ms** | probe · 50 runs |
| Median decode latency (30-layer nested stress) | **309.15 ms** | probe · 50 runs · worst-case dominant |
| P95 across all samples | **≈ 311 ms** | dominated by the 30-layer stress test |
| P99 across all samples | **≈ 314 ms** | idem |
| Target latency budget | **≤ 500 ms** at P99 | ✅ met with ≥ 37 % headroom |
| Max recursion depth exercised | **30 layers** | `test_deep_recursion_terminates_within_budget` |
| `DEFAULT_MAX_DEPTH` safety cap | **64** | `engine.py` |
| Determinism (hash stability across 3 runs / sample) | **stable · all 5 samples** | `scripts/v1_5_0_release_metrics.py` |
| Registered diagnostic codes | **11** (6 error · 3 warning · 2 info) | `diagnostic_codes.py` |
| False-positive corpus | **PASS** — benign admin PS reading `.gz` files never triggers the resolver | `test_benign_administrative_ps_does_not_false_positive` |
| Reserved diagnostic ranges for v2.0 | **DX3xxx – DX9xxx** pre-allocated | `diagnostic_codes.py` docstring + CI test |

**Reproduce the numbers**: `python3 scripts/v1_5_0_release_metrics.py`

## Supported transformations (v1.5.0)

| Category | Formats |
| -------- | ------- |
| **Base64 wrappers** | UTF-16LE base64, UTF-8 base64, raw byte base64 |
| **PowerShell surface transforms** | `-EncodedCommand`, format-string `-f`, char-array `[char]`, `IEX (…)` unwrap |
| **PowerShell embedded transforms** | Static `[Convert]::FromBase64String("<lit>")`, strict-order `[IO.Compression.GzipStream]([IO.MemoryStream][Convert]::FromBase64String("<lit>"), …Decompress)` |
| **Variable-bound compression *(NEW in v1.5.0)*** | `$VAR = FromBase64String("<lit>")` → `[IO.Compression.GzipStream]($VAR, …Decompress)` (arbitrary variable name, gzip / deflate / brotli, MemoryStream wrap optional) |
| **Compression** | GZip, DEFLATE (raw), Brotli (when library installed) |
| **Binary encodings** | Hex byte strings, ZLIB streams |

## Deterministic stopping invariants (unchanged from v1.3.0)

| Reason | Code | Severity |
| ------ | ---- | -------- |
| No further deterministic transformation applies | `DX2002` | info |
| Content hash reappeared (loop) | `DX2003` | warning |
| Safety depth cap hit (`DEFAULT_MAX_DEPTH = 64`) | `DX2001` | warning |
| Payload type has no handler | (`UNSUPPORTED`) | n/a |
| Empty input | (`EMPTY_INPUT`) | n/a |

## Machine-readable diagnostic contract

Every `TransformationChain` surfaces `diagnostics[]` on
`/api/decode/smart` with fields:

```
{
  "layer":        <int>,
  "detector":     "ps_indirect_compression_stream" | "rte.engine" | …,
  "attempted":    "<short human description>",
  "outcome":      "decode_failed" | "orchestration" | …,
  "reason":       "<evidence-based paragraph>",
  "meta":         { "blob_length": …, "blob_mod4": …,
                    "expected_padding": …, "inflate_attempted": …,
                    "bytes_available": …, "magic_bytes": …,
                    "inflate_exception": …, "compression_kind": …,
                    "variable": …, "stage": …, … },
  "code":         "DX1001" | "DX1101" | "DX2002" | …,
  "failure_type": "INVALID_BASE64_LENGTH" | … ,
  "severity":     "error" | "warning" | "info",
  "caused_by":    "<code of upstream diagnostic>" | ""
}
```

Consumers key off `code` + `severity` + `caused_by`, not free-text
`reason`.

---

## Operational go-live checklist

1. [ ] Deploy `v1.5.0` to the staging environment.
2. [ ] Run production smoke tests on:
   - [ ] a valid `-EncodedCommand` sample
   - [ ] a malformed sample (mod-4 misaligned base64)
   - [ ] a benign administrative PowerShell script
   - [ ] samples from at least three malware families
3. [ ] Verify telemetry:
   - [ ] p95 latency ≤ 500 ms
   - [ ] decoder-success rate ≥ v1.4.3 baseline
   - [ ] `DX2002` info-severity rate stable
   - [ ] no unexpected `DX2001` (max-depth) or `DX2003` (loop) spikes
4. [ ] Deploy to production (`nivxray.nivxforge.com`).
5. [ ] Monitor for ≥ 72 h.
6. [ ] Tag the release and lock the branch.

## Frozen for v1.5.0 — routed to v1.6.0+

| Feature | Route |
| ------- | ----- |
| Semantic variable-resolution (def-use analysis) | v1.6.0 (`DX3xxx` range) |
| Helper-variable resolution (`$a = FromBase64String; $b = $a; GzipStream($b, …)`) | v1.6.0 |
| Corpus auto-growth with categories | v1.6.0 (`DX8xxx` range) |
| Advanced PowerShell semantic graph | v1.6.0 |
| Crypto semantic analysis (XOR / RC4 / AES) | v1.7.0 (`DX4xxx` range) |
| Full PowerShell AST / data-flow engine | v1.7.0 (`DX6xxx` range) |
| Cross-language correlation (CMD → PS → JS → .NET) | v2.0 |
| Automatic decoder recommendations | v2.0 |
