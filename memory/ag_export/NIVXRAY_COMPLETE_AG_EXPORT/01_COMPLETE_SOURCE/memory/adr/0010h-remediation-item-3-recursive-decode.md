# ADR-0010h · Remediation Item 3 — Recursive Decode

**Status:** ✅ IMPLEMENTED · 2026-08-12 · owner authorised
**Scope:** ADR-0010e §10 item 3 · ADR-0023 §4 precondition 3
**Guiding principle:** ADR-0023 §3a Cruise-Missile — pursue the evidence chain layer by layer, but never manufacture verdicts; the decoder only surfaces new evidence for the existing correlation engine to consume.

---

## 1 · Problem (from ADR-0010e §7 Q3 · §10 item 3)

`rip-08-nested-b64-ps` produced only outer-layer evidence: `T1027, T1059.001, T1564.003` — the DIE analyzer never invoked its own single-input pipeline on the base64-decoded inner PowerShell. Result: the inner URL, inner `IEX`+`DownloadString` invocation, and the T1140 (Deobfuscate/Decode) technique were invisible even though the raw evidence was one `base64.b64decode()` call away.

## 2 · Change (additive-only · deterministic · bounded)

### 2.1 · New module `backend/services/die/recursive_decode.py`

- `extract_decoded_layers(src) -> List[DecodedLayer]` — pattern-scans for `-Enc[odedCommand]?`, `FromBase64String('…')` and `base64 -d …`, then peels each blob recursively.
- Encoding preference: **UTF-16LE first** (PowerShell default), then UTF-8. Selection is score-based (printable-ratio minus 2× NUL-density, floor 0.7).
- Hard caps: **`MAX_DEPTH = 3`**, **`MAX_LAYERS = 12`**, `MIN_B64_LEN = 20`, `MAX_B64_LEN = 500_000`.
- **Cycle guard**: SHA-256 visit set on every base64 blob (a payload that decodes into itself, base64-of-itself, etc.).
- Defensive: odd-length UTF-16LE payloads (real-world truncation artefacts) get the trailing byte dropped so a single lost byte does not blind the analyzer to the whole layer.
- `merge_evidence(outer, inner_envelopes)` — dedup on technique.id · lolbins.binary · (iocs.kind, iocs.value). Synthesises **T1140** (`Deobfuscate/Decode Files or Information`) when ≥ 1 new evidence element is added, with evidence-provenance string naming the recursive decode source.

### 2.2 · Hook in `backend/services/die/api.py::analyze()`

Post-envelope, the analyzer calls `_apply_recursive_decode(env, src)`:
1. Extract layers via `extract_decoded_layers()`
2. Re-invoke `_analyze_single()` on each decoded layer (the same code path used for the outer input)
3. Merge new techniques + lolbins + iocs into the outer envelope
4. Attach `env["decoded_layers"]` — a provenance array containing `{depth, pattern_index, source_offset, encoding, b64_sha256, decoded_sha256, decoded_preview[≤512]}` per layer so an analyst can reconstruct the pursued chain months later.

**Zero new endpoints. Zero new flags. Zero LLM. Zero new data source. Nothing removes or overwrites outer evidence.**

## 3 · Regression matrix (frozen 12-case corpus)

| # | Case | Verdict (unchanged) | DIE MITRE | Δ vs Item 2 | Layers | IOCs |
|---|------|---------------------|-----------|-------------|:------:|:----:|
| 01 | ps-enc-launcher   | Malicious (80)  | T1027, T1059.001, **T1105, T1140**, T1562.001, T1564.003 | +T1105, +T1140 | 1 | 2 |
| 02 | mshta             | Malicious (100) | T1218.005 | — | 0 | 2 |
| 03 | certutil          | Malicious (70)  | T1105, T1140, T1218 | — | 0 | 2 |
| 04 | squiblydoo        | Malicious (100) | T1218.010 | — | 0 | 2 |
| 05 | wmic              | Malicious (100) | T1047, T1059.001, T1059.003, T1105, T1218, T1564.003 | — | 0 | 2 |
| 06 | benign-recon      | Benign (10)     | — | — | 0 | 0 |
| 07 | netsh             | Low Risk (20)   | — | — | 0 | 0 |
| 08 | **nested-b64**    | Malicious (80)  | T1027, T1059.001, **T1105, T1140**, T1564.003 | **+T1105, +T1140** | **2** | **1** |
| 09 | too-short         | Benign (0)      | — | — | 0 | 0 |
| 10 | empty             | *no verdict*    | — | — | 0 | 0 |
| 11 | bitsadmin         | Malicious (80)  | T1105, T1197 | — | 0 | 2 |
| 12 | rundll32-poweliks | Malicious (80)  | T1027, T1059.007, T1105, T1218.011 | — | 0 | 1 |

**Target achieved on rip-08.** Two peeled layers surface the inner URL + T1140 (Deobfuscate/Decode) + T1105 (Ingress Tool Transfer). Bonus improvement on rip-01 (encoded PowerShell launcher) — one layer peeled, +T1105 +T1140.

**Determinism gate: 12 / 12 stable** (DIE + `/api/analyze` snapshots byte-identical across two runs; both `run1` and `run2` produce identical `decoded_layers` arrays including SHA-256 fingerprints).

**Safety gate: 100 %** — no benign / too-short / empty / ambiguous-without-evidence case gained a layer, a technique, or a verdict shift. `rip-06 / 09 / 10` remain at zero DIE evidence and zero layers.

## 4 · Explicit determinism-and-termination guarantees

- Same input ⇒ same layer set ⇒ same technique dedup ⇒ same envelope. No timestamps, no wall-clock, no external calls, no randomness inside the module.
- Recursion terminates at `MAX_DEPTH = 3` even for cycles.
- `MAX_LAYERS = 12` bounds the total work per top-level call regardless of tree shape.
- `visited: Set[b64_sha256]` short-circuits before any second attempt on the same base64 blob.
- `_try_decode` cannot raise; malformed / short / oversize blobs are ignored.

## 5 · Wider regression

* `canonical/api/` suite — **174 pass · 5 skip · 0 fail** (identical to post-Item-1 & post-Item-2 baseline).
* `git status` diff limited to `backend/services/die/recursive_decode.py` (new), `backend/services/die/api.py`, `backend/tests/canonical/ssot/test_ssot_isolation.py` (allow-list), plus memory-only files.

## 6 · Protected surfaces verified untouched

RC5 · Workspace UI (envelope shape additive-only) · IKG (shadow) · Verdict v3 (shadow) · Case Engine (shadow) · Retention sweeper · FileStore · P0 archive-guard · Item-1 risk-score calibration · Item-2 narrative bridge. No new `NIVX_FLAG_*`. No Mongo schema redesign. No shadow → live promotion.

## 7 · Cruise-Missile principle compliance

The decoder **pursues** the evidence chain (Cruise-Missile "acquire → navigate → discover → course-correct → pursue recursively → correlate") but **stops at surfacing new observables**. Verdict remains a function of the correlated evidence set. No single-indicator branch introduced. The synthesised T1140 row is evidence-of-observation ("we deobfuscated N inner layers"), never a verdict step.

## 8 · Item-3 gate: PASS

- ✅ Target case rip-08 now surfaces inner URL + T1140 + T1105 across 2 peeled layers
- ✅ Bonus improvement on rip-01 (encoded PowerShell) — one layer peeled
- ✅ Zero manufactured evidence on benign / short / empty / ambiguous-without-evidence cases
- ✅ 100 % determinism preserved (including SHA-256 layer fingerprints stable across runs)
- ✅ Hard bounds prevent unbounded recursion (MAX_DEPTH · MAX_LAYERS · visited-set)
- ✅ Zero LLM, zero new inference, zero new data source
- ✅ Canonical suite still 174 pass / 5 skip / 0 fail
- ✅ Zero protected-surface disturbance

**Item 3 closed.** Ready for owner authorisation of Item 4 (T1562.004 DIE signature).
