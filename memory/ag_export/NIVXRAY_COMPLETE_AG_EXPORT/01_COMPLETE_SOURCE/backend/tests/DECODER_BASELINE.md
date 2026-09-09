# NivXRay Decoder — Stable Baseline v1

**Frozen:** 2026-07-25  ·  **Locked with SOC user 2026-07-25**

From this point forward, every PR that touches the decoder MUST pass every
gate below before merge. This document is the contract.

---

## Regression Gates (MUST all pass)

| # | Gate | Runner | Suite size |
|---|------|--------|-----------:|
| 1 | Unit tests — investigation quality golden corpus | `pytest tests/test_investigation_quality.py` | 27 |
| 2 | XOR-brute guard (UTF-16LE race) | `pytest tests/test_ps_encodedcommand_xor_guard.py` | 3 |
| 3 | Phase 9.4 semantic AST + behaviors | `pytest tests/test_ps_semantic_v2.py` | 16 |
| 4 | Decode-error contract (corrupt sample, partial recovery, confidence bands) | `pytest tests/test_ps_decode_error_contract.py` | 13 |
| 5 | Real-world validation matrix (10 categories) | `python tests/decoder_realworld_validation.py` | 10 |
| 6 | Corpus regression (malware families, obfuscation, defense evasion, downloaders, benign) | `pytest tests/test_corpus_regression.py` | ≥ 15 |
| | **Total** | | **≥ 84** |

## Non-negotiable invariants

1. **Never render binary garbage.** On decode failure `recovered_script == ""`,
   the UI renders a Decode Failure card, and the AST / behavior extractor / verdict
   scorer are all skipped.
2. **Never fabricate a verdict.** On `decode_error` the verdict is `Undetermined`
   with `risk_score = None`, never `0/100` (which implies benign).
3. **XOR-brute never runs on PowerShell `-EncodedCommand` bytes.** The
   orchestrator and `/api/decode/smart` short-circuit through the deterministic
   recovery chain first.
4. **Every decoder attempt is logged** with plain-English status + reason.
5. **Confidence bands mean what they say:** `high` (strict encoding wins),
   `medium` (compression/XOR fallback), `low` (partial recovery only),
   `none` (no decoder produced usable text).
6. **Automatic "repair" is forbidden.** Reconstructing missing bytes = inventing
   data. Any repair suggestions must be a separate, explicitly-labeled
   experimental feature.

## What "stable" means

- The 59/59 pytest + 10/10 real-world matrix from 2026-07-25 is the floor.
- If a new decoder feature/refactor causes ANY of the gates above to fail, the
  change must be rolled back or fixed before merge — no exceptions.
- New samples added to `/app/backend/tests/corpus/` become part of the gate
  automatically.

## Baseline signature (2026-07-25)

    Backend tests:    59/59 passing
    Real-world matrix: 10/10 passing
    Combined:         69/69 gates green
