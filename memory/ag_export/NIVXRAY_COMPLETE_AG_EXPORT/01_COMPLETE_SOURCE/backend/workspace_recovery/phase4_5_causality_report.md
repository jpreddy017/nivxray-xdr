# Phase 4.5 · Runtime Causality Validation & RCA

Every row below reflects a **surgical per-file revert** on top of HEAD
(`/tmp/wsp-bisect` worktree). We invert exactly the hunks that the first-bad
commit applied to that ONE file, run the 11-sample corpus, and classify each
sample as `fixed` / `regressed_new` / `unchanged_pass` / `unchanged_fail`.

## Aggregate Causality Matrix

| File | Win | Layer | Revert | Fixed | Regressed | Unchanged✅ | Unchanged❌ |
|------|:-:|------|--------|:-----:|:---------:|:-----------:|:-----------:|
| `backend/engine/orchestrator.py` | B | engine | ok · surgical_revert_ok | 0 | 0 | 1 | 10 |
| `backend/engine/models.py` | B | engine | ok · surgical_revert_ok | 8 | 0 | 1 | 2 |
| `backend/rc22_adapter.py` | B | shared | ok · surgical_revert_ok | 0 | 0 | 1 | 10 |
| `backend/v2/semantic/ps_semantic.py` | B | shared | ok · surgical_revert_ok | 0 | 0 | 1 | 10 |
| `backend/v2/investigation/analyst_report/builder.py` | B | xlab | ok · surgical_revert_ok | 0 | 0 | 1 | 10 |
| `backend/v2/investigation/verdict/__init__.py` | B | xlab | ok · surgical_revert_ok | 0 | 0 | 1 | 10 |
| `backend/decoders/ps_alias_normalizer.py` | A | shared | SKIP · BOTH_FAILED: apply=Falling back to direct application...
err | — | — | — | — |
| `backend/decoders/ps_backtick_normalizer.py` | A | shared | SKIP · surgical_revert_ok | — | — | — | — |
| `backend/magic_decoder.py` | A | workspace | ok · surgical_revert_ok | 1 | 1 | 0 | 9 |
| `backend/routers/ops.py` | A | workspace | ok · parent_checkout_fallback (parent=8baa7aa467) | 0 | 0 | 1 | 10 |
| `backend/server.py` | A | registration | ok · surgical_revert_ok | 0 | 0 | 1 | 10 |

## Per-File Root-Cause Analysis (files that fixed ≥1 sample)

### `backend/engine/models.py` — 8 sample(s) fixed by surgical revert

- Layer: **engine**
- Window: **B**
- Revert method: `surgical_revert_ok`

**Samples restored:**
  - `S01_ps_b64_utf16le`
      HEAD ops : `['ps-encodedcommand-recovery', 'extract-payload', 'ioc-extract', 'family-emotet']`
      Reverted : `['extract-b64', 'utf16le-or-utf8-decode']`
      HEAD out : `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ DECODED OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`
      After out: `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ DECODED OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`
  - `S02_bash_xxd_b64_rev`
      HEAD ops : `['powershell-alias-normalize']`
      Reverted : `['extract-payload', 'base64-decode']`
      HEAD out : `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ DECODED OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`
      After out: `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ DECODED OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`
  - `S03_cmd_caret_escaped`
      HEAD ops : `['cmd-runtime-reconstruct', 'extract-payload', 'base64-decode', 'utf16le-or-utf8-decode']`
      Reverted : `['strip-carets', 'extract-b64', 'utf16le-or-utf8-decode']`
      HEAD out : `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ DECODED OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`
      After out: `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ DECODED OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`
  - `S05_nested_b64_gzip`
      HEAD ops : `['extract-payload', 'base64-decode', 'crypto-detect']`
      Reverted : `['extract-payload', 'base64-decode', 'gzip-decompress']`
      HEAD out : `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ INVESTIGATION BRAIN · RTE DECODER TRACE
━━━━━━━━━━━`
      After out: `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ INVESTIGATION BRAIN · RTE DECODER TRACE
━━━━━━━━━━━`
  - `S07_rc4_openssl`
      HEAD ops : `['rot47']`
      Reverted : `['extract-payload']`
      HEAD out : `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ DECODED OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`
      After out: `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ DECODED OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`
  - `S08_unicode_obfuscation`
      HEAD ops : `['extract-payload', 'ioc-extract', 'family-emotet']`
      Reverted : `[]`
      HEAD out : `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ DECODED OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`
      After out: `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NIVXRAY INVESTIGATION SUMMARY  (payload already plain`
  - `S09_hex_b64_gzip_chain`
      HEAD ops : `['hex-decode', 'base64-decode']`
      Reverted : `['hex-decode', 'base58-decode', 'xor-brute', 'powershell-backtick-normalize', 'powershell-alias-normalize']`
      HEAD out : `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ INVESTIGATION BRAIN · RTE DECODER TRACE
━━━━━━━━━━━`
      After out: `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ INVESTIGATION BRAIN · RTE DECODER TRACE
━━━━━━━━━━━`
  - `S10_bash_with_powershell_comment`
      HEAD ops : `['powershell-alias-normalize']`
      Reverted : `[]`
      HEAD out : `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ DECODED OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`
      After out: `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NIVXRAY INVESTIGATION SUMMARY  (payload already plain`

### `backend/magic_decoder.py` — 1 sample(s) fixed by surgical revert

- Layer: **workspace**
- Window: **A**
- Revert method: `surgical_revert_ok`

**Samples restored:**
  - `S001_ps_writehost_tweet`
      HEAD ops : `['extract-payload', 'base64-decode', 'xor-brute', 'powershell-backtick-normalize', 'powershell-alias-normalize']`
      Reverted : `['extract-payload', 'base64-decode', 'utf16le-decode']`
      HEAD out : `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ DECODED OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`
      After out: `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ DECODED OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`

**⚠ New regressions introduced by this revert (block Phase 5 solo-restore):**
  - `S06_xor_obfuscated` — was PASS, becomes FAIL

## Files Proven Innocent (no samples fixed, no samples regressed)

- `backend/engine/orchestrator.py` (engine) — revert had no runtime effect; **exclude from Phase 5**.
- `backend/rc22_adapter.py` (shared) — revert had no runtime effect; **exclude from Phase 5**.
- `backend/v2/semantic/ps_semantic.py` (shared) — revert had no runtime effect; **exclude from Phase 5**.
- `backend/v2/investigation/analyst_report/builder.py` (xlab) — revert had no runtime effect; **exclude from Phase 5**.
- `backend/v2/investigation/verdict/__init__.py` (xlab) — revert had no runtime effect; **exclude from Phase 5**.
- `backend/routers/ops.py` (workspace) — revert had no runtime effect; **exclude from Phase 5**.
- `backend/server.py` (registration) — revert had no runtime effect; **exclude from Phase 5**.

## Files with Ambiguous Revert (SKIP — patch could not be applied)

- `backend/decoders/ps_alias_normalizer.py` (shared) — BOTH_FAILED: apply=Falling back to direct application...
error: patch failed: backend/decoders/ps_alias_normalizer.py:1
error: backend/decoders/ps_alias_normalizer.py: patch does not apply
 checkout=error: pathspec 'backend/decoders/ps_alias_normalizer.py' did not match any file(s) known to git

- `backend/decoders/ps_backtick_normalizer.py` (shared) — surgical_revert_ok

## Prevention Recommendations (populated by hand in the final RCA)

_Populated once the machine-generated matrix is reviewed against the code diffs._