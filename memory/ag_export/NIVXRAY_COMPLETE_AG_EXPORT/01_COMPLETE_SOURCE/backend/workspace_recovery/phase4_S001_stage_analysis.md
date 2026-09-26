# Phase 4 · S001 (PowerShell `-EncodedCommand`) — Per-Stage Comparison

Owner-anchored permanent regression sample.

## Sample

**Input**
```
powershell.exe -encod VwByAGkAdABlAC0ASABvAHMAdAAgACIAdAB3AGUAZQB0ACwAIAB0AHcAZQBlAHQAIQAiAA==
```

**Expected final decoded payload**
```
Write-Host "tweet, tweet!"
```

Expected pipeline behaviour:
```
Recognize PowerShell
      ↓
Recognize -EncodedCommand (including abbreviations: -e, -en, -enc, -enco, -encod)
      ↓
Extract Base64 payload
      ↓
UTF-16LE decode
      ↓
Continue deterministic decode pipeline
```

## Runtime Evidence — Stage-by-Stage

Both trees produce **identical** behaviour on this sample.

| # | Stage | v1.5.6 Baseline | Current HEAD | First Divergence |
|---|-------|-----------------|--------------|:----------------:|
| 1 | Interpreter detection | ⚠ interpreter tag not emitted in trace ops | ⚠ interpreter tag not emitted in trace ops | none — both identical |
| 2 | `-EncodedCommand` recognition (incl. abbreviations) | ❌ `-encod` NOT recognized as EncodedCommand | ❌ `-encod` NOT recognized as EncodedCommand | none — both identical |
| 3 | Payload extraction | `extract-payload` fires — but on the *whole tail* rather than the base64 chunk after `-encod` | `extract-payload` fires — same behaviour | none — both identical |
| 4 | Base64 decode | `base64-decode` fires | `base64-decode` fires | none — both identical |
| 5 | UTF-16LE decode | ❌ **NEVER CALLED** — no `utf16le-decode` op in trace | ❌ **NEVER CALLED** — no `utf16le-decode` op in trace | none — both identical |
| 6 | XOR brute (opportunistic) | `xor-brute` fires (misfire — payload was already the target) | `xor-brute` fires (misfire) | none — both identical |
| 7 | PS backtick normalize | `powershell-backtick-normalize` fires | `powershell-backtick-normalize` fires | none — both identical |
| 8 | PS alias normalize | `powershell-alias-normalize` fires and terminates the chain with `"(powershell-alias-normalize · no known aliases found)"` as final output | same | none — both identical |
| 9 | Decoder orchestration | Chain terminates without producing the plaintext | same | none — both identical |
| 10 | Final decoded payload | `"(powershell-alias-normalize · no known aliases found)"` | `"(powershell-alias-normalize · no known aliases found)"` | none — both identical |
| 11 | Verdict | Suspicious · 80 · confidence 84 | Suspicious · 80 · confidence 84 | none — both identical |

**Full baseline op sequence:**
```
['extract-payload', 'base64-decode', 'xor-brute',
 'powershell-backtick-normalize', 'powershell-alias-normalize']
```

**Full current op sequence:**
```
['extract-payload', 'base64-decode', 'xor-brute',
 'powershell-backtick-normalize', 'powershell-alias-normalize']
```

## Interpretation (evidence-based, no source-code inference)

1. **The Jul 28 v1.5.6 tag itself does NOT decode this sample correctly.** Same failure mode as current HEAD. This is a fact, produced by executing the sample against the read-only worktree at `/tmp/workspace-v1.5.6/backend/`, not inferred from a diff.

2. **The failure happens BEFORE the base64→UTF-16LE step.** Both trees recognize this as PowerShell base64-ish content (they fire `base64-decode`), but they never fire `utf16le-decode` on the decoded bytes. Instead the pipeline falls into `xor-brute → backtick-normalize → alias-normalize` and gives up with `"no known aliases found"`.

3. **Most likely proximate cause (to be confirmed in Phase 4 via disable/swap):** the `-EncodedCommand` recognizer requires the flag to be spelled `-EncodedCommand`, `-Enc`, or a specific subset of abbreviations. `-encod` (5-char abbreviation) is not matched, so the EncodedCommand fast path is never taken. The pipeline then falls back to generic extraction which decodes the base64 but does not know it should decode UTF-16LE afterward.

4. **The owner's claim "before Jul 29 the Workspace decoded this correctly" is NOT yet supported by the v1.5.6 baseline.** The recovery target may therefore be a **pre-v1.5.6 revision** (before Jul 28 16:10 UTC), or the correct behaviour needs to be built rather than restored. This is the question the historical bisect (`phase4_bisect.py`) is designed to answer definitively — by running S001 against every reachable git anchor, not inferring from source code.

## Phase 4 investigation requirements for S001 (per owner)

- Run S001 against every reachable git anchor (v1.5.6 · pre-v1.5.6 · post-v1.5.6).
- Emit a per-revision PASS/FAIL table: `revision · date · S001-pass`.
- Identify **Last Known Good** (first revision that produces `Write-Host "tweet, tweet!"`) and **First Bad** (adjacent commit that breaks it).
- Do not restore anything until the bisect provides evidence of what "good" looked like for S001.
- If NO revision in reachable history produces the correct output, S001 is a **build-not-restore** case and must be flagged as such.

## Permanent corpus locking

S001 is now embedded in `backend/workspace_recovery/corpus.json` (v1.1.0). It must remain in the permanent 60-sample `workspace_regression_corpus/` (Phase 7.5) as the PowerShell EncodedCommand abbreviation-tolerance anchor.
