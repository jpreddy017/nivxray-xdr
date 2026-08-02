# Phase 5 · Runtime-Proven Restore Status

**Target**: 11 / 11 on `workspace_recovery/corpus.json` (v1.1.0).
**Current**: **10 / 11** with 5 surgical hunks. S001 (owner anchor) remains.

All experiments were run in `/tmp/wsp-bisect` (a read-only worktree
detached at HEAD `1a07de3`), never in `/app/backend`. The running
production tree is untouched.

## Isolated-vs-combined runtime evidence

| Experiment | PASS |
|---|:---:|
| `hunk_1_disable_rc22_preflight` | 10 / 11 |
| `hunk_2_append_not_insert` | 1 / 11 |
| `hunk_3_positional_ps_regex` | 1 / 11 |
| `hunk_4_ps_encodedcommand_abbrev` (magic_decoder) | 1 / 11 |
| `hunk_5_smart_ps_encoded_regex` (smart_decoder) | 1 / 11 |
| **combined_all_hunks** | **10 / 11** |

Hunk 1 alone already carries the workload — it disables the rc22
orchestrator preflight and lets the legacy Workspace engines
(`smart_decoder` and `magic_decoder`) win the race for S01-S10 and S04.
Hunks 2-5 are causally-correct fixes for the surrounding design flaws
(normalizer hoisting, PS-detection regex substring→positional, and the
`-EncodedCommand` abbreviation set) but are not sufficient on their own.

## The residual: S001

Runtime-verified per-engine behaviour on the S001 input
`powershell.exe -encod VwByA…` with all 5 hunks applied:

| Direct call | Output | Steps |
|---|---|---|
| `smart_decode(payload)` | `Write-Host "tweet, tweet!"` ✅ | `['extract-payload', 'base64-decode']` |
| `magic_decode(payload).top_results[0]` | `Write-Host "tweet, tweet!"` ✅ | correct chain |
| Full `/api/decode/smart` pipeline | `(powershell-alias-normalize · no known aliases found)` ❌ | `['extract-payload', 'base64-decode', 'xor-brute', 'powershell-backtick-normalize', 'powershell-alias-normalize']` |

**Both engines individually produce the correct plaintext.** The wrong
output emerges only when the full pipeline runs. The winner-picker or
a post-decode step in `analysis_core.smart_pipeline` / `routers/ops.py`
is choosing (or appending) the aggressive-normalizer chain over the
correct decoded plaintext.

## Two candidate Hunk 6 designs (for owner selection)

**Hunk 6A · Winner-picker bias for `Write-Host` / `Write-Output` / `IEX`**
When `smart_out` contains one of the classic PS cmdlet tokens
(`write-host`, `write-output`, `invoke-expression`, `iex`, `new-object`)
and `magic_out` does not, force smart to win regardless of `magic_score_val`.
Implemented in `analysis_core.py` at the winner-picker (~line 773). Minimum
diff. Low risk because it only fires when the two outputs already disagree
on whether they produced classical PS payload content.

**Hunk 6B · Suppress alias-normalize when the decoded output is already
a canonical PS statement**
In `magic_decoder.py::_next_candidates`, do not `append` (with hunk 2 in
place) the `powershell-alias-normalize` op when the current chunk already
begins with `Write-Host`, `Write-Output`, `Invoke-Expression`, `IEX`, or
`New-Object`. Removes the last redundant chain step, which lets the picker
prefer the clean upstream output.

Both hunks are individually testable with the phase5 validator by
adding `_apply_hunk_6a` / `_apply_hunk_6b` and re-running.

## What's proven with runtime evidence at this checkpoint

- 10 of 11 samples recover with the 5 approved hunks · zero regressions
  introduced (S06 stays ✅ as before).
- The Decoder Recovery Lock invariant holds: no `insert(0, ...)` in the
  new candidate list, no `\bpowershell\b` substring gates, no rc22
  hijack, no Intelligence-Layer coupling.
- Both decode engines individually decode S001 correctly — the residual
  is a post-decode selection issue, not a missing decoder.

## Next Action Items (all gated on owner approval)

- Choose **Hunk 6A** or **Hunk 6B** (or propose Hunk 6C).
- Run the phase5 validator with the new hunk in isolation and in
  combination — target 11 / 11.
- Only after 11 / 11 is confirmed on `/tmp/wsp-bisect`, promote the
  five (or six) hunks to `/app/backend` behind the
  `DECODER-RECOVERY-LOCK · phase5` markers.
- Proceed to Phase 6 (isolation) once the certified corpus is at 11/11.
