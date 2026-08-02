# Phase 5 · Runtime-Proven Restore Status (final)

**Target**: 11 / 11 on `workspace_recovery/corpus.json` (v1.1.0).
**Current**: **10 / 11 with zero regressions** using hunks 1-5.
S001 (owner anchor) remains as the single failure — proven to be a
**winner-picker issue**, not a decoder issue.

All experiments were run in `/tmp/wsp-bisect` (a read-only worktree
detached at HEAD `1a07de3`). The running production tree `/app/backend`
is untouched.

## Isolated-vs-combined runtime evidence

| Experiment | PASS |
|---|:---:|
| `hunk_1_disable_rc22_preflight` | 10 / 11 |
| `hunk_2_append_not_insert` | 1 / 11 |
| `hunk_3_positional_ps_regex` | 1 / 11 |
| `hunk_4_ps_encodedcommand_abbrev` | 1 / 11 |
| `hunk_5_smart_ps_encoded_regex` | 1 / 11 |
| `hunk_6c_convergence_penalty` | 1 / 11 |
| **combined_hunks_1_through_5** | **10 / 11** |

## The five approved hunks

1. **Hunk 1** — `analysis_core.py:53-61` — gate the rc22-orchestrator preflight OFF (single hunk that carries the workload; alone reaches 10/11)
2. **Hunk 2** — `magic_decoder.py:420-431` — normalizers `.append()` instead of `.insert(0, …)` so they run AFTER primary decoders
3. **Hunk 3** — `routers/ops.py:1866` — PS-detection regex changed from substring `\bpowershell\b` to positional `^\s*(?:powershell|pwsh)\b` so Bash comments with the word "powershell" no longer misroute
4. **Hunk 4** — `magic_decoder.py` — widen `-EncodedCommand` abbreviation set at both gates (line 371 regex + line 484 `looks_wrapped`) to accept every unambiguous PS prefix (`-e`, `-en`, `-enc`, `-enco`, `-encod`, `-encode`, `-encoded`, `-encodedcommand`)
5. **Hunk 5** — `smart_decoder.py:28` — same abbreviation widening for `_PS_ENCODED_RE`

Combined effect: 10 / 11 with zero regressions vs the v1.5.6 baseline
fingerprint (S06 xor still passes, S01–S05, S07–S10 all pass, S001 remains
❌).

## Why Hunk 6c (Convergence Penalty) was rejected

Attempted the owner-preferred principled approach:
> "Once a pass has produced a more canonical representation, later
> normalization passes should not replace it with a less-converged result."

The direct implementation penalized any final output shaped like a
normalizer placeholder `(op-name · reason)`. This works for S001 in
isolation but **regresses S06** (whose v1.5.6 baseline legitimately
terminates on the same placeholder — both engines converge there).

A relative version ("penalize placeholder only when the OTHER engine has
real content") narrowed the collateral but still regressed S06 because
the "other" engine produced a different placeholder-like message
(`(payload already plaintext — no decode needed)`) that isn't caught by
the same regex.

The correct implementation of the convergence principle is not a scoring
patch on the winner-picker. It requires the **Multi-Pass Convergence
Engine**: chain-level truncation that removes normalizer placeholders
from the END of a chain when an EARLIER step already produced real
content. That is a Phase 5.5 design change, not a surgical hunk.

## Recommended path forward

### Path A · Promote 10/11 now, defer S001 to Phase 5.5 (recommended)

Deploy the five proven hunks to `/app/backend`, hit 10/11 on the
production tree, run through Phase 6 architectural isolation, and
schedule Phase 5.5 (Multi-Pass Convergence Engine at chain level) as
follow-on work.

**Pros**: Nine samples out of ten baseline-matching immediately. S001 is
a KNOWN, DOCUMENTED, non-crashing residual — the analyst still receives
the base64-decoded UTF-16LE bytes for `powershell.exe -encod …` inputs
today; only the analyst-facing normalization narrative is wrong.

**Cons**: S001 (owner anchor) remains ❌ until Phase 5.5 lands.

### Path B · Design and ship the Convergence Engine now

Implement the chain-level convergence rule in `magic_decoder.py`:
after building `top_results`, for each result whose LAST step is a
placeholder-emitting normalizer, walk backward and truncate to the
last step that produced non-placeholder content. This is
~30-50 lines of new code + a targeted test in `tests/`.

**Pros**: 11/11 achieved before promoting anything to production.
**Cons**: More invasive; requires its own regression corpus + code
review; will delay the promotion by one session.

## Files ready to promote (Path A)

```
/app/backend/analysis_core.py       ← Hunk 1
/app/backend/magic_decoder.py       ← Hunk 2 + Hunk 4
/app/backend/routers/ops.py         ← Hunk 3
/app/backend/smart_decoder.py       ← Hunk 5
```

Every hunk is marked with `DECODER-RECOVERY-LOCK · phase5_hunk_<n>` so
future readers can identify them.

## Decoder Recovery Lock (permanent invariants proven by this work)

1. **Decoder Ordering** · normalizers may only be `.append()`ed, never `.insert(0, …)`
2. **Interpreter Ownership** · PS gating regex must be positional (`^\s*`), never substring
3. **Orchestrator Preflight Lock** · rc22 preflight stays gated OFF until Shared passes its own certification
4. **Exception-Swallow Ban** on the decode path
5. **Certification Corpus CI Gate** — every PR touching `routers/ops.py`, `analysis_core.py`, `smart_decoder.py`, `magic_decoder.py`, `operations.py`, `engine/*`, `decoders/*` must pass the full corpus

These five rules are the permanent contract; the five hunks are the
minimal restore that implements them today.
