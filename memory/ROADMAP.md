# NivXRay · Roadmap · Product Hardening Phase
_Baseline: M2 Hero build (approved). New capability development frozen._

## Rule of the road
> Perfect one workflow → observe analyst → improve workflow → only then add capability.

No feature moves to the next phase until the phase it lives in is production-quality.

---

## P0 — Complete Investigation Experience (in-flight)
Hard block on any new capability until every box below is checked. Verified against
the six analyst tasks in `USABILITY_REVIEW.md`.

- [ ] Root process immediately identifiable on landing
- [ ] Parent-child ancestry rendered from real adapter data (blocked by P1)
- [ ] Process lifetimes render as accurate spans (start → end)
- [ ] Event density comparable to enterprise EDR (30+ rows in 900 px)
- [ ] Evidence panel synchronization is instantaneous on click
- [ ] Hover and selection states polished (no flicker, no lag, no dropped tooltips)
- [ ] Keyboard navigation complete (↑ ↓ ← → F H L Esc ⌘K ⌘\ ⌘D ?)
- [ ] Smooth pan, zoom, focus (60 fps sustained)
- [ ] Investigation workflow requires minimal scrolling (fit-to-content default)
- [ ] Every major analyst task completes naturally (see usability review)

## P1 — Adapter Ancestry (backend, engineering-priority)
Every emitted event must include: `entity.iid`, `parent.iid`, `root.iid`,
`process_start` (epoch ms), `process_end` (epoch ms).
Contract change lives in `/app/backend/v2/adapters/` and the shadow observation
schema. Without this, canvas ancestry is a heuristic. **Blocks P0 items 2 and 3.**

## P2 — Report Export
PDF · Markdown · JSON · STIX 2.1 · Evidence Package. Unlocks direct customer
value the moment P0 + P1 ship.

## P3 — Phase 2 (deferred)
- Analyst Playback
- Case Comparison


## P1 — Interpreter Ownership Coverage (measurable Workspace quality signal)
_Filed 2026-08-02 by owner as part of the Workspace stabilisation phase._

Introduce a persistent, corpus-driven metric that lives alongside the unit
regression suite. Purpose: give Workspace a measurable quality indicator
beyond "395/395 tests pass" so interpreter-routing stability can be tracked
as the corpus grows.

**Deliverable** — a JSON summary at
`/app/backend/tests/investigation/interpreter_ownership_coverage.json`,
regenerated on every pytest run of a new
`test_interpreter_ownership_coverage.py`:

```
{
  "generated_at": "2026-08-XX…",
  "git_sha": "…",
  "corpus_size": N,
  "by_interpreter": {
    "bash":       { "samples": …, "correctly_routed": …, "rate": … },
    "cmd":        { "samples": …, "correctly_routed": …, "rate": … },
    "powershell": { "samples": …, "correctly_routed": …, "rate": … },
    "mixed_launcher": { "samples": …, "correctly_routed": …, "known_limitations": … }
  },
  "regressions_since_last_run": [ … ]
}
```

**Corpus sources** (growable, real-world first — no synthetic special-casing):

- Bash: real malicious shell command lines (sanitised)
- CMD: real Windows batch / cmd invocations (sanitised)
- PowerShell: real enterprise PowerShell command lines (sanitised)
- Mixed launcher: real cases where a non-PS launcher wraps a PS payload
  (documented as *known limitations*, not as production regressions)

**Acceptance:**

- Report regenerates on every test run and never raises
- Never gates cut-over or deploy — this is a health signal, not a criterion
- Mixed-launcher rows carry an explicit `known_limitations` field so
  currently-under-decoded nested cases stay visible without being flagged
  as regressions
- Corpus grows over time; new samples arrive with sanitisation notes

Not a hotfix. Awaits the current P0 hero-build work.


## P2 — Nested Interpreter Detection (Workspace decoder, future capability)
_Filed 2026-08-02 by owner as follow-up to the PowerShell Interpreter Gate hotfix._

Treat this as a **new feature**, not a bug. The Interpreter Gate that shipped in
`routers/ops.py` is a subtractive heuristic: any leading token in
`{eval, sh, bash, dash, zsh, ksh, openssl, tr, sed, awk, xxd, rev, curl, wget,
python, python3, perl, ruby, node, cmd, cmd.exe}` (plus shebangs, `$(...)`,
leading backtick substitution) skips all PowerShell-specific normalization
stages. This is deliberately conservative — the worst case is that a *nested*
PowerShell invocation such as `cmd /c powershell -enc …` or
`bash -c 'powershell …'` reaches the analyst un-decoded, which is far safer
than the alternative of rewriting Bash text as PowerShell.

**Do not close this backlog item by expanding the blocklist / allowlist.**
Owner directive: chasing launcher patterns (sh -c powershell, dash -c pwsh,
env bash -c powershell, sudo powershell, python subprocess.run([...powershell]),
Start-Process powershell, CreateProcess → powershell, …) is a losing game.

**Correct architectural solution** — a generic **Launcher Detector**:

```
Raw input
    │
    ▼
Interpreter classification (CMD / Bash / Python / …)
    │
    ▼
Launcher analysis  ← NEW
    │
    ▼
Effective interpreter (may differ from launcher)
    │
    ▼
Interpreter-specific decoder
```

Examples the Launcher Detector must handle correctly:

- `cmd /c powershell -enc …`  → launcher=CMD, payload=PowerShell
- `bash -c 'powershell Get-Process'` → launcher=Bash, payload=PowerShell
- `sh -c pwsh …` → launcher=sh, payload=PowerShell
- `python -c "subprocess.run(['powershell', ...])"` → launcher=Python, payload=PowerShell
- `sudo powershell` → launcher=sudo, payload=PowerShell
- `Start-Process powershell -ArgumentList …` → launcher=PowerShell, payload=PowerShell (nested)

Acceptance: the decoder correctly routes a **nested PowerShell payload**
through PowerShell normalization even when the outermost interpreter is
non-PowerShell. Regression tests cover every launcher shape above plus at
least one adversarial case where the payload only *mentions* PowerShell in a
string literal (must NOT be treated as a nested PS invocation).

**Priority**: P2. Not a hotfix. Waits until the current P0 + P1 hero-build
work is complete.

Not blockers. Do not start until P0 + P1 + P2 are complete.

---

## Milestone-closing template (all future milestones must follow this)
Each milestone ends with exactly four lines:
1. What was completed.
2. Screenshot or short video of the result.
3. Any blockers (if any).
4. The single next priority.

No feature suggestions, no roadmap speculation, no "next action items" list.
