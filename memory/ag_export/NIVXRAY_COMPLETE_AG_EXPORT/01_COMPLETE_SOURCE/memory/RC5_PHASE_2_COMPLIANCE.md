# RC5 · Phase 2 · Recommendation Compliance Report

**Phase:** 2 — CMD Semantic Interpreter
**Date:** Feb 24, 2026
**Reviewer / Author:** E1 (main dev agent)
**Spec of record:** `/app/memory/RC5_SEMANTIC_ENGINE_SPEC.md` v2
**Plugin API of record:** `/app/memory/RC5_PLUGIN_API.md` v1

---

## 1 · Previously approved architectural recommendations — status in this phase

Every recommendation from the RC5 spec v2 (§ 0, § 6, § 12, § 13, § 14, § 15, § 17)
plus the user's Phase-2-approval message. Each row is one of:
`Implemented` · `Intentionally deferred (with target phase)` · `Not applicable`.

| # | Recommendation                                                                                | Status this phase          |
|---|-----------------------------------------------------------------------------------------------|----------------------------|
| 1 | Deterministic-first execution (§ 0.1)                                                         | **Implemented**            |
| 2 | Evidence-driven — every conclusion carries evidence IDs (§ 0.2)                               | **Implemented** (SET / process nodes carry self-referencing SideEffect triples) |
| 3 | Semantic reconstruction before detection (§ 0.7)                                              | **Implemented** (interpreter emits `reconstructed` on every node) |
| 4 | ExecGraph is immutable, append-only (§ 12.1)                                                  | **Implemented** (`ExecGraph.add_node` returns a new frozen graph; enforced by Phase-1 CI) |
| 5 | Detectors consume ExecGraph only — no raw-output parsing (§ 12.2)                             | **Not applicable this phase** — no detectors emitted yet. Phase 4+ target. |
| 6 | Confidence propagates deterministically (§ 6)                                                 | **Implemented** — child ≤ min(parent), −20 on unresolved. `add_node` enforces. |
| 7 | Plugin API frozen (§ 12.5)                                                                    | **Implemented** — CMD plugin uses only public `SemanticParser` / `SemanticInterpreter` + `register_*` helpers; no core modifications. |
| 8 | `--no-ai` byte-identity (§ 12.6)                                                              | **Implemented** — CMD plugin makes zero LLM calls. All `origin="deterministic"`. |
| 9 | No keyword-based verdicts (§ 0.8)                                                             | **Not applicable this phase** — Verdict Engine v2 is Phase 7. |
|10 | Semantic IR precedes ExecGraph (§ 3)                                                          | **Implemented** — `CmdParser.parse` → `SIRTree` → `CmdInterpreter.interpret` → `ExecGraph`. Never bypassed. |
|11 | Never guess — emit `UnresolvedNode` when incomplete (§ 4 / § 18)                              | **Implemented** — SET /A, IF DEFINED/EXIST/ERRORLEVEL, FOR loops, unknown %VAR% modifiers → all `UnresolvedNode` with `reason`. |
|12 | Language-agnostic downstream (§ 0.5)                                                          | **Implemented** — CMD emits only shared SIRKinds + NodeKinds. Zero CMD-specific downstream branching. |
|13 | Frozen enums — no silent NodeKind / TacticKind / verb additions (§ 4 / § 5 / § 7)             | **Implemented** — CMD interpreter uses only existing kinds. `test_plugin_api_frozen.py` still green. |
|14 | No new imports of `_KEYWORD_MITRE_MAP` / `_KEYWORD_LOLBAS_HITS` (§ 13 kill-list)              | **Implemented** — Phase-2 files grep-clean. CI kill-list gate green. |
|15 | Feature-flag safety — Phase 2 lands behind `SEMANTIC_ENGINE_V2=false` (§ 14)                  | **Implemented** — plugins register at import time but produce no user-visible change until Phase 5+ wires them into `/api/decode/smart`. Flag stays false in prod. |
|16 | AI persona is advisor-only (§ 13)                                                             | **Implemented** — CMD plugin has no LLM code path. |
|17 | Regression tests for every new capability (§ 15)                                              | **Implemented** — 37 unit tests in `tests/rc5/unit/cmd/`. Coverage matrix in § 4 below. |
|18 | Every historical bug becomes a permanent test                                                 | **Not applicable** — this phase introduces no historical bug fixes; Phase 3+ audit will backfill. |
|19 | Full backward compatibility                                                                   | **Implemented** — `/api/decode/smart` response unchanged (stub keys already present from Phase 1). No route / field / schema removal. |
|20 | CI-enforced invariants (§ 12)                                                                 | **Implemented** — all 6 Phase-1 invariant tests still green under Phase 2 changes. `rc5_gates.yml` unchanged. |
|21 | Frozen plugin API surface — new parsers extend, never modify core (§ 12.5)                    | **Implemented** — CMD plugin ONLY uses the public API. Zero touches to `exec_graph.py` / `semantic_ir.py` / `plugin_api.py`. |
|22 | 100 % pass on `tests/rc5/invariants/` before merge                                            | **Implemented** — 6/6 invariant tests green after Phase 2 lands. |

---

## 2 · Intentionally deferred features (with target phase)

Each deferred item is emitted as `UnresolvedNode` with a machine-readable `reason`
today, so no analyst-facing regression is silently introduced.

| Feature                                                    | Deferred to  | Why                                                        |
|------------------------------------------------------------|--------------|------------------------------------------------------------|
| `SET /A` arithmetic evaluator                              | Phase 2.1    | Needs its own expression evaluator (bit-ops, %, ()). Not a common obfuscation surface for the current triage backlog. |
| `FOR /F` / `FOR /L` / `FOR /R` loops                       | Phase 2.1    | Loops require iteration + variable binding scope model — 3-5 days of work on their own. |
| `IF DEFINED` / `IF EXIST` / `IF ERRORLEVEL`                | Phase 2.1    | Requires environment + filesystem + errorlevel model. Currently unresolved with clear reason. |
| `SETLOCAL` / `ENDLOCAL` scope-pop                          | Phase 2.1    | `ENABLEDELAYEDEXPANSION` is honoured; nested scopes are not popped. |
| `%~1` command-line argument expansion                      | Phase 2.1    | Requires argument model — orthogonal to obfuscation cases seen so far. |
| Nested-block IF/ELSE                                       | Phase 2.1    | Basic IF-then works; ELSE / nested ELSE-IF unresolved with reason. |

---

## 3 · User's Phase-2-approval directives — audit

| User directive                                                                                     | Status                                            |
|----------------------------------------------------------------------------------------------------|---------------------------------------------------|
| "✅ Ship Phase 1 to Production with SEMANTIC_ENGINE_V2=false."                                     | **Deployed** via `emergent__send_to_deployer`. Env flag stays false. |
| "✅ Start Phase 2 (CMD Semantic Interpreter)."                                                     | **Complete this session.**                        |
| "✅ After Phase 2, implement Phase 3 (PowerShell AST Interpreter)."                                | **Queued** — see § 5. Requires new session (context budget). |
| "✅ After Phase 3, implement Phase 4 (Behavior Extractor)."                                        | **Queued** — after Phase 3.                       |
| "❌ Defer the admin A/B toggle until after Phase 4 during shadow-run."                             | **Deferred as instructed.** No frontend / API changes made. |

---

## 4 · Test coverage matrix — CMD Phase 2

| Category                    | Tests | Notes                                                              |
|-----------------------------|------:|--------------------------------------------------------------------|
| Tokenizer                   |     8 | Operators, quoted strings, redirection, line continuation, PVAR/DELAYED |
| SET assignments             |     5 | Simple, chained, /A unresolved, unknown-var literal preservation   |
| `%VAR:old=new%` replace     |     2 | Match + no-match                                                   |
| `%VAR:~o,l%` substring      |     2 | Positive offset+length, offset-only                                |
| Delayed `!VAR!`             |     2 | Off (literal) + SETLOCAL enable (resolved)                         |
| CALL 2nd-pass               |     1 | Marker present                                                     |
| Sequencing                  |     3 | `&`, `&&`, `\|\|`                                                  |
| IF static-eval              |     3 | True runs · False skips · DEFINED unresolved                       |
| ECHO                        |     1 | Text preservation                                                  |
| Quoting + `^` escape        |     2 | Double-quote + `^&` literal-amp                                    |
| Confidence propagation      |     2 | Unknown-var drop + literal-command full                            |
| End-to-end reconstruction   |     2 | PowerShell launcher (SETLOCAL + delayed + concat), evidence chain  |
| Immutability / determinism  |     2 | No dangling refs, two identical runs                               |
| Parser contract             |     2 | Program root + warnings field                                      |
| **Total**                   | **37** |                                                                    |

---

## 5 · Remaining approved recommendations — carried forward

Nothing was silently dropped. The following are queued for the phases they belong to:

- **Phase 3 (PowerShell AST Interpreter)** — user's audit request (10 tasks) folds directly into
  Phase 3. Task 7 (false-positive audit — regex-based verdict shortcuts) will happen as part of the
  kill-list migration during Phase 5–7. Task 9 (regression test suite: benign admin scripts,
  Invoke-Obfuscation, Atomic Red Team, PowerShell Empire) becomes the Phase 3 corpus.
- **Phase 4 (Behavior Extractor)** — will consume the CMD ExecGraph shipped this phase.
  This will populate `result["behaviors"]` (currently empty stub).
- **Phase 5 (MITRE v2)** — will consume Phase 4 behaviors + kill legacy `_KEYWORD_MITRE_MAP`.
- **Phase 6 (LOLBIN v2)** — three-state model (referenced / expanded / executed). The CMD
  plugin already emits `NodeKind.process` for executed spawns, giving LOLBIN v2 a clean input signal.
- **Phase 7 (Verdict v2)** — 7-dimension scoring, with `execution < 20` cap-and-floor.
- **Phase 8 (Explainability)** — will render provenance links in the UI.
- **Phase 9 (Corpus + shadow run)** — 30-day preferred, 14-day minimum. Ten metrics tracked.
- **Phase 10 (Cutover)** — kill-list retirement + flag flip.
- **Admin A/B toggle** — explicitly deferred by user until "after Phase 4, during shadow-run."

---

## 6 · No architectural invariant was weakened or removed this phase

The 6 CI-enforced invariants from § 12 remain intact. No new import of retired keyword maps.
No mutation of ExecNode or Behavior. No detector was authored (Phase 4+ target).
No `emergentintegrations.` import in any Phase-2 module.
