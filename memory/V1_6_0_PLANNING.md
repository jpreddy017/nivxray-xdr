# NivXRay v1.6.0 · Semantic Variable Resolution — Planning Document

**Status**: PLANNING · no code · no branch created
**Author**: main-agent, per SME direction 2026-02-XX
**Prerequisite**: v1.5.2 UI verification + tag + branch freeze

---

## 1 · Why v1.6.0 exists

Every v1.5.x cycle patched a specific PowerShell obfuscation shape by
adding another regex. `ps_indirect_compression_stream` (v1.5.0) was the
tipping point — the fix required a bespoke regex to link
`FromBase64String` → `MemoryStream` variable → `GzipStream` consumer.
Each new adversary idiom (variable renaming, expression re-ordering,
nested calls, string concatenation of the variable name itself) will
demand another bespoke regex under the current architecture.

**The right primitive is not more regex, it is def-use analysis over a
PowerShell AST slice** — deterministic, generic, and finite.

The v1.6.0 goal is to replace the regex-based extraction sites listed
below with a single **def-use resolver** that answers one question per
call site:

> "For this variable-usage site, what is the effective literal value
> or method-call chain that produced it — traced back through
> assignments, concatenations, and dereferences — without executing
> user code?"

Every existing regex site becomes a thin adapter that asks the
resolver instead of scanning text.

---

## 2 · Non-goals of v1.6.0

| Non-goal | Rationale |
| --- | --- |
| Full PowerShell parser | AST slicing is enough for def-use; a full parser is a v1.7.x concern. |
| Runtime evaluation | Determinism directive is inviolable. No `Invoke-Expression`, no eval. |
| New intent categories | The intent surface is orthogonal; v1.5.2 already covered reflective injection. |
| Frontend refactor | `OutputView` still consumes the v1.5.1 promoted text. Deferred to v1.6.1. |
| Deprecating any existing regex prematurely | Every regex site keeps its current behaviour as a **fallback** during migration; the resolver only *upgrades* the accuracy — never regresses it. |

---

## 3 · Regex inventory (extraction surface today)

### 3.1 · Categorised by role

| Category | Files · patterns (representative — full inventory below) |
| --- | --- |
| **A · Variable assignment** | `_VAR_B64_ASSIGN_RE`, `_GET_VAR_DEREF_RE`, `_VAR_STATIC_ACCESS_RE`, `_DOLLAR_BRACE_RE` (ps_deobfuscate) · `_DIAG_ASSIGN_RE` (ps_indirect_compression_stream) |
| **B · String reconstruction** | `_CONCAT_RE`, `_FORMAT_RE`, `_STRING_JOIN_LITERAL_RE`, `_NUM_LIST_RE` |
| **C · Compression / crypto stream** | `_COMPRESSION_RE`, `_VAR_COMPRESSION_CONSUMER_RE`, `_DIAG_CONSUMER_RE`, `_ASSIGN_MARKER_RE`, `_CONSUMER_MARKER_RE` |
| **D · Static base64 / encoding** | `_B64_STATIC_RE`, `_UTF16_B64_RE`, `_XOR_STATIC_RE`, `_XOR_MULTIBYTE_RE`, `_XOR_ROLLING_RE`, `_RC4_STATIC_RE`, `_AES_*_RE` |
| **E · Reflection / invocation** | `_REFLECTION_RE`, `_DYNAMIC_INVOKE_RE`, `_TYPE_GETTYPE_LITERAL_RE`, `_TYPE_GETTYPE_DYNAMIC_RE`, `_STATIC_METHOD_BY_STRING_RE`, `_STATIC_METHOD_BY_QUOTED_RE`, `_METHOD_INVOKE_RE`, `_CALL_OP_RE` |
| **F · Environment / boundary** | `_ENV_VAR_RE`, `_TYPE_NAME_COERCION_RE`, `_BOUNDARY_RE`, `_IEX_LITERAL_RE`, `_SCRIPTBLOCK_LITERAL_RE`, `_SCRIPTBLOCK_DYNAMIC_RE`, `_INVOKE_COMMAND_SB_RE`, `_KEYED_DECRYPT_SIG_RE` |

### 3.2 · Regex counts (top offenders — v1.6.0 primary targets)

| File | `re.*` sites | Migration priority |
| --- | ---: | :---: |
| `v2/semantic/ps_deobfuscate.py` | 59 | **P0** |
| `v2/investigation/rte/transformations/ps_indirect_compression_stream.py` | 4 | **P0** |
| `v2/investigation/rte/transformations/ps_encoded_command.py` | (~4) | **P1** |
| `v2/investigation/intent/rules/defense_evasion.py` | 11 signatures | P2 (rules stay pattern-based; only the *values* they consume become def-use-resolved) |
| `v2/investigation/intent/rules/*.py` (7 files) | ~30 total | P2 (same rationale) |
| `v2/investigation/cre/wrappers/*.py` (7 files) | ~20 total | P2 |

*Full per-site enumeration is in `V1_6_0_REGEX_INVENTORY.md` (produced
in the P0.1 milestone below).*

### 3.3 · Regex sites that CAN stay (by design)

- **Boundary detectors** (`_BOUNDARY_RE`, marker regexes that decide
  "does this file plausibly contain X" before invoking the resolver).
  These are cheap, correct, and don't need semantic backing.
- **Terminal shape recognisers** in the Intent Layer (e.g.
  `VirtualAlloc.*0x40`) — they operate on the ALREADY-RESOLVED
  effective payload, so replacing regex here buys nothing.

---

## 4 · Def-use graph architecture (design sketch)

### 4.1 · Data model

```
Symbol       :: str                # normalised variable name ("$s" → "s")
Position     :: int                # byte offset in source
StmtKind     :: Assign | Update | Consume | Alias | ImplicitEnv
Literal      :: str | bytes
CallExpr     :: {method_name, args: list[Expr], receiver: Expr | None}
Expr         :: Literal | CallExpr | VarRef | Concat | Format
Statement    :: {kind, symbol, expr, pos_start, pos_end}
DefUseGraph  :: {statements: list[Statement],
                 defs: dict[Symbol, list[Statement]],
                 uses: dict[Symbol, list[Statement]]}
```

### 4.2 · Slicing algorithm (deterministic)

1. **Tokenise** the recovered PowerShell text (comment / string / code
   segmentation only — no full parse). Reuses existing
   `v2/semantic/ps_ast.py::_tokenize` scaffolding.
2. **Statement partition**: split on unescaped `;` and newline where the
   preceding token is not inside a string / here-string / parenthesis /
   brace / bracket.
3. **Classify each statement** as an assignment (`$x = expr`), update
   (`$x += expr`), consumer (contains `$x` on the RHS of a method-call),
   alias (`$y = $x`), or none-of-the-above (ignored for def-use).
4. **Build `defs` and `uses` maps** — every symbol name maps to the
   list of statements that define / use it, in source order.
5. **Resolve on demand**: `resolver.value_of(symbol, at_pos)` walks
   the most-recent-def-before-`at_pos`, then recursively resolves
   any sub-symbols in its expression tree until a Literal is reached
   or a cycle is detected (in which case return
   `Unresolved(reason="cycle")`).

### 4.3 · Determinism guarantees

- **No user code executed.** The resolver only substitutes literals and
  simple concatenations; it never invokes .NET types or shells out.
- **Fixed cycle-breaking policy.** A symbol that transitively depends
  on itself resolves to `Unresolved(reason="cycle")` — never to an
  arbitrary intermediate.
- **Fixed depth budget.** Resolution depth capped at 32 (same budget
  as the RTE). Exceeded budget → `Unresolved(reason="depth_exceeded")`.
- **Determinism hash contribution.** The resolved literal (or the
  `Unresolved(reason=…)` object) is added to the RTE determinism hash
  so two identical inputs produce two identical resolver traces.

### 4.4 · Failure modes and how the pipeline explains them

| Resolver outcome | Downstream behaviour |
| --- | --- |
| `Literal(value=b"…")` | Feed to decoder as if it were a source-order literal. |
| `Unresolved(reason="cycle")` | Emit new diagnostic `DX3001 · VAR_CYCLE`. Consumer plugin skips. |
| `Unresolved(reason="depth_exceeded")` | Emit new diagnostic `DX3002 · VAR_DEPTH_EXCEEDED`. |
| `Unresolved(reason="dynamic_expr")` | Emit new diagnostic `DX3003 · DYNAMIC_VALUE`. Consumer skips. |
| `MultipleDefs(count=N)` | Emit new diagnostic `DX3004 · AMBIGUOUS_DEF`. Consumer picks last-def-before-consumer (documented policy) and warns. |

*Diagnostic range `DX3000-DX3999` is reserved by this planning doc for
def-use resolver events; the codes are minted in the P1.3 milestone
below.*

---

## 5 · Corpus samples that will benefit

Ordered by how likely they are to expose today's regex fragility.

| # | Sample id / origin | Idiom | Current behaviour | v1.6.0 expectation |
| --- | --- | --- | --- | --- |
| 1 | `PS_ENCODEDCOMMAND_GZIP_REFLECTIVE_LOADER_002` (v1.5.2 corpus) | Single-var b64 → MemoryStream → GzipStream | ✅ decodes (regex works) | remains ✅ · def-use path validates equivalence |
| 2 | `PS_ENCODEDCOMMAND_GZIP_STAGE2_001` (v1.5.0 corpus) | Same idiom · corrupt inner b64 | ✅ stops at L1 with DX1001 | remains ✅ · resolver emits `Unresolved(dynamic_expr=false, literal_but_invalid=true)` and DX1001 still fires |
| 3 | **synthetic-a** (to be created) | Two-hop `$a="H4sI…"; $b=[Convert]::FromBase64String($a); $s=New-Object IO.MemoryStream(,$b); IEX (…GzipStream($s,…))` | ❌ stops at L1 today (regex requires the b64 literal to appear inline in the MemoryStream ctor) | ✅ resolves through `$a → $b → $s` chain |
| 4 | **synthetic-b** | String-concatenated variable name (`$s = New-Object IO.MemoryStream(...); & (${'s'.substring(0,1) + ''}) …`) — unusual but observed in mid-2025 samples | ❌ | ✅ resolves `${'s'…}` static substring → `s` → assigned MemoryStream |
| 5 | **synthetic-c** | Assignment inside a subexpression (`IEX (New-Object IO.StreamReader( New-Object IO.Compression.GzipStream( ($s = New-Object IO.MemoryStream(...)),…) )).ReadToEnd()`) | ❌ | ✅ resolver treats subexpression-assign as a proper def scoped to the enclosing statement |
| 6 | **PowerSploit `Invoke-Shellcode.ps1` (excerpt)** | Multi-level helper: `$var_code = [Convert]::FromBase64String('…')` then XOR-decode + VirtualAlloc + Marshal.Copy | ✅ intents fire on the recovered text (v1.5.2) but the b64 literal is a leaf; resolver contributes nothing new here | ✅ · already-working case stays working (regression proof) |
| 7 | **Nishang `Invoke-ReflectivePEInjection`** (public red-team) | Multi-file assembly loading via variable-bound `Reflection.Assembly` | ❌ static analysis today | ✅ resolver traces `$Bytes → [Reflection.Assembly]::Load($Bytes)` and fires `runtime_dependent` with the b64 preview |
| 8 | **Nishang `Invoke-Encode` output shape** | Format-operator obfuscation: `$s = "H{0}sI…" -f 4;` | partial (regex `_FORMAT_RE` handles simple cases) | ✅ resolver composes the format op cleanly and passes the assembled literal downstream |
| 9 | **Empire `launcher.ps1`** | GZip-then-b64-then-utf16le with `[System.Text.Encoding]::UTF8.GetString()` on a variable | ❌ variable indirection | ✅ resolver + existing UTF-8 decoder chain |
| 10 | **Sophos-labs "Decoding malicious PowerShell" sample #4** (external reference the SME provided) | Same 3-layer shape as sample #1, byte-for-byte from the blog | ✅ already-working case | ✅ regression proof |

Samples 3-5 will be MINTED as part of P1.4; samples 6-10 imported from
public references as part of P1.5. Each new corpus entry is a locked
YAML with `must_fire_intents`, expected verdict, expected diagnostics,
and expected resolver outcome.

---

## 6 · Phased implementation plan

**Total scope**: ~4 milestones over v1.6.0. Every milestone is
independently shippable behind a feature flag
`INVESTIGATION_DEF_USE_RESOLVER=on|off` (default off until P2.3).

### P0 · Instrumentation & inventory (no runtime changes)

- **P0.1** Produce `V1_6_0_REGEX_INVENTORY.md` — per-file per-regex
  table with source lines, category (A-F), migration priority, and
  the exact query the resolver must be able to answer to replace it.
  *No code touched.*
- **P0.2** Extend the Decode Trace Report (already built for v1.5.2)
  with a "Resolver Trace" section — a no-op stub while resolver is
  off, so the tracing shape is finalised before the resolver ships.

### P1 · Def-use resolver core

- **P1.1** Data model + AST slicer (§4.1, §4.2). Standalone module at
  `v2/semantic/def_use/{__init__.py, slicer.py, models.py, resolver.py}`.
  No production caller yet.
- **P1.2** Resolver unit tests — 40+ cases covering: single-def,
  redef, alias, concat, format-op, cycle, depth budget, dynamic expr,
  interpolation, subexpression-assign, string-op resolved name.
- **P1.3** New diagnostic codes `DX3001-DX3010` in the RTE registry.
  Same causal-chain contract as `DX1xxx` / `DX2xxx`.
- **P1.4** Mint synthetic samples 3-5 into the trust corpus with
  `resolver_off_expected` and `resolver_on_expected` blocks. Trust
  gate stays green in resolver-off mode.
- **P1.5** Import samples 7-10 into the corpus behind
  `resolver_on_only: true` flag (skipped by trust gate until P2.3).

### P2 · Wiring the resolver into the RTE

- **P2.1** `ps_indirect_compression_stream` grows a
  **resolver-first** path: try resolver, fall back to today's regex
  if resolver returns `Unresolved`. Feature-flag gated.
- **P2.2** Same treatment for `ps_encoded_command` (variable-bound
  base64 in the EncodedCommand slot — currently never observed but
  the SME reference blog #6 shows the shape exists).
- **P2.3** Flip `INVESTIGATION_DEF_USE_RESOLVER=on` by default. Trust
  corpus samples 3-10 flip from `resolver_off_expected` to full
  ground-truth. If any regresses → fail CI → rollback flag.
- **P2.4** Migrate `_VAR_B64_ASSIGN_RE`,
  `_VAR_COMPRESSION_CONSUMER_RE`, `_DIAG_ASSIGN_RE` in
  `ps_deobfuscate.py` and `ps_indirect_compression_stream.py` to
  thin adapters that call the resolver. Keep old regex around as
  `# LEGACY fallback` for one release cycle, then delete in v1.6.1.

### P3 · Retire the multi-hop regexes

- **P3.1** Delete legacy fallbacks in files migrated in P2.4.
- **P3.2** Add a "Resolver Trace" panel in the Analyst Report so the
  analyst can see the def-use walk that produced every recovered
  literal. Same evidence-anchored discipline as DX diagnostics.

Each of P1-P3 lands as its own PR with its own regression proof
(unit tests + trust-corpus delta + full pytest suite green + E2E
`test_e2e_decode_smart_http_contract.py` still passing at 10/10).

---

## 7 · Risk register

| Risk | Likelihood | Mitigation |
| --- | :---: | --- |
| Resolver false-positive: reports a literal that is not actually what runs at runtime | LOW | Conservative slicer — only recognises literal/concat/format expressions; anything else → `Unresolved(dynamic_expr)`. Never guesses. |
| Resolver performance blow-up on adversarial pathological inputs | MEDIUM | Depth cap 32, statement cap 4,000, per-call wall-time budget 250 ms. Exceeded → `Unresolved(reason=budget_exceeded)`. |
| Trust corpus flake as new diagnostics change hash surface | LOW | New DX3xxx codes are additive; existing determinism hashes stay stable when resolver is OFF. |
| Regression in v1.5.2 detections | LOW | E2E `test_e2e_decode_smart_http_contract.py` is a hard gate; resolver-off mode is byte-identical to today. |
| Scope creep — someone wants "full PS parser now" | HIGH | This document explicitly declares full parsing a non-goal (§2); anything more than def-use for literals is v1.7.x. |

---

## 8 · Exit criteria (for the v1.6.0 GA tag)

1. Trust corpus at 100 % · investigation integrity ≥ 95 %
   (up from today's 94.1 %; each newly-added sample counts).
2. E2E HTTP contract test 10/10 passing.
3. 5 net-new corpus samples locked (synthetic 3-5 + Nishang + Empire).
4. Full regression suite green at the same numbers as v1.5.2 baseline.
5. `INVESTIGATION_DEF_USE_RESOLVER=on` by default with a documented
   rollback path (`=off`) that reproduces v1.5.2 byte-for-byte.
6. Analyst report renders a Resolver Trace when the resolver fires.
7. Every migrated regex site cites its DX3xxx counterpart in the
   trace when the resolver contributed to the decision.

---

## 9 · Open questions for the SME

- **Q1** Should `Unresolved(reason=…)` outcomes surface as **INFO**
  or **WARN**-severity diagnostics? INFO is honest (we tried, we
  don't know); WARN is louder for analysts. My recommendation: INFO
  for `depth_exceeded` / `dynamic_expr`; WARN for `cycle`
  (suspicious in a real payload).
- **Q2** Do we want the resolver to also run on the CRE effective
  payload (before RTE), or only inside RTE plugins? My recommendation:
  RTE-only in v1.6.0; CRE is a v1.7.x scope.
- **Q3** Do you want the Resolver Trace exposed via a "Download
  Resolver Trace" UI button (parallel to the v1.5.2 Decode Trace
  Report), or only via the JSON payload? Analyst-experience call.

---

## 10 · Non-scope reminders

The following items appeared in earlier planning conversations and
are DEFERRED past v1.6.0 — captured here so nobody re-litigates them
mid-implementation:

- **OutputView native structured rendering** — v1.6.1.
- **Golden Corpus auto-growth automation** — v1.6.1.
- **Resource-layer / Evidence-Graph expansion** — v1.7.x.
- **Static control-flow simulation (Phase 4.5)** — v1.8.x.
- **Behavior correlation across multiple samples** — v1.9.x.
- **Analyst PDF export** — v1.6.1 candidate.
- **Custom-domain deploy, prod key rotation UX, etc.** — orthogonal
  release channel; not this document's concern.

---

_This document is the SOLE authority for v1.6.0 scope. Any additions
must be proposed as a diff to this file and reviewed against the exit
criteria in §8 before landing on the branch._
