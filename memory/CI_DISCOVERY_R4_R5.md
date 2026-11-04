# LANE B · COMMAND INTELLIGENCE — DISCOVERY REPORT (READ-ONLY, PRE-R-4/R-5)

Answers items 1–20 of the owner directive's FIRST RETURN. **No production code
was changed to produce this report.** R-1/R-2/R-3 remain as delivered and
evidenced in `CI_R1_R3_EVIDENCE.md`.

---

## 1 · Repository state
```
branch : feature/rc2-alignment
HEAD   : 6caa3698
worktree: clean except  ?? memory/AUTHORITATIVE_XDR_yarn.lock  (untracked, unrelated)
```

## 2 · Files involved
| layer | file | role |
|---|---|---|
| API | `backend/routers/ops.py:575` | `POST /api/analyze/command` → `run_offloaded(analyze_command)` |
| contract | `backend/schemas.py:75` | `CommandAnalyzeIn{input, force_decode_span}` |
| pipeline | `backend/command_analyzer.py` (1,340 ln) | interpreter profile, pipeline split, tokenize, span discovery, decode, recursion, AST call, IOC/MITRE/behaviour/exec-flow/LOLBin aggregation, summary |
| PS rewrites | `backend/powershell_ast.py` (≈430 ln) | 7 regex rewrites + (new) `find_unresolved()` |
| codecs | `backend/smart_decoder.py`, `magic_decoder.py`, `payload_sanitizer.py`, `shellcode_analyzer.py` | per-span decode chains, XOR key hints, shellcode |
| AMSI | `backend/amsi_detector.py` | AMSI/ETW bypass + its own ATT&CK ids |
| LOLBAS | `backend/lolbas.py` (~239-entry official catalog + 40 curated argv rules, Mongo-cached), `backend/lolbas_chain.py` | **exists, NOT wired into `analyze_command`** |
| OSINT | `backend/osint.py` (VT, AbuseIPDB, Shodan, GreyNoise, URLScan, OTX, IPinfo + free baseline), `backend/services/ioc_intelligence/providers/virustotal_abuseipdb.py` | **exists, NOT wired into `analyze_command`** |
| UI | `apps/nivxray-xdr/src/xdr/pages/XdrCommandIntelPage.jsx` (117 ln) | renders `JSON.stringify(res,null,2)` as the primary view |
| UI (new) | `apps/nivxray-xdr/src/xdr/ux0/Ux0CommandIntel.jsx` | prototype composition; awaiting UX approval, not promoted |

## 3 · Current end-to-end dataflow
```
input
 → detect_interpreter()                     (profile: payload flags, lolbin, high-risk switches)
 → split_pipeline()                         (| ; && || >)
 → tokenize_with_mode(primary_seg)          [R-1: windows-argv | posix-shlex]
 → parsed_structure{executable, executable_span, evidence_preserved, tokenizer,
                    switches, arguments, pipeline_*, shell_token_count}
 → _find_payload_spans(text, tokens, prof)  (semantic flags → PS/JS/PY b64 wrappers
                                             → standalone-b64 → url/unicode/chr/hex)
 → _classify_spans()                        [R-3: FRAGMENT detection]
 → confidence gate ≥0.80 (+ tie → needs_choice/AMBIGUOUS)
 → _decode_span() per span (hint_xor_key from wrapper)
 → recursive frontier, _MAX_NESTED=3, fragments excluded   [R-3]
 → deobfuscate_ps(text + all decoded outputs, JOINED AS ONE FLAT STRING)
 → combined_text = original + every final_output + ast final
 → extract_iocs(combined_text)  classify_behaviors(pipeline, ORIGINAL text, prof)
   _execution_flow(combined_text)  map_mitre(combined_text)
   detect_lolbins(TOKENS ONLY, prof)  summarize(prof, behaviors, iocs, decodes)
 → decode_status / unresolved_expressions / canonical_decoded_artifact  [R-2/R-3]
 → JSON response → UI raw dump
```
**The structural defect that survives R-1…R-3: `combined_text`.** Every
downstream consumer reads a concatenation of wrapper + all layers, so no
consumer is reading *the canonical artifact*. That is precisely D-7.

## 4 · Where PowerShell parsing occurs
`powershell_ast.py`. Its own docstring says *"Not a full PowerShell parser — a
pattern-based mini-AST"*. There is **no lexer, no AST, no statement list, no
expression tree, no scope, no dataflow graph**. It is 7 regex rewrites applied
in a fixed order over the whole text as one flat string, up to `max_passes=3`.
A second, unrelated PS analyser exists at
`backend/services/die/powershell_ast.py` (used by DIE, not by this pipeline) —
a candidate to consolidate, not to fork.

## 5 · Where string concatenation fails
`powershell_ast.py` `_CONCAT_RE` / `_collapse_string_concat`:
```python
_STR_LIT   = r"(?:'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")"
_CONCAT_RE = re.compile(rf"({_STR_LIT})(?:\s*\+\s*({_STR_LIT}))+")
```
The alternation admits **only quoted literals**.

## 6 · Why `+ A +` / `+ 9 +` survive
The rule is a *regex over adjacent literals*, not a constant folder. A `+`
whose operand is a number, variable, cast, call or parenthesised expression is
outside the pattern, so the run terminates there and the operator text is
emitted verbatim. `'cnl7DQo7JE' + 9 + 'jckptTC'` matches on each side
independently → `'cnl7DQo7JE' + 9 + 'jckptTC'` with the literal characters
`+ 9 +` now *inside the rendered artifact*. PowerShell's `+` with a `String`
left operand coerces `Int32`, so the correct value is `…JE9jckptTC…`.
R-2 now reports this as `non-string-concat-operand` instead of hiding it;
**R-4 is what actually evaluates it.**

## 7 · Why Base64 fragments became standalone payloads
`_BASE64_INLINE_RE = \b[A-Za-z0-9+/]{40,}={0,2}\b` fires per *fragment*
because it runs on raw text with no expression context, and a payload-flag
position gives the fragment `confidence 0.98`. R-3 now classifies any literal
that is an operand of a `+` chain as `FRAGMENT` and excludes it from the
confidence gate and the recursive frontier. The *ordering* defect remains:
span discovery still runs before value reconstruction. D-4 requires
reconstruct-parent-then-classify; today it is classify-then-maybe-reconstruct.

## 8 · Why the executable path lost backslashes
`tokenize()` used `shlex.split(cmd, posix=True)`; POSIX mode treats `\` as an
escape and deletes it. **Fixed in R-1** (`tokenize_windows`, backslash literal;
`executable_span` byte-for-byte; `evidence_preserved` flag).

## 9 · Why `applied=true` coexisted with an incomplete artifact
`if deob["transformations"]: applied = True` — truthiness of the transformation
list, including cosmetic `case-normalization`. **Fixed in R-2**: `applied`
mirrors semantic transformations only, `decode_status` is the real state, and
`RECOVERED` is structurally impossible while `unresolved_expressions[]` is
non-empty.

## 10 · How `final_decoded_inline` is selected
`reconstruct_inline(original, to_decode, decodes)` — the **original command**
with `«decoded: …»` annotations spliced in. It is a *diff aid*, never a
canonical artifact, yet it is the most prominent decoded-looking field in the
response. R-3 added `canonical_decoded_artifact` beside it; R-7 must make the
canonical artifact the one consumers use and demote this to labelled context.

## 11 · Which artifact each consumer reads today
| consumer | input | correct input (D-7) |
|---|---|---|
| `summarize()` | interpreter + behaviour tags + ioc urls + decode count | canonical artifact narrative |
| `classify_behaviors()` | **original text only** | wrapper *and* canonical, labelled |
| `extract_iocs()` | `combined_text` | canonical artifacts, per-layer |
| `map_mitre()` | `combined_text` | canonical, with evidence refs |
| `_execution_flow()` | `combined_text` | canonical + reparse nodes |
| `detect_lolbins()` | **outer tokens only** | every executable in every layer |
| `amsi` | all layers joined | OK |
None of them receives the canonical artifact. This is the single highest-value
repair after R-4/R-5.

## 12 · Existing OSINT / TI
`backend/osint.py` — 7 keyed providers (VirusTotal, AbuseIPDB, Shodan,
GreyNoise, URLScan, OTX, IPinfo) + free baseline (ip-api.com, system DNS),
keys read from the settings collection, async httpx with an 8s timeout.
`services/ioc_intelligence/providers/virustotal_abuseipdb.py` returns an
explicit `pending` ProviderResult when keys are absent — exactly the honesty
D-13 demands. **Neither is called from `analyze_command`.** Verdict: **ADOPT**
as-is; add a canonical-IOC → provider call site plus
`NOT_APPLICABLE` / `WAITING_FOR_CANONICAL_IOC` states.

## 13 · Existing LOLBAS / native-tool intelligence
`backend/lolbas.py` — full ~239-entry official LOLBAS catalog auto-synced from
`lolbas-project.github.io`, Mongo-cached (`lolbas_cache._id="catalog"`), plus 40
curated argv-regex rules; `lolbas_chain.py` for chain reasoning. Meanwhile
`command_analyzer.detect_lolbins()` ignores all of it and returns
`{name, role}` from the tiny `INTERPRETERS` index over **outer tokens only**.
Verdict: **REPAIR the call site, ADOPT the catalog.** Catalog membership must
stay distinct from the NivXRay behavioural assessment (D-14).

## 14 · Existing ATT&CK mapping
`command_analyzer.map_mitre(all_text)` — keyword/regex table over
`combined_text`, returning `{id, name}` only: **no tactic, no confidence, no
evidence_ref, no artifact_layer, no mapping_reason**. `_EXEC_FLOW_SIGNALS` does
carry `mitre_id` + an evidence snippet (the only citable path today; the UX0
prototype renders only those and withholds the rest). `amsi_detector` adds
T1562.001/.006. Verdict: **REBUILD the contract** per D-11.

## 15 · Existing Executive Summary
`command_analyzer.summarize()` — string concatenation of at most 6 canned
sentences beginning `Runs under {interpreter}.` It never reads the recovered
payload. Verdict: **BUILD** a deterministic evidence-driven narrative
generator over the canonical artifact. **No LLM as authoritative decoder.**

## 16 · ADOPT / EXTEND / REPAIR / BUILD matrix
| component | decision | note |
|---|---|---|
| `osint.py` providers | **ADOPT** | wire to canonical IOCs only |
| `lolbas.py` catalog | **ADOPT** | keep catalog provenance separate from assessment |
| `smart_decoder` / `magic_decoder` / codecs | **ADOPT** | codec layer is not the defect |
| `amsi_detector` | **ADOPT** | already cites techniques |
| R-1/R-2/R-3 contracts | **ADOPT** | shipped and evidenced |
| tokenizer / evidence span | **EXTEND** | per-segment spans, not just the leading token |
| recursion loop | **EXTEND** | fixed point + `provenance[]` + explicit stop reason (R-6) |
| `detect_lolbins()` call site | **REPAIR** | all layers, catalog-backed, evidence refs |
| `map_mitre()` | **REPAIR→REBUILD** | full D-11 mapping record |
| consumer inputs (`combined_text`) | **REPAIR** | canonical propagation (R-7) |
| `summarize()` | **BUILD** | evidence-driven narrative (D-8) |
| PS lexer + expression evaluator | **BUILD** | R-4 |
| statement list + dataflow graph | **BUILD** | R-5 |
| IOC record contract | **BUILD** | value/type/normalized/source_artifact/evidence_ref/decode_layer/confidence/extraction_method (D-12) |
| `analysis_completeness` object | **BUILD** | separate from confidence (D-21/22) |
| Command Intelligence page | **BUILD** | only after contracts are trustworthy (D-17) |

## 17 · Minimal repair architecture
```
R-4  ps_lexer.py + ps_expr.py        safe expression evaluator:
                                      literal · number · [char] · cast · parens ·
                                      + with .NET String/Int32 coercion · -f · -join ·
                                      .Replace · .Substring    (NO execution, ever)
R-5  ps_program.py                    statement list + variable dependency graph;
                                      per-variable RUNTIME_RESOLVED /
                                      STATICALLY_RECOVERED / UNRESOLVED;
                                      reference-before-assignment preserved
R-4b artifact_graph.py                nodes with artifact_id / parent_artifact_id /
                                      source_span / transformation / in / out /
                                      deterministic_or_heuristic / confidence /
                                      unresolved_dependencies[]; fixed-point loop
                                      with an explicit stop_reason
R-7  canonical fan-out                one canonical artifact consumed by summary,
                                      behaviour, exec-flow, IOC, MITRE, LOLBAS;
                                      wrapper retained as labelled context
R-7b ioc_records / mitre_records /    full D-11/D-12/D-14 contracts with evidence_ref
     lolbas_records
R-13 osint bridge                     canonical IOC → osint.py; NOT_APPLICABLE /
                                      WAITING_FOR_CANONICAL_IOC; never a fake Clean
D-8  exec_summary.py                  deterministic narrative from the graph
D-21 analysis_completeness            RECOVERED / UNRESOLVED / NOT_EVALUATED /
                                      UNSUPPORTED / EVIDENCE_GAPS (+ reasons)
```
Old regex rewrites stay as a fallback until the evaluator proves
equal-or-better on the existing corpus. Nothing is deleted on approval day.

## 18 · Exact files proposed to change
**New:** `backend/ps_lexer.py`, `ps_expr.py`, `ps_program.py`,
`artifact_graph.py`, `exec_summary.py`, `command_intel_records.py`.
**Modified:** `command_analyzer.py` (call sites + fan-out), `powershell_ast.py`
(delegate folding to the evaluator, keep regexes as fallback), `routers/ops.py`
(response additions only, no breaking removals), `schemas.py` (additive).
**Later, separate gate:** `pages/XdrCommandIntelPage.jsx`.
**Untouched:** W1, W2-1, RBAC, `lolbas.py`, `osint.py`, `amsi_detector.py`,
every corpus gate.

## 19 · Regression tests to add (D-19)
Pin the owner's exact sample byte-for-byte, then assert: evidence unchanged ·
backslashes preserved · fragments not promoted · `'JE'+9+'jck'` → `JE9jck` ·
variable dependency reconstructed · runtime vs static distinguished ·
recursion continues through recovered layers · unresolved stays unresolved ·
partial never reports `RECOVERED` · canonical propagates to summary/behaviour/
IOC/MITRE/LOLBAS · OSINT receives only validated canonical observables ·
every ATT&CK mapping has `evidence_ref` · every LOLBAS finding has
`evidence_ref` · every exec-chain node has `evidence_ref` · summary reflects
recovered behaviour · no fabricated IOC/ATT&CK/attribution · no PowerShell
executed. Plus benign + adversarial fixtures (`'a'+1+'b'` in an innocuous
script, a long legitimate certificate blob, a heavy-concatenation build
script, a truncated payload) so the engine is not overfitted.

## 20 · Risks to the existing corpus/gates
1. `test_regression_150plus.py` + `test_ps_ast_and_amsi.py` assert *current*
   folding output; a stronger evaluator can change strings they compare →
   gate the evaluator behind an equal-or-better corpus run, never edit the
   assertions.
2. Canonical propagation narrows consumer input from `combined_text`, so
   wrapper-only IOC/MITRE hits some tests rely on may disappear → keep the
   wrapper as an explicitly labelled second input rather than dropping it.
3. `lolbas.py` performs network sync + Mongo cache; wiring it into a synchronous
   analyser path risks the request starvation `run_offloaded` exists to avoid →
   catalog reads must be cache-only on this path.
4. OSINT in the request path adds an 8s-timeout network dependency → must be
   opt-in/async with an explicit `pending` state, never blocking the verdict.
5. A real lexer changes `shell_token_count` semantics for nested programs →
   introduce `program_statement_count` separately; do not redefine the existing
   field.
6. `_MAX_NESTED=3` → a true fixed point needs size/depth/time budgets or a
   crafted sample becomes a DoS.

---

## STOP
Discovery complete. **Awaiting owner approval before R-4/R-5.**
Still outstanding from the owner: the exact byte-for-byte obfuscated PowerShell
sample for the permanent D-19 fixture.
