# P0 · COMMAND INTELLIGENCE DECODER — ROOT-CAUSE REPORT (NO IMPLEMENTATION)

Owner directive: *OWNER DEFECT — COMMAND INTELLIGENCE SEMANTIC DEOBFUSCATION /
CANONICAL ARTIFACT CONSISTENCY*, D-1…D-12.
Instruction honoured: **reproduce → root-cause → report → STOP.**
No decoder, analyzer, corpus gate or UI file was modified.

Reproduction: `/app/scripts/ci_decoder_rca_repro.py` (read-only; imports the
production modules and prints a deterministic verdict table).

> **Fixture caveat, stated plainly.** The exact original sample was not
> supplied as a file. The fixture is reconstructed to the **shape the owner
> disclosed** — obfuscated PowerShell whose payload variable is assembled from
> quoted fragments interleaved with **non-string operands**, then
> Base64-decoded, UTF-8 converted and executed via
> `[ScriptBlock]::Create` + `Invoke-Command`, with the recovered behaviour
> including `ipconfig /release|/renew`, `netsh winsock reset`,
> `netsh int ip reset`, `Start-Sleep -Seconds 5`,
> `[System.Net.ServicePointManager]::SecurityProtocol`, a second
> `FromBase64String` and a `C:\Users\Public\` path.
> **The exact original must replace this fixture before it is pinned as the
> permanent regression case (D-11).**

---

## 1 · Answer to the acceptance question

> *Why do `+ 9 +` / `+ A +` survive a transformation reported as successful?*

**Because the transformation is not a constant folder. It is a regex that only
matches runs of *adjacent string literals*, and it reports success whenever the
text changed at all.**

`backend/powershell_ast.py:82-83`
```python
_STR_LIT   = r"""(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")"""
_CONCAT_RE = re.compile(rf"({_STR_LIT})(?:\s*\+\s*({_STR_LIT}))+")
```
The alternation admits **only** single- or double-quoted literals. A `+`
whose operand is anything else — a bare numeric literal (`9`), a variable, a
method call, a cast, a parenthesised sub-expression — is **not** part of the
pattern, so the run terminates there.

Given the PowerShell source
```
'cnl7DQo7JE' + 9 + 'jckptTC' + 'A' + 'aGVsbG8'
```
`_CONCAT_RE` matches the two sides **independently** and rewrites them in
place, leaving the operator text between them **verbatim**:
```
'cnl7DQo7JE' + 9 + 'jckptTCAaGVsbG8'
```
The literal characters `` + 9 + `` are now inside the *rendered* artifact even
though no semantic evaluation of `9` ever happened. `9` is a
`System.Int32`; PowerShell's `+` with a `String` left operand coerces it, so
the **correct** result is `...JE9jckptTC...` — the digit joined with **no
surrounding spaces or plus signs**. The engine produces the source text instead
of the value. That is the defect, exactly as the owner diagnosed.

Reproduced output excerpt (Stage 1 of the repro script):
```
ZWxlYXN' + 9 + 'lDQppcGNvbmAZpZyAvcmVuZ' + 9 + 'XcNCm5ldHNoAIHdpbnNvY2s' + 9 + …
```
…while the transformation record simultaneously reads
```
op     : string-concat
reason : Collapsed adjacent string-literal concatenations
```

---

## 2 · Failing stages

| # | stage | module · line | what happens |
|---|---|---|---|
| S0 | tokenizer | `command_analyzer.py:255` | `shlex.split(cmd, posix=True)` — POSIX mode treats `\` as an **escape character** |
| S1 | backtick strip | `powershell_ast.py:40` | fine |
| S2 | `[char]NNN` | `powershell_ast.py:60` | handles only the literal `[char]<int>` form |
| S3 | variable binding | `powershell_ast.py:201-249` | `_VAR_ASSIGN_RE` requires `$name = <ONE string literal>` → a concat chain **never binds** |
| S4 | constant folding | `powershell_ast.py:104-117` | string-literal runs only; **non-string operands abort the run and are emitted verbatim** |
| S5 | format string | `powershell_ast.py:129` | literal args only |
| S6 | `.Replace()` | `powershell_ast.py:163` | literal receiver only |
| S7 | status | `command_analyzer.py:1009-1011` | `applied = True` iff `transformations` is non-empty |
| S8 | canonical artifact | `command_analyzer.py:1090` | `final_decoded_inline = reconstruct_inline(...)` — the **wrapper** with decoded spans re-inserted |
| S9 | consumers | `command_analyzer.py:1043-1091` | IOC / MITRE / behaviour / exec-flow read `combined_text`, which contains the wrapper and the *partially folded* text |

---

## 3 · Current AST / dataflow behaviour — measured, not asserted

There is **no AST and no dataflow model.** The module's own docstring says so:
> *"Not a full PowerShell parser — a pattern-based mini-AST"*
> — `powershell_ast.py:3`

What exists is 7 independent regex rewrites applied in a fixed order, up to
`max_passes = 3`, over the **whole text as one flat string**
(`deobfuscate_ps:292-320`). There is no statement list, no expression tree, no
variable dependency graph, no scope, no evaluation order and no notion of an
unresolved node.

Two structural consequences:
1. **Binding is impossible for the common malware shape.** `_VAR_ASSIGN_RE`
   (`:201`) demands the right-hand side be a *single* `_STR_LIT` terminated by
   `$`/`;`/newline/`}`. `$BnWKB = 'a' + 9 + 'b'` matches nothing, so
   `bindings` is **empty** and `$EbaYA` / `$BnWKB` are never substituted.
   Reproduced: `bindings : []`.
2. **Ordering is not modelled.** `_substitute_variables` uses
   `bindings.setdefault` — *"First assignment wins"* (`:221-224`). For the
   owner's sample, where `$EbaYA` is **referenced before it is assigned**, the
   engine has no way to express the difference between what PowerShell would
   evaluate at that point and what static analysis can recover from a later
   assignment. The directive's D-3 `runtime_value` vs
   `statically_recovered_value` distinction has no representation today.

---

## 4 · Reproduced findings

Run: `cd /app/backend && python3 /app/scripts/ci_decoder_rca_repro.py`

| id | finding | status |
|---|---|---|
| **F1** | POSIX `shlex` deletes Windows path separators | **REPRODUCED** — `executable` = `C:WindowsSystem32WindowsPowerShellv1.0powershell.exe` |
| **F2** | Non-string operand breaks folding and is emitted verbatim | **REPRODUCED** — `+ 9 +` survives |
| **F3** | Payload variable is never bound | **REPRODUCED** — `bindings: []` |
| **F4** | `ast_deobfuscation.applied = true` with **zero** recovery | **REPRODUCED** — inner script absent from `ast_deobfuscation.final` |
| **F5** | Fragments promoted to `role: "standalone base64"` | **not reproduced by this fixture** — mine is wrapped in one `-c "…"` argument, so a single `powershell-c` span claims the range. The owner's sample evidently exposes the expression outside a claimed span, where `_BASE64_INLINE_RE` (`command_analyzer.py:267`, `\b[A-Za-z0-9+/]{40,}={0,2}\b`) fires per fragment at `confidence 0.72` with `role="standalone base64"` (`:359-364`). **Code path confirmed by inspection; needs the exact sample to reproduce.** |
| **F6** | `final_decoded_inline` is the wrapper, not the canonical artifact | **REPRODUCED** — `final == original: True` |
| **F7** | `mitre: []` / `execution_flow: []` / `behavior_summary: "Runs under powershell."` | **partially** — my fixture still yielded `T1027` and one `Invoke-Command` exec-flow node because those markers sit in the *wrapper*. The owner's emptiness is the same root cause seen from the other side: **nothing from the recovered payload reaches the consumers**, because there is no recovered payload. `behavior_summary` reproduced as wrapper-only. |
| **F8** | `token_count: 5` | **REPRODUCED** — it is `len(tokenize(cmd))` (`:920`), i.e. **shell** tokens of the outer command line. It is not, and was never, a measure of PowerShell program complexity. Presenting it as `parsed_structure.token_count` is misleading rather than wrong. |

Two additional findings not in the owner's list:

- **F9 · the `-c` argument is decoded as one opaque span.** Because
  `powershell-c` claims the whole quoted argument, the interior PowerShell
  program is never parsed as a program. Any fix at the folding layer alone will
  still be applied to a flat string.
- **F10 · `applied` is also `true` for cosmetic-only passes.**
  `_normalize_case` (`:270`) appends a `Transformation` whenever a keyword's
  casing is canonicalised. A sample where *only* case changed still reports
  `ast_deobfuscation.applied = true`. Case normalisation is not deobfuscation.

---

## 5 · Expected reconstruction chain (D-5) for this sample

```
L0  observed command line                         [evidence, immutable]
      ↓ shell-argument split (Windows semantics, backslashes preserved)
L1  powershell.exe · -ExecutionPolicy bypass · -c <program>
      ↓ PowerShell lexing + statement/expression parse
L2  statement list:
      ref  $EbaYA
      ref  $BnWKB
      asn  $BnWKB = <concat expr>
      asn  $EbaYA = UTF8.GetString(FromBase64String($BnWKB))
      call Invoke-Command -ScriptBlock (ScriptBlock::Create($EbaYA))
      ↓ safe constant evaluation over the concat expr
        (String + Int32 → String; String + String → String)
L3  $BnWKB = "DQp0cnl7DQo7JE9jckptTC…"       [CONSTRUCTED_VALUE]
      ↓ dataflow: $EbaYA depends on $BnWKB (statically recovered, NOT runtime)
L4  Base64 validate + decode                  [ENCODED_ARTIFACT → bytes]
L5  UTF-8 decode                              [DECODED_ARTIFACT]
L6  reparse recovered PowerShell              [EXECUTABLE_ARTIFACT]
      → ipconfig /release · ipconfig /renew · netsh winsock reset
      → netsh int ip reset · Start-Sleep -Seconds 5
      → ServicePointManager::SecurityProtocol  (TLS modification)
      → nested FromBase64String  → recurse to L4'
      → C:\Users\Public\…                      [file artifact]
      ↓ fixed point / limit
CANONICAL_DECODED_ARTIFACT = L6 (+ L6' if the nested layer resolves)
      ↓
Summary · IOC · MITRE · Execution Flow · Auto Investigation · Reports
```
Decode status for this sample under D-7 would be **`PARTIALLY_RECOVERED`** if
the nested layer stops, **`RECOVERED`** at a true fixed point — and **never**
`RECOVERED` while any `unresolved_expressions[]` entry remains.

---

## 6 · Files / modules involved

| file | lines | role |
|---|---|---|
| `backend/powershell_ast.py` | 321 | the 7 regex rewrites; **owns F2, F3, F10** |
| `backend/command_analyzer.py` | 1,121 | pipeline; **owns F1 (`:255`), F4 (`:1009`), F5 (`:267`,`:359`), F6 (`:1090`), F8 (`:920`), F9** |
| `backend/routers/ops.py` | `:575` | `POST /api/analyze/command` |
| `backend/schemas.py` | `:75` | `force_decode_span` / `needs_choice` contract |
| `apps/nivxray-xdr/src/xdr/pages/XdrCommandIntelPage.jsx` | — | **owns D-10**: renders the service JSON as the primary analyst view |
| `backend/tests/test_ps_ast_and_amsi.py` | — | existing AST expectations — **must not be weakened** |
| `backend/tests/test_regression_150plus.py` | — | existing corpus gate — **must not be weakened** |
| `backend/decoded_artifacts.py`, `routers/decoded_artifacts.py` | — | candidate home for the artifact-class model (D-4) |

---

## 7 · Proposed minimal repair (for owner approval — NOT implemented)

Deliberately ordered so each step is independently testable and the honest
states land **before** any new reconstruction capability.

| step | change | why first |
|---|---|---|
| **R-1** | Evidence preservation: split the tokenizer into `tokenize_posix` and a Windows-aware split; `parsed_structure.executable` must equal the observed substring byte-for-byte. Rename/retire `token_count` as `shell_token_count`. | pure repair, no semantics, closes F1 + F8 |
| **R-2** | Honest status: replace the boolean with `decode_status ∈ {NOT_REQUIRED, DETECTED, PARTIALLY_RECOVERED, RECOVERED, AMBIGUOUS, UNSUPPORTED, LIMIT_REACHED, FAILED}`; keep `applied` as a deprecated mirror. Exclude `case-normalization` from counting as recovery. Emit `unresolved_expressions[]`. | closes F4 + F10 **without** needing a better decoder — the product stops over-claiming immediately |
| **R-3** | Artifact classes `FRAGMENT / CONSTRUCTED_VALUE / ENCODED_ARTIFACT / DECODED_ARTIFACT / EXECUTABLE_ARTIFACT`; a span that participates in a larger expression is `FRAGMENT` and is **not** independently decoded. | closes F5, and stops 12 misleading payloads |
| **R-4** | Real expression evaluation: a small PowerShell expression parser (literal, number, `[char]`, cast, parens, `+`, `-f`, `-join`, `.Replace`, `.Substring`) with .NET `+` coercion semantics. Replaces `_CONCAT_RE` **inside the new evaluator only**; the old regexes stay as a fallback until the evaluator proves equal-or-better on the existing corpus. | closes F2 |
| **R-5** | Statement + dataflow model: statement list, variable dependency graph, `runtime_value` vs `statically_recovered_value` vs `unresolved`. | closes F3 and D-3 |
| **R-6** | Recursive fixed-point loop with **explicit** stop reasons; every artifact carries `provenance[]` (source artifact, transformation, input span, output, confidence, deterministic/heuristic, unresolved deps). | D-5, D-8 |
| **R-7** | Canonical-payload propagation: a single `canonical_decoded_artifact` that Summary / IOC / MITRE / Execution Flow / Auto Investigation / Runtime Simulation / Reports consume, with the wrapper retained only as labelled context. | closes F6, D-6, D-9 |
| **R-8** | Command Intelligence UI: `Assessment · Decode Status · Execution Chain · Recovered Behavior · Decoded Payload · Indicators · MITRE · Decoder Chain`, with raw JSON demoted to **Technical Details**, and visible Original / Reconstructed / Decoded / Inferred / Unresolved provenance badges. | D-10 |

**Non-goals, explicitly:** no arbitrary PowerShell execution; no additional
Base64 regexes; no invented ATT&CK mappings; no weakening of
`test_ps_ast_and_amsi.py` or `test_regression_150plus.py`.

---

## 8 · Regression tests required (D-11)

Pin the **exact** owner sample, then assert:
original evidence unchanged · `C:\Windows\…` backslashes preserved ·
fragments not promoted to standalone payloads · deterministic concatenation
across non-string operands (`'JE' + 9 + 'jck'` → `JE9jck`) · variable
dependency reconstruction · recursive decoding to the inner script ·
provenance chain complete · `decode_status` honest (never `RECOVERED` with a
non-empty `unresolved_expressions[]`) · canonical payload propagation ·
IOC / behaviour / execution-flow extracted **from the recovered artifact** ·
no fabricated ATT&CK · no PowerShell execution.
Plus benign adversarial cases (`'a' + 1 + 'b'` in an innocuous script, a long
legitimate Base64 certificate blob, a build script with heavy concatenation) so
that stronger reconstruction does not raise benign false positives.

---

## 9 · Scope held (D-12)
W1 not reopened · W2-1 untouched · RBAC not mixed in · no unrelated XDR page
redesigned · no corpus gate weakened · **no production code changed by this
report**.

## 10 · STOP
Root cause identified and the acceptance question answered.
**Awaiting owner approval, plus the exact original sample, before R-1.**

Owner decisions required:
- **C-1** supply the exact PowerShell sample (file/paste) to pin as the D-11
  fixture and to reproduce F5/F7 exactly.
- **C-2** approve the R-1…R-8 order, or pull R-2 (honest status) forward as a
  standalone hotfix so the product stops over-claiming while R-4/R-5 are built.
- **C-3** confirm `applied` may be retained as a deprecated mirror of
  `decode_status`, or must be removed outright (breaking any consumer).
