# LANE B · COMMAND INTELLIGENCE P0 — R-1 / R-2 / R-3 ACCEPTANCE PACKAGE

Scope implemented: **R-1, R-2, R-3 only.** R-4 (semantic expression evaluator)
and R-5 (statement + dataflow reconstruction) are **NOT** implemented and are
NOT self-authorized. This package is the foundation, not the closure of the
Command Intelligence P0.

Owner instruction honoured: *"These changes are a foundation, not closure…
return regression evidence before proceeding to R-4/R-5."*

---

## 1 · Files changed

| file | change |
|---|---|
| `backend/command_analyzer.py` | R-1 `tokenize_windows` / `tokenize_with_mode` / `first_token_span`; `parsed_structure` evidence contract; R-3 artifact classes + fragment ranges; R-2 `decode_status`, `unresolved_expressions[]`, `canonical_decoded_artifact` |
| `backend/powershell_ast.py` | `Transformation.complete`; `COSMETIC_KINDS`; partial-fold honesty on `string-concat`; `find_unresolved()`; `deobfuscate_ps()` now returns `unresolved`, `semantic_transformations`, `incomplete_transformations` |
| `backend/tests/test_ci_r1_r3_decoder_honesty.py` | **new** · 22 acceptance tests |

Not touched: W1, W2-1, RBAC, any SPA page, `test_ps_ast_and_amsi.py`,
`test_regression_150plus.py`, any corpus gate, `routers/ops.py`,
`schemas.py`. No test was weakened. No new Base64 regex was added. No
PowerShell is executed.

---

## 2 · Before / after evidence

Fixture: the **non-authoritative** reconstruction from `CI_DECODER_P0_RCA.md`
(labelled as such in the test file). The owner's exact sample replaces it as
the authoritative D-11 specimen when supplied.

### 2.1 F1 · evidence preservation (R-1)
```
BEFORE  parsed_structure.executable = C:WindowsSystem32WindowsPowerShellv1.0powershell.exe
AFTER   parsed_structure.executable = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
        parsed_structure.executable_span = {text: "<byte-for-byte slice>", start, end}
        parsed_structure.evidence_preserved = true
        parsed_structure.tokenizer = "windows-argv"
```
POSIX command lines are unchanged: `tokenize("bash -c 'echo hi'")` still
returns `["bash","-c","echo hi"]` (`posix-shlex`). The Windows grammar is
selected only on Windows-proving shapes (`C:\`, `\\host\share`, `%VAR%`,
`$env:`, or a Windows executable extension).

### 2.2 F8 · `token_count` named honestly (R-1)
```
BEFORE  parsed_structure.token_count = 5          (presented as program complexity)
AFTER   parsed_structure.shell_token_count = 5    (what it always was)
        parsed_structure.token_count = 5          (deprecated mirror, retained)
```

### 2.3 F2 + F4 · the over-claim is gone (R-2)
```
BEFORE  ast_deobfuscation.applied = true
        no decode_status field at all
        `+ 9 +` present in the rendered artifact with no explanation

AFTER   decode_status = "PARTIALLY_RECOVERED"
        decode_status_reason = "1 layer(s) recovered, but 9 construct(s) were not evaluated."
        ast_deobfuscation.applied = false        ← no SEMANTIC transformation occurred
        ast_deobfuscation.semantic_transformations = 0
        ast_deobfuscation.incomplete_transformations = 0
        unresolved_expressions = [
          {kind: "unbound-variable",            expression: "$EbaYA"},
          {kind: "non-string-concat-operand",   expression: "'ZWxlYXN' + 9"},
          {kind: "non-string-concat-operand",   expression: "'lDQppcGNvbmZpZyAvcmVuZ' + 9"},
          {kind: "non-string-concat-operand",   expression: "'XcNCm5ldHNoIHdpbnNvY2s' + 9"},
          {kind: "dynamic-encoding-getstring",  …},
          {kind: "dynamic-base64",              …},
          {kind: "unbound-variable",            expression: "$BnWKB"},
          {kind: "dynamic-invoke",              …},
          {kind: "dynamic-scriptblock",         …}
        ]
```
Each entry carries `kind`, `expression`, `offset`, `reason`, `found_in`.

**Invariant enforced in code:** `decode_status` can never be `RECOVERED`
while `unresolved_expressions[]` is non-empty. If the status calculation ever
produced that combination it is downgraded to `PARTIALLY_RECOVERED` with an
explicit reason, rather than trusted.

### 2.4 F10 · cosmetic passes no longer count as recovery (R-2)
```
input   InVOkE-eXpReSsION (Get-Content C:\x.txt)
BEFORE  ast_deobfuscation.applied = true          (only keyword casing changed)
AFTER   ast_deobfuscation.applied = false
        semantic_transformations = 0
        decode_status = "NOT_REQUIRED"
```
A `case-normalization` transformation also no longer manufactures a synthetic
`ps-ast` decode chain into IOC / MITRE / behaviour aggregation.

### 2.5 partial folds are labelled at the step level (R-2)
```
deobfuscate_ps("$x = 'AB' + 9 + 'CD' + 'EF'")
  → transformation {kind: "string-concat", complete: false,
       detail: "Collapsed adjacent string-literal concatenations — PARTIAL:
                1 concatenation(s) still have a non-string operand and were
                NOT evaluated"}

deobfuscate_ps("$x = 'AB' + 'CD' + 'EF'")
  → transformation {kind: "string-concat", complete: true}
```

### 2.6 F5 · fragments are no longer promoted to payloads (R-3)
```
input   powershell.exe -enc 'aQBwAGMAbwBuAGYAaQBnACAALwBhAGwAbAAAAAAAAAAA' + 'BBBBBBBBBBBBBBBB'

BEFORE  payload  conf 0.98  auto_decoded=True   (no class)   → 2 decode chains
AFTER   payload  conf 0.98  auto_decoded=False  class=FRAGMENT → 1 decode chain
        fragment_of = "'aQBw…AAAA' + 'BBBBBBBBBBBBBBBB'"
```
Artifact classes now present on every candidate and every decode layer:
`FRAGMENT · CONSTRUCTED_VALUE · ENCODED_ARTIFACT · DECODED_ARTIFACT ·
EXECUTABLE_ARTIFACT · SHELLCODE_ARTIFACT`. Fragments are excluded from the
confidence gate **and** from the recursive nested-decode frontier, so the
exclusion no longer depends on an incidental 0.72 threshold.

### 2.7 F6 · nothing partial is promoted as canonical (R-3)
```
obfuscated fixture → canonical_decoded_artifact = {
  promoted: false, text: null, artifact_class: "DECODED_ARTIFACT",
  candidate_text: "<partial>", depth: 0, source_role: "powershell-c",
  reason: "Not promoted — decode status is PARTIALLY_RECOVERED. A partial or
           ambiguous reconstruction is never presented as the canonical
           decoded artifact." }

clean single layer  → canonical_decoded_artifact = {
  promoted: true, text: "ipconfig /all", artifact_class: "EXECUTABLE_ARTIFACT" }
```
`LIMIT_REACHED` is now emitted when the recursive frontier still had work at
the 3-layer budget, instead of silently truncating.

---

## 3 · Regression evidence

```
tests/test_ci_r1_r3_decoder_honesty.py   22 passed   (new acceptance suite)
tests/test_ps_ast_and_amsi.py            ─┐
tests/test_regression_150plus.py          │  277 passed, 0 failed, 0 skipped
tests/test_command_analyzer.py            │  (run together, serial, no xdist)
tests/test_die_powershell.py              │
tests/test_meterpreter_gzip_xor_stager.py ─┘
```
End-to-end through the API (preview, authenticated):
```
POST /api/analyze/command {"input":"powershell.exe -enc aQBwAGMAbwBuAGYAaQBnACAALwBhAGwAbAA="}
→ decode_status = RECOVERED
→ canonical_decoded_artifact.promoted = true, text = "ipconfig /all"
→ parsed_structure.tokenizer = windows-argv, shell_token_count = 3,
  evidence_preserved = true
→ unresolved_expressions = [], fragment_count = 0
```
The only consumers of `ast_deobfuscation.applied` anywhere in the repo are the
two pre-existing test files above; both still pass, so the deprecated mirror
did not break a consumer.

---

## 4 · What is still broken — R-4 / R-5 gaps

These are stated explicitly so the honest status is not mistaken for a fix.

| gap | consequence today | closed by |
|---|---|---|
| No expression evaluator with .NET `+` coercion | `'JE' + 9 + 'jck'` is still not folded to `JE9jck`; it is reported unresolved instead of silently corrupted | **R-4** |
| No statement list / variable dependency graph | `$BnWKB` and `$EbaYA` are still never bound; `runtime_value` vs `statically_recovered_value` has no representation | **R-5** |
| `-c "<program>"` is still decoded as one opaque span (F9) | the interior PowerShell program is never parsed *as a program* | **R-4/R-5** |
| No recursion to a true fixed point with per-artifact `provenance[]` | depth is tracked, full provenance chains are not | **R-6** |
| Canonical artifact is reported but not yet propagated to IOC / MITRE / behaviour / exec-flow consumers | those consumers still read `combined_text` including the wrapper | **R-7** |
| Command Intelligence production page still renders raw JSON | the new composition exists only in the UX0 prototype | **R-8 / Lane A approval** |
| No LOLBAS / GTFOBins offline matching, no OSINT enrichment | out of R-1…R-3 scope entirely | later waves |

Target architecture unchanged and unreduced:
`Parse → AST → statement/dataflow reconstruction → constant folding →
constructed artifact recovery → recursive decode/decompress/deobfuscate →
reparse → fixed point → canonical artifact → explain → impact → IOC/OSINT →
LOLBAS/GTFOBins → ATT&CK → Workspace investigation services.`

---

## 5 · D-11 fixture status

**NOT SATISFIED.** The exact owner sample has not been supplied. The fixture
in `test_ci_r1_r3_decoder_honesty.py` is the RCA reconstruction and is
labelled `NON-AUTHORITATIVE` in the file docstring. On receipt of the exact
byte-for-byte input it is pinned unchanged as the authoritative regression
specimen and F5/F7 are reproduced against it directly.

## 6 · STOP
R-1/R-2/R-3 complete and evidenced. **Awaiting owner review before R-4/R-5.**
