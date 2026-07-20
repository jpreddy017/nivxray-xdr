# NivXRay — Deterministic-First Malware Command Intelligence Platform (MCIP)

## Original Problem Statement
Build a deterministic-first analyst workspace that decodes / reconstructs
obfuscated malware command lines with zero AI hallucinations, honest
"partial reconstruction" verdicts, and full analyst trace.

## Current Release: RC4.4 (Feb 2026)

### RC4.4 · CMD Environment-Variable Runtime Reconstruction Engine
**Ships:**
- `/app/backend/decoders/cmd_runtime_reconstruct.py` — new module
- `@op("cmd-runtime-reconstruct", …)` — analyst-facing op with the
  windows profile arg (windows-10-x64 default; +11/x64, srv2019, srv2022,
  x86, de-DE localized, analyst-custom).
- `CmdRuntimeReconstructDecoder(BaseDecoder)` registered with the RC2.2
  Orchestrator. Confidence 0.99 on substring-slice patterns.
- Deterministic engine covers:
  * `%VAR%`, `%VAR:~n%`, `%VAR:~n,l%` (positive + negative n & l)
  * `%VAR:from=to%` substitution
  * `!VAR!` delayed expansion (all three variants)
  * `%%` literal-percent escaping
  * Caret escapes `c^m^d` → `cmd`
  * Quote fragmentation `"c""m""d"` → `"cmd"`
  * Adjacent variables `%A%%B%`
  * Nested expansion via multi-pass with fixed-point termination
  * Runtime-time RHS resolution of inline `set` statements
- Character-extraction table + reconstruction trace + confidence
  breakdown (parser / environment / runtime / behavioural / overall).
- Verdict engine differentiates: benign, benign-demonstration,
  suspicious, malicious (LOLBIN execution), partial-reconstruction
  (unresolved vars / residuals).
- ATT&CK mapping: T1027 + T1140 + T1059.003 + T1218 (only when evidence).
- 23 regression tests in `/app/backend/tests/test_cmd_runtime_reconstruct.py`.
- Wired into `/api/decode/smart` — attaches banner to `output_raw`,
  fills `cmd_runtime_reconstruct` structured field, adds
  `cmd-runtime-reconstruct` to recipe, appends per-character extraction
  rows to `transformation_trace`.

### Prior releases still in effect
- RC4.3 · PowerShell normalizer + runtime simulator (safe built-ins).
- RC4.2 · PS semantic mini (`-replace`/`ForEach reverse`).
- RC4.1 · Crypto-aware honest-verdict engine (RC4/AES/DPAPI/OpenSSL/GPG).
- RC4.0 · 6-pattern advanced decoder roadmap (hex-CSV inline,
  byte[]-XOR, reverse-slice, regex-swap, batch envvar-substitute,
  cmd-envvar-substring-picker).

## Completed (Feb 2026)
- ✅ RC4.4 CMD Runtime Reconstruction (this session)
- ✅ RC4.3 PowerShell normalizer + runtime simulator
- ✅ RC4.2 PS semantic mini + honesty linter
- ✅ RC4.1 Crypto Honest-Verdict Engine deployed to production
- ✅ 6-Pattern decoder roadmap
- ✅ 575-case regression corpus (97.6% pass)

## Backlog / Roadmap
### P0
- Full CMD Semantic Engine — `CALL` second-pass, %NUMBER for-loop args
- Full PowerShell AST Evaluator (`-split`, `-f`, `Substring`, `[char]`,
  `[Convert]`)
- Constant propagation across `$a = $b + "..."` chains
- Sleeper Hunter & Fuzzer scripts (`rc45_sleeper_hunter.py`,
  `rc45_fuzzer.py`)

### P1
- Backtick / line-continuation normalizer (`po``we``rshell` → `powershell`)
- Cmdlet-alias normalizer (`iex` → `Invoke-Expression`, `gci` → `Get-ChildItem`)
- Fix GitHub Actions CI (`.github/workflows/rc23_quality_gate.yml` → RC4.x)
- AST view in UI
- Decoder coverage dashboard
- UI panel for CMD profile selection + custom env override

### P2
- 4 remaining `xfail` crypto fixtures
- Corpus expansion 575 → 2000-5000 cases
- LiteLLM cold-start pre-warming (15 s p95 latency)
- `magic_decoder.py`/`operations.py` refactor: auto-register plugins

## Key API endpoints
- `POST /api/decode/smart` — returns `cmd_runtime_reconstruct` structured
  field + rendered banner in `output_raw` for any input containing
  `%VAR:~a,b%` / adjacent / delayed / caret patterns.
- `POST /api/documents/batch-decode`
- `POST /api/recipe/run` — accepts `op: "cmd-runtime-reconstruct"` with
  optional `args.profile` and `args.env`.

## Test Credentials
See `/app/memory/test_credentials.md` (unchanged this session).
