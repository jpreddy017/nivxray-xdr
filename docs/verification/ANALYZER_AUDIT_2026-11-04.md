# Command analyzer audit and prioritized implementation register

Scope: inspected XDR main baseline 752a00ff plus draft PR61, independent EDR draft PR1 and local Forensics UI candidate. Source inspection and targeted local tests only. Not a comprehensive production penetration test or proof of every algorithm's correctness. P0 = release blocker, P1 = next functional work, P2 = expansion. FIXED means candidate code with tests, not deployed.

| ID | Priority | Product | Finding / required work | State / acceptance |
|---|---|---|---|---|
| A01 | P0 | Both | Leading whitespace corrupts original evidence/offsets | FIXED; original-string and span slicing tests |
| A02 | P0 | Both | CMD/COMSPEC PowerShell wrapper missed | FIXED for bounded grammar; non-invocations tested |
| A03 | P0 | XDR | POSIX tokenizer removes Windows path backslashes | FIXED for Windows executable selection; quoted/unquoted paths tested |
| A04 | P0 | EDR | Windows-looking argument selected wrong grammar for POSIX executable | FIXED; executable-based selection, POSIX regressions |
| A05 | P0 | EDR | Full submitted evidence not recoverable from legacy truncated display field | FIXED; exact canonical submission retained in report and returned; >2048-character roundtrip |
| A06 | P0 | EDR | Invalid requests reach worker/cache and surface as infrastructure failure | FIXED; common validation before cache/process and in worker/API; no-spawn tests |
| A07 | P0 | EDR | Malformed worker top-level JSON may cause AttributeError | Defensive type check added; hostile protocol tests still required |
| A08 | P0 | EDR | No HTTP-level auth/permission/audit proof | OPEN; API unmounted, FastAPI unavailable locally; test 401/403/422/503 and audit failure before mounting |
| A09 | P0 | EDR | Storage durability/concurrency not verified | OPEN; collection doubles only; isolated real Mongo required, no production DB access |
| A10 | P0 | EDR | Python audit guards are not OS sandbox | OPEN; non-root worker, resource/egress/filesystem limits, pathological corpus and launch/cancel races |
| A11 | P0 | Both | Complete source-to-live-route provenance unverified | OPEN; identify deployed commit/API and smoke test exact runtime before release |
| A12 | P0 | EDR | UI/API contract mismatch | OPEN; local UI expects older envelope/endpoint contract; adapt before preview |
| A13 | P1 | XDR | Command Intelligence route renders reserved page, hardcoded zeros called authoritative | OPEN; remove misleading assertions and wire tenant-authorized operational route; no fake telemetry |
| A14 | P1 | NivXRay analyzer UI | Old response can overwrite edited/cleared input; planner requests lack cancellation | OPEN; request generation + abort + input/tenant invalidation, renderer/browser tests |
| A15 | P1 | Both | Full shell grammar unsupported | OPEN; quoted executable, CMD escapes/delayed expansion, PowerShell scopes/subexpressions, Bash substitutions; document unsupported cases |
| A16 | P1 | EDR | Discovery only selected payload or whole input | OPEN; traverse parser payloads and recovered branches, preserve source spans, enforce global budget |
| A17 | P1 | EDR | Discovery ranking/alternative paths incomplete | OPEN; explicit scoring reasons, binary/Unicode coverage, retain ambiguity; readability never a verdict |
| A18 | P1 | Both | Broader decode accuracy not measured | OPEN; versioned benign/malicious/malformed corpus, exact ground truth, false recovery/FN/timeout metrics; no percentage claimed |
| A19 | P1 | EDR | Original evidence retention and exports policy incomplete | OPEN; encrypted access-controlled persistence, audit export, quotas, version migration; no input in debug logs |
| A20 | P1 | EDR | IOC enrichment absent | OPEN; EDR-owned providers/cache/credentials, source/time/status, unsupported vs unknown vs failed; no automatic public sample upload |
| A21 | P1 | Both | Encryption support limited | OPEN; explicit key/IV/mode/padding validation and known-answer tests for supported ciphers; missing key must be unresolved |
| A22 | P1 | Both | Behavior/ATT&CK/IOC provenance incomplete | OPEN; source layer and byte/text span, hypothesis vs observed behavior, no verdict from encoding alone |
| A23 | P2 | EDR | Recipe management incomplete | OPEN; versioned save/import/export, parameter validation, step inspector; native format not CyberChef compatibility |
| A24 | P2 | Both | Scale and operational monitoring unverified | OPEN; latency/CPU/memory/load budgets, per-tenant quotas, bounded logs and retention |

## Execution order

1. Evidence correctness and input boundaries (A01–A07): this batch.
2. API permission/audit tests and isolated persistence, worker resource controls (A08–A10); repair actual failures before app activation.
3. Runtime provenance, complete UI/API route, stale-request fixes and misleading states (A11–A14).
4. Parser/discovery integration, candidate explanations and corpus metrics (A15–A18, A22).
5. Evidence export, independently owned intelligence, explicit-key encryption and recipes (A19–A21, A23).
6. Load tests, visual/end-to-end verification, G0–G6 release/rollback, then disposable preview cleanup (A24).

## Current validation

EDR: 31 local unittest methods pass including worker subprocesses, recipes/discovery and simulated storage. XDR: five targeted methods pass including twelve wrapper/whitespace subcases. API modules compile; HTTP tests NOT RUN. No real database or production test is claimed. No full shell grammar, arbitrary decryption or commercial maturity claim.

## Independence / preservation

Separate repository code changes only; no EDR runtime call to XDR/Workspace. Existing source preserved through Git ancestry. XDR backend source is shared with NivXRay in its current repository, so downstream Workspace behavior needs regression checks before merging PR61. Neither PR is deployed. Cleanup follows verified deployment and must retain evidence, audit records and required rollback assets.
