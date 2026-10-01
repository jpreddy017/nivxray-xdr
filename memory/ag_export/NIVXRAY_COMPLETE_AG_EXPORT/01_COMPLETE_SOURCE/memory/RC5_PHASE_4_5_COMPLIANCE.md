# RC5 · Phase 4.5 · Recommendation Compliance Report

**Phase:** 4.5 — `/api/rc5/parse` diagnostic endpoint
**Date:** Feb 24, 2026
**Preview URL:** https://greeting-app-5782.preview.emergentagent.com/api/rc5/parse
**Prod URL:** https://nivxray.nivxforge.com/api/rc5/parse — reachable only if `RC5_DIAG_ENABLED=true` set on Prod (currently OFF by design).

## 1 · Previously approved recommendations — status this phase

| # | Recommendation                                              | Status |
|---|-------------------------------------------------------------|--------|
| 1-14 | All spec § 0 / § 6 / § 12 invariants                     | **Preserved** — endpoint is read-only, immutable, evidence-first, deterministic |
| 15 | Feature flag safety                                       | **Extended** — new `RC5_DIAG_ENABLED` env flag; defaults false; also enabled by `SEMANTIC_ENGINE_V2=true` |
| 16 | AI persona advisor-only                                   | **Enforced** — endpoint imports NEITHER `emergentintegrations` NOR `litellm` (static test locks this) |
| 17 | Regression tests                                          | **Implemented** — **57 API tests** covering auth, gating, response shape, language detection, CMD/PS parses, confidence summary, determinism, OpenAPI docs, evidence integrity |
| 21 | Frozen plugin API — extend not modify                     | **Preserved** — endpoint consumes existing `get_parser` / `get_interpreter` / `extract_behaviors`; zero core edits |

## 2 · User directives — Phase-4.5 approval

| Requested field                | Status |
|--------------------------------|--------|
| `semantic_ir`                  | ✅ Full SIRTree JSON |
| `exec_graph`                   | ✅ Full ExecGraph JSON |
| `behaviors`                    | ✅ Full Behavior[] JSON |
| `evidence_refs`                | ✅ `{behavior_id: [node_ids]}` map |
| `confidence_summary`           | ✅ `{min, median, max, unresolved_count, total}` |
| `reconstructed_commands`       | ✅ Non-empty + non-unresolved reconstructed strings |
| `plugin_versions`              | ✅ Per-plugin schema_version dict |
| `semantic_engine_version`      | ✅ Integer, currently `1` |
| `processing_time_ms`           | ✅ Rounded to 3 decimal places |
| `decode_chain`                 | ✅ Named pipeline steps |
| `warnings` / `unresolved_nodes`| ✅ Both present; unresolved carries `{id, reason}` |
| `api_version`                  | ✅ String `"1"` |

| Additional requirement          | Status |
|--------------------------------|--------|
| Read-only diagnostic            | ✅ No writes to DB/state |
| Disabled in Prod unless Admin+Debug | ✅ `require_admin` dep + `RC5_DIAG_ENABLED` (or `SEMANTIC_ENGINE_V2`) env |
| No AI involvement (`--no-ai` compatible) | ✅ Static import test locks this |
| Deterministic JSON output       | ✅ Structural determinism test locks kinds/reconstructions/behaviors |
| 50+ API regression tests        | ✅ **57 tests, all green** |
| OpenAPI/Swagger documentation   | ✅ Verified via `/openapi.json` — `ParseRequest` / `ParseResponse` schemas + summary + description exposed |

## 3 · Live verification

```
$ curl -X POST $URL/api/rc5/parse -H "Authorization: Bearer …" \
       -d '{"input":"Start-Process notepad.exe"}'
{
  "api_version": "1", "semantic_engine_version": 1,
  "language": "powershell",
  "exec_graph": { "nodes": [ 1 ProcessNode ], "schema_version": 1 },
  "behaviors": [ {"tactic":"execution","sub_kind":"process_spawn",...} ],
  "confidence_summary": {"min":100,"median":100,"max":100,"unresolved_count":0,"total":1},
  "processing_time_ms": 0.266,
  …
}
```

## 4 · Test coverage matrix

| Category                       | Tests |
|--------------------------------|------:|
| Auth & gating                  |     8 |
| Response shape                 |    12 |
| Language auto-detection        |     6 |
| CMD parse paths                |     5 |
| PowerShell parse paths         |     7 |
| Confidence summary             |     5 |
| Determinism + AI absence       |     5 |
| OpenAPI documentation          |     4 |
| Download URL hint              |     2 |
| Evidence-refs integrity        |     3 |
| **Total**                      |  **57** |

## 5 · Grand total RC5 tests: **337 passing**

97 Phase-1 + 37 Phase-2 CMD + 111 Phase-3 PS + 35 Phase-4 Behavior + 57 Phase-4.5 API = **337**.

## 6 · Env-var contract additions

- `RC5_DIAG_ENABLED` — new env flag (`true` on Preview, unset/false on Prod).
- No other env changes.

**No architectural invariant weakened.** Phase 4.5 complete. Ready for Phase 5.
