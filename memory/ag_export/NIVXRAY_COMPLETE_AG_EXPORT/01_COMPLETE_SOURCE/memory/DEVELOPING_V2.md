# NivXRay v2 · Contributor Onboarding

> **Read this before touching any file under `/app/backend/v2/` or `/app/frontend/src/v2/`.**
> The rules below are enforced by CI (`tests/test_regression_gate.py`, `tests/test_v2_framework.py`, `tests/test_v2_phase2.py`).

---

## 1. The single most important rule

**RC5 is FROZEN.** Every file under:

- `/app/backend/engine/`
- `/app/backend/routers/rc5_*.py`
- every collection listed in `GOVERNANCE.md §2`
- every UI page currently under `/app/frontend/src/pages/`

is immutable. You do **not** modify these to enable v2 features. If your work needs an RC5 change, **STOP** and raise it via `ask_human` before writing any code.

---

## 2. Where to put new code

| Kind | Backend | Frontend |
|------|---------|----------|
| Adapter | `v2/adapters/<name>.py` (registered via `@register`) | — |
| Normalizer | `v2/normalization/<name>_normalizer.py` | — |
| Parser | `v2/parser/` | — |
| Storage schema | `v2/case_engine/schema.py` (indexes) + `v2/case_engine/store.py` (bootstrap) | — |
| CEM entity or event kind | `v2/cem/v2/` (never mutate v1) | — |
| Behavior detector | `v2/behavior/detectors/<name>.py` | — |
| Enricher | `v2/enrichment/enrichers/<name>.py` | — |
| Trajectory view | `v2/trajectory/<kind>.py` | — |
| Report exporter | `v2/reports/<name>.py` | — |
| API endpoint | `v2/routers/<name>.py` prefixed `/api/v2/` | — |
| Workspace page | — | `src/v2/pages/<Page>.jsx` |
| Reusable widget | — | `src/v2/components/<Widget>.jsx` |
| API client | — | `src/v2/api/<name>.ts` |

Nothing v2 imports from `engine.*`. This is enforced by `tests/test_v2_framework.py::TestIsolationFromRC5`.

---

## 3. Feature flags (3-state)

Every new capability lives behind a flag declared in `v2/flags.py`. Three states:

| State | Meaning |
|-------|---------|
| `disabled` | Code path is off. Zero cost. Byte-identical RC5 behaviour. **This is the default in CI.** |
| `shadow` | Code runs in parallel to RC5, produces evidence, but MUST NOT influence any RC5 output. |
| `enabled` | Code path is authoritative. Reached only after the shadow phase closes its regression gate. |

Read a flag:

```python
from v2.flags import get
if get("ADAPTERS").observable():
    ...   # active in shadow or enabled
if get("ADAPTERS").enabled():
    ...   # authoritative only
```

Env keys are prefixed `NIVX_FLAG_` (e.g. `NIVX_FLAG_ADAPTERS=shadow`). Values accept `disabled | shadow | enabled` plus aliases (`on/true/1` = enabled, `sidecar/observe` = shadow).

**Contract**: when every flag is `disabled`, the process is byte-identical to the frozen RC5 release. This is enforced by `test_regression_gate.py::test_all_v2_flags_disabled_by_default`.

---

## 4. Shadow-mode discipline

- A shadow module **may** read from RC5 outputs (via already-exported stable interfaces) but **never** write back into RC5 storage or mutate RC5 responses.
- A shadow module runs on a **separate call graph**. Do not add hooks inside RC5 handlers.
- A shadow module emits into its own storage (e.g. `v2_shadow_observations`, `v2_case_events`) — never into `investigation_events` or any RC5 collection.
- Latency: shadow work must not sit on the request thread of any RC5 endpoint.

---

## 5. Versioned CEM

- `v2/cem/v1/` is FROZEN. Never edit these files.
- Need a new field? Ship `v2/cem/v2/` and update `v2/cem/registry.py`.
- Adapters declare `cem_version = "v1"` (or later) so the pipeline can dispatch.

---

## 6. Provenance

Every entity / event / relationship you emit carries a `Provenance` record. Fields to populate at minimum:

- `origin` — `"customer-upload" | "api" | "adapter-stream" | "shadow-adapter"`
- `adapter` — `"<name>@<version>"`
- `normalization` — `"cem@v1"` (or later)
- `confidence` — deterministic, evidence-backed
- Timestamps — `observed_at` / `ingested_at` / `derived_at`
- `engine_versions` — `{ "rc5": "...", "adapter": "..." }`

No conclusion may lose traceability. Ever.

---

## 7. Regression gate (blocks PRs)

`tests/test_regression_gate.py` runs on every PR. It fails if any of the following regress:

1. Golden Corpus pass rate
2. Per-sample verdict / MITRE / weighted-confidence map hash
3. Accuracy dimensions (verdict / MITRE / LOLBIN / behavior)
4. Latency p50 / p95 / p99 (with 10 ms absolute noise budget)
5. Public Interface Contract endpoint list
6. `/api/rc5/parse` response schema
7. Any v2 feature flag leaking into the test environment
8. Deterministic re-run fingerprint
9. **OpenAPI snapshot diff** — additions welcome; removals & breaking changes fail

If you break one, the fix is almost never "update the baseline". Rebasing the baseline requires the tool at `tests/tools/rebaseline.py` **and** a governance-approved ticket in `NIVX_REBASELINE_TICKET`.

---

## 8. Adding a new v2 API endpoint

- Prefix path with `/api/v2/`.
- Router file goes under `v2/routers/`.
- Register in `server.py` behind the appropriate flag guard so a `disabled` flag makes the endpoint invisible to clients.
- Never modify an existing frozen endpoint (see `baselines/public_interface_contract.json`).

Additive-only: new endpoints do not require a governance amendment.

---

## 9. Testing

- Unit tests: alongside your module, e.g. `tests/test_v2_<feature>.py`.
- Integration: use `httpx.AsyncClient(app=server.app)` — never call real prod URLs from tests.
- Determinism test: call your public entry point twice with identical inputs and hash the outputs; they must match.
- Isolation test: if your module could leak into RC5, add a test that reads RC5 source for offending imports (see `TestIsolationFromRC5` for the pattern).

---

## 10. When you get stuck

- **Uncertain if a change is additive?** Assume it isn't. Ask.
- **Uncertain about determinism?** Add a fingerprint test.
- **Uncertain about the flag state?** Default to `disabled`.
- **RC5 seems to have a bug?** Do not fix it in v2. Escalate.

---

## 11. Governance links

- `/app/memory/GOVERNANCE.md` — the directive. Highest precedence.
- `/app/memory/ARCHITECTURE_v2.md` — architectural artefacts 1–8.
- `/app/memory/ENGINES_UI_PERF.md` — artefacts 9–15.
- `/app/backend/baselines/rc5_baseline.json` — frozen metrics.
- `/app/backend/baselines/public_interface_contract.json` — frozen endpoints.
- `/app/backend/baselines/openapi_snapshot.json` — OpenAPI diff baseline.

Read them before writing code you're not sure about.
