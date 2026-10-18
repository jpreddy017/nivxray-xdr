# N-3 · Unauthenticated HTTP 500 — root-cause investigation (READ-ONLY)

**Branch** `engineering/n3-http500-investigation` · **baseline** `1158afcc266b08b2b3ae6485bd5cdb40cbb28f74`
(tree `d7ce3457066822b65e89212e98a6362fd8305dbc`, from `engineering/n5-ci-gate`).
**No application code changed.** Worktree `/app/rocket-p0/n3` is clean at the
baseline tree. Evidence: `/app/rocket-evidence/n3/`.

**RELEASE STATUS: NO-GO** (unchanged — nothing here lifts an existing HOLD).

---

## 1 · The three endpoints

From the F1 acceptance package §5, "three unauthenticated 500s (identical on A3)":

| # | Endpoint | Handler that actually serves it | Collection read |
|---|---|---|---|
| 1 | `GET /api/telemetry/frontend/recent` | `routers/telemetry.py::recent_frontend_telemetry` (L95) | `frontend_telemetry` |
| 2 | `GET /api/xdr/vendor/cortex/actions` | `routers/xdr_cortex_actions.py::list_cortex_actions` (L208) | `xdr_response_actions` |
| 3 | `GET /api/xdr/vendor/cortex/connections` | **`routers/xdr_vendor_wizard.py::vendor_list` (L175)** — *not* `xdr_cortex_wizard.cortex_list` | `xdr_integrations` |

Endpoint 3 is worth stating precisely: two routers claim this path.
`xdr_vendor_wizard` is mounted first (`server.py` L561) with the parameterised
`/{vendor_key}/connections`, `xdr_cortex_wizard` later (L616) with the literal
`/cortex/connections`. Starlette matches in registration order, so the
parameterised route wins and the literal one is dead for `cortex`. Confirmed
by route introspection and by the 500 being logged against
`route=/api/xdr/vendor/{vendor_key}/connections`. Any fix applied only to
`cortex_list` would therefore change nothing.

All three take **no authentication dependency at all** — no `Depends`, no
`get_current_user*`. An anonymous caller reaches the handler, the query and
the exception. (That open-surface fact is N-2; its consequence here is that
the fault is anonymously reachable.)

---

## 2 · Reproduction

Methodology mirrors the F1 probe: the candidate backend is started from this
worktree on a free port against a **disposable** mongod (the security-harness
preconditions: per-run generated secrets, `NIVXRAY_REPO_ROOT` pinned to the
candidate). Every parameterless GET from the candidate's own OpenAPI is probed
with no credential. Nothing writes to any pre-existing database.

### 2.1 Surface sweep — the 500s do **not** reproduce on current data

| run | DB state | probed | 200 | 403 | 401 | 404 | **500** |
|---|---|---|---|---|---|---|---|
| `empty-sweep.json` | empty | 354 | 75 | 271 | 3 | 5 | **0** |
| `seeded-sweep.json` | the preview rows for all three collections, restored into the disposable DB | 354 | 75 | 271 | 3 | 5 | **0** |

The five 404s are the known un-shipped artefacts (4 audit PDFs + the fixed
deck). The live preview also answers 200 on all three paths today.

**So the F1-era 500 bodies are not reproducible from the data that exists
now**, and I will not pretend otherwise. The three router files are
byte-identical between `/app/backend` and this candidate, so the code has not
moved since A3 — which leaves the stored documents as the only variable.
`xdr_response_actions` is empty today (0 documents) and a scan of all rows in
the three collections finds **zero** non-JSON BSON values, consistent with the
offending rows having been removed between the F1 probe and now.

### 2.2 Defect reproduction — deterministic, on all three paths

`repro_data.py` inserts **one** document at a time into the disposable
database, probes, then deletes it and re-probes. `before` and
`after_removal` are 200 in every case, so each 500 is attributable to exactly
one stored value:

| case | collection | before | with doc | after removal | client-visible detail |
|---|---|---|---|---|---|
| nested `ObjectId` | `frontend_telemetry` | 200 | **500** | 200 | `Unable to serialize unknown type: <class 'bson.objectid.ObjectId'>` |
| `Binary` (UTF-8-decodable) | `frontend_telemetry` | 200 | 200 | 200 | — (silently rendered as a string) |
| `Decimal128` | `frontend_telemetry` | 200 | **500** | 200 | `Unable to serialize unknown type: <class 'bson.decimal128.Decimal128'>` |
| nested `ObjectId` in `result` | `xdr_response_actions` | 200 | **500** | 200 | `[TypeError("'ObjectId' object is not iterable"), …]` |
| `datetime` in `result` | `xdr_response_actions` | 200 | 200 | 200 | — (encoder handles datetime) |
| nested `ObjectId` | `xdr_integrations` | 200 | **500** | 200 | `[TypeError("'ObjectId' object is not iterable"), …]` |
| non-UTF-8 `Binary` | `xdr_integrations` | 200 | **500** | 200 | `'utf-8' codec can't decode byte 0xbe in position 2` |

Server-side frames (`traces.txt`, secrets-free — the traces carry file paths
and BSON type names only):

```
route=/api/telemetry/frontend/recent status=500
    fastapi/routing.py serialize_response → fastapi/_compat.py serialize
    pydantic_core._pydantic_core.PydanticSerializationError:
        Unable to serialize unknown type: <class 'bson.objectid.ObjectId'>

route=/api/xdr/vendor/cortex/actions status=500
    fastapi/routing.py serialize_response → fastapi/encoders.py jsonable_encoder
    TypeError: 'ObjectId' object is not iterable
    ValueError: [TypeError("'ObjectId' object is not iterable"),
                 TypeError('vars() argument must have __dict__ attribute')]

route=/api/xdr/vendor/{vendor_key}/connections status=500
    UnicodeDecodeError: 'utf-8' codec can't decode byte 0xbe in position 2
```

Two encoder paths, one defect: `recent_frontend_telemetry` is annotated
`-> Dict[str, Any]`, so FastAPI serialises through a pydantic `TypeAdapter`
(`PydanticSerializationError`); the other two are unannotated and go through
`jsonable_encoder` (`ValueError` / `UnicodeDecodeError`). Same cause, different
exception class.

### 2.3 Dependency availability is **ruled out** as the cause of a 500

`repro_dbdown.py` kills mongod under a running backend and re-probes:

```
database_up    : /api/health 200 · /api/incidents 200 · /api/behaviors/registry 200
                 + all three targets 200
database_down  : /api/health 200 (0.0s) · /api/incidents 200 · /api/behaviors/registry 200
                 /api/telemetry/frontend/recent      504  (30.0s)
                 /api/xdr/vendor/cortex/actions      504  (30.0s)
                 /api/xdr/vendor/cortex/connections  504  (30.0s)
```

An unreachable database produces **504** from `request_hardening` (30 s
timeout), not 500. So the attractive theory — "these are the few open GETs
that touch Mongo with no fail-closed guard, so a slow database shows up as
500 on exactly these three" — is wrong, and is recorded here as tested and
rejected. Note also that `/api/incidents` answers 200 with the database down:
the anonymous scope sentinel short-circuits before any query.

---

## 3 · Classification

| # | Endpoint | Authentication handling | Missing configuration | Unavailable dependency | **Application logic** |
|---|---|---|---|---|---|
| 1 | `/api/telemetry/frontend/recent` | no | no | no (504, §2.3) | **yes** |
| 2 | `/api/xdr/vendor/cortex/actions` | no | no | no (504, §2.3) | **yes** |
| 3 | `/api/xdr/vendor/cortex/connections` | no | no | no (504, §2.3) | **yes** |

**Single root cause, all three: raw Mongo documents are handed to the response
encoder with no BSON→JSON normalisation.** Each handler returns the documents
as it read them:

* `recent_frontend_telemetry` stringifies only the **top-level** `_id` and
  only `recorded_at`; any other BSON type, at any depth, is untouched.
* `list_cortex_actions` projects `{"_id": 0}` and returns the rest verbatim —
  including the vendor `result` envelope, which is third-party-shaped data.
* `vendor_list`'s `_redact` pops `credentials_encrypted` and nothing else.

The projection/`str()` idioms look like normalisation but only cover `_id`.
A document is legal in Mongo and fatal at the boundary.

Severity is low and matches the F1 note ("an unguarded code path"): no
authorization boundary is crossed, no tenant isolation is affected, and no
customer data is disclosed by the fault itself. Two aggravating details:

* **The exception text is returned to the anonymous caller.** The 500 body
  carries `detail` verbatim — BSON type names and, for the encoder path,
  Python-internal messages. Reconnaissance value, not secret leakage; no
  credential, key or document content appeared in any body or trace observed.
* **Zero test coverage.** No test in `backend/tests` references any of the
  three paths or the `frontend_telemetry` collection, which is why the defect
  survived A3 and F1 unnoticed. Related to N-4.

---

## 4 · Recommended smallest safe correction

Not implemented — reporting only, as instructed.

1. **Normalise at the three handlers** (smallest change that closes N-3).
   One small recursive BSON→JSON coercion applied to each returned document:
   `ObjectId`/`Decimal128` → `str`, `datetime` → `isoformat()`, `Binary`/
   `bytes` → an explicit, non-lossy encoding, unknown types → `str`. Three
   call sites, no behavioural change on data that already serialises (§2.2
   shows those cases are 200 today and must stay byte-identical).
   *Note: a top-level-only sanitiser already exists at
   `models_studio.py::_sanitize_doc` — it is not recursive, so it is a
   precedent for the idea, not a reusable fix.*
2. **Keep the fix at the handler, not in a global encoder.** Registering a
   BSON-aware `default_response_class` app-wide would silently change the
   response shape of every route in the platform, including evidence and
   audit surfaces where a type coercion is a provenance question. Out of
   proportion to N-3; owner decision if ever wanted.
3. **Do not "fix" this by catching the exception.** A `try/except` returning
   an empty list would convert a visible fault into silent data loss on an
   evidence-adjacent surface.
4. **Add a regression test** that inserts a nested `ObjectId` and a
   non-UTF-8 `Binary` into each collection and asserts 200 plus a correct
   body — i.e. §2.2 as a test. It fails today on all three paths and passes
   after (1).
5. **Then, separately, gate it.** Adding that suite to a mandatory gate is a
   distinct authorised step, as with N-1 and N-5.
6. **Unchanged by this fix:** all three endpoints remain **unauthenticated**.
   Normalisation removes the crash, not the open surface. Whether
   `frontend_telemetry` (session ids, timings) and `xdr_integrations`
   (tenant ids, base URLs, capability matrices — credentials redacted) should
   answer an anonymous caller at all is **N-2**, and is not addressed here.

---

## 5 · Evidence index · `/app/rocket-evidence/n3/`

| file | what it shows |
|---|---|
| `probe.py`, `probe.json`, `probe.log` | first reproduction attempt — the three paths answer 200 on an empty candidate database |
| `sweep.py`, `empty-sweep.json`, `sweep-empty.log` | 354 parameterless GETs, empty DB: 0 × 500 |
| `seeded-sweep.json`, `sweep-seeded.log`, `seed/` | same sweep with the preview rows restored: 0 × 500 |
| `repro_data.py`, `repro_data.json`, `repro_data.log` | the deterministic defect reproduction (§2.2) |
| `repro-backend.log`, `traces.txt` | server-side stack traces, secrets-free |
| `repro_dbdown.py`, `repro_dbdown.json`, `repro_dbdown.log` | database-down control: 504, not 500 (§2.3) |

No merge, deploy, staging re-pin or production access. The frozen Hetzner
package was not touched. No test was weakened, skipped or deleted.
