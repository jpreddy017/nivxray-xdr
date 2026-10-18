# N-3A · Telemetry BSON serialization repair

**Branch** `engineering/n3a-telemetry-bson` · **commit**
`38e294c614456406c0198163d896afb03f8575f9` · **tree**
`a7ff378c4be3a6b375f06a3b0c1ca27272c5f821` · parent
`1158afcc266b08b2b3ae6485bd5cdb40cbb28f74` (`engineering/n5-ci-gate`).
Worktree `/app/rocket-p0/n3a` clean. Evidence `/app/rocket-evidence/n3a/`.

**RELEASE STATUS: NO-GO.** Nothing merged, deployed or re-pinned. F1, N-1 and
N-5 are untouched — the parent commit is their head and this branch adds one
commit on top.

---

## 1 · Root cause addressed

`GET /api/telemetry/frontend/recent` returned the documents exactly as it read
them, normalising only the **top-level** `_id` and `recorded_at`. Any other
BSON value, at any depth, reached FastAPI's response serializer. Because the
handler is annotated `-> Dict[str, Any]`, that is the pydantic `TypeAdapter`
path, which raises `PydanticSerializationError` on an unknown type — an
unauthenticated HTTP 500 caused by stored data rather than by the request.

Fixed at the response boundary of this one endpoint. The two other N-3
endpoints, the global encoder, authentication and tenant behaviour are
unchanged.

## 2 · Files changed

| file | change |
|---|---|
| `backend/routers/telemetry.py` | +61 / −7 — new module-level `_json_safe()`; `recent_frontend_telemetry` now maps it over the documents instead of patching `_id`/`recorded_at` in place |
| `backend/tests/test_n3a_telemetry_bson_serialization.py` | new — 14 focused tests |

Nothing else. `POST /api/telemetry/frontend`, the rolling 500-entry window and
the 5000-row soft cap are untouched.

## 3 · Conversion rules

| stored value | returned as | why this rule |
|---|---|---|
| `str`, `int`, `float`, `bool`, `None` | unchanged, type preserved | JSON-native; no numeric value is reformatted |
| `ObjectId` | 24-char hex `str` | same form the top-level `_id` already used |
| `Decimal128`, `decimal.Decimal` | exact decimal `str` | **not** `float` — that silently loses precision the client stored |
| `bytes`, `Binary`, `bytearray` | base64 ASCII | **not** a UTF-8 decode: binary is not text, and guessing raises `UnicodeDecodeError` on the first non-UTF-8 byte |
| `datetime`, `date`, `time` | ISO-8601 | unchanged from the previous `recorded_at` handling |
| `UUID` | canonical `str` | — |
| mapping | recursive, keys stringified | insertion order preserved |
| list / tuple | recursive list | element order preserved |
| anything else (`Regex`, `Code`, `Timestamp`, `MinKey`, `DBRef`, …) | `str(value)` | a type nobody anticipated degrades to a readable value instead of a 500 |

Guarantees the tests hold the code to: no field is added, dropped or renamed
(`set(response_record) == set(stored_document) | {"_id"}`); no exception is
caught or suppressed anywhere in the path; no previously excluded field
becomes visible; `limit`, ordering and the response envelope
(`{"count", "records"}`) are byte-for-byte what they were.

One deliberate behavioural change: a `Binary` whose bytes happen to be valid
UTF-8 used to be rendered as text by the encoder's own guess and is now
base64, like every other `Binary`. The alternative — decode when it works,
500 when it does not — is the defect.

## 4 · Before / after

**Before (baseline `1158afc`, the fix absent, same tests, same harness).** The
endpoint-level tests were run against the parent commit; the three helper unit
tests were excluded there because `_json_safe` does not exist yet:

```
8 failed, 3 passed, 24 warnings in 170.06s
FAILED test_nested_objectid_no_longer_returns_500
FAILED test_decimal128_is_exact_and_never_a_lossy_float
FAILED test_invalid_utf8_binary_is_base64_not_a_decode_attempt
FAILED test_utf8_decodable_binary_is_also_base64_not_text
FAILED test_nested_dicts_and_arrays_are_walked_and_order_preserved
FAILED test_no_field_is_added_dropped_or_renamed
FAILED test_response_is_deterministic
FAILED test_limit_and_ordering_are_unchanged
ERROR nivxray.middleware [nvx-…] 500 unhandled path=/api/telemetry/frontend/recent
```

The 3 that passed are exactly those that store no BSON — ordinary record,
JSON-native types, empty collection — i.e. the suite fails only on the defect.

**After (this commit):** `14 passed, 24 warnings in 165.45s`.

**Real data unchanged.** The N-3 probe re-run on both trees with the preview
rows genuinely restored (74 `frontend_telemetry`, 6 `xdr_integrations`;
`xdr_response_actions` is empty at source), 354 parameterless GETs each:

```
baseline 1158afc : 200×75  403×271  401×3  404×5  500×0
this commit      : 200×75  403×271  401×3  404×5  500×0
status differences across all 354 paths: none
/api/telemetry/frontend/recent response body: BYTE-IDENTICAL (50 real records)
```

*Also corrected while doing this:* the first "seeded" sweep quoted in the N-3
report restored nothing (`--nsFrom 'src.*'` matched no namespace and exited 0).
`sweep.py` now maps the namespace correctly and **aborts if the restore lands
zero documents**; the N-3 report has been annotated. The conclusion there is
unchanged — 0 × 500 on populated data too — but that row had not earned it.

## 5 · Focused regression results

`python3 tools/security-harness/run.py --suite tests/test_n3a_telemetry_bson_serialization.py`
→ **14 passed** (`/app/rocket-evidence/n3a/focused.log`). Coverage:

| test | asserts |
|---|---|
| `test_nested_objectid_no_longer_returns_500` | `ObjectId` in a sub-document *and* in an array → hex string |
| `test_decimal128_is_exact_and_never_a_lossy_float` | `0.1000000000000000000000000001` survives exactly, as `str` |
| `test_invalid_utf8_binary_is_base64_not_a_decode_attempt` | `b"\xde\xad\xbe\xef"` → `3q2+7w==`, base64-round-trips |
| `test_utf8_decodable_binary_is_also_base64_not_text` | one rule for all bytes |
| `test_ordinary_record_is_unchanged` | the real record shape, compared against the value as Mongo returns it |
| `test_json_native_values_keep_their_types` | `True`/`None`/`int`/`float`/`str` identity |
| `test_nested_dicts_and_arrays_are_walked_and_order_preserved` | 3-deep nesting, array order |
| `test_no_field_is_added_dropped_or_renamed` | exact key set |
| `test_response_is_deterministic` | two GETs byte-identical |
| `test_limit_and_ordering_are_unchanged` | `limit=2`, recency order |
| `test_empty_collection` | `{"count": 0, "records": []}` |
| `test_unanticipated_bson_types_degrade_to_strings_not_500s` | `Regex`, `Code`, `Timestamp`, `MinKey` |
| `test_uuid_and_bare_bytes` | helper rules |
| `test_helper_suppresses_nothing` | a value that cannot convert **raises** — no silent omission |

The suite snapshots the existing `frontend_telemetry` rows and reinserts them
on teardown, so running it against a populated database destroys nothing.

## 6 · Mandatory security gate

`python3 tools/rocket-validation/run.py --gate security --output …`

```
security: 126 tests, 0 failures, 0 errors, 1 skipped — exit 0  (253s)
```

Identical to the accepted N-5 baseline (126 / 0 / 0 / 1). The one skip is
pre-existing. No test was modified to obtain this.

## 7 · Remaining risks

* **The endpoint is still unauthenticated.** Normalisation removes the crash,
  not the open surface: anyone can still read session ids and timings. **N-2**,
  untouched here by instruction.
* **The 500 body still echoes the exception text** on any *other* unhandled
  error on this route. Out of N-3A scope (middleware-level).
* **The sibling endpoints still carry the defect** —
  `/api/xdr/vendor/cortex/actions` and `/api/xdr/vendor/cortex/connections`,
  reproduced in N-3 §2.2, are explicitly out of scope and remain exposed.
  `_json_safe` is intentionally private to `routers/telemetry.py`; promoting
  it to a shared utility is the natural N-3B/N-3C step and is an owner call.
* **This suite is in no mandatory gate.** Gating it is a separate authorised
  step, as with N-1 and N-5.
* **`float('nan')`/`inf` are passed through unchanged** — they emit the
  non-standard `NaN` token rather than a 500. Pre-existing, unrelated to the
  reported defect, and changing a stored numeric value silently is worse than
  the symptom; recorded rather than fixed.
* The candidate inherits the F1 HOLDs (egress denial, `emergentintegrations`
  provenance, gate coverage). Nothing here lifts them.
