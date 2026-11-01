# Event detail timeout hotfix

## Report and diagnosis

The Events list loads, but selecting a row waits 30 seconds and reports an unavailable event. The owner reports that opening, closing and switching rows previously worked.

The detail route, EventPane and getEvent client function are unchanged between production source 35d47cc9 and Files candidate 0ac4134d. This does not establish the deployed backend revision or explain a runtime regression. Production index inventory, query plan and request timing remain unverified.

The raw-event index declarations lack a direct `(tenant_id, raw_id)` index for the detail lookup. This is a demonstrated performance defect, not yet a confirmed explanation of the production incident.

## Current, targeted and implemented flow

| Layer | Previous flow | Implemented flow |
| --- | --- | --- |
| Browser | Select row; wait for request; stale results suppressed | Select row; abort superseded/closed request; suppress stale result; explicit Retry on failure |
| API | Tenant scope check; unbounded detail read; optional hostname read | Same scope check; detail query has 5-second Mongo budget and 8-second application bound; optional hostname has 2/3-second bounds |
| Storage | Exact tenant/raw identity query without matching index declaration | Nonunique tenant/raw index installed through existing startup index setup |
| Response | Database failure may outlast client timeout | Unavailable read produces sanitized 503; missing event remains 404; failed optional hostname does not hide raw evidence |

Target behavior: opening, closing, reopening and switching events preserves the selected event's verbatim payload and never substitutes another event's result. The existing global client timeout is unchanged. No evidence replay, deletion or identity rewrite is included.

## Verification

- Seven backend tests passed on an isolated runtime: exact tenant lookup, payload/derivations, 404, timeout/transport 503, optional hostname failure, scope refusal, idempotent index and real Mongo plan.
- A fresh UUID database with 50,000 synthetic records examined 50,000 index entries using the existing keyset index for a worst-case lookup; the new direct index examined one key and one document. This is a fixture result, not a production benchmark. Only that UUID fixture database was dropped afterward.
- The actual EventPane component passes a React regression harness for Retry, cancellation, rapid selection, stale completion suppression, close callback, unmount and reopen with another event.
- Run the UI harness with `NIVX_TEST_NODE_MODULES=/path/to/node_modules node tools/test-edr-event-detail.cjs`. It requires React, react-test-renderer and esbuild.
- Backend tests require the existing backend dependencies; opt into the isolated localhost Mongo test with `NIVX_EVENTS_MONGO_INTEGRATION=1`.

## Before production readiness

1. Confirm the backend revision and inspect the actual failing request and deployed index inventory. Do not infer the deployed revision from health alone.
2. Build and browser-check the final frontend artifact. Component tests are not a live browser check.
3. Deploy the approved backend first. Confirm `tenant_raw_id_lookup` exists and the exact tenant/raw lookup uses it. Index creation is additive and nonunique; allow for build time and storage on the live collection.
4. Authenticated checks: open A, close, open B, switch rapidly, reopen A, confirm payload identities, test missing event and Retry. Check request timing and optional enrichment behavior.
5. Deploy the approved frontend and repeat the checks on the production domain. Keep purge disabled and retain previous deployment references.

No production change or end-to-end recovery is claimed by these tests. This hotfix is independent of the draft Files feature.
