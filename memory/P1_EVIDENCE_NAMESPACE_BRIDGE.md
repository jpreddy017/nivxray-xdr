# P1 · Evidence Namespace Bridge (2026-06) — CLOSED

## IDENTIFIER INVENTORY (traced read-only, live data)
| Stage | Identifier | Minted / persisted |
|---|---|---|
| raw (sensor) | `edr_raw_events.raw_id` (`raw_<hex>`) | authenticated endpoint ingest |
| raw (connector) | `xdr_canonical_events._id` + `collector_id` | `routers/xdr_ingest.py` |
| **canonical evidence** | **`xdr_canonical_evidence.event_id`** — `uuid4` (CEF/LEEF, M365, AWS, win-sec), `sysmon-<eid>-<uuid>` (`telemetry/sysmon_dsm.py:220`), `cev_*` (`edr_plane/canonical_bridge.py:346`, `linux_auditd_dsm.py:570`) | normalizer / DSM; row carries `tenant_id` + `raw_ref` |
| observation | `v2_shadow_observations.canonical_event_id` (top level, `v2/ingestion/telemetry_bridge.py:109`) + `event.iid` = `evt_<sha16>` + `input_sha256` | live telemetry bridge |
| trajectory frame | `frame_iid` = `tf_<sha16(ts,kind,adapter,sequence,evt_iid)>`, `evidence_ids=[evt_*]` | `v2/trajectory/device.py` |
| incident | `xdr_pipeline.canonical_event_id`, `endpoint_campaign.detections[].canonical_event_id` | detection fabric |
| IKG anchor | `proc_* dev_* cmd_* file_* net_* reg_*` | CEM entity iids |
| Evidence tab row | `${domain}-${i}` — browser-generated, ARRAY POSITION | `EvidenceTab.jsx:bulletRow` |

## ROOT CAUSE
1. The authoritative identity already existed and already matched
   (`inc_7742fe7120174204be36`: incident pipeline id == observation
   `canonical_event_id` == `xdr_canonical_evidence.event_id` ==
   `edd3e983-…`), but `build_from_observations()` read only `row["event"]`
   and **dropped the sibling `canonical_event_id`**; `TrajectoryFrame` had no
   field for it. A propagation drop, not a missing identity.
2. The Evidence table had **no persisted row identity at all** — its ids are
   array positions invented in the browser over capability-pointer bullets.

## AUTHORITATIVE IDENTITY
`canonical_evidence_id` := `xdr_canonical_evidence.event_id`. No new
namespace. `evt_*` (observation) and `tf_*` (frame) keep their own identity.

## BRIDGE CONTRACT (`services/evidence_bridge.py`)
- Frames carry `canonical_evidence_id` (propagated) + `bridge_state`.
- States: `BRIDGED` · `REFERENCED_RECORD_ABSENT` (deterministic reference,
  record not resolvable under the incident's tenant authority — NOT missing
  evidence, NOT benign) · `LEGACY_UNBRIDGED` (identifier never persisted).
- Access authority is the INCIDENT (`authorized_incident`), never an id. The
  canonical set is read from what the incident itself persists (pipeline ·
  campaign detections · case-linked observations). A record stamped to
  another tenant is never disclosed (`tenant_assertion: CONFLICT` →
  `REFERENCED_RECORD_ABSENT`, no record body).
- Zero label / hash / timestamp / proximity / position / client-id matching.
- One-to-many (many frames → one record) and many-to-one (one record cited by
  pipeline + campaign + observation) both representable. Reverse lookup is
  derived, not persisted (no new store, per owner decision).

## FILES / SCHEMAS CHANGED
- `backend/services/evidence_bridge.py` (new · the bridge)
- `backend/routers/incident_canonical_evidence.py` (new ·
  `GET /api/incidents/{id}/canonical-evidence`, read-only projection) +
  `server.py` registration
- `backend/v2/trajectory/schema.py` (`canonical_evidence_id` field),
  `backend/v2/trajectory/device.py` (propagation),
  `backend/v2/routers/trajectory.py` (bridge-state annotation)
- `backend/services/evidence_inspector/service.py` (`kind=event` resolves the
  incident's FULL authoritative canonical set, tenant-checked)
- `apps/nivxray-xdr/src/xdr/incidents/CanonicalEvidenceRecords.jsx` (new),
  `…/incidents/anchorEvidence.js`, `…/tabs/EvidenceTab.jsx`,
  `src/lib/incidentsApi.js`
- No schema migration. No collection created. No historical row rewritten.

## NEW-EVIDENCE E2E PROOF (`scripts/p1_evidence_namespace_bridge_e2e_proof.py`)
39 PASS · 0 FAIL. Dedicated proof tenant created through the tenancy control
plane (`ten_1dd3bcf5879f758035ccb803d9`, slug `p1-bridge-proof`), collector
`col_6256c58f331b453b950e`, 3+1 Sysmon documents delivered through real
authenticated ingest → normalizer → canonical evidence (`sysmon-1-*`) →
observation → incident promotion → trajectory frame
(`canonical_evidence_id` + `BRIDGED`) → anchor citation → the exact canonical
record → inspector → normalizer + raw source. Multi-reference case proven
live on a pipeline-built incident (`inc_8ddc1dee7a4c46aa93c9`: 62 BRIDGED
records, 61 of them NOT the `xdr_pipeline` id, inspector resolves them).

## UI PROOF (`scripts/p1_evidence_bridge_dom_proof.py`)
21 PASS · 0 FAIL, real browser, no screenshots: canonical evidence records
section, exact addressable row, referenced-by, raw source, inspector
resolution, anchor → same record (`SELECTED ANCHOR`), and an
`REFERENCED_RECORD_ABSENT` incident stating the truth without substitution.

## FOCUSED TESTS
`tests/test_p1_evidence_namespace_bridge.py` — 18 passed (propagation
determinism, three states, multi-id per incident, cross-tenant
non-disclosure, anonymous refusal, 404 semantics, fabricated /
`evt_*` / `tf_*` / tampered-id non-enumeration, unretained record).
Regression: + `test_v2_trajectory`, `test_p01_*`, `test_p0_*`,
`test_xdr_response_evidence` → 69 passed.

## LEGACY BEHAVIOR
Nothing rewritten. Legacy observations (`command_line` / `golden@1.0`, 723
rows) carry no canonical identifier → `LEGACY_UNBRIDGED`, reported in their
own namespace with the reason. 252 canonical rows carry no `tenant_id` →
`tenant_assertion: NOT_STAMPED_ON_RECORD` (access authority was the
incident). 60 incidents reference a canonical id with no retained record →
`REFERENCED_RECORD_ABSENT`.

## RESIDUALS / LIMITATIONS
- **Sibling-evidence association gap (product, not bridge)**: on the
  connector ingest path only the PROMOTING observation receives `case_id`;
  the other canonical events of the same delivery stay `case_id: None` and
  are therefore not part of the incident's authoritative set. Truthful today,
  but real evidence is unassociated. Own task.
- Frame-level MULTI-id could not be proven live: no incident in this
  environment has more than one case-linked observation, and the
  62-reference incident has no engine observations at all
  (`engine_association: NOT_ASSOCIATED`). Covered by pytest.
- `LEGACY_UNBRIDGED` could not be shown live on an `inc_*` incident: no
  incident-linked observation lacks a canonical id. Covered by pytest.
- The Evidence tab still renders capability pointers with browser-generated
  ids; making Evidence a first-class object was explicitly deferred.
- Pre-existing, unrelated stale test:
  `tests/canonical/incidents/test_incidents_projection.py::test_row_projection_shape`
  still expects the `assignee` → `user_email` fallback removed by P0-2b.

## RESIDUAL PROOF DATA (preview only, clearly tagged, retained as evidence)
tenant `ten_1dd3bcf5879f758035ccb803d9` (slug `p1-bridge-proof`) ·
7 incidents · 15 canonical evidence rows · 15 observations · 15 raw rows ·
collector `col_6256c58f331b453b950e` · 4 ingest keys, **all revoked**
(`enabled: false`, `revoked_at` set) — no active credential remains.
