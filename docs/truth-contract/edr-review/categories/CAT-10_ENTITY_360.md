# CAT-10 · Entity 360 (user / device / IP / domain / URL / hash / process / file / mailbox / app / cloud resource / service account)

> STRICT READ-ONLY deep-dive.

## 1 · PRE-AG baseline

**PARTIAL — module without a plane.**

| Artifact | Evidence at `5d67934e` | Reality |
|---|---|---|
| `backend/layer_360.py` | present, Emergent-authoritative, **not in the AG diff** | a **360 layer module**, not an entity API |
| `backend/services/activity/` (`ActivityInventory`, `projector.build_inventory`) | present | provides `parent_entity_id` + `child_entity_ids` — the **process-graph primitive** |
| `/api/activity/inventory` | live | activity inventory projection |
| `/api/v2/artifacts/{artifact_iid}/link/entity` | live | links an artifact to an entity — **the only entity-typed path in the whole API** |
| IUE entity extraction | `xdr_pipeline.py:279-287` → stage emits `entities=len(iue["entities"])` | entities **are** extracted per event |
| `/api/edr/{endpoints,device-trajectory,process-tree}` | live | device/process views — see CAT-13 |
| `entity-search` nav tab | `apps/nivxray-xdr/src/xdr/XdrShell.jsx:92` | UI entry point |
| `ENTITY_CORRELATION`, `CROSS_USER`, `CROSS_HOST` correlation operators | live `/api/xdr/correlation/status` — all **implemented** | entity-aware correlation exists |

## 2 · AG delta

**NONE.** No entity router, model or store was added by AG. `layer_360.py` is untouched.

## 3 · Current state (live) — the hard finding

```
$ 733 live API paths matching /entity/i:
  ['/api/v2/artifacts/{artifact_iid}/link/entity']

$ Mongo:
  v2_case_entities        →  0 docs
  v2_case_relationships   →  0 docs
```

And `GET /api/v2/cases` returns, for every case:
```json
"event_count": 0, "entity_count": 0
```

So: **IUE extracts entities per event, correlation operators reason over entities, the UI has an entity-search tab — and there is no persisted entity record and no entity-centric API.**

| Dimension | Verdict |
|---|---|
| Implemented | 🟡 extraction + correlation primitives only |
| Registered | 🔴 **1** entity-typed path, and it is an artifact link |
| Executed | 🟡 entities extracted transiently inside the pipeline |
| Runtime-proven | 🔴 `v2_case_entities` = 0 |
| Production-ready | 🔴 **NOT IMPLEMENTED** as an Entity-360 plane |

### Per-entity-type coverage

| Entity type | Persisted? | API? | Evidence |
|---|---|---|---|
| Device / host | 🟡 projection | `/api/edr/endpoints`, `/api/edr/device-trajectory`, `/api/v2/cases/{id}/trajectory/device` | `edr.py:29-45` extracts host from `workspace_cases.ssot.investigation_object.host`, **returns `None` rather than fabricating** when absent |
| Process | 🟡 projection | `/api/edr/process-tree`, `/api/analyze/process-tree` | reuses `ActivityInventory` — explicitly "we do NOT introduce a second process-correlation model" (`edr.py:8-14`) |
| Hash / file | 🟡 | `/api/v2/decoded-artifacts/{sha256}`, `/api/v2/artifacts/by-sha` | artifact-centric, not entity-centric |
| IP / domain / URL | 🟡 enrichment only | `/api/ioc/enrich`, `/api/osint/lookup`, `/api/threat-intel/lookup/{value}` | **lookup, not a 360 record** |
| User / identity | 🔴 | none | `CROSS_USER` operator exists with no user record |
| Mailbox | 🔴 | none | CAT-15 |
| Application / cloud resource / service account | 🔴 | none | CAT-15 |

## 4 · Industry benchmark

| Vendor | Entity-360 capability |
|---|---|
| **Microsoft Defender XDR** | Entity-centric investigation pages for device/user/mailbox/app; incident queue filterable by device group; entities queryable in advanced hunting |
| **Cisco XDR** | **Asset Insights** — consolidated device + user inventory from all integrated products; **asset value assignment feeds incident priority**; AI-generated per-asset activity summary; "View asset insight" drill-down with analysis timeline + detection groups |
| **Cortex XDR** | Causality view centred on the Causality Group Owner; per-endpoint/per-user pivots |
| **CrowdStrike** | Threat Graph `get_ran_on` — "look up indicators (hashes, IPs, domains) observed on devices"; `get_vertices` / `get_edges` for entity metadata and relationships |
| **SentinelOne** | Storyline unifies process/file/network/**identity** per entity, 365-day context |
| **Splunk ES** | Risk index is **entity-keyed**; findings groupable by entity or threat object |
| **Trellix** | Endpoint + identity + email entity context across 1,000+ sources |

## 5 · Gap — P0

| Gap | Severity | Why (NivXRay-evidence-led) |
|---|---|---|
| **No persisted entity record** | **P0** | `v2_case_entities` = 0 while IUE already extracts entities every event (`xdr_pipeline.py:279`). The extraction work is **already being done and thrown away** |
| **No entity-centric API** | **P0** | The `entity-search` tab (`XdrShell.jsx:92`) has nothing to call. This is the clearest "UI ahead of plane" instance in the product |
| **No entity relationship graph** | **P1** | `v2_case_relationships` = 0; `xdr_evidence_graph_edges` = 10. Blocks CrowdStrike-style pivoting and feeds master DEV-4 |
| **No identity entity at all** | **P1** | `CROSS_USER` correlation operator is implemented against a user concept that is never persisted |
| No asset-value / criticality on entities | P1 | Cisco monetises exactly this; NivXRay has `xdr_cve_assets` (24) unjoined to verdict (CAT-08) |
| No entity timeline / 360 view | P1 | `/api/timeline/*` (7 paths) is **investigation-scoped**, never entity-scoped |

**Recommendation (justified, and minimal):** an entity-360 **read projection** over `xdr_canonical_evidence` + `xdr_iue_understanding`. This is a projection, not a new engine — it does not violate the single-engine rule, and it converts already-computed IUE entities into a queryable plane. It is also the cheapest unlock for CAT-04 (`entity-search`), CAT-06 (graph density) and CAT-09 (pivot targets).

## 6 · Honest positive

`routers/edr.py:29-45` `_extract_host()` returns `None` — with the comment *"never fabricated (rule #13)"* — when a case has no endpoint context. The absence of Entity 360 is a **missing capability, honestly represented**, not a fabricated one.

## 7 · UNKNOWN

- U-10.1 — Whether `layer_360.py` implements a usable 360 projection that is simply unrouted, or is a partial scaffold. Determining this needs a full read of the module plus execution; **not claimed here**.
- U-10.2 — Whether `v2_case_entities` is empty by design (v2 not in use) or by defect. Not determinable read-only.
