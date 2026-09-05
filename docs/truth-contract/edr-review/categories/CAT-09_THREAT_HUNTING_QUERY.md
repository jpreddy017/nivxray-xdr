# CAT-09 · Threat Hunting / Query Capabilities

> STRICT READ-ONLY deep-dive. **Second-most consequential finding after CAT-02.**

## 1 · PRE-AG baseline

**NOT IMPLEMENTED as a plane.** What existed at `5d67934e`:

| Artifact | Evidence | What it actually is |
|---|---|---|
| `/api/investigation/{case_id}/hunting` | `backend/routers/workspace_investigation.py:17` (self-documented route map), `:50` `from l2_investigation.services.hunting_queries import run as run_hunting_queries`, `:267` `"hunting": run_hunting_queries` | **Generates suggested hunting queries for one case.** It does not execute anything |
| `routers/mitigations_evidence_driven.py:123,144` | `"hunting": v1.get("hunting") or []` — a bucket alongside `immediate`, `containment`, `hardening` | **Advisory text**, not a query engine |
| `detection_content/corpus/hunting_anomaly_corpus.py` | AG-added (see §2) | corpus content |
| `xdr_rbac.py:157` `"threat_hunting": {"actions": ["read","execute"]}`; `:211` `"threat_hunting.*"`; `:230` role described as *"Senior investigator · advanced hunting…"* | live RBAC | **A permission with no route behind it** |

## 2 · AG delta

| Change | Type | Effect on the hunting plane |
|---|---|---|
| `detection_content/corpus/hunting_anomaly_corpus.py` | ADDED | content only |
| `detection_content/translation/hunting_translator.py` | ADDED | can *translate* hunting content between dialects |
| — | — | **AG added no hunting execution capability, no query language, no retention plane** |

## 3 · Current state (live)

```
$ 733 live API paths, matches for /hunt/i:
  ['/api/investigation/{case_id}/hunting']
```

**One path. Case-scoped. Advisory.**

| Dimension | Verdict |
|---|---|
| Implemented | 🟡 query *suggestion* only |
| Registered | ✅ 1 path |
| Executed | ✅ (returns suggestions) |
| Runtime-proven | 🟡 as a suggestion generator; ❌ as a hunting plane |
| Production-ready | 🔴 **NOT IMPLEMENTED** as an XDR hunting capability |

### Root cause is upstream, not in hunting

Hunting requires **retained, queryable telemetry**. NivXRay has none:

| Prerequisite | State | Evidence |
|---|---|---|
| Connected telemetry sources | **0** | `/api/xdr/data-sources` → `{"data_sources":[],"count":0}` |
| Live collector instances | **0** | `/api/xdr/collector/telemetry-health` → rest/webhook/syslog all `never_connected`, `instances: 0` |
| Retained raw event store | **absent** | `xdr_canonical_evidence` = 222 docs (pipeline output, not a retention plane); Security Data Lake tab is **disabled** at `XdrShell.jsx:195` |

**Therefore: building a query language now would produce a language with nothing to query.** This is recorded explicitly so that no future session treats hunting as an independent P0.

## 4 · Industry benchmark — every vendor has an executable query plane

| Vendor | Query language | Retention | Notable limits (documented) |
|---|---|---|---|
| **Microsoft Defender XDR** | **KQL** advanced hunting, guided + advanced modes | **30 days raw** | max 100,000 records, 10-min timeout, 64 MB result cap, CPU quota per tenant refreshed every 15 min; `DisruptionAndResponseEvents` table queryable; URBAC-gated (`Security operations > Raw data`) |
| **Cortex XDR** | **XQL** over the Cortex Native Data Lake; BIOCs are XQL; rules testable in XQL search before promotion | data-lake retention | `dataset = xdr_data \| filter event_type = ENUM_PROCESS_START` |
| **Splunk ES** | **SPL** over the risk data model + macros | index retention | 100 findings/investigation, 50 events aggregated per finding group |
| **CrowdStrike** | event queries + Threat Graph API (`get_ran_on`/`get_vertices`/`get_edges`) + LogScale | LogScale retention | Fusion can run queries as workflow actions |
| **SentinelOne** | Deep Visibility / Singularity Data Lake queries; Purple AI natural-language over OCSF | **365-day EDR context** | Purple AI NL queries require browser-session `teamToken`, not service tokens |
| **Cisco XDR** | investigation/observable queries across integrations | — | — |
| **Trellix** | queries across 1,000+ integrated sources | — | — |

## 5 · Gap

| Gap | Severity | Sequencing constraint |
|---|---|---|
| **No executable hunting query language** | **P2 (deliberately not P0)** | Blocked by, and must follow, (a) a connected real telemetry source and (b) a retention/SDL decision |
| **No retention / security-data-lake plane** | **P1** | This is the true blocker. `sdl` tab already disabled at `XdrShell.jsx:195` — the product already admits the gap honestly |
| No retro-scan on rule creation | P1 | Cortex retro-scans on BIOC creation. Impossible without retention. Also blocks CAT-05's backtest gap |
| No saved hunts / scheduled hunts | P2 | `xdr_saved_views` collection exists with **0 docs**; `/api/xdr/saved-views` is live — the primitive is there |
| RBAC advertises `threat_hunting` with no route | P2 | Master DEV-6 — registration without capability; either implement or remove the permission |
| Hunt→detection promotion loop absent | P2 | Vendors promote a successful hunt into a detection. `detection_content/translation/hunting_translator.py` (AG) is the asset that would enable this once hunting exists |

## 6 · Honest positive

`/api/investigation/{case_id}/hunting` **does not pretend to be hunting.** It returns advisory queries alongside `immediate`/`containment`/`hardening` buckets (`mitigations_evidence_driven.py:144`). That is Honest-State compliant. The gap is a **missing capability, not a false claim** — which is the correct kind of gap to have.

## 7 · UNKNOWN

- U-09.1 — Whether the generated hunting queries are dialect-valid (KQL/SPL/EQL). Requires execution + a target platform.
- U-09.2 — Whether an SDL/retention design decision has already been taken by the owner. Not discoverable from code.
