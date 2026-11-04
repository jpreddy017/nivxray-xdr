# CAT-06 · Correlation / Attack Chaining

> STRICT READ-ONLY deep-dive.

## 1 · PRE-AG baseline (proven)

| Artifact | Evidence | Status |
|---|---|---|
| **ICE — Intelligent Correlation Engine** | `backend/detection_content/xdr_ice.py`, **first added `fc33871c` (2026-08-31)** — 5 days before AG. 205 lines | IMPLEMENTED, PRE-AG |
| Attack-chain graph | `backend/detection_content/xdr_attack_chain_graph.py` at `5d67934e` | IMPLEMENTED, PRE-AG |
| Correlation router | `backend/routers/xdr_correlation.py` at `5d67934e` (AG modified content) | IMPLEMENTED, PRE-AG |
| Correlations router (case-level) | `backend/routers/correlations.py` at `5d67934e` — 17 paths incl. `/graph`, `/timeline`, `/fingerprint`, `/provenance`, `/find-related`, `/cem`, `/compare`, `/scan` | IMPLEMENTED, PRE-AG |
| Evidence traversal | `xdr_evidence_traversal.py` | IMPLEMENTED, PRE-AG |
| Attack-chain redesign | commit `ac94a747` `## Attack Chain / Attack Graph Redesign · SHIPPED` — pre-AG | IMPLEMENTED, PRE-AG |

**The correlation engine is PRE-AG NivXRay. This is one of the strongest PRE-AG claims in the audit.**

## 2 · AG delta

| Change | Type |
|---|---|
| `backend/detection_content/xdr_ice.py` | **MODIFIED** by AG (per the separation rule, the *current content* of ICE is POST-AG; the *capability* is PRE-AG) |
| `backend/routers/xdr_correlation.py` | **MODIFIED** by AG |
| `backend/detection_content/correlation_library.py` | **ADDED** by AG |
| `detection_content/corpus/behavioral_correlation_corpus.py` | **ADDED** by AG |
| `detection_content/translation/correlation_translator.py` | **ADDED** by AG |
| `xdr_pipeline.py:290` `await ice_correlate(db, canonical, iue, trace_id)` | call-site present PRE-AG; file AG-modified |

## 3 · Current state (live)

```
/api/xdr/correlation/{status,matches,replay,signals}
/api/xdr/correlation/rules  (3 paths)
/api/correlations + /api/correlations/{cid}/*  (17 paths)
/api/incidents/{id}/attack-graph · /attack-story · /attack-evidence
/api/correlations/{cid}/graph · /timeline
```

**RUNTIME-PROVEN** — `GET /api/xdr/correlation/status` (live, authenticated):

```json
{"ok":true,"data":{"rules_total":10,"rules_active":10,"matches_total":6,
 "supported":2,"candidates":4,
 "operators":["COUNT","CROSS_HOST","CROSS_SOURCE","CROSS_USER","ENTITY_CORRELATION",
   "EVENT_MATCH","GROUP_BY","NEGATIVE_EVIDENCE","SEQUENCE","TEMPORAL",
   "TEMPORAL_ORDERED","THRESHOLD","VALUE_COUNT"],
 "operators_implemented":[ …all 13… ]}}
```

**13 of 13 declared correlation operators are implemented** — including `NEGATIVE_EVIDENCE`, which is unusual and directly serves the honest-state contract.

Runtime volumes: `xdr_correlation_rules` 10 · `xdr_correlation_matches` 21 · `xdr_correlation_state` 11 · `xdr_evidence_graph_edges` **10**.

| Dimension | Verdict |
|---|---|
| Implemented | ✅ 13/13 operators |
| Registered | ✅ 25+ live paths |
| Executed | ✅ pipeline `correlation` stage `EXECUTED` (`xdr_pipeline.py:290-295`) |
| Runtime-proven | ✅ 10 active rules, 21 matches |
| Production-ready | 🔴 — correlates within **one** telemetry domain; that is not XDR correlation |

## 4 · Industry benchmark

| Vendor | Correlation / chaining model |
|---|---|
| **Cortex XDR** | **Causality Analysis Engine** — automatic causality chains with a **Causality ID (CID)** tracing back to the **Causality Group Owner (CGO)**; log stitching in the data-digestion layer builds a "unified session story"; XQL correlation rules can generate issues / write datasets / update lookups |
| **SentinelOne** | **Storyline** — automatic correlation of process/file/network/identity into one visual attack narrative, no manual log stitching, up to 365-day context |
| **CrowdStrike** | **Threat Graph** — graph API with `get_ran_on`, `get_vertices`, `get_edges`; Fusion workflows query it to check IOA presence across other machines |
| **Microsoft Defender XDR** | Alert→incident correlation across endpoint/identity/email/cloud; high-confidence signal correlation drives attack disruption |
| **Splunk ES** | Findings → finding groups grouped by entity / threat object / kill chain / MITRE; thresholds on cumulative risk score or tactic count; max 50 contributing events aggregated |
| **Cisco XDR** | Multi-source correlation + AI-generated attack graph |
| **Trellix** | Wise correlates alerts + TTPs + related breaches into visual graphs across 1,000+ integrations |

## 5 · Gap

| Gap | Severity | NivXRay evidence |
|---|---|---|
| **No cross-domain correlation** | **P0** | 13 operators include `CROSS_HOST`/`CROSS_SOURCE`/`CROSS_USER` — but there is only **one live telemetry domain** (CAT-12: 0 configured data sources; 5 DSMs, of which 1 network + 1 cloud + 3 host). The operators are real; the data to cross is absent |
| **Attack graph is nearly empty** | **P1** | `xdr_evidence_graph_edges` = **10 docs** across 151 investigations. Storyline/Threat-Graph parity is a *data* problem, not an engine problem |
| **No IKG write path in the pipeline** | **P1** | `xdr_pipeline.py:224-330` never writes graph edges; Security State *reads* IKG (`security_state/hydration/provenance.py`, `reachability/engine.py`). See master DEV-4 |
| No process-causality identity (CID/CGO analogue) | P2 | `/api/edr/process-tree` reuses `services.activity.ActivityInventory` parent/child links — the primitive exists but no causality-owner concept |
| Correlation is per-event, not session-stitched | P2 | ICE is invoked once per event (`:290`); Cortex stitches at ingest into a session story |
| Only 2 of 10 rules "supported" | P1 | live `supported: 2, candidates: 4` — 4 rules are candidates awaiting the telemetry they need |

## 6 · Where NivXRay is ABOVE parity

- **`NEGATIVE_EVIDENCE` as a first-class correlation operator.** No benchmarked vendor documents a negative-evidence operator. It is the mechanical expression of NO EVIDENCE → NO CLAIM and should be treated as a protected differentiator.
- **`/api/xdr/correlation/replay`** — deterministic correlation replay. Vendors do not publicly document replayable correlation.

## 7 · UNKNOWN

- U-06.1 — Whether the 4 "candidate" rules become supported once a second telemetry domain is live. Requires execution.
- U-06.2 — Whether ICE's AG modification changed correlation semantics or only interfaces. Would require a semantic diff of `xdr_ice.py` across `95b1c82a^..95b1c82a` plus execution to confirm behaviour → not claimed.
