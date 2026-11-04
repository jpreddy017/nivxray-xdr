# CAT-02 · Alerts and Alert Triage

> STRICT READ-ONLY deep-dive. **This is the single most consequential finding of the audit.**

## 1 · PRE-AG baseline

**NOT IMPLEMENTED.** No alert object, collection, model, router or engine existed at `5d67934e`.

Search evidence:
- `git ls-tree -r --name-only 5d67934e -- backend/routers` → no `alert*` router.
- No `xdr_alert*` module in `backend/detection_content/` at the PRE-AG anchor.

## 2 · AG delta

**NONE.** AG added detection-content manufacturing (corpora, translators, IR, validation gates) but **no alert tier**. `git diff --name-status 95b1c82a^ 95b1c82a` contains no file matching `alert`.

## 3 · Current state (live, HEAD `869f7336`)

```
$ live GET /api/openapi.json  →  733 paths
$ paths matching /alert/i     →  0
$ Mongo collections matching /alert/i → 0
```

**Status: NOT IMPLEMENTED.** There is no alert entity anywhere in NivXRay XDR.

### What exists instead

The canonical pipeline goes **detection → incident directly**:

| Step | Evidence |
|---|---|
| Detection evaluation | `backend/detection_content/xdr_pipeline.py:179` `evaluate_detection(canonical)`; delegates to `library.REGISTRY.evaluate_event` at `:185-199` |
| Detection stage record | `xdr_pipeline.py:266-271` — `_s("detection", "EXECUTED", detection_status=…, matched=…, engine_id=…, rule_id=…)` |
| Straight to incident | `xdr_pipeline.py:305` `materialise_incident(db, canonical, iue, ice, detection, verdict, trace_id)` — gated; emits `NOT_CREATED` + `reason` when the gate is not met (`:314-317`) |

So a detection match is either **promoted to a full incident** or **discarded with a reason**. There is no persisted, triageable, tunable intermediate object.

### Triage surface that does exist

| Surface | Evidence | What it triages |
|---|---|---|
| `/api/xdr/mss/soc-queue` | live | **incidents**, not alerts |
| `/api/xdr/incidents/bulk/assign`, `/bulk/state` | live | **incidents** |
| `/api/incidents/{id}/assignee`, `/state` | live | **incidents** |
| `xdr_analyst_annotations` (31 docs) | Mongo | incident-level analyst notes |
| `/api/corrections/verdict-mark`, `/api/corrections/{id}/approve` | live | **verdict corrections** — the closest thing to FP feedback, but it operates on verdicts, not alerts |

## 4 · Industry benchmark — every benchmarked vendor has an alert tier

| Vendor | Alert tier evidence |
|---|---|
| **Microsoft Defender XDR** | Alerts from Defender for Endpoint/Identity/Cloud Apps/Office 365 + Sentinel are aggregated into incidents; the incident queue filters explicitly **by detection source and alert severity**; alerts are separately queryable in advanced hunting |
| **Cortex XDR** | BIOC/ABIOC rules raise **issues/alerts** which are then grouped into incidents; a BIOC scan runs against existing data then alerts on new matches |
| **Cisco XDR** | Incident Manager "centralises high-priority **alerts** correlated from various sources" |
| **CrowdStrike** | Fusion SOAR triggers on **detections** or incidents as distinct event types |
| **SentinelOne** | Purple AI Agentic Investigation triggers "when critical **alerts** are flagged"; verdicts are TP/FP/Unknown per alert |
| **Splunk ES** | Two-tier by design: event-based detections → **intermediate findings** in the risk index → finding-based detections → finding groups |
| **Trellix** | Wise correlates **alerts** + TTPs into graphs |

## 5 · Gap — P0

| Consequence of having no alert tier | Evidence it is already hurting NivXRay |
|---|---|
| **Detection quality is unmeasurable** | 98 rules and **4,300 rule versions** exist (`xdr_detection_rules`, `xdr_detection_versions`) with no per-detection outcome record to tune against |
| **No FP/TP feedback loop into detection engineering** | the only feedback path is `/api/corrections/*` on *verdicts* (`verdict_shadow_observations` = 280) — it cannot attribute a FP back to a rule |
| **Incident volume is misleading** | `xdr_incidents` = **1** doc. Either the gate is near-always closed or detections are silently dropped; without an alert record it is **impossible to tell which** |
| **No suppression / dedup at the alert layer** | AG shipped `detection_content/deduplication/{engine,fingerprint}.py`, which has nothing to deduplicate because no alert objects are persisted |
| **No triage SLA plane** | `XdrShell.jsx:76` `{ key: "sla-aging", … disabled: true }` — the tab is disabled because there is nothing to age |

**Recommendation (justified by NivXRay evidence, not by vendor parity):** introduce a persisted alert record between `evaluate_detection` and `materialise_incident`. It is the missing measurement substrate for the 4,300 rule versions that already exist, and it is what makes AG's already-shipped deduplication engine reachable. This is a **new persisted projection**, not a new reasoning engine — it does not violate the single-engine rule.

## 6 · UNKNOWN

- U-02.1 — How many detections have fired historically. Without an alert record there is no counter; `xdr_correlation_matches` (21) and `xdr_incidents` (1) are the only downstream traces. **Unrecoverable from the current schema.**
- U-02.2 — Whether the incident gate in `materialise_incident` is intentionally strict or misconfigured. Determining this requires executing the pipeline → out of read-only scope.
