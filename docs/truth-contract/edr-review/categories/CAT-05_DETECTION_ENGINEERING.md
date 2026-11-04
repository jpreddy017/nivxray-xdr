# CAT-05 · Detection Engineering / Detection Rules

> STRICT READ-ONLY deep-dive. **This is the category where AG contributed the most.**

## 1 · PRE-AG baseline (proven — substantial, and must not be understated)

| Artifact | Evidence at `5d67934e` | Status |
|---|---|---|
| Sigma ingest + strict mode | `backend/detection_content/sigma_ingest.py`, `sigma_strict.py` | IMPLEMENTED |
| NivXRay native Sigma dialect | `backend/detection_content/nivxray_native_sigma.py` | IMPLEMENTED |
| Sigma router / export | `backend/routers/sigma.py`, `backend/sigma_export.py`, `sigma_generator.py` | IMPLEMENTED |
| YARA export | `backend/yara_export.py` | IMPLEMENTED |
| STIX export | `backend/stix_export.py` | IMPLEMENTED |
| Detection harness | `backend/detection_content/detection_harness.py` | IMPLEMENTED |
| Engine registry / classifier / control plane | `engine_registry.py`, `engine_classifier.py`, `engine_control_plane.py` | IMPLEMENTED |
| Capability contract + contract registry | `capability_contract.py`, `contract_registry.py` | IMPLEMENTED |
| Rule binding | `rule_binding.py` | IMPLEMENTED |
| Detection content router | `backend/routers/xdr_detection_content.py` (mounted `server.py:340-341`, sync hook `server.py:849`) | IMPLEMENTED |
| Rule Studio | `apps/nivxray-xdr/src/xdr/pages/XdrRuleStudioPage.jsx`, `XdrDetectionRuleEditorPage.jsx`, `XdrRuleTuningPage.jsx` | IMPLEMENTED |
| Detection stores | `xdr_detection_rules` (98), `xdr_detection_versions` (4,300), `xdr_capability_contracts` (339), `xdr_engines` (339) | IMPLEMENTED |

## 2 · AG delta (large, and 100% AG — never attribute to PRE-AG)

Added at `95b1c82a`:

| Package | Files | Purpose |
|---|---|---|
`detection_content/corpus/` | 10 corpora + `__init__` | `sigma_corpus`, `yara_corpus`, `eql_corpus`, `spl_kql_corpus`, `ioc_threat_intel_corpus`, `behavioral_correlation_corpus`, `hunting_anomaly_corpus`, `adversarial_corpus`, `mapping_response_corpus`, `ot_ics_rmm_corpus` |
`detection_content/translation/` | 13 translators + `base` + `manager` | Sigma, KQL, SPL, EQL, YARA, IOC, behavioral, anomaly, correlation, hunting, mapping |
`detection_content/canonical_ir/` | `models`, `nodes`, `evaluator` | rule **intermediate representation** + evaluator |
`detection_content/validation_framework/` | `gates`, `tiers`, `lifecycle`, `binding_bridge` | content validation gates & lifecycle |
`detection_content/deduplication/` | `engine`, `fingerprint` | content dedup |
`detection_content/library/` | `models`, `registry`, `rules_enterprise` | enterprise rule library + **the registry the pipeline actually calls** |
`detection_content/yara_engine.py` | 1 | YARA runtime |
`detection_content/{correlation_library,corpus_expansion,canonical_content_model,artifact_router,rmm_model,engine_fabric_contracts}.py` | 6 | supporting models |
29 `backend/tests/test_phase2*` files | 29 | AG's own validation suite |

Modified by AG: `contract_registry.py`, `rule_binding.py`, `sigma_strict.py` (PRE-AG files, AG-touched → per the separation rule these three are **POST-AG** for any capability claim).

## 3 · Current state (live)

```
/api/xdr/detection/{status,inventory,policy,sources,sync,versions,ensure-synced}
/api/xdr/detection/rules  (4 paths)
/api/xdr/rule-studio/{status,lanes(3),rules(4)}
/api/admin/content-supply-chain/*  (42 paths)
/api/emit/sigma · /api/cases/{id}/sigma · /api/cases/{id}/yara
/api/corpus/validate (3)
```

**RUNTIME-PROVEN** (live, authenticated):
- `GET /api/xdr/detection/status` → `{"ok":true,"data":{"active_version":{"id":"det_v_cfd8bead7ace4a58","source":"MITRE ATT&CK","outcome":"COMPLETE","stages":{"DISCOVERED":{"status":"OK"},"DOWNLOADED":{"status":"OK","bytes":9088,"sha256":"366b79c5…","acquisition_state":"LIVE"},"PARSED":{"status":"PENDING"},…}}}` — a real content-supply-chain state machine with SHA-pinned artifacts.
- `GET /api/xdr/detection/inventory` → `immutable_truth_commit: d3f7a0a0…`, `content_fabric_registry_framework: {status: IMPLEMENTED_AND_WORKING, module_count: 58, modules_sha256: 962a0a52…}`, and — importantly — the **615 figure is labelled `historical_ag_audit_claim`**, not asserted as runtime truth.
- Pipeline binding: `xdr_pipeline.py:185` `from .library import REGISTRY as DETECTION_REGISTRY`; `:199` `library_matches = DETECTION_REGISTRY.evaluate_event(canonical)` → **AG's library is genuinely wired into the canonical pipeline, not shelved.**

| Dimension | Verdict |
|---|---|
| Implemented | ✅ strong |
| Registered | ✅ 60+ live paths, registry bound into the pipeline |
| Executed | ✅ detection stage `EXECUTED` in the pipeline |
| Runtime-proven | ✅ for status/inventory/registry binding; ⚠️ `PARSED: PENDING` on the active content version |
| Production-ready | 🟡 — content manufacturing is above parity; **outcome measurement is absent** (CAT-02) |

## 4 · Industry benchmark

| Vendor | Detection authoring |
|---|---|
| **Cortex XDR** | **BIOC** rules in XQL (initial retro-scan, then live alerting); **ABIOC** via ML profiles; correlation rules as XQL that can generate issues, write datasets or update lookups; custom prevention rules on agent 7.2+ can terminate a malicious causality chain |
| **Microsoft Defender XDR** | Custom detections from KQL advanced-hunting queries |
| **Splunk ES** | Two-tier: event-based → finding-based detections; mandatory Risk data model + `generate_findings_summary` / `calculate_findings_fields` macros; content management UI |
| **CrowdStrike** | Custom IOAs + Foundry-authored logic |
| **SentinelOne** | Custom STAR rules over OCSF-normalised data |
| **Cisco XDR** | Automation Exchange content (Cisco-managed / verified / community) |
| **Trellix** | Behaviour-based detections mapped to MITRE ATT&CK |

## 5 · Gap

| Gap | Severity | NivXRay evidence |
|---|---|---|
| **No detection outcome measurement** | **P0** (inherited) | 4,300 rule versions with no alert record to score them — CAT-02 |
| No rule test/backtest against retained telemetry | **P1** | `detection_harness.py` + `/api/corpus/validate` test against **corpora**, not against historical telemetry (there is none — CAT-12). Cortex's "retro-scan on BIOC creation" is impossible here |
| Active content version stuck at `PARSED: PENDING` | P1 | live `/api/xdr/detection/status` |
| No suppression / tuning telemetry loop | P1 | `XdrRuleTuningPage.jsx` exists; no per-rule firing statistics to tune with |
| Deduplication engine has nothing to dedup | P2 | AG's `deduplication/{engine,fingerprint}.py` operates on content, not on unpersisted alerts |
| No agent-side prevention rules | P2 | Cortex terminates chains at the endpoint; NivXRay has no agent (CAT-13) |

## 6 · Where NivXRay is ABOVE parity (do not "fix")

- **Content lifecycle governance:** `validation_framework/{gates,tiers,lifecycle}` + `contract_registry` + SHA-pinned acquisition + `xdr_detection_versions` (4,300) + `immutable_truth_commit` is **stricter than any benchmarked vendor documents publicly.**
- **Multi-dialect translation:** 13 translators (Sigma/KQL/SPL/EQL/YARA/IOC/behavioral/anomaly/correlation/hunting/mapping) via a **canonical IR**. Vendors translate *into* their own dialect; NivXRay translates across dialects.

## 7 · UNKNOWN

- U-05.1 — The **615 active-certified content objects** claim (master U-1). The API itself flags it as historical. Mongo shows 98 rules / 339 capability contracts / 339 engines. **Not manufactured, not confirmed.**
- U-05.2 — Whether all 10 AG corpora are loaded at runtime or only imported. Requires execution.
- U-05.3 — Decoder count (master U-2) — out of scope.
