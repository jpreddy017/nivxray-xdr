# CAT-11 · Threat Intelligence / IOC / MITRE / YARA / Enrichment

> STRICT READ-ONLY deep-dive. **This is the category where PRE-AG NivXRay is at or above industry parity, and where AG contributed essentially nothing.**

## 1 · PRE-AG baseline (proven — deep, and 100% original NivXRay)

| Plane | Artifact | Runtime volume |
|---|---|---|
| OSINT | `backend/osint.py`, `/api/osint/lookup`, `/api/admin/osint/{services,settings,test/{id}}` | `xdr_osint_cache` 18 |
| MITRE ATT&CK | `backend/mitre_catalogue/`, `/api/mitre/{catalogue,catalogue/coverage,heatmap,heatmap/probe,heatmap/tactic/{name}}`, `/api/v2/cases/{id}/mitre/coverage` | `xdr_framework_mappings` **1,094** |
| Framework mapping engine | `detection_content/xdr_framework_mapping.py` | 1,094 mappings |
| LOLBAS | `backend/lolbas.py`, `lolbas_chain.py`, 12 `/api/*lolbas*` paths incl. `/coverage`, `/match`, `/primitives`, `/versions`, `/rollback` | `xdr_lolbas_primitives` **11,196** · `xdr_lolbas_entries` 242 · `xdr_lolbas_versions` 13 |
| TI feeds | `backend/ti_feed_sync.py`, `feeds.py`, `/api/threat-intel/{config,feeds/status,feeds/sync,iocs,lookup/{value},enrich,enrich-batch}` | `ti_sync_runs` **1,894** · `ti_source_meta` 8 |
| TI RSS / trending | `routers/threat_intel_rss.py` — 8 paths incl. `/pending/promote-high-confidence`, `/trending` | — |
| TAXII / STIX | `backend/taxii/`, `stix_export.py`, `/api/admin/taxii/{config,history,push,test}` | `taxii_push_log` **91** · `taxii_config` 1 |
| Enrichment | `backend/threat_intel_enrich/`, `/api/enrichment/{ioc,bulk,classify,config}`, `/api/ioc/{enrich,enrich/one,health}` | `v2_enrichment_cache` 0 |
| YARA | `backend/yara_export.py`, `/api/cases/{id}/yara` | — |
| Sigma | `backend/sigma_export.py`, `sigma_generator.py`, `/api/emit/sigma`, `/api/cases/{id}/sigma` | see CAT-05 |
| IOC intelligence | `routers/ioc_intelligence.py`, `services/ioc_intelligence/providers/` (incl. Hybrid Analysis) | `xdr_intelligence_observations` 172 |
| Threat family | `detection_content/xdr_threat_family.py`, `/api/admin/content-supply-chain/incidents/{id}/threat-family` | — |
| Mitigation intelligence | `detection_content/xdr_mitigation_intelligence.py`, `routers/mitigations_evidence_driven.py` | `xdr_recommendations` 688 |
| Knowledge base | `/api/kb/{entries,entries/{slug},search,rebuild,save-from-investigation,stats}` | — |
| CVE / exposure | 9 `/api/xdr/cve/*` paths | `xdr_cve` 12 · `xdr_cve_assets` 24 · `xdr_cve_exposures` 16 · `xdr_cve_software` 16 |
| Intelligence policy | `/api/intelligence/policy/*` + `/api/intelligence/health` | `xdr_intelligence_policy_audit` **251** · `_global` 8 · `_incident` 1 |
| Intelligence overlays | `routers/intelligence_overlay.py` — per-field overlay + history | `xdr_intelligence_overlays` 9 · `_audit` 12 |
| Configured OSINT providers | `memory/test_credentials.md` — VirusTotal, AbuseIPDB, URLScan.io, AlienVault OTX, Hybrid Analysis, all **configured** | — |

Boundary proof: `git ls-tree -r --name-only 5d67934e -- backend/threat_intel_enrich backend/mitre_catalogue backend/osint.py` → **8 files present pre-AG**; none appear in the AG diff.

## 2 · AG delta

| Change | Type |
|---|---|
| `detection_content/corpus/ioc_threat_intel_corpus.py` | ADDED — corpus content |
| `detection_content/translation/ioc_translator.py`, `mapping_translator.py` | ADDED — dialect translation |
| `detection_content/yara_engine.py` | ADDED — **YARA runtime** (PRE-AG had YARA *export* only) |
| Everything else in this category | **PRE-AG, Emergent-authoritative** |

**AG's only genuine TI capability addition is the YARA runtime engine.**

## 3 · Current state (live)

30+ TI/IOC/MITRE paths live. RUNTIME-PROVEN by volume: 1,894 TI sync runs · 11,196 LOLBAS primitives · 1,094 framework mappings · 91 TAXII pushes · 251 intelligence-policy audit records.

| Dimension | Verdict |
|---|---|
| Implemented | ✅ deep |
| Registered | ✅ 30+ live paths |
| Executed | ✅ |
| Runtime-proven | ✅ highest-volume real data in the product |
| Production-ready | 🟢 **yes — this plane is the most production-ready in NivXRay XDR** |

## 4 · Industry benchmark

| Vendor | TI capability |
|---|---|
| **Trellix** | Strongest documented TI story: 1,000+ sources, Advanced Research Center, intel from 40,000 organisations; **Insights** predicts whether current countermeasures stop a given attack and prioritises by sector/geography |
| **Microsoft Defender XDR** | Threat Analytics reports; TI-driven detections |
| **CrowdStrike** | Falcon Intelligence + Threat Graph IOA/indicator lookup (`get_ran_on`) |
| **Cortex XDR** | WildFire/Unit-42 intel feeding BIOCs |
| **SentinelOne** | Intel over OCSF-normalised data lake |
| **Cisco XDR** | Talos intel across integrated products |
| **Splunk ES** | Threat-intel framework (weaker than the RBA/detection story) |

## 5 · Gap — genuinely small

| Gap | Severity | NivXRay evidence |
|---|---|---|
| Enrichment cache unpopulated | P2 | `v2_enrichment_cache` = **0 docs** while `xdr_osint_cache` = 18. Two cache paths; one unused |
| No "would my countermeasures stop this?" projection | P2 | Trellix Insights is the benchmark. NivXRay has the ingredients — `xdr_framework_mappings` (1,094), `/api/mitre/catalogue/coverage`, `xdr_detection_rules` (98) — and no composed answer. **This is a projection away, and it is a differentiator-grade one** |
| TI not joined to entity records | P1 (inherited) | CAT-10 — enrichment is lookup-by-value, not entity-attached, because no entity record exists |
| No malware-family intelligence surface | P2 | `XdrShell.jsx:111` `malware` tab is enabled; only `xdr_threat_family.py` + `response-strategies/{family}` back it |
| YARA runtime not surfaced | P2 | AG's `yara_engine.py` has no live API path of its own (`/api/cases/{id}/yara` is the PRE-AG *export*) |
| TI feed provenance/licence governance | — | **Already present** — `UNIVERSAL_DECODER_LICENSE_MATRIX.md`, `test_phase2_1_license_policy.py`. Above parity |

## 6 · Where NivXRay is ABOVE parity — protect this

1. **LOLBAS depth: 11,196 primitives, 242 entries, 13 versions, with `/coverage`, `/match`, `/rollback`.** No benchmarked vendor documents a versioned, rollback-capable LOLBAS primitive corpus.
2. **Intelligence *policy* plane** — per-global/per-incident/per-scope control of how intelligence is applied, with 251 audit records and effective-policy resolution. Vendors let you *ingest* intel; NivXRay governs *how it is allowed to influence a verdict*.
3. **Intelligence overlays with per-field history** — field-level intel attribution and history (`/api/incidents/{id}/intelligence/overlays/{target_kind}/{target_id}/{field_key}/history`). Directly serves NO EVIDENCE → NO CLAIM.
4. **TAXII push (91 records)** — NivXRay both consumes *and publishes* intel.

## 7 · UNKNOWN

- U-11.1 — Whether all 5 configured OSINT providers currently authenticate successfully. `/api/admin/osint/test/{service_id}` exists; **not executed** (read-only, and it would make outbound calls).
- U-11.2 — Freshness of the 1,894 sync runs (last-success timestamp not sampled).
