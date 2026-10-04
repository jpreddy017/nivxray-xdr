# DT-I1E · Threat-Intelligence Inventory (Phase 1)

This inventory is read-only. It was verified against the source at `6185974b` on `feature/e3-edr-engines`.

**Classification vocabulary:** EXISTS_AND_PROVEN, EXISTS_PARTIAL, EXISTS_NOT_WIRED, DUPLICATED, MISSING, DEFERRED.

**Earlier sources:** the ownership register (`/app/memory/NIVXFORGE_EDR_OWNERSHIP_REGISTER.md` §3) and the consolidation proposal (`NIVXFORGE_E1_CONSOLIDATION_PROPOSAL.md` D6). Each claim from them was re-checked below.

## 1. Provider clients

| ID | Client · file:function | Providers | Classification | Notes from source |
|---|---|---|---|---|
| A | `backend/enrichment/__init__.py`: `_lookup_virustotal`, `_lookup_otx`, `_lookup_abuseipdb`, `_verdict_from_ratio` | VirusTotal, OTX, AbuseIPDB | DUPLICATED · EXISTS_PARTIAL | `_verdict_from_ratio` returns `"clean"` for 0 detections, and OTX with no pulses → `"clean"`. **A label of "clean" is not a known-good assertion.** VT 404 → `"unknown"` with `details.status=404`. No 429 handling (generic `error`). |
| B | `backend/threat_intel_enrich/__init__.py`: `_lookup_virustotal`, `_lookup_otx`, `_lookup_abuseipdb`, `enrich` | VirusTotal, OTX, AbuseIPDB | DUPLICATED · EXISTS_PARTIAL | Returns raw counts (`status: ok`, plus malicious/harmless/…, `pulse_count`, `abuse_confidence_score`); no verdict label. 404 → `status: not-found`; `no-key` / `disabled`. No 429 handling. |
| C | `backend/services/ioc_intelligence/`: `engine.enrich_ioc`, `_fan_out`, `_safe`; `consensus.build_card`; `providers/virustotal_abuseipdb.lookup_virustotal` / `lookup_abuseipdb`; plus keyless `talos`, `dshield`, `urlhaus`, `threatfox`, `malwarebazaar`, `urlscan`, `hybrid_analysis` | VT, AbuseIPDB + 7 more | EXISTS_PARTIAL (**candidate authority**) | `source` ∈ live/cache/pending/error. Missing key → `pending` (not fabricated). **Defect:** a "not found / not listed" result maps to `verdict="clean"` in VT 404 (`virustotal_abuseipdb.py:50`), talos, dshield, threatfox, malwarebazaar (`hash_not_found`), urlhaus and hybrid_analysis. AbuseIPDB score < 0.3 → `"clean"`. Only `urlscan.py:45` handles HTTP 429. `consensus._consensus` keeps "unknown" when there is no live data. Callers: `routers/ioc_intelligence.py`, `detection_content/xdr_response_executor.py:150`, `services/session/summary_narrative.py`. |
| D | `backend/osint.py`: `_virustotal_ip/_domain/_url/_hash`, `_abuseipdb`, `_otx`, `_shodan_ip`, `_greynoise`, `_urlscan_search`, `_ipinfo`, `_hybrid_analysis_hash`, `enrich_iocs` | VT, AbuseIPDB, OTX, Shodan, GreyNoise, URLScan, IPinfo, HA | DUPLICATED | Keys come from Mongo `settings`. No cache in the file. Used by the analysis/decoder path. |
| E | `backend/detection_content/xdr_osint_cache.py`: `read`, `write`, `fetch`, `ttl_for` | cache layer | EXISTS_NOT_WIRED (for EDR/DT) | Per-provider TTLs: talos/dshield/urlhaus/threatfox 6 h, abuseipdb/urlscan 12 h, VT/malwarebazaar 24 h, consensus 1 h. Has a stale flag. Mongo `xdr_osint_cache`. This is the best existing persistent-tier candidate. |
| F | `backend/nivxforge/investigation/osint_enricher.py`: `enrich_cio`, `_project_virustotal`, `_project_abuseipdb`, `_project_otx`, `_aggregate` | projections over D and `db.iocs` | DUPLICATED | In-memory cache, 300 s. Projects each provider into its own card shapes. |
| G | `backend/feeds.py`: `fetch_otx`, `fetch_abuseipdb`, `fetch_threatfox`, …, `sync_source`; `backend/ti_feed_sync.py`: `_up`, `_pull_*` | bulk feeds | EXISTS_PARTIAL | Writes `db.iocs`. That collection is read by `detection_content/ioc_watchlist.py` and by `edr_plane/reputation/providers/local_ioc.py`. |
| H | `backend/edr_plane/reputation/`: `contract.ReputationResult`, `service.ReputationService._lookup_one/_from_cache/_cache_key`, `providers/local_ioc.LocalIOCProvider` | LocalIOC only | EXISTS_NOT_WIRED | **This is the best contract.** Its verdicts are KNOWN_MALICIOUS, KNOWN_GOOD, UNKNOWN (≠ benign), LOOKUP_FAILED and NOT_SUPPORTED. It distinguishes fresh and stale cache hits, and its cache key is tenant-keyed (`service.py:136`). There is no runtime caller. |

**Verified counts:**
- Live VT/AbuseIPDB HTTP implementations: 4 (A, B, C, D). OTX is implemented in A, B and D, and as a feed in G.
- Key stores: 4, all verified. They are env vars (C: `VT_API_KEY`/`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `ABUSE_CH_AUTH_KEY`, `URLSCAN_API_KEY`, `HYBRID_ANALYSIS_API_KEY`), Mongo `enrichment_config` (A, singleton), Mongo `threat_intel_config` (B), and Mongo `settings` (D, F, G).
  - The earlier register said "3 + A UNVERIFIED". A's collection is now verified as `enrichment_config`.
- Caches: 7, which is more than the earlier "5":
  - `enrichment_cache` (24 h)
  - `threat_intel_cache` (60 min)
  - C in-process (6 h, `cache.py`)
  - `xdr_osint_cache` (per-provider 1–24 h)
  - F in-process (300 s)
  - C dshield/talos list caches (15 min)
  - H `ReputationService` in-process (3600 s, tenant-keyed)

## 2. Models, state and handling

| Concern | Locations | Classification |
|---|---|---|
| IOC models | `canonical/ssot/models.py::IOCProjection`, `nivxforge/cim/fact_substrate.py::IOCRecord`, `engine/models.py::IOCBundle`, `v2/investigation/analyst_report/models.py::IOC`, `l2_investigation/schemas.py::IocEvidence`, `edr_plane/reputation/contract.py::Observable` | DUPLICATED |
| IOC extraction / normalization | `edr_plane/reputation/observables.extract`, `services/ioc_intelligence/engine._normalize`, `detection_content/xdr_iue._extract_entities`, `services/die/ioc_semantic.py`, `decoders/ioc_extractor.py::IocExtractor` | DUPLICATED (no single refang/canonical form) |
| Reputation / disposition models | C `schema.ProviderVerdict` / `IocCard`; H `ReputationResult`; DT `edr_investigation/contracts.TIResult` | DUPLICATED |
| TTL logic | A `DEFAULT_TTL_HOURS`, B `CACHE_TTL_MIN`, C `cache._TTL_SECONDS`, E `_PROVIDER_TTL`, F `_CACHE_TTL_S`, H `DEFAULT_TTL_SECONDS` | DUPLICATED |
| Quota / rate limiting | Only C `urlscan.py:45` (HTTP 429 → unknown + detail). No quota accounting anywhere (`grep quota` finds nothing in A/B/C/D/E/H). | MISSING |
| Stale semantics | H `CACHE_HIT_STALE`; E stale flag. A, B and C have none (they evict silently). | EXISTS_PARTIAL |
| Provider health | C `health.provider_health` (env-key presence only) | EXISTS_PARTIAL |
| Tenant separation | H only (tenant in cache key; LocalIOC tenant scope). A–G caches are global, with no tenant notion. | EXISTS_PARTIAL |

## 3. Device Trajectory TI rendering

| Item | Location | Classification |
|---|---|---|
| DT TI section | `frontend/src/v2/investigation/activityView.mjs::tiSection` | EXISTS_PARTIAL. It renders per-provider rows and degradation statements, but the trajectory API serves no TI; the rows come from fixtures only. |
| DT TI view mapping | `backend/edr_investigation/ti.py::normalize_ioc_card` | EXISTS_PARTIAL, **with a defect fixed in this phase**. It mapped C's `"clean"` → BENIGN, so NO_HIT became BENIGN. It now routes through the dt-i1e.ti.v1 C adapter. |
| TI → trajectory API wiring | none | MISSING (E1 route change; documented in the design, not done) |

## 4. Retrospective hooks

| Hook | Location | Classification |
|---|---|---|
| Behavioral replay reason `INTEL_CHANGED` | `edr_behavior/replay.py::REASONS`, `ReplayRequest` | EXISTS_NOT_WIRED (no INTEL producer) |
| Assessment history trigger `INTEL_CHANGE` / `REPUTATION_CHANGE` | `edr_investigation/contracts.py::RETRO_TRIGGERS`, `RetroEntry` | EXISTS_PARTIAL (contract only) |
| ML retro | `edr_ml/*` | MISSING (no retro hook) |
| Detection replay | `edr_plane/detection_replay.py::replay_endpoint` | EXISTS_PARTIAL (rule-set fingerprint; not intel-triggered) |
| INTEL_CHANGE event producer | none until now | MISSING. Contract added in `edr_investigation/ti_contracts.py`; replay is DEFERRED to DT-I1G. |

## 5. Duplication findings (summary)
1. Four live VT/AbuseIPDB HTTP implementations (A, B, C, D) and three OTX implementations (A, B, D).
2. Four key stores and seven caches with conflicting TTLs. The same IOC can get different answers depending on which route asked.
3. "clean" is overloaded across A and C. It means "not found", "not listed", "0 detections" or "low score", and none of these is a known-good assertion.
4. Rate limiting is handled in one provider only; there is no quota accounting.
5. Only H separates tenants; every other cache is global with no tenant notion.
6. There are six IOC models and five IOC extractors.
