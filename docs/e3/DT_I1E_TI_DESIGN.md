# DT-I1E · Threat-Intelligence Normalization Design (Phase 2)

This phase covers the design and contracts only. There are no provider clients, no network calls, and no E1 changes.

- **Contract:** `backend/edr_investigation/ti_contracts.py` (`dt-i1e.ti.v1`)
- **Tests:** `backend/tests/edr_investigation/test_dt_ti_contracts.py`, using recorded synthetic shapes in `fixtures/ti_recorded_responses.json`

## Flow
```
OBSERVABLE → normalize_observable (refang, canonical form, type check)
  → TIBroker (tenant_id mandatory)
    → ProviderRoute per provider (supported types · scope GLOBAL|TENANT · ttl_s · quota)
      → existing client wrapped by an adapter (A / B / C / H output shape → NormalizedTIResult)
  → NormalizedTIResult (one per provider; never collapsed into a verdict)
  → ProviderProvenance (client, adapter@version, source_verdict, verdict_origin, raw_ref, basis)
  → cache_state / freshness / stale_state / failure_reason
  → ReputationHistory (append-only) → IntelChangeEvent (INTEL_CHANGE) → future DT-I1G replay
```

## States (kept distinct)
`MALICIOUS · SUSPICIOUS · BENIGN · UNKNOWN · NO_DATA · NO_HIT · UNAVAILABLE · RATE_LIMITED · ERROR · STALE`

- **Judgement states:** MALICIOUS, SUSPICIOUS and BENIGN require a verdict the provider actually returned (`source_verdict`) and no failure.
- **BENIGN** additionally requires `basis = PROVIDER_ASSERTED_KNOWN_GOOD`. Only H (`KNOWN_GOOD`, e.g. a local allowlist) can produce it. None of the existing A, B or C output shapes carries a known-good assertion, so none ever yields BENIGN.
- **Legacy "clean"** maps to NO_HIT (not found / not listed) or UNKNOWN (0 detections, low score), with the raw label kept in provenance.
- **Failure states** (UNAVAILABLE, RATE_LIMITED, ERROR) state a `failure_reason` and carry no verdict.
  - 429, "rate limit" or "quota" text maps to RATE_LIMITED.
  - A missing key maps to UNAVAILABLE `NOT_CONFIGURED`.
  - A local quota maps to RATE_LIMITED `LOCAL_QUOTA_EXHAUSTED`.
- **STALE** names its `stale_state` and has `cache_state = HIT_STALE`. A failure on refresh serves the prior answer as STALE, never as fresh, and the cache is never overwritten.
- **Confidence** is allowed only on judgements, in the range [0, 1].
- **verdict_origin:** PROVIDER_NATIVE (H), CLIENT_DERIVED (thresholds computed by A or C), or NONE. B returns raw counts, which are kept in `reputation`; no verdict is invented from them.

## Tenancy
- **GLOBAL intel** (VT, AbuseIPDB, OTX, feeds) is shareable. Its cache key is `ti:v1:global:{provider}:{type}:{value}` and the result never stores tenant evidence.
- **TENANT intel** (e.g. LocalIOC with `tenant_scope`) uses the key `ti:v1:tenant:{tenant_id}:…`. A tenant_id is required; there is no default tenant.
- **Tenant evidence** is attached only at view time through `to_tenant_view(result, tenant_id, evidence_refs)`. A cross-tenant TENANT result is rejected.
- **The broker** rejects an empty tenant_id, and rejects any adapter result outside its route scope.

## INTEL_CHANGE contract (consumed later; no replay is implemented)
- **What is recorded:** `ReputationHistory.record(result)` appends every lookup, including failures and STALE.
- **When it emits:** an `IntelChangeEvent` is emitted only when the latest *informative* state changes.
  - The informative states are MALICIOUS, SUSPICIOUS, BENIGN, UNKNOWN, NO_HIT and NO_DATA.
  - Failures and STALE never change intel.
  - A first observation and a re-served cached answer are not changes.
- **Event fields:** `event_id` (deterministic), provider, ioc_type, observable, scope, tenant_id, previous/new state, previous/new version, at, `provenance_ref`, `retro_trigger = INTEL_CHANGE` (`edr_investigation.contracts.RETRO_TRIGGERS`), `behavior_replay_reason = INTEL_CHANGED` (`edr_behavior.replay.REASONS`), and schema_version.

## Proposed single authority (PROPOSAL — owner decision)
- **Broker contract:** dt-i1e.ti.v1 as defined here. Its semantics match H; it does not replace H.
- **Live provider authority (candidate): C, `services/ioc_intelligence`.**
  - It is env-keyed.
  - It returns `pending` instead of fabricating a result.
  - It already serves the response executor.
  - It covers VT, AbuseIPDB and keyless providers.
- **Persistent cache tier (candidate): E, `xdr_osint_cache`.** It has per-provider TTLs and stale semantics.
- **Retire as HTTP paths:**
  - A and B (keep their routes as adapters over C).
  - D's VT, AbuseIPDB and OTX calls.
  - F's own cache.
- **Unverified:** which client production uses with live keys. Choosing between A, B and C changes E1 ownership, so it is an **OWNER DECISION**. Nothing is chosen in code.

## E1 changes this design needs (documented, NOT done)
1. **C providers:** emit an explicit "not found" marker (or `verdict="no_hit"`) instead of `"clean"`. Until then the adapter relies on the provider name and detail text, which is brittle.
2. **429 handling:** add it to C `virustotal_abuseipdb` and to A and B.
3. **Trajectory API:** serve normalized TI per frame through the broker. This is an E1 route change.
4. **Key migration:** move the four key stores to one secret store (`security/secret_policy`).
5. **H registration:** register the C adapter in H `ReputationService` (`edr_plane/reputation/providers/ioc_intelligence.py`).

## Limits
- The adapters are verified against recorded synthetic shapes copied from the source code, not live responses.
- The broker cache is a store-independent dict; the persistent tier is not wired.
- Consensus/assessment (DT-I1F) and replay (DT-I1G) are out of scope.
