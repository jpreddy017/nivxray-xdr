# NIVXFORGE_SHARED_TI_INTEGRATION_DESIGN

**MODE:** READ-ONLY DISCOVERY + DESIGN ONLY · **no code changed, nothing deployed, nothing executed**
**Date:** 2026-06
**Isolation from STEP 35:** total. No file touched. STEP 35 apply/revert not run, the 1,236 rows
unmodified, Behavior not run, no KUSHU canary prepared, DESKTOP-A9HGFJJ untouched, no sensor or
provider configuration changed, no ThreatFox/AbuseIPDB/Talos credential troubleshooting, no index
or production DB change, no UI.

---

## HEADLINE FINDING — READ THIS FIRST

**The shared normalized TI contract you asked me to design already exists, is written, and is
tested. It is simply not wired to anything.**

`backend/edr_investigation/ti_contracts.py` (schema `dt-i1e.ti.v1`, 436 lines) is a
store-independent, network-free normalization contract with **adapters over all four existing TI
clients**, a broker with TTL/quota/scope, tenant-vs-global cache keys, stale semantics, and an
`IntelChangeEvent` already bound to the retrospection triggers. Its own module docstring states
the exact principle you sent me:

> "A provider result is EVIDENCE, never final verdict authority. NO_DATA / NO_HIT / UNAVAILABLE /
> RATE_LIMITED / ERROR / STALE never become BENIGN. BENIGN exists only where a provider
> affirmatively asserts known-good."

And `backend/edr_plane/reputation/` (B4, 732 lines, `tests/edr/test_b4_reputation.py`) is the
EDR-side observable→provider→result path, also already written.

So this task is **not a design problem. It is a wiring problem.** Designing a new contract would
have been the third parallel TI stack in this repository. The rest of this report therefore
documents what exists, names the five wiring gaps precisely, and proposes the minimum work to
close them.

---

## EXISTING_NIVX_TI_ARCHITECTURE

There are **four independent TI clients**, one shared indicator store, and **two** already-written
normalization layers. Established from code and live preview data, not from the UI.

### Client A — `backend/enrichment/` (394 lines)
Provider-verdict enrichment returning `{provider, verdict, score, sources, details, queried_at,
_cached}`. Verdict vocabulary includes a literal `"clean"` and `"no-key"`.

### Client B — `backend/threat_intel_enrich/` (323 lines)
VirusTotal / OTX / AbuseIPDB. **Admin-configured keys stored in MongoDB**, not env:
`threat_intel_config` (singleton doc) with `_redact()` on read. Cache in `threat_intel_cache`,
60-minute TTL, SHA-256 key over `(provider, kind, value)`. Returns **raw counts, never a verdict
label** — the most honest of the four. `detect_kind()` supports url/ip/domain/md5/sha1/sha256.
Live: `threat_intel_cache` is empty, so this path is effectively dormant.

### Client C — `backend/services/ioc_intelligence/` (1,383 lines)
Live fan-out across **nine** providers — malwarebazaar, threatfox, urlhaus, urlscan,
hybrid-analysis, talos, dshield, virustotal, abuseipdb — `asyncio.gather`, 10s per-provider
timeout, `_safe()` wrapper so a provider failure degrades to `pending`/`error` rather than raising.
A weighted **consensus engine** (`consensus.py`) produces one `IocCard` with
`verdict · trust_score · confidence_percent · evidence[]`. Cache is `cache.py`: **process-local,
in-memory, 6h TTL, 4,096 entries, FIFO, keyed `(kind, value.lower())` with NO tenant component.**

### Client H — `backend/edr_plane/reputation/` (B4, 732 lines) — the EDR-native one
This is the good one, and it already satisfies most of your section-3 brief:
* `contract.py` — observable types `SHA256 · SHA1 · MD5 · DOMAIN · IP · URL`; **subjects**
  (`PROCESS_IMAGE · FILE_CONTENT · NETWORK_PEER · DNS_QUESTION · URL_RESOURCE`) so a process-image
  hash is never confused with a written-file hash; verdicts
  `KNOWN_MALICIOUS · KNOWN_GOOD · UNKNOWN · LOOKUP_FAILED · NOT_SUPPORTED` with
  `INTELLIGENCE_VERDICTS` and `NON_JUDGEMENTS` separated by constant, and a `__post_init__` that
  **raises** if a non-judgement is marked as a match.
* `observables.py` — canonical evidence → observables, read-only, carries `source_field`,
  `evidence_refs`, `tenant_id`, `endpoint_id`, per-field provenance, and already honours G-30
  (identity from `additional_fields.endpoint_id`, never a source host id).
* `service.py` — provider registry + **tenant-keyed cache** (`(provider_id, f"{tenant}|{type}|{value}")`),
  `LOOKUP_FAILED` is **never cached**, freshness via `expires_at` then TTL, and aggregation states
  that are deliberately *not* verdicts: `MALICIOUS_ASSERTED · GOOD_ASSERTED · NO_INTELLIGENCE ·
  NO_LOOKUP_COMPLETED · NOT_SUPPORTED`, with `provider_disagreement` surfaced and every per-provider
  answer retained.
* `providers/local_ioc.py` — the **only registered provider**: reads the `iocs` collection,
  `offline = True`, tenant-scoped entries cannot judge another tenant, and an entry with an
  unreadable `disposition` is `LOOKUP_FAILED` rather than guessed.

### Shared indicator store — `db.iocs` (live preview numbers)
| Property | Observed |
|---|---|
| Documents | **148,262** |
| Indexes | `uniq_ioc {kind,value,source}`, `source_1`, `severity_1`, `last_seen_-1` |
| Sources | abuse.ch/feodo, abuse.ch/urlhaus, alienvault_otx, blocklist.de, cins_army, cisa_kev, feodo_tracker, otx, sans_dshield, urlhaus |
| Kinds | ip, domain, url, md5, sha1, sha256, **and `null` (8,896 rows)** |
| `tenant_id` present | **0** — every indicator is platform-scope |
| `disposition` present | **0** |
| `confidence` present | 134,421 |
| `valid_until` present | **0** — nothing expires |
| Values under >1 source | **0** |

### Synchronization — `backend/ti_feed_sync.py` (266 lines)
`asyncio.create_task` hourly loop armed at server startup, 30s boot delay. Pulls ThreatFox,
URLhaus, Feodo, Blocklist.de, OTX; `bulk_write` upsert on `(kind, value)` with
`$setOnInsert: first_seen`. Writes a receipt per run to `ti_sync_runs`. Latest live receipt:
`{threatfox: 0, urlhaus: 5000, feodo: 5, blocklist_de: 5000, otx: 630, total: 10635}`.
A second, broader ingest path has written `cins_army`, `cisa_kev`, `sans_dshield` into the same
store and maintains **`ti_source_meta`** — 8 documents carrying real
`last_status / last_error / last_sync / total_indicators`, including live
`"HTTP 403 from source"` and `"HTTP 401 from source"`.

### Normalization layer 1 — `edr_investigation/ti_contracts.py` (DT-I1E, `dt-i1e.ti.v1`)
* States: `MALICIOUS · SUSPICIOUS · BENIGN · UNKNOWN · NO_DATA · NO_HIT · UNAVAILABLE ·
  RATE_LIMITED · ERROR · STALE`, partitioned into `JUDGEMENTS`, `FAILURES`, `INFORMATIVE`.
* `BENIGN` is structurally impossible without `basis == PROVIDER_ASSERTED_KNOWN_GOOD` — enforced in
  `__post_init__`, not by convention.
* Adapters for **all four clients**: `adapt_enrichment` (A), `adapt_threat_intel_enrich` (B),
  `adapt_ioc_intelligence` (C), `adapt_edr_reputation` (H). Each maps a legacy `"clean"` to
  `UNKNOWN` or `NO_HIT` — never `BENIGN` — and detects rate-limiting from text.
* `cache_key(scope, provider, obs, tenant_id)`: `GLOBAL` keys **must not** carry a tenant,
  `TENANT` keys **must**; there is **no default tenant**.
* `TIBroker` — per-route TTL, local quota, `mark_stale()` on failure so **a failure never
  overwrites cached intelligence**, and one result per provider with no consensus collapse.
* `ReputationHistory` + `IntelChangeEvent` — append-only; re-serving a cache hit is explicitly not
  new intelligence; emits `retro_trigger = INTEL_CHANGE` and
  `behavior_replay_reason = INTEL_CHANGED`.
* `to_tenant_view()` — tenant evidence refs attach at **view** time; shared GLOBAL intel never
  stores tenant evidence.
* Tested: `tests/edr_investigation/test_dt_ti_contracts.py`.

### Normalization layer 2 — `edr_investigation/ti.py` + `contracts.TIResult`
A per-provider view row; `TIResult.__post_init__` refuses a reputation claim with no provider
provenance. `normalize_ioc_card()` explicitly does **no consensus collapse** so disagreement stays
visible.

### E3 Behavior's intel seam — `edr_behavior/`
Already present and correctly shaped:
* `rules.py` — a stage may declare `intel: {observable_field, observable_type, verdict_in,
  min_confidence, confidence_bonus}`.
* `engine.py::_intel()` — per-rule, per-stage, **deduplicated by `(tenant_id, observable)`**, and
  calls `self.enrichment.lookup(tenant_id=…, observable=…, observable_type=…)`.
* `provider.py` — `EnrichmentProvider` Protocol, `NullEnrichmentProvider` (**the default**, whose
  docstring says "no TI wired. INTEL stages therefore evaluate to UNKNOWN"), and
  `StaticEnrichmentProvider` for replay fixtures.
* `matcher.py::stage_value()` — **three-valued**: no observable → `UNKNOWN`; no enrichment or
  `UNKNOWN` verdict → `UNKNOWN`; a hit requires both `verdict_in` membership **and**
  `confidence >= min_confidence`. A missing lookup can never become a match, and `UNKNOWN`
  propagates rather than silently becoming `FALSE`.
* `replay.py::REASONS` includes `INTEL_CHANGED`; `edr_investigation/contracts.RETRO_TRIGGERS`
  includes `INTEL_CHANGE` **and** `REPUTATION_CHANGE`.

---

## REUSABLE_COMPONENTS

Reuse as-is, no redesign:

| Component | Reuse verdict |
|---|---|
| `edr_investigation/ti_contracts.py` (`dt-i1e.ti.v1`) | **The shared contract.** Adopt it verbatim as the EDR consumption contract. |
| Its four adapters A/B/C/H | Reuse. Every existing client is already mapped. |
| `TIBroker` | Reuse as the single lookup front door (TTL, quota, scope, stale-on-failure). |
| `ReputationHistory` + `IntelChangeEvent` | Reuse as the retrospection contract — it already exists. |
| `edr_plane/reputation/observables.py` | Reuse as the EDR observable extractor (subjects + provenance + G-30 identity). |
| `edr_plane/reputation/contract.py` + `service.py` | Reuse as the EDR-native provider registry and tenant-keyed cache. |
| `edr_plane/reputation/providers/local_ioc.py` | Reuse as the offline provider over `iocs`. |
| `services/ioc_intelligence/` providers | Reuse **behind the boundary** — nine provider adapters, already written. |
| `threat_intel_enrich` config store + `_redact()` | Reuse as the admin credential home. |
| `ti_feed_sync.py` + `db.iocs` + `ti_source_meta` | Reuse as the ingestion/persistence estate. |
| `edr_behavior` intel seam | Reuse. The hook, dedupe, three-valued matcher and replay reason all exist. |

**Nothing in the provider layer needs to be rebuilt.** Not one connector.

---

## EDR_INTEGRATION_GAPS

Five gaps. All are wiring or honesty gaps — none requires a new contract.

### GAP-1 · The shared contract has no production caller *(highest value, lowest risk)*
`ti_contracts.py` is imported by exactly two things: its own test file, and `ti.py` (a view
helper). **`TIBroker` is never constructed outside tests. No `ProviderRoute` exists in production
code.** Likewise `ReputationService` is never instantiated in any router or startup path — B4 is
reachable only from `tests/edr/test_b4_reputation.py` and a measurement script.
*Consequence:* E1/E3 cannot query TI at all today, despite two finished contracts and 148,262
stored indicators.

### GAP-2 · E3 Behavior's enrichment provider is `NullEnrichmentProvider`
Every `INTEL` stage therefore evaluates `UNKNOWN` forever. The seam is right; nothing is plugged
into it. **No `EnrichmentProvider` implementation bridges to `TIBroker`, B4 or `iocs`.**
Secondary issue: `edr_behavior.contracts.Enrichment.verdict ∈ {MALICIOUS, SUSPICIOUS, BENIGN,
UNKNOWN}` has **no failure state**, so at the matcher `e is None` collapses three different
situations — *TI not wired*, *lookup failed*, *nobody knows* — into one `UNKNOWN`. `UNKNOWN` is
honest for all three, but the distinction DT-I1E and B4 both preserve is **lost at the E3
boundary**. That is the one genuine contract extension this work needs.

### GAP-3 · Provider health reports configuration, not health — the G-37 "7/7 live" root
`services/ioc_intelligence/health.py` computes state **purely from env-var presence**:
`"live" if present else "pending"`, with the docstring "no calls happen here; we only inspect env
vars". A provider with a rejected key reports **live**. Meanwhile `ti_source_meta` already holds
the truth (`last_status: "error"`, `last_error: "HTTP 401 from source"`, `last_sync`).
*Also found, reported not fixed (G-37 is deferred by owner instruction):* an **env-var name
mismatch** — `ti_feed_sync.py:61` reads `ABUSECH_AUTH_KEY`, while `health.py` and all three
abuse.ch providers read `ABUSE_CH_AUTH_KEY`. The latest sync receipt shows `threatfox: 0`.
No state vocabulary exists for `HEALTHY / STALE / RATE_LIMITED / AUTH_FAILED / UNAVAILABLE /
NEVER_SYNCED`; DT-I1E has the *result* states but nothing maps a **provider** to them.

### GAP-4 · The shared store cannot express tenant-private policy, disposition or expiry
`db.iocs`: `tenant_id` on **0** of 148,262 rows, `disposition` on **0**, `valid_until` on **0**.
Three consequences:
1. `local_ioc.py` defaults a dispositionless entry to `KNOWN_MALICIOUS` — correct per its stated
   contract, but it means **every one of the 148,262 feed rows is a `KNOWN_MALICIOUS` assertion**,
   including 5,000 `blocklist.de` scanner IPs the feed itself rated `confidence: 50`.
2. No `ALLOW / AUDIT-DETECT / BLOCK` policy can be expressed, and no allow-list is possible
   (`KNOWN_GOOD` must be explicit and nothing sets it).
3. Nothing expires, so staleness cannot be computed from the store.
Query shape: `local_ioc._find()` does `find_one({kind, value})` while the unique index is
`{kind, value, source}` — today harmless (0 values appear under >1 source) but it is a
**latent non-determinism**: the first multi-source indicator will return an arbitrary source's
severity and tags. And 8,896 rows have `kind: null`, so they are unreachable by every lookup path.
There is **no index on `tenant_id`**, which a tenant-scoped store will need.

### GAP-5 · Client C's cache is process-local and tenant-blind
`services/ioc_intelligence/cache.py` keys on `(kind, value.lower())` with **no tenant component**,
in-process, 4,096 entries, FIFO. The moment any tenant-private indicator enters that path, one
tenant's answer can be served to another. B4 and DT-I1E both already key by tenant; C does not.
C must therefore stay **GLOBAL-scope only** until its cache is replaced — a constraint to state
explicitly rather than discover later.

---

## PROPOSED_SHARED_TI_CONTRACT

**Adopt `dt-i1e.ti.v1` as-is.** It already carries every field your brief required:

| Your requirement | Already in the contract |
|---|---|
| observable + type | `observable`, `ioc_type ∈ SHA256·SHA1·MD5·IPV4·IPV6·DOMAIN·URL` |
| source / provider | `provider`, `provenance.source_client`, `provenance.adapter` |
| provider-native reference | `provenance.raw_ref` |
| confidence / reputation | `confidence` (only where a judgement was returned, `[0,1]`), `reputation{}` |
| first_seen / last_seen | `result_at` (intelligence timestamp) + `reputation{}` payload |
| fetched_at | `lookup_at` |
| freshness / staleness | `freshness ∈ FRESH·STALE·UNKNOWN`, `cache_state`, `stale_state` |
| expiration | route `ttl_s`; B4 carries `expires_at` per result |
| tags / classification | `reputation{}` |
| family / campaign / actor | `reputation{}` (C already unions families/campaigns/threat_types) |
| provenance | `ProviderProvenance` with `verdict_origin ∈ PROVIDER_NATIVE·CLIENT_DERIVED·NONE` |
| provider availability state | `UNAVAILABLE · RATE_LIMITED · ERROR` |
| never auto-benign | `BENIGN` requires `basis == PROVIDER_ASSERTED_KNOWN_GOOD`, enforced in `__post_init__` |
| missing stays missing | `UNKNOWN · NO_HIT · NO_DATA` distinct from the three `FAILURES` |
| never manufacture fields | `confidence` is refused unless a judgement was returned; `source_verdict` is `None` when none came back |

**IPv6:** `IOC_TYPES` includes `IPV6` and `normalize_observable` resolves version via
`ipaddress.ip_address`. However `edr_plane/reputation` uses a single `OBS_IP`, and
`observables.py` accepts both versions under it. Reconciling `OBS_IP → IPV4/IPV6` at the adapter
is a small, named task.

**Certificate / signing identity:** **not supported anywhere today** and I am not inventing it.
`IOC_TYPES` has no certificate type, no provider judges one, and `observables.py` extracts no
signer. Adding `OBS_CERT_THUMBPRINT` is a future extension; per your instruction it is recorded as
absent, not manufactured.

**One additive change only** — the E3 boundary (GAP-2):
extend `edr_behavior.contracts.Enrichment` with a non-judgement `state` field carrying the DT-I1E
state, so Behavior can distinguish *we could not ask* from *nobody knows*. `verdict` keeps its
current four values for rule compatibility; `matcher.stage_value` keeps returning `UNKNOWN` for
both, so **detection semantics do not change** — only the provenance a rule and an investigation
can see. Nothing else in any contract needs to change.

---

## E1_INTEGRATION_POINT

```
endpoint telemetry
  → E1 durable raw evidence                      (unchanged, synchronous, no TI)
  → canonical evidence                            (unchanged, no TI)
  → edr_plane.reputation.observables.extract()    ← READ-ONLY, exists
  → TIBroker.lookup(obs, tenant_id=…)             ← route table to be built (GAP-1)
  → enrichment record, keyed to the observable + evidence_refs
```

**Hard rule, already architecturally satisfied:** ingestion must never await a provider. Evidence
durability is synchronous; enrichment is a **separate read-side act**, exactly as `observables.py`
is a read that "never writes evidence". TI is therefore an enrichment record *referencing*
canonical evidence by `evidence_refs`, never a field inside it, and never a canonical event of its
own. An unavailable TI service degrades enrichment and cannot affect ingest.

The `evidence_refs` + `source_field` + `subject` triple already carried by `Observable` is the
provenance link you asked for: it says which value, from which field, about which object, in which
event, caused the lookup.

---

## E3_BEHAVIOR_INTEGRATION_POINT

```
SequenceRule.stages[].intel {observable_field, observable_type, verdict_in, min_confidence}
  → engine._intel()  dedupes by (tenant_id, observable)      ← exists
  → EnrichmentProvider.lookup(tenant_id, observable, type)   ← Protocol exists
  → [GAP-2] an adapter: TIBroker / ReputationService → Enrichment
  → matcher.stage_value() three-valued TRUE / FALSE / UNKNOWN ← exists
```

Properties that are already correct and must be preserved: per-tenant dedupe; a missing observable
or missing enrichment yields `UNKNOWN`, never a match; a hit needs both verdict membership and a
confidence floor; `UNKNOWN` propagates instead of collapsing to `FALSE`.

**The rule that must not be weakened:** an `INTEL` stage is one stage of a sequence. A TI hit
alone cannot satisfy a rule unless an author writes a single-stage intel-only rule — and such a
rule would be a detection *about an indicator*, not a verdict about an endpoint. This is the
`TI_MATCH != MALICIOUS_VERDICT` rule expressed in the engine rather than in a policy document.

---

## INVESTIGATION_INTEGRATION_POINT

```
NormalizedTIResult  →  to_tenant_view(res, tenant_id, evidence_refs)
                    →  edr_investigation.contracts.TIResult  (per provider, no collapse)
                    →  supporting / contradicting / missing evidence
                    →  assessment (TRUE_POSITIVE · FALSE_POSITIVE · EXPECTED_ACTIVITY ·
                                   AUTHORIZED_TEST · …) with the existing certainty model
```

Already enforced in code: `TIResult.__post_init__` refuses a `MALICIOUS/SUSPICIOUS/BENIGN` claim
with no provider; `normalize_ioc_card()` performs no consensus collapse; `to_tenant_view()` rejects
a cross-tenant result. A TI hit enters as **one piece of supporting evidence** alongside process
ancestry, command line, user, signer, prevalence, network behaviour, persistence, behaviour
detections, causal relationships and authorization — and a `RATE_LIMITED` or `UNAVAILABLE` state
should enter the **missing-evidence** channel, because "we could not ask" is a visibility gap, not
an absence of threat.

**Client C's consensus engine must not cross this boundary.** Its `trust_score` /
`confidence_percent` / weighted `verdict` is a presentation device for the XDR IOC card. Feeding a
collapsed consensus into an EDR investigation would re-introduce exactly the single-number verdict
the investigation model exists to avoid. Consume C **per provider, through `adapt_ioc_intelligence`**
— which is precisely what that adapter is for.

---

## RETROSPECTION_CONTRACT

**Also already written** — `ReputationHistory` + `IntelChangeEvent` in `ti_contracts.py`:

* append-only per `(scope, tenant, provider, observable)`;
* re-serving a fresh cache hit returns `None` — **a cache replay is not new intelligence**;
* a change is emitted only between two **informative** states, and only forward
  (`new_version > previous_version`); a failure or `STALE` is recorded but **never** counts as an
  intel change, so a provider outage can never trigger a retrospective sweep;
* carries `previous_state → new_state`, both versions, `at`, `provenance_ref`;
* pre-bound to the consumers: `retro_trigger = INTEL_CHANGE`
  (`edr_investigation.contracts.RETRO_TRIGGERS`) and
  `behavior_replay_reason = INTEL_CHANGED` (`edr_behavior.replay.REASONS`).

This is already compatible with evidence-first architecture: an `IntelChangeEvent` is **new
provenance appended at its own timestamp**. Historical canonical evidence is never rewritten and
nothing pretends we knew earlier. The later reassessment is a new assessment *citing* a new intel
version — which is also why the `authority`/`version` fields matter.

**Not implemented and not to be implemented here:** the sweeper that, on `INTEL_CHANGE`, finds
historical endpoint evidence for the observable and reopens affected investigations. The contract
and both consumer enums exist; the executor does not. Note for later: that sweep is an
observable→evidence reverse lookup, which `db.iocs` and the canonical indexes do not currently
support — it needs its own bounded query design, exactly like STEP 34/35.

---

## CUSTOM_PRIVATE_IOC_READINESS

**Can the current architecture support tenant-private indicators without redesign? YES at the
contract layer, NO at the store layer.**

Ready now:
* `dt-i1e.ti.v1` has `scope ∈ GLOBAL·TENANT`, enforces `(scope == TENANT) == bool(tenant_id)`,
  has separate cache key namespaces, and has **no default tenant**;
* `ProviderRoute.scope` lets a private provider be registered alongside public ones;
* B4's cache is tenant-keyed and `local_ioc._find()` already refuses a cross-tenant entry;
* `ioc_watchlist` carries the same tenant rule: "a watchlist entry scoped to a tenant may only
  judge that tenant's evidence. Unscoped entries are platform threat intel."

Not ready:
* `db.iocs` has **0** tenant-scoped rows, **0** dispositions, **0** expiries, and no `tenant_id`
  index. Private indicators cannot be stored, and `ALLOW / AUDIT-DETECT / BLOCK` cannot be
  expressed at all.
* A policy is **not** intelligence. `ALLOW/AUDIT-DETECT/BLOCK` is a **response policy**, and the
  architecture already separates intelligence from response. It therefore belongs in a
  tenant-scoped, audited policy store — note that
  `xdr_intelligence_policy_global` / `_incident` / `_policy_audit` / `_overlay_audit` collections
  and `services/intelligence_policy/` (358 lines) **already exist** on the XDR side and are the
  obvious reuse candidate. That needs its own discovery pass before anyone designs a second one.

No redesign of the shared contract is required to support private IOCs. The work is a store schema
addition plus a policy decision, both out of scope here.

---

## FUTURE_SANDBOX_COMPATIBILITY

The contract can accept sandbox-derived intelligence **without modification**, provided the
boundary is respected:

* a sandbox is registered as a `ProviderRoute` with `provider_id` naming it, `verdict_origin =
  PROVIDER_NATIVE`, and `provenance.raw_ref` pointing at the analysis;
* its file verdict → a `MALICIOUS/SUSPICIOUS` state on the submitted hash;
* extracted hashes, domains, IPs, URLs and dropped files → **new observables**, each with its own
  lookup and its own result. They must enter as observables, not as fields of the parent verdict;
* behaviour, family and configuration → `reputation{}` payload and `tags`;
* `scope = TENANT` whenever the sample came from a tenant's endpoint — a customer's sample must
  not become global intelligence by default. The contract already forbids a GLOBAL key from
  carrying a tenant.

**The boundary rule:** a sandbox verdict enters as intelligence/evidence and flows through
Investigation. It never becomes a direct response authority and never writes canonical endpoint
evidence — a sandbox observed a file in a sandbox, it did not observe the endpoint.

One genuine extension needed later: dropped-file and configuration artefacts may require
observable types the contract lacks (certificate thumbprint, mutex, registry path). Those are
additions to `IOC_TYPES`, not a redesign.

---

## TENANT_SECURITY_ANALYSIS

| Requirement | Status |
|---|---|
| Tenant isolation — contract | **PASS.** `(scope == TENANT) == bool(tenant_id)`; no default tenant; `to_tenant_view` rejects cross-tenant; broker asserts a route cannot return a result outside its scope. |
| Tenant isolation — B4 cache | **PASS.** Key includes tenant; `local_ioc` refuses a foreign-scoped entry. |
| Tenant isolation — client C cache | **FAIL (GAP-5).** `(kind, value)` only, no tenant. Must stay GLOBAL-scope only. |
| Tenant isolation — store | **N/A today** (0 tenant-scoped rows) and **unenforceable at scale** without a `tenant_id` index. |
| Least privilege | B4's `local_ioc` is `offline = True`: core EDR reputation needs no credential and no network at all. |
| No provider credentials exposed to EDR clients | **PASS by construction** — providers live behind the service boundary; `threat_intel_enrich._redact()` masks keys on config read; `test_34h_a` already asserts no secret leaves the migration surface and the same pattern should be asserted here. |
| No secrets in frontend responses / logs | Client C's `IocCard` docstring states the UI never sees provider raw payloads; `ProviderVerdict.raw` **is** returned inside `sources` for drill-down, so the route that serves it needs an explicit no-secret assertion. **Named risk, not a finding of leakage.** |
| Bounded queries | B4 lookups are exact-match `find_one`; Behavior dedupes per `(tenant, observable)` and caps window events. The one unbounded thing is the retrospective sweep — which is why it is not being built yet. |
| Rate-limit protection | `ProviderRoute.quota` + `_rate_limited()` text detection + `RATE_LIMITED` state. Present in the contract, unused in production (GAP-1). |
| Timeout / failure isolation | Client C: 10s per provider, `_safe()` wrapper. B4: per-provider try/except → `LOOKUP_FAILED`. Broker: exception → recorded `ERROR` state. **Failures never raise into the caller.** |
| Cache safety | B4 **never caches `LOOKUP_FAILED`**; the broker's `mark_stale` means a failure never overwrites good cached intel. Client C caches the whole card including `pending` providers — a staleness risk to note. |
| Provider provenance | `ProviderProvenance` is mandatory on every result. |
| Freshness | `freshness`, `cache_state`, `stale_state`, `ttl_s`, `expires_at`. |
| Auditability | `ReputationHistory` append-only; `ti_sync_runs`; `ti_source_meta`; existing `*_audit` collections on the XDR side. |
| **Ingest never depends on TI** | **PASS architecturally** — TI is a read-side act; `observables.extract()` is a pure read and no ingest path imports any TI client. This must be asserted by a test when wiring happens, because it is the property most easily lost. |

---

## FAILURE/STALE/UNKNOWN_SEMANTICS

Already correct in both written contracts, and the single most valuable thing to preserve:

```
MALICIOUS / SUSPICIOUS   a provider asserted it
BENIGN                   ONLY with basis = PROVIDER_ASSERTED_KNOWN_GOOD
UNKNOWN                  the lookup succeeded; nobody holds reputation. NOT benign
NO_HIT                   the provider answered "not in my list". NOT benign
NO_DATA                  this provider cannot judge this observable type
UNAVAILABLE              not configured / unreachable — we failed to ask
RATE_LIMITED             quota or 429 — we failed to ask
ERROR                    the lookup broke — we failed to ask
STALE                    a prior informative answer served past its TTL; names its prior state
```

B4's equivalent, with aggregation states that are deliberately not verdicts:
`MALICIOUS_ASSERTED · GOOD_ASSERTED · NO_INTELLIGENCE · NO_LOOKUP_COMPLETED · NOT_SUPPORTED`.

**Required provider-level states (your section 2) do not exist yet** and are GAP-3. The proposal is
to derive them from data already being recorded rather than invent a new store:

| Provider state | Derived from |
|---|---|
| `NEVER_SYNCED` | no `ti_source_meta` record and no successful lookup |
| `AUTH_FAILED` | `last_error` 401/403, or an adapter `UNAVAILABLE` with a credential-rejected reason |
| `RATE_LIMITED` | `_rate_limited()` on the last error, or local quota exhausted |
| `UNAVAILABLE` | credentials absent (`pending`), or transport failure |
| `STALE` | `last_sync` older than the source's declared interval |
| `HEALTHY` | last sync or lookup succeeded within interval, no error |

**"Configured" must never render as "healthy."** That is the whole of G-37's misleading
`7/7 live`: today the health endpoint answers a question about env vars and labels it a question
about providers.

---

## COMPARISON_WITH_PUBLICLY_DOCUMENTED_MATURE_EDR_PATTERNS

Public product documentation only; no proprietary internals, private APIs or undocumented
detection logic.

| Principle (publicly documented) | NivXForge position |
|---|---|
| Indicators shared across cloud detection, endpoint prevention and investigation; indicator *policy* separate from evidence verdicts (Microsoft Defender for Endpoint) | **Architecture matches** — `dt-i1e.ti.v1` is the shared enrichment contract and intelligence is separated from response policy. **Policy store missing** (GAP-4). |
| Continuous endpoint history + collective intelligence + retrospective re-evaluation (Cisco Secure Endpoint) | `IntelChangeEvent` → `INTEL_CHANGE` / `INTEL_CHANGED` is exactly this contract. **Executor not built** — deliberately. |
| IOC management distinct from a broader intelligence graph; IOCs distinguished from behaviour-oriented IOAs (CrowdStrike Falcon) | **Matches and is enforced in code**: `iocs` + `ioc_watchlist` are the indicator layer; `edr_behavior` sequence rules are the behavioural layer and treat intel as *one stage*, not a verdict. |
| Live intelligence lookups for file context, decision verification, FP suppression and reputation, integrated into investigation (Sophos / Intelix) | Lookup + investigation integration are contracted. **FP suppression needs `KNOWN_GOOD`/allow-list, which the store cannot express today** (GAP-4) — this is the one product capability the gap actually blocks. |
| Endpoint + cloud intelligence correlation (SentinelOne Singularity and others) | Supported in shape: GLOBAL public intel and TENANT private intel coexist with separate scopes and cache namespaces. |
| Provider / source provenance surfaced to the analyst | **Stronger than typical**: provenance is mandatory, `verdict_origin` distinguishes a provider's own verdict from one our client derived, and provider disagreement is retained rather than collapsed. |
| Response policy separated from intelligence verdict | **Matches** — and `TI_MATCH != MALICIOUS_VERDICT` is enforced structurally by the three-valued matcher and the assessment model, not by documentation. |

Where NivXForge is genuinely ahead of the common pattern: the explicit, type-enforced separation
of *"we failed to ask"* from *"nobody knows"*. Most products show one "unknown". Keep it.

Where it is behind: no private/customer indicator storage, no allow-listing, no retrospective
executor, no provider health truth, and — the thing that matters most — **none of the finished
contract is actually connected**.

---

## MINIMUM_IMPLEMENTATION_PLAN

Strictly sequenced, each step independently testable, none of it to start before the current gate.

**T1 · Provider health truth (closes GAP-3).** Replace env-var-presence health with the six
derived states, sourced from `ti_source_meta` + last lookup outcome. No provider call, no
credential change. *Test:* a configured-but-rejected provider reports `AUTH_FAILED`, never
`HEALTHY`; a never-synced provider reports `NEVER_SYNCED`. Smallest, highest-trust win, and it
retires the misleading `7/7 live` without touching G-37's credentials.

**T2 · One production route table (closes GAP-1).** Build the `ProviderRoute` list — B4
`local_ioc` as the offline GLOBAL route first, then client C routes via
`adapt_ioc_intelligence`, scoped GLOBAL only until GAP-5 is fixed. *Test:* broker returns one
result per route; a provider exception becomes `ERROR`, never an answer; a failure does not
overwrite cached intel; `GLOBAL` keys carry no tenant.

**T3 · E1 read-side enrichment path.** `observables.extract()` → broker → enrichment record keyed
by `evidence_refs`. *Test:* no ingest path imports a TI client; evidence is durable with TI
unavailable; enrichment never mutates canonical evidence.

**T4 · The E3 bridge (closes GAP-2).** One `EnrichmentProvider` implementation over the broker,
plus the additive non-judgement `state` on `Enrichment`. *Test:* `INTEL` stages still evaluate
`UNKNOWN` when TI is unavailable; a `RATE_LIMITED` lookup can never produce a match; existing
`test_e3_detection_replay` stays green.

**T5 · Investigation surfacing.** `to_tenant_view` → `TIResult` rows into supporting evidence, with
failure states routed to **missing** evidence. *Test:* no consensus collapse; a cross-tenant result
is rejected; a TI hit alone never yields a TRUE_POSITIVE assessment.

**T6 · Store schema for private IOCs and allow-listing (GAP-4).** `tenant_id` index, explicit
`disposition`, `valid_until`, and a decision on the 8,896 `kind: null` rows and the
`find_one({kind,value})` vs `{kind,value,source}` mismatch. **Needs its own bounded migration
design — STEP 34/35 discipline applies.**

**T7 · Retrospective executor.** Only after T1–T6. Needs its own observable→evidence reverse-lookup
design and index work.

GAP-5 (client C's tenant-blind cache) is a prerequisite only for tenant-scoped use of C; GLOBAL-only
use is safe and is what T2 proposes.

---

## FILES THAT WOULD NEED CHANGES — **DO NOT CHANGE THEM**

Listed for the plan's sake. **Nothing in this list was modified in this task.**

| File | Step | Change shape |
|---|---|---|
| `backend/services/ioc_intelligence/health.py` | T1 | derive real provider states; stop equating configured with live |
| *(new)* `backend/edr_plane/ti_routes.py` or similar | T2 | the production `ProviderRoute` table — the only genuinely new file needed |
| `backend/edr_plane/reputation/service.py` | T2 | register more than `local_ioc` (registry already supports it) |
| `backend/edr_plane/reputation/observables.py` | T3 | `OBS_IP` → `IPV4`/`IPV6` reconciliation only |
| `backend/edr_behavior/contracts.py` | T4 | **additive** non-judgement `state` on `Enrichment` |
| `backend/edr_behavior/provider.py` | T4 | one real `EnrichmentProvider` beside Null/Static |
| `backend/edr_investigation/ti.py` | T5 | surface failure states into missing-evidence |
| `backend/ti_feed_sync.py` | T6 / G-37 | `ABUSECH_AUTH_KEY` vs `ABUSE_CH_AUTH_KEY` mismatch; set `disposition`/`valid_until` — **deferred, do not touch now** |
| `db.iocs` schema + indexes | T6 | `tenant_id` index, disposition, expiry — bounded migration design required |

**Explicitly NOT to be changed:** `edr_investigation/ti_contracts.py` (adopt as-is),
`edr_plane/reputation/contract.py`, `edr_behavior/matcher.py`, `edr_behavior/engine.py`,
`services/ioc_intelligence/providers/*` (nine working connectors), anything under STEP 35.

---

## BLOCKERS / OWNER DECISIONS

1. **Consensus must not enter EDR — confirm.** Client C's weighted `trust_score` / single
   `verdict` is right for an XDR IOC card and wrong for an EDR investigation. I propose consuming C
   strictly per provider via `adapt_ioc_intelligence` and never surfacing its consensus inside
   NivXForge. This is the biggest fork in the road; it needs your explicit yes.
2. **The 148,262 feed rows are all implicit `KNOWN_MALICIOUS`.** `local_ioc` defaults a
   dispositionless entry to malicious, so 5,000 `blocklist.de` scanner IPs the feed itself rated
   `confidence: 50` would assert `MALICIOUS_ASSERTED` on a match. Options: require explicit
   disposition on ingest (T6), gate on a confidence floor, or scope low-confidence sources to
   `SUSPICIOUS`. **This should be decided before any TI route goes live**, because it directly
   shapes false-positive rate on real endpoints.
3. **8,896 `kind: null` rows** are unreachable by every lookup path. Repair, classify or retire —
   needs a decision, and it is evidence-adjacent data so it deserves STEP 35 discipline.
4. **Private-IOC policy store:** reuse the existing XDR `xdr_intelligence_policy_*` collections and
   `services/intelligence_policy/` (358 lines), or build an EDR-native one? I recommend a
   discovery pass on those before anyone designs a second policy engine. **Not in this task.**
5. **G-37 remains deferred by your instruction.** I found a likely contributing cause while
   mapping the estate — the `ABUSECH_AUTH_KEY` / `ABUSE_CH_AUTH_KEY` env-var name mismatch between
   `ti_feed_sync.py:61` and every other abuse.ch consumer, alongside `threatfox: 0` in the latest
   sync receipt. **Recorded, not touched, not investigated further.**
6. **Certificate / signer observables do not exist** anywhere in the estate. Confirm it stays a
   future extension rather than something I should design now.

---

## VERDICTS

**SHARED_TI_REUSE = YES**
Reuse the existing estate wholesale: `dt-i1e.ti.v1` as the contract, its four adapters, `TIBroker`,
`ReputationHistory`/`IntelChangeEvent`, B4's observables + registry + tenant-keyed cache,
`local_ioc` over `db.iocs`, the nine client-C connectors behind the boundary, and
`ti_feed_sync`/`ti_source_meta` for ingestion and health truth.

**EDR_TI_DUPLICATION_REQUIRED = NO**
Not one provider adapter, feed connector, scheduler, normalizer or verdict model needs to be
rebuilt for NivXForge. Building an EDR TI ingestion stack would have created the **third** parallel
TI estate in this repository. The only new file the plan needs is a production route table.

**SAFE_TO_IMPLEMENT_AFTER_CURRENT_GATE = YES**
With these conditions: T1 and T2 are additive and touch nothing in the STEP 35 path; T6 (the
`db.iocs` schema and index work) is a **bounded migration that must get its own STEP-35-style
design, gates and tests**; and decisions 1 and 2 above should be settled before any route serves a
real detection.

**STOP.** Design report only. Nothing implemented, nothing deployed, no production data read beyond
read-only counts on the preview database.

---

# OWNER ARCHITECTURE DECISIONS — RECORDED 2026-06 · TI IMPLEMENTATION ON HOLD

Discovery report ACCEPTED. Both open decisions are now settled. **Neither is implemented. TI
implementation remains HOLD until STEP 35 completes.**

## TI-DECISION-1 — PER-PROVIDER EVIDENCE (binding)

NivXForge EDR consumes normalized TI **per provider**. Client C's weighted consensus
(`services/ioc_intelligence/consensus.py` — `verdict` / `trust_score` / `confidence_percent`) is
**NOT** an EDR verdict and **NOT** a detection authority. It remains an XDR IOC-card presentation
device only.

Preserved independently, per provider, never collapsed:
`provider · observable · provider verdict/context · confidence · freshness · provenance ·
availability/failure state`.

Multi-provider agreement MAY later contribute to Investigation confidence, but it must stay
**explainable** and must never become an opaque truth score. Blocker #1 of the report is closed:
consume C strictly through `adapt_ioc_intelligence`, one `NormalizedTIResult` per provider.
`normalize_ioc_card()`'s existing "no consensus collapse" property is now a requirement, not an
implementation detail.

## TI-DECISION-2 — A STORED IOC IS NOT AUTOMATICALLY MALICIOUS (binding)

**REMOVED from the target architecture:** the assumption
`indicator exists in db.iocs  =>  KNOWN_MALICIOUS`.

Public-feed records are **threat-intelligence observations, not endpoint verdicts**. Confidence-50
scanner/blocklist data, stale intelligence, reputation observations, sightings and other ambiguous
records must **never** automatically produce a malicious endpoint detection.

Required semantic direction:
```
TI observation
  → contextual enrichment / supporting evidence
  → Behavior + causal evidence + Investigation
  → assessment
```
`UNKNOWN` is preserved whenever the available evidence cannot justify a stronger conclusion.
Provider failure or unavailability must **never** become `BENIGN`.

**Direct consequence for the later work (not to be actioned now):** GAP-4's finding — that
`edr_plane/reputation/providers/local_ioc.py` defaults a dispositionless `iocs` entry to
`KNOWN_MALICIOUS`, making all 148,262 feed rows implicit malicious assertions — is now a
**target-architecture defect to correct during the bounded TI integration stage**, not a behaviour
to preserve. Blocker #2 of the report is closed in favour of observation semantics.

## WHAT STAYS

Keep and reuse: `dt-i1e.ti.v1` (`edr_investigation/ti_contracts.py`), `TIBroker`,
`ReputationService` / `edr_plane.reputation`, the four existing adapters (A/B/C/H), and the
retrospective seams (`ReputationHistory`, `IntelChangeEvent`, `RETRO_TRIGGERS.INTEL_CHANGE`,
`replay.INTEL_CHANGED`). **Do not create another TI stack or another contract.**

GAP-1 … GAP-5 remain recorded for the later bounded TI integration stage.

## EXPLICITLY NOT TO BE DONE NOW

No provider credential work (G-37 stays deferred), no health-semantics fix, no `db.iocs` schema or
index work, no cache changes, no E3 enrichment wiring, no TI UI.

**CURRENT PRIORITY: STEP 35 ONLY.**
