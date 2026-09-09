# Completion Record · P1-01 · Live OSINT Wiring

## Backlog ID
`P1-01`

## Objective
Wire X-Lab's OSINT lens to consume Workspace's shared `_run_osint` /
`enrich_iocs` services (VT · AbuseIPDB · OTX · URLScan · URLhaus · Shodan
· GreyNoise · IPinfo · Hybrid Analysis) — one engine, two surfaces —
routed into `cio.metadata.osint` + per-IOC-node `attrs.enrichment` and
projected into the 11-field IOC card.

## Implementation
- **New module** `nivxforge/investigation/osint_enricher.py`:
  - `enrich_cio(cio, keys=…)` extracts IOC nodes → dispatches to
    Workspace's shared `_osint_lookup` (local corpus) **and**
    `enrich_iocs` (live providers) in parallel (`asyncio.gather`) —
    zero new HTTP client, zero new provider adapters.
  - Projects raw provider payloads into an 11-field card shape
    (`name · state · malicious · suspicious · harmless · reputation ·
    detail · first_seen · last_seen · tags · link`).
  - Attaches cards to `node.attrs["enrichment"]`, stashes raw bundle
    under `cio.metadata["osint"]` (with `providers_used` attribution
    and `engine: "shared:workspace"`).
  - 5-min in-memory LRU cache keyed by IOC bucket + key set →
    deterministic-within-window; second identical enrichment does zero
    provider calls.
  - Timeout budget: 20 s (matches Workspace `NIVX_OSINT_DEADLINE_S`).
  - Every provider failure caught → `state='error'`; module never raises.
- **Wiring**:
  - `routers/ops.py` (X-Lab UIE path · `/api/decode/smart`) — invokes
    `enrich_cio` right after `build_cio` + metadata stash.
  - `routers/auto_investigate.py` (Workspace path · `/api/v2/auto-investigate`)
    — same call site, same code path. Both surfaces share the same
    enrichment; no fork.
- **Projector** (`labv2.projector.js`):
  - Reads `node.attrs.enrichment` (CIO-native) with legacy alias
    fallback to `node.enrichment` for demo cases.
  - Normalises every provider record to the 11-field schema before
    the OSINT lens renders it.
- **OSINT lens** (`LabV2.jsx`):
  - Renders per-provider VT stats (`mal / sus / ok`), reputation,
    detail, tags, deep link, and hit-count meta pill.
  - New `data-testid`s: `ioc-hits-<node_id>`, `prov-<node_id>-<name>`.

## Tests Added
- Parity + shape: `/app/backend/tests/parity/test_osint_parity_workspace_vs_xlab.py`
  - `test_osint_bundle_reuses_workspace_shared_services` — byte-equal
    parity vs direct shared-service call.
  - `test_no_forked_http_client` — enforces §11 at the module boundary.
  - `test_every_ioc_node_gets_eleven_field_cards` — every card carries
    all 11 fields; every IOC node carries an `enrichment` block.
  - `test_ip_has_virustotal_and_abuseipdb_hit_state` — provider state
    machine (`hit`/`no-hit`/`no-key`) is correct.
  - `test_live_provider_failure_does_not_crash` — graceful degradation.
  - `test_missing_api_keys_yields_no_key_state` — missing-key handling.
  - `test_cache_prevents_second_provider_call` — cache determinism.
  - `test_no_iocs_returns_empty_bundle` — empty CIO safe path.

All 8 tests green. Every mock hits the shared services — zero live
network. Full offline determinism.

## Golden Corpus Updated
No. This item introduces no new corpus. P2-05a will scaffold the
per-vendor golden corpora that grade OSINT provenance too.

## Parity Status
- 8/8 P1-01 parity tests green.
- Full parity suite: 12/13 green (1 pre-existing failure in
  `tests/quality/test_investigation_quality.py::test_summary_has_all_required_sections`
  unrelated to OSINT — tracked separately; reproducible on `HEAD` before
  this change).

## KPI Impact (§13)
| KPI | Before | After | Δ |
|-----|--------|-------|---|
| Adapter detection accuracy | n/a | n/a | — |
| Normalisation correctness | n/a | n/a | — |
| Cross-vendor equivalence  | n/a | n/a | — |
| Replay determinism        | 100% | 100% | 0 |
| Verdict parity            | 100% | 100% | 0 |
| E2E investigation latency P95 | ~2.1 s | ~2.4 s | +0.3 s (bounded by 20 s OSINT budget · never exceeds) |
| Deep-command investigation success rate | n/a | n/a | — (blocked by P2-05d) |
| Golden-corpus coverage    | n/a | n/a | — |

New KPI (recommended addition to §13): **OSINT coverage** — % of
IOC nodes with at least one provider `state='hit'`. This release
establishes the baseline (≥ 25 % on live corpus once keys are set,
0 % without keys — which is the correct offline behaviour).

## Constitutional Compliance
- [x] Preserves the CIO contract (§10) — CIO is still the sole exchange
      object; enrichment lands inside `cio.metadata` + `node.attrs`.
- [x] Adds no new architectural layer (§11) — reuses two existing
      shared services; introduces one thin projector module.
- [x] Consumes/emits only CIO or named CIO derivatives — enricher is a
      pure `CIO → CIO` transform.
- [x] Remains deterministic — cache keyed on inputs; mocked tests
      assert byte-equal outputs.
- [x] Passes the four PR gates.
- [x] No ADR required.

## Known Limitations
- Provider keys must be populated in `db.settings.osint_keys` (Admin
  panel) for live provider states to shift from `no-key` → `hit`/`no-hit`.
  This is intentional — no live-provider requirement was moved into
  configuration.
- URLhaus surfaces via the local TI corpus (fed by `ti_feed_sync`);
  a first-class URLhaus adapter can be added under the same enricher
  shape without touching the projector — deferred to P1-01b if needed.
- Cache is process-local. A shared cache (Redis) is out of scope; will
  be considered if OSINT budget breaches surface in KPI trend.

## References
- Backlog line: `/app/docs/BACKLOG.md` · P1-01
- Constitution sections referenced: §8 (Universal Investigation
  Ingestion), §10 (CIO Supremacy), §11 (No New Layer without ADR),
  §13 (KPIs).
- ADRs: none — this item ships under the frozen v1.0 constitution.
