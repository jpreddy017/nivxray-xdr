# D15 — SNORT TENANT CONTRACT + DECLARED SOURCE ROUTING (owner review gate)

Date: 2026-09-15 · **PREVIEW ONLY — no production deployment, no merge.**

```
cd /app/backend && python -m pytest tests/test_d15_declared_source_routing.py -q
cd /app          && python scripts/p0_d15_declared_source_routing_live_proof.py
```

## RESULT: **PASS**

| Proof | Result |
|---|---|
| `tests/test_d15_declared_source_routing.py` | **54 passed** |
| `scripts/p0_d15_declared_source_routing_live_proof.py` (real HTTP, preview) | **PASS** — 60/60 checks |
| D11 / D12 / D13 / D14 live proofs re-run | **PASS** (all four) |
| D4 stitching live proof re-run | **PASS** |
| Regression vs clean tree (15-file ingest/provenance suite) | **identical**: 11 failed / 24 errors before and after; passed 314 → 368 (+54 new D15 tests) |
| Regression vs clean tree (23-file pipeline suite) | **identical**: same 12 pre-existing failures (`test_xdr_content_pipeline.py`, `test_xdr_detection_consolidation.py`) on a stashed clean tree |

## THE AUTHORITY CHAIN (now enforced)

```
authenticated collector identity
  -> collector-authorized source set   (server-side record, not caller-sent)
  -> explicit per-request declaration  (envelope.declared_source)
  -> declaration / allowlist validation
  -> DSM selection
  -> content compatibility validation  (VALIDATE only, never select)
  -> canonical evidence
```

Four questions, four answers, none substitutable: authentication answers WHO
is sending; the allowlist answers WHAT that collector may send; the
declaration answers what THIS delivery claims to be; content answers whether
the payload is structurally consistent with that claim.

### Outcomes, with distinct codes

| Case | Result |
|---|---|
| declared + authorized + compatible | ACCEPT |
| declared but not authorized for this collector | BLOCK · `SOURCE_NOT_AUTHORIZED` |
| declaration missing | BLOCK · `DECLARATION_REQUIRED` (never collapsed into mismatch) |
| declared source unknown | BLOCK · `UNSUPPORTED_SOURCE` |
| declaration incompatible with payload | BLOCK · `SOURCE_FORMAT_MISMATCH` |
| declared DSM not loaded | BLOCK · `SOURCE_DSM_UNAVAILABLE` (a CODE failure, named as one) |

No registry-order fall-through. No content-inferred fallback. No grace path:
an undeclared delivery is refused, and every existing test/script/forwarder
was updated to declare explicitly.

## CHANGED

| File | Δ | What |
|---|---|---|
| `backend/services/source_routing.py` | **NEW**, 265 | the catalog, the allowlist contract, `route()`, and the refusal codes |
| `backend/detection_content/telemetry/registry.py` | +45 | `get(dsm_id)` (select BY id), `compatible()` (validate only), `recognize()` (mismatch evidence only) |
| `backend/detection_content/xdr_pipeline.py` | ±60 | **Snort joins the D14 tenant contract**; pipeline takes the routing decision; parser refusal is recorded, never re-routed; `provenance.routing` written on every event |
| `backend/routers/xdr_ingest.py` | +95 | `declared_source` on the envelope; `route_batch()` gate BEFORE persistence and BEFORE the idempotency claim; `routing_blocked` receipt + `events_routing_blocked` counter; refusal evidence in `xdr_ingest_routing_blocks` |
| `backend/routers/xdr_collectors.py` | +40 | `authorized_sources` on create/update, validated at configuration time; `GET /api/xdr/collectors/sources/catalog` |
| `tests/test_p0_ingest_idempotency.py`, `tests/test_p0_dedupe_hardening.py` | 4 sites | now register an allowlist and declare their source |
| `scripts/p0_d11..d14`, `p0_d4`, `nivxray_auditd_forwarder.py`, `restart_retry_proof.py` | 14 sites | same |
| `tests/test_d15_declared_source_routing.py` | **NEW**, 54 tests | |
| `scripts/p0_d15_declared_source_routing_live_proof.py` | **NEW** | 60/60 PASS in preview over real HTTP |

## 1 · SNORT TENANT CONTRACT (the D14 asymmetry, closed)

`snort-eve` was the only supported DSM outside the D14 tenant invariant: its
normalizer took no tenant at all and its canonical projection carried no
`tenant_id`. Now:

* `SnortNormalizer.normalize(..., tenant_id=None)` — no `"default"`, no
  payload fallback; a missing authenticated tenant raises
  `TenantAuthorityError` and produces no evidence;
* `canonical["tenant_id"]` is the authenticated delivery tenant;
* an EVE record naming its own tenant survives only as
  `additional_fields.tenant_claim` = `UNTRUSTED_SOURCE_CLAIM`, `used: false`;
* proved live: authenticated `t-d15-owner-b`, payload claiming
  `t-d15-victim-a` → evidence in B, victim A gained **zero**.

A test now asserts the invariant for **every** loaded DSM at once
(`test_every_dsm_normalizer_takes_the_authenticated_tenant_explicitly`), so a
future DSM cannot re-open the gap quietly.

## 2 · ADVERSARIAL PROOF (all required vectors, all ZERO evidence)

Live, over the authenticated HTTP path, two collectors in the SAME tenant with
DIFFERENT server-side authorization sets (B: snort/windows/sysmon/auditd/cef —
C: cloudtrail only):

* authorized + correct declaration + correct payload → evidence (5 sources,
  each interpreted by the DSM it declared)
* authenticated collector + unauthorized declaration → ZERO
* missing declaration → ZERO
* unknown declaration → ZERO
* declaration/content mismatch → ZERO
* document crafted to resemble another DSM (Sysmon doc declared Windows) → no
  reroute, ZERO
* Snort EVE delivered under the auditd declaration → ZERO
* CEF content under another declaration → ZERO
* collector C attempting a source authorized only for B → ZERO
* tenant B + payload claiming tenant A → evidence stays B, A gets ZERO
* mixed legitimate sources in one batch → each routed by its own declaration;
  one bad declaration blocks only itself
* a legitimate Windows document containing `message` → still Windows (content
  recognition *would* have offered `linux-auditd`, and is never consulted)
* registry position 0 (`snort-eve`) is proved to be no authority

Refused deliveries produce **no raw row, no idempotency claim, no canonical
evidence, no detection, no incident**, and are counted apart in
`events_routing_blocked` so the CONNECTED gate cannot be inflated by them.

## 3 · PROVENANCE PRESERVED

On accepted evidence (`provenance.routing`) and on refusals
(`xdr_ingest_routing_blocks.routing`):

```
routing_result · routing_authority · declared_source ·
declared_source_resolved · collector_authorized_sources · selected_dsm_id ·
payload_shape · content_compatible · content_recognized_as ·
mismatch_reason · reason
```

Plus, on refusals only: `tenant_id`, `collector_id`, `source_event_id`,
`payload_keys` and a 300-char `payload_excerpt` as bounded mismatch evidence.
No credential material is recorded — asserted by test and by live check.

## 4 · ONE HONEST LIMIT, STATED PLAINLY

Internal (non-HTTP) callers of `process_event_through_pipeline` — unit tests,
replay utilities — have no authenticated collector and no declaration, so they
still resolve a DSM by content. That path is **labelled for what it is**:

```
routing_authority = CONTENT_RESOLVED_INTERNAL_CALLER_NOT_INGEST_PATH
```

It is not presented as declared routing, and it is not reachable from the
authenticated ingest boundary, which always declares. If the owner wants the
internal path to require a declaration too, that is a deliberate follow-up —
it would rewrite ~24 existing suites and belongs in its own gate.

## 5 · PRE-EXISTING FAILURES (untouched, as instructed)

`test_collector_api_key_adversarial_regression.py` (5),
`tests/edr/test_p1_10_live_contract.py` (5), `tests/edr/test_cross_tenant.py`
(1), `test_xdr_data_sources_collectors.py` (24 errors),
`test_xdr_content_pipeline.py` + `test_xdr_detection_consolidation.py` (12) —
all verified identical on a stashed clean tree. They belong to the Work Mode
control-plane track and were left alone.

**TEST/SYNTHETIC telemetry throughout. No real host, cloud account or IDS
sensor is connected. Nothing was deployed; no protected branch was touched.**
