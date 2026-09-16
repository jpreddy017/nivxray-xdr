# GATE X1 — ENTITY RESOLUTION + MULTI-EVIDENCE INCIDENT · COMPLETION REPORT
_preview only · no merge · no deployment · no major UI · no narrative/story_

---

## 1 · ENTITY MODEL

One service, `services/entity_resolution.py`, replaces the question that
used to be answered separately in `xdr_spread_watchlist`, `xdr_ice` and the
`edr_plane` contracts. Types: `endpoint`, `process`, `user`, `ip`,
`domain`, `file_hash`, `application`, `cloud_identity`.

Every entity carries `entity_id` (deterministic, **tenant-scoped** hash),
`entity_type`, `key`, `identity_state`, `identity_basis`,
`evidence_refs[]`, `first_observed`, `last_observed`, `sources[]`,
`attributes`.

| identity_state | Meaning | Examples |
| --- | --- | --- |
| `AUTHORITATIVE` | a source minted an identity unique by construction | authenticated `endpoint_id`, Sysmon `ProcessGuid`, minted `process_iid`, sha256, cloud principal (UPN) |
| `DECLARED` | genuinely observed, but not unique | hostname, address, domain, bare username, application/workload |
| `NOT_OBSERVED` | the evidence did not carry it | — |

Two hard rules in code, not convention:
`NEVER_AUTHORITATIVE = (ip, domain)` — an address is a lease and a domain
is a name — and **a PID-only process produces no entity at all** (N2.1
already decided that question; X1 does not re-litigate it).

## 2 · RESOLUTION RULES

`resolve_entities(canonical)` reads one record and nothing else.
Endpoint: authenticated enrolment → AUTHORITATIVE; a hostname inside a log
record → DECLARED with the basis *"hostnames are reused, renamed and
spoofable, so this is context, not identity"*. Process: only when N2.1 says
`SOURCE_PROCESS_IDENTITY`. User: a UPN → `cloud_identity` AUTHORITATIVE; a
bare username → `user` DECLARED. Addresses, DNS answers and query names →
DECLARED. sha256 → AUTHORITATIVE (content addressing genuinely is unique).

## 3 · RELATIONSHIP TRUTH MODEL

`derive_relationships()` emits only what ONE record states — a relationship
between things seen at different times by different sources is exactly the
coincidence the last two gates removed. Every relationship carries
`relationship_type`, `source_entity`, `target_entity`, `state`,
`identity_basis`, `reason`, `evidence_refs[]`, `first_observed`,
`last_observed`, `sources[]`, `tenant_id`.

| State | Used for |
| --- | --- |
| `AUTHORITATIVE` | endpoint→process (authenticated endpoint), process→connected peer, process→resolved domain, process→image hash — the source stated both ends in one record and both ends are authoritative |
| `SUPPORTED` | domain→resolved address (the resolver said so, but addresses rotate); user→endpoint (a username is not a principal); endpoint→process when the endpoint scope is only a hostname |
| `AMBIGUOUS` | endpoint→address: observed on the endpoint's own evidence, and still never identity |
| `CONTRADICTED` | two pieces of evidence disagree; **both retained** |
| `UNRESOLVED` | asserted then retracted |
| `FORBIDDEN` | address→endpoint identity. **Recorded on purpose**, so the refusal is visible and nobody later mistakes its absence for an oversight |

## 4 · MULTI-EVIDENCE INCIDENT MODEL

`services/multi_evidence_incident.py`. The composition rule is the entire
safety argument:

> Two pieces of evidence belong to one incident **only** when they share an
> entity whose `identity_state` is `AUTHORITATIVE`.

An incident holds `event_ids[]`, `anchor_entity_ids[]`, `entity_ids[]`,
`relationship_ids[]`, `detections[]`, `correlations[]`, `sources[]`,
`composition_basis`, `first/last_observed`, `capability_not_verdict: true`.
Evidence with no authoritative entity (a Zeek flow, for example) gets its
**own** incident rather than being attached to whatever shares its address.
`trace()` returns every entity and relationship with
`every_relationship_cites_evidence` — an incident that cannot be traced to
canonical evidence is not an incident, it is an opinion.

## 5 · POSITIVE MERGE PROOF (live, real ingest — 25/25 checks PASS)

```
1 REAL INGEST   3 records accepted (Sysmon EID 22, EID 3, Zeek conn)
2 COMPOSITION   two endpoint records → ONE incident  minc_c0acb3fb…
                cites BOTH canonical events (sysmon-22-…, sysmon-3-…)
                carries the detection AND the correlation
                composed on authoritative entities: process:ProcessGuid…
4 RELATIONSHIP TRUTH
                endpoint→process        SUPPORTED   (hostname scope)
                process→connected peer  AUTHORITATIVE
                domain→resolved address SUPPORTED
                endpoint→address        AMBIGUOUS
                address→endpoint        FORBIDDEN
                every relationship traces to canonical evidence
```

A detail worth stating plainly: the Sysmon endpoint→process edge came back
**SUPPORTED, not AUTHORITATIVE** — because Sysmon names its endpoint only
by hostname. The incident still composed, on the *process* identity. The
first run of the proof asserted AUTHORITATIVE and failed; the system was
right and the assertion was wrong.

## 6 · FALSE-MERGE PROOF

Live: a Zeek connection to the **same address at the same instant** as the
endpoint's own connection does **not** join the incident, and says why
(*"no authoritative entity was resolved; this evidence stands alone"*).

In-process (22 tests): a shared address does not merge · a shared hostname
+ username + address across two endpoints does not merge · a different
process does not join · unrelated evidence stays separate · a PID-only
process is not an entity · addresses and domains can never be
authoritative · a hostname-only endpoint is DECLARED.

## 7 · TENANT ISOLATION

`entity_id` hashes the tenant, so identical evidence in two tenants
resolves to **disjoint** entity ids and separate incidents (proven live and
in tests). Every query is tenant-filtered; `trace()` on another tenant's
incident returns `found: False`.

## 8 · CONTRADICTION HANDLING

When the same two entities are related with a different state, the stored
relationship becomes `CONTRADICTED` and gains a `contradictions[]` entry
recording `previous_state`, `asserted_state` and **both** sides'
evidence refs. Nothing is overwritten and the newer claim never quietly
wins. Proven live (SUPPORTED vs AUTHORITATIVE) and in tests.

## 9 · REPLAY / IDEMPOTENCY

Deterministic ids mean a replayed record re-resolves to the same entities,
relationships and incident: `event_ids` stays `["cev-x1-dns"]` after three
composes, the process entity count stays 1, `evidence_refs` stays 1, and
`first_observed == last_observed`. Proven live and in tests.

## 10 · PROVENANCE

Every entity and relationship carries `evidence_refs`
(`xdr_canonical_evidence/<event_id>`), `identity_basis`, `sources` and both
observation bounds. Retraction (`retract_relationship`) sets `UNRESOLVED`,
records the reason, and **keeps the evidence refs** — the evidence was
still observed even when the conclusion was wrong. Proven: after
retraction, entity count was unchanged (7/7).

## 11 · REGRESSION

* `tests/test_x1_entity_resolution_incident.py` — **22 passed** (real
  database, per-run tenant, cleaned up)
* X1 + N2.1 + N1 + D12 + EDR sensor suites together — **196 passed**, with
  the one pre-existing red being the D12 `m365-unified-audit` coverage gap
  (Microsoft track, untouched)
* X1 adds **new modules only**. It modifies no existing evaluation path:
  `compose()` is not wired into the live pipeline, so no tenant's
  behaviour changed. The wide regression established at N2.1 therefore
  still holds; `server.py` gained one index call.

## 12 · REMAINING GAPS

* **Not wired into the pipeline.** Composition is an explicit call today.
  Wiring it would change behaviour for every tenant and belongs to its own
  gate, with its own proof.
* **No narrative.** Deliberately: per owner, story comes after the evidence
  graph is proven. The graph now exists and is traceable.
* **Cross-source composition still cannot happen** for network-only
  evidence, because it has no authoritative entity — which is correct, not
  a defect. It changes only when a source supplies an authoritative
  identity (real endpoint telemetry, or `community_id` on both sides).
* **Lateral movement / identity correlation** are now unblocked in
  principle (they were waiting on this), but neither is built.
* **Entity lifecycle** (merge on later authoritative evidence, expiry,
  re-imaging) is not modelled.
* Real sources unchanged: Sysmon `ABSENT`, NivXForge host and Zeek
  `EXTERNAL_ACCESS_BLOCKED`, M365 `EXTERNAL_ACCESS_BLOCKED` pending
  owner-side onboarding — which X1 never depended on.

---

## 13 · STANDING ARCHITECTURE RULE (recorded, owner-set)

> NivXRay XDR must aim beyond current industry-leading XDR/XSIAM
> capability, but advanced capability must not translate into analyst
> complexity. **Internally**: deep telemetry + deterministic engines +
> evidence graph + correlation + automation + verification.
> **Externally**: simple, progressive, task-oriented UX. A routine analyst
> task should need one obvious action or a short guided workflow; advanced
> controls live behind drill-down, not on the default screen.
> **Complexity belongs in the platform, not in the analyst's workflow.**

Target shapes when UI returns: Add Integration → Sandbox → Authenticate →
Test → Enable · Add Device → Choose method → Enroll/Test → Enable ·
"Why suspicious?" → evidence chain immediately visible · Contain →
impact/approval → execute → independently verify.

X1 was built to serve that rule: the incident already answers "why" in one
object, and the `identity_state` / relationship-state model is what will
let a UI show a confident answer *and* its uncertainty without asking the
analyst to assemble either.

---

**STOP — awaiting owner review.** Next decision point per owner: Store Rule
Triage (0 of 98 authored rules can fire) vs real-source onboarding /
detection content.
