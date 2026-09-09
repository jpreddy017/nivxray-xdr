<!-- NIVX-DOC
layer: TARGET_SPEC
status: AUTHORED
-->

> **TARGET** specification. Volumes and maturity:
> `08_VALIDATION/REALITY_MATRIX.md` (generated).

# EVIDENCE ARCHITECTURE

The platform's foundation, and the part that is genuinely strongest.
Adopts `memory/ARCHITECTURAL_DIRECTION_IEDDE.md`,
`memory/IDA_ARCHITECTURE.md`, `memory/P0_2C_ALIAS_SITE_SWEEP.md`.

## 1 · The three evidence objects — never conflate them

| Object | Store | What it is | Mutability |
|---|---|---|---|
| **Raw event** | `edr_raw_events` | exactly what a producer presented, as presented | immutable |
| **Observation** | `v2_shadow_observations` | a projected, lane-classified view of activity | derived |
| **Canonical event** | `xdr_canonical_events` | the normalised, cross-source representation | derived, rebuildable |

Prose that uses these interchangeably is a defect
(`00_PRODUCT/TERMINOLOGY.md`). A derived store must be rebuildable from
its authority; if it is not, it is secretly authoritative and must be
reclassified.

## 2 · Provenance is mandatory

Every piece of evidence carries: producer identity, tenant attribution,
collection time, ingest time, sensor/source version, and the
transformation chain that produced any derived form.

Incidents were the one place provenance was missing. **Closed in P-2
(2026-06):** every incident now carries a class, a basis and the
artefact it traced, enforced at write time. See
`INCIDENT_ARCHITECTURE.md` §5.

## 3 · Tenant attribution

Attribution happens **at ingest**, from the producer's authenticated
session. A producer can never assert its own tenant, and unattributable
evidence is recorded as unattributed rather than guessed into a tenant.

Legacy observations exist that carry no tenant. They are handled as
`UNATTRIBUTED_LEGACY_OBSERVATION` and, critically, **the alias resolver
narrows to the caller's authorised tenants** in that case — it never
widens.

## 4 · Endpoint identity — the reference invariant

The single most important structural property in the platform, because
it is what makes evidence *findable*.

```
external identifier  (dev_… | ep_… | hostname | future alias)
      ↓  tenant-scoped resolution        services/edr/device_identity.py
canonical endpoint identity + VALIDATED ALIAS SET
      ↓  predicate over the store's DECLARED identity fields
downstream evidence query
```

Rules:

1. **One resolver.** `device_identity.resolve()` +
   `identity_refs()`. A second resolver is an architecture violation.
2. **Declared stores.** `services/edr/endpoint_query.py` declares every
   endpoint-keyed store and its identity fields. An undeclared store or
   field **cannot be queried** through the invariant.
3. **Alias-set querying, not forced canonicalisation.** A store may
   legitimately hold records under more than one historical alias, so it
   is addressed by the whole validated set. No historical record is
   rewritten.
4. **Never widen authorisation.** The reverse lookup
   (`device_iid`/hostname → enrolled `endpoint_id`) is tenant-constrained.
   Before this was enforced, a hostname enrolled in two customers would
   have handed one customer's surface the other customer's
   `endpoint_id` — a genuine cross-customer read path.
5. **`ENDPOINT_NOT_RESOLVED`, never `200 []`.** A supplied but
   unresolvable identifier returns an explicit state. An empty collection
   is reserved for *"no identifier supplied and zero results is a valid
   answer"*.
6. **A foreign identifier is indistinguishable from an unknown one.**
   Existence is never disclosed across customers.
7. **Empty alias set ⇒ unsatisfiable predicate**, never an unfiltered
   read of an endpoint-keyed store.

Enforcement is three-layered and honest about its boundary: an AST
bypass guard anchored on *store × declared identity field* (a rename
cannot defeat it), a route-contract test over a pinned live-site
inventory, and a runtime proof asserting **identical evidence IDs** for
every alias. Static analysis cannot see runtime-assembled names or opaque
filter dicts; the runtime proof covers those. No single layer is claimed
to be sufficient.

**Why this is the reference pattern:** the same defect recurred three
times when fixed per-site. It stopped recurring when it became a
contract with a guard. Every future platform invariant should follow this
shape — declared contract + structural guard + runtime proof.

## 5 · Evidence honesty rules

| Situation | Required behaviour |
|---|---|
| identifier supplied, resolvable | evidence + the alias set actually queried (`addressed_by`) |
| identifier supplied, unresolvable | `ENDPOINT_NOT_RESOLVED` + a note that this is an authorisation/identity outcome, **not** a statement about the evidence |
| no identifier, collection route | unchanged collection semantics |
| endpoint resolves, observation does not | the distinct `OBSERVATION_NOT_RESOLVED` |
| evidence exists outside the queried window | **must disclose how much** — see the open gap below |
| producer silent | *last delivery* must be shown; silence is a fact, not an empty screen |

### Open gap · `WINDOW_HONESTY_GAP`

A surface can be truthful about its window and still mislead. Measured
example: process tree at `hours=24` returns 0 nodes while `hours=48`
returns 439 — the producer's last delivery is just outside the default
window. The screen says *"no matching evidence"* and never mentions the
439 nodes 25 hours away. Additionally the page does not honour a `?hours=`
parameter, so an analyst **cannot widen the window from the console at
all**.

Required (`LAB_VALIDATED`): an empty in-window result must state the
out-of-window count, and every evidence surface must expose its window.

## 6 · Retention, rebuild and lifecycle — `SPEC_PENDING`

Not defined for any store. Tracked in
`02_ARCHITECTURE/DATA_ARCHITECTURE.md`. Every store needs: authoritative
vs derived, writer, tenancy key, retention, rebuild procedure. Until
then, backup and DR cannot be specified.
