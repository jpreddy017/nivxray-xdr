# NivXForge EDR · Exclusions Guide

## The rule

**An exclusion record in the database is not an exclusion.** An
exclusion exists only when it demonstrably changes what a named engine
does, and the record preserves which engine, at which enforcement
point, and what actually happened.

An exclusion is **inert until a second operator approves it**. The
operator who created it may not approve it (`SELF_APPROVAL_REFUSED`):
accepting a protection blind spot requires a second pair of eyes.

## Six truth states, never collapsed

| State | Means |
|---|---|
| `EXCLUDED` | a finding EXISTED and was suppressed. The finding, its evidence refs and its analyzer survive; only its state changes, and it names the exclusion that suppressed it. |
| `NOT_EVALUATED_DUE_TO_EXCLUSION` | the engine was bypassed **before it ran**. Nothing was evaluated. |
| `SERVER_EXCLUSION_APPLIED` | enforced in the backend detection fabric |
| `ENDPOINT_EXCLUSION_APPLIED` | enforced on the endpoint itself |
| `EXCLUSION_PENDING_POLICY` | approved, but no policy version carrying it has been acknowledged as applied by the endpoint |
| `EXCLUSION_NOT_SUPPORTED_BY_ENGINE` | the target engine cannot honour it at all |

The first two describe what happened to the **evidence**; the rest
describe **where** enforcement happened. Both are reported, separately.

## Anatomy of an exclusion

Every exclusion carries all of this, by construction:

tenant · exclusion set · type · value · match kind · reason (recorded
verbatim, minimum 10 characters) · creator · approval state, approver
and approval time · affected engines · scope · policy version bindings
· effective from · expires at · review at · append-only audit trail.

### Types and match kinds

| Type | Evaluated against |
|---|---|
| `PATH` | the observed image path |
| `FILE_EXTENSION` | the observed image path suffix |
| `FILE_HASH` | the observed SHA-256 (value must be a 64-char hex digest) |
| `PROCESS` | the observed process/entity name |
| `PROCESS_COMMANDLINE` | the observed command line |
| `NETWORK_ADDRESS` | the observed remote address |

Match kinds: `EXACT`, `PREFIX`, `SUFFIX`, `CONTAINS`, `GLOB`.

**An absent attribute never matches.** An exclusion cannot silently
swallow activity whose relevant attribute was never observed.

### Scope

`TENANT` (all endpoints) · `GROUP` (listed group ids) · `ENDPOINT`
(listed endpoint ids).

### Engines

| Engine | Enforcement point | Implemented |
|---|---|---|
| `server.deterministic.rule` | `SERVER_FABRIC` | **yes** |
| `endpoint.prevention` | `ENDPOINT` | no — release 0.1.0 does not declare `endpoint_exclusions` |
| `endpoint.collection` | `ENDPOINT` | no — same |

Aiming an exclusion at an endpoint engine is allowed and is reported
truthfully: it reads `EXCLUSION_NOT_SUPPORTED_BY_ENGINE` (release
cannot honour it) or `EXCLUSION_PENDING_POLICY` (a release could, but
the endpoint has not acknowledged a policy version carrying it).
Server-side enforcement is unaffected either way.

## Lifecycle

| State | Means |
|---|---|
| `INACTIVE_PENDING_APPROVAL` | no engine consults it; protection is unchanged |
| `NOT_YET_EFFECTIVE` | approved, but `effective_from` is in the future |
| `ACTIVE` | approved, effective, not expired — it changes what an engine does |
| `REVIEW_OVERDUE` | **still enforced**, and flagged: `review_at` has passed |
| `EXPIRED` | past `expires_at`; it no longer affects any engine |
| `REVOKED` | withdrawn, with who and why. The record is retained. |

Only `ACTIVE` and `REVIEW_OVERDUE` ever reach an engine. Nothing is
ever deleted: "what were we not looking at, and between when and when"
stays answerable.

## How server-side enforcement works

The fabric runs the exclusion gate **before** an analyzer:

1. the candidate attributes are extracted from the observed activity,
2. the first approved, effective, in-scope exclusion aimed at that
   engine wins,
3. on a match the analyzer is **not called** — the outcome is
   `NOT_EVALUATED` with reason
   `NOT_EVALUATED_DUE_TO_EXCLUSION`, enforcement point
   `SERVER_FABRIC`.

If an engine already produced findings (for example the deterministic
derivation was recorded at ingest, before the exclusion existed), those
findings are marked `SUPPRESSED` with `suppressed_by` set to the
exclusion id, truth state `EXCLUDED`. History is not rewritten into
"nothing was found".

## Proving it

`Exclusions → Enforcement proof → Run against real evidence`
(`GET /api/edr/exclusions/enforcement-proof?sample=N`)

Read-only. It executes the registered detection fabric over the
tenant's real persisted evidence **twice** — with and without the
exclusion gate — and reports:

* `baseline_outcomes` vs `gated_outcomes`,
* `evidence_bypassed`, `findings_suppressed`,
* `changed_engine_behaviour`,
* per-example: the matched attribute, the observed value, the baseline
  outcome, the gated outcome, the evidence truth state and the
  enforcement truth state.

A record that changes nothing cannot pass it. If no approved exclusion
matched the sample, the verdict says exactly that — it does not claim
that exclusions do not work.

## Authoring workflow

1. `Exclusions → New set` — a named set a policy version can carry.
2. `New exclusion` — type, value, match, reason, affected engines,
   scope. It lands `PENDING_APPROVAL` and is inert.
3. A **different** operator approves it.
4. Attach the set to a policy version (`exclusion_set_ids`) to record
   the policy version binding. That binding is what makes endpoint-side
   state derivable later.
5. Run the enforcement proof.
6. Revoke when the reason no longer holds.

## API summary

| Method | Path |
|---|---|
| `GET` | `/api/edr/exclusions/taxonomy` |
| `GET` / `POST` | `/api/edr/exclusions/sets` |
| `GET` / `POST` | `/api/edr/exclusions` |
| `POST` | `/api/edr/exclusions/{id}/approval` |
| `POST` | `/api/edr/exclusions/{id}/revoke` |
| `GET` | `/api/edr/exclusions/enforcement-proof` |
