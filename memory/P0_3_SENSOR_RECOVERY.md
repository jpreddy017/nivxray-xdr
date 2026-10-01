# P0-3 · Blindness/Staleness Detection + Linux Sensor Recovery

**Status: `REAL_RUNTIME_VERIFIED` · proof 41 PASS · 0 FAIL · 0 BLOCKED**
Proof: `scripts/p0_3_sensor_recovery_proof.py` →
`memory/p0_3_sensor_recovery_proof.json`
Event generator: `scripts/p0_3_generate_physical_event.py`
Owner decisions honoured: order **A** (observability first, then
recovery) · thresholds **A** (derived from the sensor's own cadence, the
formula documented) · persistence **A** (supervised, root cause fixed) ·
window honesty **A** (truthful out-of-window count **and** an analyst
window control) · scope **STOP after P0-3**.

---

## 1 · ROOT CAUSE — it was never a sensor bug

The sensor had delivered 8,070 real events and then stopped on
`2026-09-06T15:46Z`. Every component people expected to be broken was
healthy: the sensor code, the local outbox, the transport, the enrolment
credential model, the authenticated ingest route and the canonical bridge
were all intact and, once started, worked first time.

The outage was **two structural mistakes plus one blind platform**:

1. **The sensor was not a supervised program.** It had been started by
   hand. When the container was recreated the process was simply gone,
   and nothing started it again. There was no
   `/etc/supervisor/conf.d/nivxforge_sensor.conf` at all.
2. **Its durable state lived on an ephemeral path.**
   `NIVXFORGE_SENSOR_STATE` defaulted to `/var/lib/nivxforge-sensor`,
   which is correct for a real endpoint but does not survive container
   recreation here. `/var/lib/nivxforge-sensor` **did not exist** —
   so the enrolment credential (`identity.json`, 0600), the outbox and
   the "already reported" set were destroyed with the process. Even a
   supervisor would have restarted the sensor straight into
   `not enrolled: run enrol first`.
3. **The platform could not notice.** `last_telemetry_at` froze on
   2026-09-06 and every endpoint surface kept rendering — empty. There
   was no state, no route and no UI that could say *"we are receiving
   nothing"*. This is why the owner's insertion of observability BEFORE
   recovery was right: without it, "the sensor is fixed" would have been
   an assertion.

Two facts that made recovery clean rather than destructive:
`endpoint_id` is minted by the platform from `/etc/machine-id`, which is
unchanged on this box, so re-enrolment resolved to **the same**
`ep_2d57cbe6f80152062109` and the historical trajectory stayed attached
to it (verified by recomputing the mint: `guid` basis →
`ep_2d57cbe6f80152062109`, `hostname` basis → a different id, so the
precedence order is what saved the identity).

---

## 2 · FIVE REAL DEFECTS FOUND WHILE FIXING IT

### D1 · Re-enrolment ERASED the delivery record — P0
`store.enroll()` wrote `$set: record.model_dump()` for the whole
`EndpointRecord`, and that model contains `sensor_state`,
`last_telemetry_at` and `event_count`. So re-issuing a credential to an
endpoint that had delivered 225 events reset it to
`ENROLLED_NEVER_REPORTED · last_telemetry_at: null · event_count: 0`.
**The delivery record is the exact evidence blindness detection is
derived from**, so a credential rotation would have destroyed the ability
to detect the very outage being recovered from — and would have made a
recovered endpoint indistinguishable from a brand-new one.
Fixed: identity/credential fields stay in `$set`; the seven delivery
facts moved to `$setOnInsert`. `enroll()` now also reports the truth for
a re-enrolment (`delivery_history_preserved`, and it no longer prints
"has NOT sent any" to an endpoint that has).
Proven live: re-enrolment printed `sensor_state=REPORTING`, and
`event_count` is `225 + everything since`.

### D2 · A poll-based sensor cannot be judged by `last_telemetry_at` alone
The sensor legitimately has cycles where nothing new happened. Judged
only on delivery, a healthy quiet sensor and a dead sensor look
**identical**. So the sensor now declares **liveness** every cycle:
`POST /api/edr/agent/heartbeat`, carrying its own
`report_interval_seconds`.
A heartbeat is deliberately **not telemetry**: `mark_heartbeat()` writes
`last_heartbeat_at` only — it never advances `last_telemetry_at`, never
increments `event_count` and never creates a raw event, because a
heartbeat that counted as evidence would make a silent endpoint look like
a delivering one. Proven by calling the real route with the endpoint's own
credential: `event_count 7018 → 7018`, `last_telemetry_at` unchanged,
raw-event count unchanged (gates B13–B15).

### D3 · Live sensor incidents were born `PROVENANCE_UNKNOWN` — P0 honesty
The first fresh incident created after recovery
(`INC000000446`, `inc_57fee8bc67a047da9685`, created from real
`/proc`-read process evidence) was labelled **`PROVENANCE_UNKNOWN`** with
the basis *"canonical event provenance does not attribute this evidence
to a sensor"*. The raw event said `source_kind: sensor`,
`sensor_version: 0.1.0`, `trust_state: AUTHENTICATED` — but
`canonical_bridge` built `canonical["provenance"]` as
`{trace_id, normalizer_id}` and **dropped the attribution**, so
`_provenance_of_pipeline()` had nothing to read.
So the platform could not label its own live telemetry as real. The
previous phase's provenance work was not wrong; the **creation path**
was.
Fixed at the layer that owns the fact: the authenticated ingest passes
the raw event's own recorded `source_kind`/`sensor_version` into the
bridge, the bridge stamps them onto canonical provenance, and the DSM
normalizer copies them **only** from the authenticated-ingest envelope —
so a sensor-shaped event arriving through any other path still cannot
manufacture a `REAL_SENSOR_DERIVED` label.
`scripts/backfill_incident_provenance.py --relabel-unknown` re-runs the
**same** evidence rule over `PROVENANCE_UNKNOWN` incidents only; it may
move an incident **off** unknown and never onto it, records
`provenance_previous`, and states the re-classification in the basis.
Result: **exactly 1** of 573 documents relabelled (the one this defect
created), 385 stayed unknown, 171 `SYNTHETIC_TEST` and 16
`REAL_SENSOR_DERIVED` untouched. Not a blanket relabel.

---

## 3 · PHASE A · BLINDNESS/STALENESS — one authority, cadence-derived

`services/edr/endpoint_health.py` was **extended**, not duplicated. It
already held two independent dimensions (agent lifecycle · telemetry
health); dimension **C · delivery freshness** answers the narrower
operational question the console has to be able to ask about itself.

```
stale_after_s = max(report_interval_s × 3,  60)
blind_after_s = max(report_interval_s × 20, 900)
```

`report_interval_s` is **the sensor's own configured cadence**, declared
by the running sensor at ingest and at every heartbeat
(`cadence_basis: DECLARED_BY_SENSOR`). Three consecutive missed cycles
cannot be explained by jitter or one retry; twenty missed cycles is not
lateness. There is **no threshold anywhere in the UI** — the browser
renders the backend's tokens and prints the formula verbatim. Endpoints
that have never declared a cadence read
`CADENCE_NOT_DECLARED_BY_SENSOR` against a stated policy fallback, so the
answer never pretends the interval was measured.

Three states, and a `basis` that carries what the state alone cannot:

| state | basis | meaning |
|---|---|---|
| `DELIVERING` | `DELIVERY_WITHIN_DECLARED_CADENCE` | inside its own cadence |
| `STALE` | `LINK_ALIVE_NO_NEW_EVIDENCE` | heartbeat confirms the sensor and its outbox is empty — it is reporting no NEW evidence, not gone |
| `STALE` / `BLIND_NO_DELIVERY` | `DELIVERY_BACKLOGGED_AT_SENSOR` | heartbeat confirms the sensor and it still holds queued events — evidence is DELAYED, not absent |
| `STALE` | `DELIVERY_LATE_LINK_UNCONFIRMED` | late **and** no heartbeat confirms the link |
| `BLIND_NO_DELIVERY` | `NEVER_DELIVERED` | enrolled, never delivered — enrolment is not visibility |
| `BLIND_NO_DELIVERY` | `DELIVERY_CEASED` | it delivered before and has now stopped |
| `BLIND_NO_DELIVERY` | `CREDENTIAL_REVOKED` | cannot deliver and is not expected to |

`GET /api/edr/telemetry/freshness[?endpoint=]` ·
`services/edr/telemetry_freshness.py` is a **projection only** — every
token comes from `resolve_delivery_freshness()`, so there is one place
where "are we blind?" is decided. Fleet roll-up:
`DELIVERING · PARTIALLY_DELIVERING · FLEET_BLIND · NEVER_DELIVERED ·
NO_ENROLLED_ENDPOINTS`, and `never_delivered` is counted **separately**
so a lab endpoint that never started does not read as a pipeline failure.
Every non-delivering answer carries: *"Blind means the platform is
receiving nothing from this endpoint. It is NOT a statement that nothing
is happening on it."*

**The before/after reading is the point of the whole phase:**

| | fleet | the recovered endpoint |
|---|---|---|
| before recovery, `00:31:11Z` | `FLEET_BLIND` · 0 delivering · **161 BLIND_NO_DELIVERY** · latest delivery `2026-09-07T16:53Z` | `BLIND_NO_DELIVERY` |
| after recovery | `PARTIALLY_DELIVERING` · 1 delivering · 160 blind (108 never delivered · 52 revoked) | `DELIVERING` · `link_confirmed` · cadence `DECLARED_BY_SENSOR 15s` |

### A resolution gap found by the UI
`resolve_endpoint()` resolves through **observed evidence**, so it could
not address an endpoint that is enrolled and has **never reported** —
exactly the endpoint blindness detection is most about
(`ep_a01197382b9aeb861045` returned `ENDPOINT_NOT_RESOLVED`). The
freshness projection now falls back to the **enrolment registry**,
tenant-constrained, disclosed as
`resolved_via: ENROLMENT_REGISTRY_DIRECT` — the same doctrine as
`routers/edr_response.py::_canonical_endpoint_id` (the registry is the
authority on enrolment). A forged identifier still returns
`ENDPOINT_NOT_RESOLVED` and a cross-tenant analyst still learns nothing
(gates E1–E2).
When an identifier is supplied but unresolvable the route now still
returns the **fleet** answer, explicitly labelled
`scope: FLEET_WIDE_NOT_THE_SUPPLIED_IDENTIFIER`, because the fleet fact
does not depend on the identifier — and the banner says so in words.

---

### D4 · The observability could lie under load — found by its own proof

The proof script failed against the real box, which is the point of
running it against the real box. Three findings, all fixed:

- **Liveness depended on throughput.** The heartbeat was sent *after* the
  drain, so while the sensor was delivering a large backlog its own
  liveness signal arrived 68s late — past a 60s stale threshold — and the
  platform reported *"no sensor heartbeat confirms the link"* about a
  sensor that was visibly busy delivering. The heartbeat is now sent at
  the **start** of every cycle. Liveness must not depend on evidence
  throughput.
- **A backlog was reported as a silence.** A live sensor that is *behind*
  is not a sensor with nothing to say, so the heartbeat now carries
  `queue_depth` (unsent lines in the local outbox) and the freshness
  authority reports `DELIVERY_BACKLOGGED_AT_SENSOR` — *"evidence is
  DELAYED, not absent"* — instead of `LINK_ALIVE_NO_NEW_EVIDENCE`. A
  backlog claimed by a sensor whose link is **not** confirmed cannot
  soften the answer.
- **An unbounded drain starved the API.** One HTTP request per event
  means a 650-event cycle saturated ingest hard enough to time out
  unrelated API calls at 15s (it broke the review agent's own login).
  The drain is now bounded to 200 events per cycle; nothing is dropped or
  skipped — the remainder stays queued and is reported as `queue_depth`,
  which is now a first-class visible state rather than an invisible one.

---

## 4 · PHASE A · WINDOW HONESTY — `NO EVIDENCE` may never mean "outside your window"

Two problems sat behind one screen, both disclosed in P0-2C and both
fixed here.

**Backend.** `_window_honesty()` re-runs the **same endpoint predicate
with the time bound removed** and returns
`observations_in_window · observations_outside_window ·
processes_outside_window · earliest/latest_evidence_at ·
retained_observations_total · max_window_hours` plus a state:
`OK` · `EVIDENCE_OUTSIDE_WINDOW` · `NO_EVIDENCE_RETAINED`. The count has
to come from the backend, because only the backend can see past the
caller's own filter. `reason` gains the distinct
`evidence_outside_window`.

**Frontend.** `EdrProcessTreePage` previously ignored `?hours=`
entirely and exposed no control, so an analyst could not widen the
window from the console at all. It now reads `?hours=`, offers
`1h · 1d · 3d · 7d · 30d`, and the empty state reads
**"EVIDENCE EXISTS OUTSIDE THIS WINDOW"** with the real count and the
real latest timestamp instead of "NO MATCHING EVIDENCE".

Live: `dev_a0267ae20737` at 24h → `EVIDENCE_OUTSIDE_WINDOW`, *"3 observed
process(es) across 40 observation(s) exist for this endpoint, but ALL of
them fall OUTSIDE the last 24h. The most recent is
2026-02-25T14:00:20Z. This window is empty; the endpoint is not."*
`dev_42e8c6dc74b9`: 1h → 66 in window / 449 outside / 515 retained;
720h → 501 in window. `max_window_hours: 720` is disclosed, so evidence
older than the maximum window is **unreachable but not silently
unreachable**.

---

## 5 · PHASE B · RECOVERY, AND THE FRESH PHYSICAL EVENT

`/etc/supervisor/conf.d/nivxforge_sensor.conf` +
`scripts/nivxforge_sensor_supervise.py`:
persistent state at `/app/agents/nivxforge-linux/.state`, idempotent
enrolment (it mints its own one-time token through the operator
credential already in `backend/.env` — no human with a token needed on a
restart), then `exec`s the sensor. If it cannot enrol it **exits with a
stated reason** and the console keeps reporting `BLIND_NO_DELIVERY`,
which is the truth. Nothing is fabricated to make the program stay up.

**The fresh, real, physical event** (`p0_3_generate_physical_event.py`
copies `/bin/sleep` to a unique name in the watched directory and really
runs it — no seed, no replay, no DB insert, no synthetic probe):

```
real process nivx-p03-proof-1788829159 pid 7641
 → sensor /proc poll → local outbox → authenticated POST /api/edr/agent/telemetry
 → raw_0e6ed575e3b216b4dad99ece  AUTHENTICATED  ingest 00:59:22Z
 → canonical  cev_0e6ed575e3b216b4dad99ece_0  proc_6ef2a7c5247b
 → provenance {source_kind: sensor, sensor_version: 0.1.0, trust_state: AUTHENTICATED}
 → EDR Process Tree · pid 7641 · real sha256 · real command line
 → Device Trajectory (6,788 events in the 1h window)
 → detection fabric: 18 post-recovery raw events carry DETECTION_MATCHED
 → XDR incident INC000000446 · provenance REAL_SENSOR_DERIVED
```

Since recovery: **~5,000 real raw events**, 4,972
`CANONICAL_EVIDENCE_CREATED`, 4,960 `DETECTION_EVALUATED_NO_MATCH`, 18
`DETECTION_MATCHED` (rule `EDR-LNX-002`, execution from a world-writable
directory — the proof binary itself lives in `/var/tmp`, so the rule is
firing on genuinely fresh evidence).

**Restart survivability, proven not asserted:** the sensor was
`SIGKILL`ed; supervisor restarted it (`pid 7644 → 7748`), it resumed the
**same** `ep_2d57cbe6f80152062109` from persistent state, **1** enrolment
row still exists for this hostname (no duplicate endpoint, no orphaned
history) and the console returned to `DELIVERING` within one cadence.

---

## 6 · CONSOLE — the four states an analyst must be able to tell apart

`nivxforge/components/TelemetryFreshness.jsx`
(`TelemetryFreshnessBanner` + `DeliveryChip`), wired into **Endpoint
Overview** and **Process Tree**. It renders the backend's own
`data-delivery-state` / `data-delivery-basis` / `data-fleet-state` and
computes nothing.

Verified live in the browser as admin:

| screen | rendered |
|---|---|
| recovered endpoint | `PIPELINE · DELIVERING` · chip `DELIVERING · 4s` · *"1 of 1 enrolled endpoint(s) are delivering within their declared cadence"* · thresholds line `(DECLARED_BY_SENSOR, 15s): stale_after_s = max(report_interval_s × 3, 60) · blind_after_s = max(report_interval_s × 20, 900)` |
| sensor stopped 120s | `PIPELINE · FLEET BLIND` (red) · chip `STALE · 120s` (amber) · `DELIVERY_LATE_LINK_UNCONFIRMED · last delivery 120s ago, past 60s and no sensor heartbeat confirms the link` · blindness note shown |
| sensor stopped >900s | chip `BLIND · NO DELIVERY` · `DELIVERY_CEASED` |
| enrolled, never reported | chip `BLIND · NO DELIVERY` · `NEVER_DELIVERED` |
| revoked credential | chip `BLIND · NO DELIVERY` · `CREDENTIAL_REVOKED` |
| evidence outside window | `EVIDENCE EXISTS OUTSIDE THIS WINDOW` + real counts + window control |
| forged identifier | `ENDPOINT NOT RESOLVED · NO DELIVERY RECORD`, and the fleet line says it is the fleet answer, not an answer about that identifier |

---

## 7 · WHAT WAS NOT DONE (stated, not hidden)

- **No alerting.** Sensor silence is now an operator-visible **state on
  the console**, refreshed every 30s. It is **not** a notification: there
  is no e-mail, webhook or ticket channel, so
  `05_OPERATIONS/OBSERVABILITY_GUIDE.md` stays `SPEC_PENDING` for the
  alert half. Claiming "alerting" would be exactly the kind of
  over-assertion the doc gate exists to catch.
- **Ingest throughput is one HTTP POST per event.** Measured, not
  assumed, and now bounded (200 events per sensor cycle) so it can no
  longer starve the API. A **batch ingest envelope** is the right fix and
  it is a new API contract, so it was not added in this pass. Until then
  a sustained collection rate above ~13 events/second on one endpoint
  will grow the local queue — which is honestly reported as
  `queue_depth` / `DELIVERY_BACKLOGGED_AT_SENSOR` instead of silently
  lagging.
- **The outbox was proven, not just trusted.** On restart after the
  15-minute blind window the sensor reported
  `collected=170 sent=313` — it delivered more than it collected that
  cycle because the events queued while the platform was blind were
  **replayed, not lost**.
- **Isolation stays `BLOCKED_ENVIRONMENT`.** The recovered sensor drained
  18 queued `ISOLATE_ENDPOINT` commands and reported
  `CAPABILITY_UNAVAILABLE: MISSING_PRIVILEGE: CAP_NET_ADMIN` for every
  one. Not simulated, not written around.
- **One endpoint, one platform.** `platforms with a real producer: LINUX
  only` is unchanged. Windows is next in the owner's order and was not
  started.
- **The 3 pre-existing `test_p0_f4_endpoint_process_tree.py` failures**
  remain, untouched and separately classified (P2).
- 52 `CREDENTIAL_REVOKED` and 108 `NEVER_DELIVERED` lab endpoints are
  reported as they are; they were not cleaned up to make the fleet
  summary look better.

---

### D5 · The outage RECURRED the same day — and blindness detection caught it

Hours after the recovery, the pod restarted. The sensor came back, drained
its backlog, and then **died**:

```
_serve_commands → _open_session → _post → urlopen
OSError [Errno 99] Cannot assign requested address
```

Local **ephemeral-port exhaustion**. One HTTP request per event with no
keep-alive had churned through the 32768–60999 range while draining
thousands of queued events. `_drain` handles this correctly (it holds the
queue back and loses nothing), but `_serve_commands` → `_open_session`
was **unguarded**, so the error escaped `run()`, the process exited,
supervisor burned its **default 3 retries** and marked the program
`FATAL` — permanently dead and silent. The same outage, same day, same
class: *nothing keeps the sensor alive.*

**It was caught in minutes instead of days, by the thing built in Phase A.**
The console read `PIPELINE · FLEET BLIND · BLIND · NO DELIVERY · 901s ·
DELIVERY_CEASED`. That is the whole point of P0-3 working in anger — but
blindness detection is not a substitute for a sensor that keeps trying.

Fixed:
- **Every network phase of a cycle is now inside a catch-all** in
  `run()`. A transport error prints `cycle_error=…`, drops the session
  token so it is re-opened, abandons that cycle only, and retries next
  interval. Unsent events stay in the durable outbox and replay. Nothing
  can terminate the sensor except a real signal.
- **`startretries=1000`** in the supervisor program. A `FATAL` sensor is
  silent blindness; supervisor may not give up on it.
- Guarded by two tests
  (`test_the_run_loop_cannot_die_of_a_transient_transport_error`,
  `test_supervisor_never_gives_up_on_the_sensor`).

Still open, disclosed: the underlying churn is the one-POST-per-event
design. The 200/cycle bound plus the loop guard contain it; **batch
ingest** is the real fix and remains unbuilt.

---

## 8 · FILES

**Backend**
- `services/edr/endpoint_health.py` — dimension C, thresholds, formula
- `services/edr/telemetry_freshness.py` — fleet/endpoint projection (new)
- `routers/edr.py` — `GET /edr/telemetry/freshness`, `_window_honesty()`
- `routers/edr_enrollment.py` — `POST /edr/agent/heartbeat`,
  `report_interval_seconds` on telemetry, sensor attribution to the bridge
- `edr_plane/enrollment/store.py` — `mark_heartbeat()`, cadence on
  `mark_reported()`, **D1** fix in `enroll()`
- `edr_plane/enrollment/identity.py` — heartbeat/cadence fields
- `edr_plane/canonical_bridge.py` + `detection_content/telemetry/nivxforge_sensor_dsm.py` — **D3** fix

**Sensor / ops**
- `agents/nivxforge-linux/nivxforge_sensor.py` — heartbeat each cycle,
  cadence declared on telemetry
- `scripts/nivxforge_sensor_supervise.py` (new) ·
  `/etc/supervisor/conf.d/nivxforge_sensor.conf` (new)

**Frontend**
- `nivxforge/components/TelemetryFreshness.jsx` (new)
- `nivxforge/pages/EdrProcessTreePage.jsx` — window control + honest
  empty state
- `nivxforge/pages/EdrOverviewPage.jsx` — fleet banner
- `nivxforge/edrApi.js` — `getTelemetryFreshness()`

**Proof / scripts**
- `scripts/p0_3_sensor_recovery_proof.py` — **41 PASS · 0 FAIL · 0
  BLOCKED** · `scripts/p0_3_generate_physical_event.py` ·
  `scripts/backfill_incident_provenance.py --relabel-unknown`
- `backend/tests/edr/test_p0_3_telemetry_freshness.py` (16 tests) — pins
  the cadence derivation, the three boundaries, live-vs-lost link,
  backlog-vs-silence, the three blindness bases, that the heartbeat is
  sent before the drain, that the run loop cannot die of a transport
  error, that supervisor never gives up, that a heartbeat can never write
  a delivery field, and that re-enrolment keeps `$setOnInsert`.
- `backend/tests/edr/test_iter107_p0_3_freshness_review.py` (11 tests,
  written by the independent review pass)

**Regression — none, no baseline reset**
`tests/edr` **365 passed / 3 failed** (330 before; the 3 are the
long-standing pre-existing `test_p0_f4` trio, untouched) ·
P0-2C alias sweep **52 PASS · 0 FAIL** · P-2 incident provenance
**27 PASS · 0 FAIL** · detection attribution **12/12** · X1–X3/Y2
**22/22** · `docs_reconcile --gate` **PASS · 0 violations**.
