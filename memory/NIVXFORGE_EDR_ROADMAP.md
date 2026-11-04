# NivXForge EDR — ROADMAP (EDR-only track)

Authority: `/app/docs/architecture/NIVXFORGE_EDR_MASTER_DIRECTIVE.md`
Truth baseline: `GET /api/edr/wave0/capabilities` · console at
`/xdr/admin/edr-capability-truth`

Governing principle: **Full architecture now. Full capability inventory
now. Full contracts now. Incremental implementation. No fake completion.**

Scope is **EDR only**. XDR incident orchestration, SIEM, NDR, ITDR, email
security, cloud security, UEBA/UBAE, SOAR/XSOAR, external TI aggregation
and cross-product XDR correlation are explicitly OUT of this track.
(`/app/memory/ROADMAP.md` is the separate, older XDR-wide gate list.)

---

## Where we actually are (2026-06, machine-graded, 127 capabilities)

```
effective state              gap class
OPERATIONAL              11  NONE                    44
END_TO_END_VALIDATED      7  TELEMETRY_MISSING       66
GOLDEN_CORPUS_VALIDATED   9  CONTROL_DRIVER_MISSING  15
BACKEND_IMPLEMENTED      33  UI_ONLY                  5
UI_IMPLEMENTED            2  OWNER_INPUT_PENDING      1
CONTRACT_DEFINED         28
NOT_IMPLEMENTED          41   (131 rows after P0-A.2)
```

**The one fact that explains this whole roadmap**: 66 of 131 capabilities
are blocked on `TELEMETRY_MISSING`. The trust boundary is now closed —
an endpoint can enrol, authenticate and have its evidence attributed —
but **no agent software exists to walk through it**. The gap is the
SENSOR, not the capability and no longer the trust plane. Eight capabilities are
BIND-don't-BUILD — File Trajectory, fleet propagation, spread watchlist,
quarantine, process termination, isolation, custom hash detections,
policy — real code, starved of endpoint evidence.

---

## P0 — the critical path to a real endpoint substrate

### ✅ Wave 0 · Architecture & contracts · DONE (2026-06)
12 executable contracts · JSON Schema export · field-level epistemic
enforcement · Capability Registry + API + console · immutable
`edr_raw_events` + replay · 127-row honesty baseline. 147 tests.
iteration_89: 100% backend / 100% frontend, zero issues, zero action
items.

### ✅ P0-A.2 · Endpoint Enrolment, Identity & Authentication · DONE (2026-06)
Delivered as ONE atomic boundary per owner instruction. One-time token →
platform-minted `endpoint_id` → opaque durable credential (HMAC-SHA-256
keyed digest at rest, never a JWT) → short-lived endpoint-scoped session →
immutable `edr_raw_events` stamped with the endpoint/credential/session
that produced it. Rejected Sensor Alarm records every refusal as a
security signal that can never become evidence. Transport pluggable;
mTLS reserved as an honest 501. 185 tests; iteration_90 100%/100%, zero
issues. **`edr_raw_events` is now the live authenticated write path.**
Registry 127 → 131 rows.

Original locked requirements, all met:
First CONSUMER of the Wave 0 `EndpointIdentity` contract. Owner-locked:
- One-time, short-TTL, single-use enrolment token → invalidated on use.
  Reusable fleet tokens are REJECTED as the P0 bootstrap primitive.
- Durable per-agent credential: **opaque, NOT a JWT**, hashed at rest,
  unique per endpoint, high entropy, endpoint-scoped, revocable,
  rotatable, tenant-scoped, never retrievable after issuance, never
  logged. Exchanged for a short-lived endpoint-scoped session token.
- Unenrolled/revoked telemetry: reject 401/403 **and** raise a visible
  security signal (tenant, source IP, presented identity, credential
  fingerprint, timestamp, reason, request id). Never silently dropped;
  the rejected payload is a security signal and is **never** trusted
  endpoint evidence.
- UI: minimal enrolment panel only (generate token, show once, TTL,
  single-use status, enrolled endpoints, credential status, revoke).
- Boundary that must hold: `Endpoint Identity ≠ Authentication Mechanism
  ≠ Transport ≠ Telemetry Envelope`, so mTLS drops in later untouched.
- `integration_expert` MUST be called before any auth code is written.
- 13 required tests: enrolment · expired token · reused token · invalid
  token · rotation · revocation · unauthorised telemetry rejection ·
  revoked-agent rejection · tenant isolation · endpoint-scoped
  enforcement · no secret leakage in responses or logs ·
  restart/persistence · concurrent enrolment idempotency.
- Acceptance: a real endpoint can be enrolled with a one-time bootstrap
  token, receive its durable credential, authenticate, be represented by
  authoritative identity, and be revoked deterministically — with **no
  ambiguity about trust state**.

### ✅ P0-B · Real Linux NivXForge Agent · DONE (2026-06, iteration_91)
`agents/nivxforge-linux/nivxforge_sensor.py` — a genuinely executable
sensor. It enrols with a one-time token, stores its durable credential
0600, opens sessions, collects REAL process / file / network activity from
`/proc`, buffers to a local durable queue (offset advanced only after a
confirmed accept) and streams authenticated telemetry. Real
PID/PPID/ancestry, SHA-256, command lines and users. Nothing simulated.
Durable observed-state means a restart does not re-report the process
table. Honest limits declared in the sensor's own capability block: no
eBPF, process EXIT never observed, file WRITER never attributed,
sub-poll-interval processes missed.
**By owner decision the sensor is MANUAL/on-demand — not under
supervisor.**

### ✅ P0-C · On-endpoint durable queue + authenticated transport · DONE
Delivered as part of P0-B (`_enqueue`/`_drain`) and P0-A.2
(`transport.py`, mTLS reserved as an honest 501).

### ✅ P0-D · Process / File / Network telemetry → canonical · DONE (2026-06)
`edr_plane/canonical_bridge.py` — a sensor DSM on the same pattern as
`cef-leef`, feeding the EXISTING `telemetry_bridge` / CES / CEM path. No
new reasoning engine. Adds two guarantees the proof forced into existence:
real parent lineage survives into CES so a process tree links, and
`activity_identity()` means one real activity is exactly ONE piece of
evidence (a re-observation is linked, never re-counted).

### ✅ P0-E · Device Trajectory on real sensor evidence · PARTIAL, honestly
Device Trajectory now renders real sensor evidence and accepts the
platform-minted `endpoint_id` as a pivot. **Not claimed**: the
`/api/edr/process-tree` route and File Trajectory have NOT been re-proven
against sensor evidence, and the exact-event pivot is still open.

### ✅ P0-F · Endpoint Detection Activation · DONE (2026-06)
Endpoint evidence now enters the authoritative XDR fabric via
`NivXForgeSensorDSM` + a 5-rule Linux pack, both built on the EXISTING
DSM registry and `DetectionRuleContent` model. Proven on real behaviour
(`scripts/p0_f_detection_proof.py`, 20/20) with negative false-positive
proof. Incident promotion NOT claimed — the VEEE gate declined at
LIKELY_BENIGN/45, honestly.

### ✅ P0-F.1 · Verdict Threshold Proof · DONE (2026-06)
Real endpoint behaviour → MALICIOUS/80 → REAL incident, with the VEEE
gate UNCHANGED. Root cause was IUE reading only a vendor severity band,
which a sensor never supplies; the band now falls back to the severity of
the rule that actually fired (`iue.severity_source` records which).

### ✅ P0-F.2 · Endpoint incident consolidation + identity · DONE (2026-06)
One attack campaign on one endpoint is ONE incident, keyed on
`(tenant, endpoint_id)` + a rolling 30-minute window while the case is
open. All contributing evidence retained; escalate-only; titles derived
from the rule that actually fired plus hostname. Proven on the real
sensor: 6 detections → 1 incident (INC000000230).

### ✅ P0-F.3 · Rule store → runtime binding · DONE (2026-06)
No second engine. All 98 authored rules classified store → binding →
evaluator; 0 can fire today (23 licence-blocked, 52 content-incomplete,
22 no telemetry, 1 unsupported) — the binding is real, the store content
is the gap. A store-authored Linux rule was proven to fire on real sensor
evidence and then withdrawn.

### ✅ P0-F.4 · Process Tree re-key · DONE (2026-06)
Endpoint-keyed ancestry from real sensor evidence, honest ghost roots,
pid/ppid restored to the CEM projection.

**Next (owner sequencing):** ENDPOINT RESPONSE (the biggest remaining
capability — real isolate/kill + verification), then Campaign Story View,
Live Attack Replay, Rule Health Panel, and separately the detection
CONTENT authoring work (52 incomplete store rules).

### ▶ P0-F · superseded section below (kept for history)
The question P0-F exists to answer: *can NivXForge actually detect
malicious or suspicious behaviour from the real endpoint evidence it now
holds?* Behavioural + IOC rules over canonical EDR evidence, using the
existing detection / IUE / ICE / VEEE chain — no new engine.

### P0-G EDR Hunting / Forensics / Live Query
### P0-H Real response drivers (unlocks the whole §10 loop)
### P0-I Windows NivXForge Agent
### Sensor Operational Persistence — run the sensor as a managed service

---

## Wave backlog (directive §15)

| Wave | Scope | Blocked on |
|---|---|---|
| 1 | Process EDR, proven E2E | P0-B |
| 2 | File EDR · File Repository state machine · Fetch · Fleet trajectory | P0-B |
| 3 | Network EDR · DNS | P0-B |
| 4 | Persistence / system (registry, services, tasks, cron, drivers) | P0-B |
| 5 | Identity / user | P0-B |
| 6 | Endpoint response · policy engine · playbook engine · outbreak control | P0-H |
| 7 | Forensic snapshot · Live Query | P0-B |
| 8 | Malware analysis (dynamic sandbox at P3) | — |
| 9 | Advanced detection · retrospective detection (self-contained, high value) | — |
| 10 | Fleet operations · patient zero · global IOC search | P0-E |

---

## P1 · Owner input required

- **43-item filter taxonomy.** The five categories are frozen
  (Activity · System · Disposition · Flags · File Types). The verbatim
  item list is NOT in this repository and was deliberately not
  reconstructed from memory (owner decision 4B). Entry point is
  `edr_plane.capability.taxonomy.register_baseline_items()`, which
  refuses anything other than exactly 43 items and refuses unknown
  categories. Until it is registered, both the API and the console
  disclose `0/43` rather than present a partial filter set as complete.

## P2 · Deferred, explicitly not blockers

- Dynamic sandbox — owner-confirmed P3. It would add a ninth evidence
  producer while eight consumers sit starved.
- macOS agent.
- SHA-256 universal pivot context menu (needs File Repository first).
- Retiring the main SPA / 8-tab consolidation.
