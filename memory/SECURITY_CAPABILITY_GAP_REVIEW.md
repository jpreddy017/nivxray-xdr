# NivXRay XDR — SECURITY CAPABILITY GAP REVIEW (READ-ONLY)
_N2.1 accepted/locked · no code, no UI, no new source, no merge, no deployment_

Invariants carried forward and verified still enforced in code:
**PID ≠ PROCESS IDENTITY** (`ProcessIdentity.mint` refuses without start
time) · **IP OBSERVATION ≠ ENDPOINT IDENTITY**
(`endpoint_address_observation.lookup()` returns
`usable_for_attribution: False` in every branch; `xdr_spread_watchlist`
excludes source IP, username and hostname from identity) ·
**TEMPORAL COINCIDENCE ≠ CAUSAL ATTRIBUTION** (CORR-EP-001's conditions
require `SOURCE_PROCESS_IDENTITY`; weaker evidence carries no key) ·
**NETWORK CORRELATION ≠ PROCESS ATTRIBUTION** (CORR-NET-002's entity key
names no process).

States: `IMPLEMENTED` · `SYNTHETIC/REPLAY PROVEN` · `REAL SOURCE PROVEN` ·
`EXTERNAL_ACCESS_BLOCKED` · `ABSENT`

---

## 0 · THE FINDING THAT REFRAMES EVERYTHING

Two facts, already in the tree, matter more than any individual gap:

1. **`edr_plane/capability/inventory.py:255` — of the 98 authored store
   rules, ZERO can fire today**: 23 LICENSE_BLOCKED, 52
   STORE_CONTENT_INCOMPLETE (39 declare no logsource, 13 no detection
   block), 22 NO_TELEMETRY (Windows/proxy content we collect nothing for),
   1 UNSUPPORTED_BY_EVALUATOR. The binding is real; the **content** is the
   gap. The in-code library is 32 rules — 16 endpoint, 6 event, 4 behavior,
   4 content, **2 network** — plus 5 Linux EDR rules.
2. **An incident is anchored to ONE canonical event.**
   `xdr_investigation` lanes read a single linked `canonical`;
   `campaign_story` narrates one endpoint's activity. There is no object
   that says "these detections, across these sources, are one attack".
   Spread tracking exists (`xdr_spread_watchlist`, owner-locked identity
   keys) but it counts sightings — it does not compose an incident.

So the platform's honest shape today is: **excellent evidence discipline,
thin detection content, and no cross-domain incident.** Ranking the
fourteen areas without that context would put effort where it cannot pay.

---

## 1 · THE FOURTEEN AREAS

### 1.1 Linux DNS / process → domain evidence
* **CURRENT STATE** `ABSENT` at source. The sensor collects PROCESS, FILE,
  NETWORK only (`CAPABILITIES.collects`); `ActivityType.DNS` exists in the
  contract and nothing emits it; `canonical_bridge.parse` rejects any
  activity outside the three.
* **SECURITY VALUE** High for Linux estates — it is the missing half of
  what N2.1 just proved on Windows.
* **ATTACKS UNLOCKED** Linux C2 over DNS, DGA on servers, process-attributed
  malicious-domain contact, data exfil via DNS from a container host.
* **DEPENDENCIES** Sensor change (evidence producer). Everything downstream
  (canonical DNS fields, CORR-EP-001, N1 content) already exists.
* **EVIDENCE AVAILABLE** none today; would need eBPF, or a resolver-log
  tail, or `/proc` socket + DNS parsing.
* **REAL-SOURCE STATUS** live host `EXTERNAL_ACCESS_BLOCKED` regardless.
* **FALSE-POSITIVE RISK** Low — DNS evidence is factual; FP risk sits in
  the content, not the evidence.
* **COST** Medium-high: real sensor engineering (capture path, not a field).
* **SMALLEST GATE** Sensor DNS activity for the resolver path only, reusing
  the N1 canonical DNS fields and CORR-EP-001 unchanged.

### 1.2 Endpoint ↔ Zeek cross-source correlation
* **CURRENT STATE** `ABSENT`. N2 classified the join as FORBIDDEN without
  NAT mapping, an IP↔endpoint inventory and clock tolerance.
* **SECURITY VALUE** Medium *today*, high later — it is how a network
  detection gets an owner.
* **ATTACKS UNLOCKED** Attributing a wire-observed C2 flow to a process.
* **DEPENDENCIES** Real Zeek source (blocked), IP↔endpoint evidence (D
  exists, deliberately non-attributive), NAT mapping (`ABSENT`), clock
  tolerance model (`ABSENT`).
* **EVIDENCE AVAILABLE** `community_id` in the canonical model — but only
  Zeek emits it; no endpoint source does.
* **REAL-SOURCE STATUS** both sides unproven.
* **FALSE-POSITIVE RISK** **The highest on this list.** Every hazard N2
  named (NAT, proxy, DHCP, container reuse, shared host) attacks exactly
  this join. Built early, it would quietly reintroduce the coincidence
  attribution the last two gates removed.
* **COST** High, and mostly risk, not code.
* **SMALLEST GATE** Do not attempt until at least one side is REAL SOURCE
  PROVEN and `community_id` exists on both.

### 1.3 C2 / beaconing detection
* **CURRENT STATE** `ABSENT` as content; the engine exists
  (`GROUP_BY`/`TEMPORAL`/`THRESHOLD`) and N1 stores `duration_ms`,
  bytes/packets and `conn_state`.
* **SECURITY VALUE** High — beaconing is the single most durable C2
  signature.
* **ATTACKS UNLOCKED** Cobalt-Strike-class implants, RAT check-ins,
  long-haul low-and-slow channels.
* **DEPENDENCIES** **Real traffic volume.** Interval-regularity scoring on
  replay data proves arithmetic, not detection.
* **EVIDENCE AVAILABLE** flow evidence is ready; nothing else is needed.
* **REAL-SOURCE STATUS** `EXTERNAL_ACCESS_BLOCKED` (no live Zeek).
* **FALSE-POSITIVE RISK** High without baselining — every telemetry agent,
  updater and monitoring probe beacons perfectly.
* **COST** Low-medium in code, high in tuning.
* **SMALLEST GATE** Defer until a real flow source exists; then destination
  prevalence + interval variance, disabled by default.

### 1.4 Richer DNS / network behavioural detections
* **CURRENT STATE** 2 network rules in-code + 2 disabled correlation rules.
* **SECURITY VALUE** Medium-high, and immediately usable — the canonical
  fields landed in N1.
* **ATTACKS UNLOCKED** DGA, DNS tunnelling, rare-destination egress,
  denied-sweep patterns (the last needs firewall evidence).
* **DEPENDENCIES** Volume for prevalence; nothing structural.
* **EVIDENCE AVAILABLE** query, qtype, rcode, answers, TTLs, bytes,
  duration, conn_state — all canonical now.
* **REAL-SOURCE STATUS** replay only.
* **FALSE-POSITIVE RISK** Medium; prevalence-based rules need a baseline
  the platform does not yet compute.
* **COST** Low.
* **SMALLEST GATE** A prevalence primitive (first-seen / rarity per tenant)
  — which is reusable for §1.3, §1.9 and §1.10 — then two rules on it.

### 1.5 Ransomware precursor / prevention
* **CURRENT STATE** Content exists for T1486 (impact), T1490 (shadow-copy
  deletion), T1485 (data destruction); the Linux sensor emits FILE
  activity with `operation`, path, size, sha256. **Prevention is
  CONTRACT_DEFINED only** — `PolicyMode` AUDIT/PROTECT/PREVENT exists with
  **no policy driver bound to any endpoint** (`GC.CONTROL_DRIVER_MISSING`).
* **SECURITY VALUE** **Highest business value on this list.** Ransomware is
  the loss event buyers actually fear.
* **ATTACKS UNLOCKED** Mass-encryption behaviour, shadow-copy destruction,
  backup tampering, staging before encryption.
* **DEPENDENCIES** Precursor *detection* needs only existing FILE evidence
  plus a rate/entropy primitive. Prevention needs a control plane the
  product does not have.
* **EVIDENCE AVAILABLE** FILE create/modify with hashes — but the sensor
  **polls** a watched directory, so mass-encryption rate is observed
  coarsely. That is a real limit to state, not to paper over.
* **REAL-SOURCE STATUS** `EXTERNAL_ACCESS_BLOCKED` (live host).
* **FALSE-POSITIVE RISK** Medium-high (backup jobs, archivers, build
  systems) — manageable if bound to process identity, which N2.1 now
  provides.
* **COST** Detection: medium. Prevention: **large** (real-time hooks, a
  policy plane, and an enforcement driver — a product phase, not a gate).
* **SMALLEST GATE** Process-attributed mass-file-modification precursor
  (rate + distinct-extension + shadow-copy/backup tampering), evidence-only,
  disabled by default. Prevention stays out.

### 1.6 Persistence detection
* **CURRENT STATE** Partial: T1547.001 (run keys), T1543.003 (services),
  T1053.005 (scheduled tasks) authored — all **Windows** lanes. Linux
  persistence (cron, systemd units, `~/.ssh/authorized_keys`, LD_PRELOAD)
  is `ABSENT`; the sensor watches one directory.
* **SECURITY VALUE** High — persistence is where dwell time is won or lost.
* **DEPENDENCIES** Windows content needs a real Sysmon feed (`ABSENT`);
  Linux content needs sensor file-watch scope.
* **FALSE-POSITIVE RISK** Low-medium (admin activity).
* **COST** Low per rule, **but the telemetry is the gate.**
* **SMALLEST GATE** Linux persistence paths on the existing FILE lane,
  process-attributed via N2.1.

### 1.7 Credential access
* **CURRENT STATE** T1003.001 (LSASS), T1003.003 (NTDS), T1552.005,
  T1558.003/004 (Kerberoasting / AS-REP) authored — **every one needs
  Windows telemetry we do not receive**. Linux credential access
  (`/etc/shadow` reads, SSH key theft, memory dumping) is `ABSENT`.
* **SECURITY VALUE** High — it is the pivot step in most real intrusions.
* **DEPENDENCIES** Real Sysmon / Windows Security channel (`ABSENT`).
* **FALSE-POSITIVE RISK** Low when evidence-bound.
* **COST** Low code, blocked on telemetry.
* **SMALLEST GATE** Linux credential-file access on the FILE lane; Windows
  content only once a real feed exists.

### 1.8 Lateral movement
* **CURRENT STATE** T1021.002/006, T1047, T1078.004 authored (event lane).
  The pieces exist — but detecting lateral movement means relating activity
  on **endpoint A** to activity on **endpoint B**, and the platform has no
  object that spans two endpoints. Spread tracking counts sightings only.
* **SECURITY VALUE** High.
* **DEPENDENCIES** **Cross-domain incident/entity correlation (§1.14).**
  This is a dependent capability, not an independent one.
* **FALSE-POSITIVE RISK** High without identity joins (admin tooling looks
  identical).
* **COST** Medium — after the prerequisite.
* **SMALLEST GATE** Blocked; do not start before §1.14.

### 1.9 Identity / email / cloud correlation
* **CURRENT STATE** Evidence plane is genuinely there:
  `m365-unified-audit` DSM (Phase 1), plus the legacy parallel fabric's
  `entra_signin_log`, `okta_system_log`, `aws_cloudtrail` adapters (still
  REPORT-ONLY, untouched). Content: T1114.003 (forwarding rules), T1098
  (account manipulation), T1078.004 (cloud accounts) — event lane. What is
  missing is the **join**: identity activity cannot be related to endpoint
  or network activity, because there is no shared entity.
* **SECURITY VALUE** **Very high** — BEC, token theft and OAuth abuse are
  the most common real incidents, and the identity domain is where XDR
  differentiates.
* **DEPENDENCIES** §1.14 (entity), plus real M365 credentials (owner-side).
* **EVIDENCE AVAILABLE** M365 audit records; `IdentityEntity` exists on
  canonical evidence and is populated by Sysmon (`User`) and the sensor.
* **REAL-SOURCE STATUS** M365 `EXTERNAL_ACCESS_BLOCKED` pending owner
  credentials; the legacy adapters are not on the authoritative path.
* **FALSE-POSITIVE RISK** Medium (travel, shared mailboxes, service
  principals).
* **COST** Medium.
* **SMALLEST GATE** After §1.14: user principal as a first-class entity,
  joining M365 identity evidence to endpoint `IdentityEntity`.

### 1.10 Firewall telemetry / enforcement evidence
* **CURRENT STATE** `cef-leef` DSM is real and capable; **no canonical
  allow/deny action field** (N1 deliberately did not add placeholders).
* **SECURITY VALUE** Medium-high — enforcement evidence answers "was it
  blocked?", which nothing else can.
* **ATTACKS UNLOCKED** Repeated-denied-connection patterns, egress-policy
  violations, blocked-C2 retries.
* **DEPENDENCIES** A real appliance (owner-side).
* **REAL-SOURCE STATUS** `ABSENT` (no appliance).
* **FALSE-POSITIVE RISK** Low.
* **COST** Low-medium (canonical action/zone/rule fields + one DSM pass).
* **SMALLEST GATE** Only when a real firewall exists; the parsing path is
  already proven.

### 1.11 NivXForge EDR prevention / runtime depth
* **CURRENT STATE** Detection + response are real (kill, isolate, release,
  with independent verification). **Prevention is not**: the policy engine
  is `CONTRACT_DEFINED` with no driver, and the sensor is a `/proc`
  **poller** — it observes state, it does not intercept.
* **SECURITY VALUE** Very high commercially, and it is what "EDR" means to
  a buyer.
* **DEPENDENCIES** Real-time interception (eBPF/kernel), a policy plane, an
  enforcement driver, and a Work-Mode boundary decision — **this is the
  NivXForge EDR product track, not an XDR gate.**
* **REAL-SOURCE STATUS** `EXTERNAL_ACCESS_BLOCKED`.
* **COST** **Largest on this list** — a product phase.
* **SMALLEST GATE** Out of scope for NivXRay XDR; belongs to the EDR track
  the owner has fenced off.

### 1.12 Response + independent verification
* **CURRENT STATE** **The strongest area in the platform.** `KILL_PROCESS`
  bound to an observed pid **and its start identity**, `ISOLATE_ENDPOINT`
  that refuses to act if it cannot resolve the endpoint, and `verify()`
  that re-reads `/proc` after the fact — an unproven isolation is recorded
  as unproven, never as isolated.
* **SECURITY VALUE** High, already delivered.
* **GAP** Only breadth (Windows actions, network containment) and the
  playbook engine (contracted, unbound).
* **RECOMMENDATION** **Leave it alone.** Adding actions before there is a
  cross-domain incident to respond to would be motion, not capability.

### 1.13 Real-source onboarding
* **CURRENT STATE** Every capability the platform has is
  `SYNTHETIC/REPLAY PROVEN`. Zeek `EXTERNAL_ACCESS_BLOCKED` (no CAP_NET_RAW,
  machine-verified), Sysmon `ABSENT`, NivXForge host
  `EXTERNAL_ACCESS_BLOCKED` (D20), M365 `EXTERNAL_ACCESS_BLOCKED` (owner
  credentials).
* **SECURITY VALUE** **Highest truth value of anything on this list**, and
  near-zero engineering cost on our side — the runbooks already exist
  (`M365_REAL_SOURCE_ONBOARDING.md`,
  `PRODUCTION_TELEMETRY_ONBOARDING_RUNBOOK.md`).
* **DEPENDENCIES** Owner environment only.
* **COST** Ours: small. Owner's: real.
* **SMALLEST GATE** **One** real source — the cheapest is the M365 app
  registration (no hardware), then a Linux host running the sensor.
* **NOTE** This is not an alternative to building capability; it is what
  converts everything already built from "proven in replay" into a product
  claim. It should run **in parallel**, not instead.

### 1.14 Cross-domain incident / correlation capability
* **CURRENT STATE** `ABSENT` — and it is the product's defining claim.
  An incident links **one** canonical event; `campaign_story` narrates one
  endpoint; correlation matches exist but do not compose an incident;
  entity keys exist in three different places
  (`xdr_spread_watchlist` identity keys, `xdr_ice` signals, the
  `edr_plane` contracts) with **no single entity resolution service**.
* **SECURITY VALUE** **Highest capability value on this list.**
* **ATTACKS UNLOCKED** Not one technique — it unlocks *relating* them:
  lateral movement (§1.8), identity↔endpoint (§1.9), network↔endpoint
  (§1.2), and any multi-stage intrusion narrative.
* **DEPENDENCIES** None external. Uses only evidence already canonical.
* **EVIDENCE AVAILABLE** endpoint_id, process identity (N2.1), user
  principal, domain, address, file hash, flow id — all present, none
  unified.
* **REAL-SOURCE STATUS** independent of it.
* **FALSE-POSITIVE RISK** **This is where the risk lives**: entity merging
  is exactly how platforms fabricate relationships. The N1/N2 discipline
  (authoritative keys only, states for everything else) is the antidote and
  already exists in code.
* **COST** Medium — one entity resolution primitive + incident aggregation.
* **SMALLEST GATE** See §3.

---

## 2 · PREREQUISITES AND REUSABLE PRIMITIVES

**Prerequisite graph** (→ means "needs"):

```
lateral movement      ─┐
identity↔endpoint     ─┤
network↔endpoint      ─┼──→  ENTITY RESOLUTION + MULTI-EVIDENCE INCIDENT  (§1.14)
cross-domain story    ─┤
attack narrative      ─┘

beaconing (§1.3) ──→ prevalence/baseline primitive ──→ also serves §1.4, §1.9
ransomware precursor (§1.5) ──→ rate/entropy primitive ──→ also serves §1.6
Windows credential/persistence/lateral content (§1.6–1.8) ──→ REAL SYSMON FEED
firewall enforcement (§1.10) ──→ real appliance
endpoint↔Zeek (§1.2) ──→ real source on at least one side + NAT/clock model
EDR prevention (§1.11) ──→ its own product track (Work Mode)
```

**Reusable primitives** (build these; they compound):
1. **Entity resolution** — one service that turns canonical evidence into
   typed entities with authoritative-or-declared states. Feeds five areas.
2. **Multi-evidence incident** — an incident that aggregates detections and
   correlation matches by entity, citing every event. Feeds narrative,
   lateral, identity, response targeting.
3. **Prevalence / first-seen baseline** — per tenant, per entity type.
   Feeds beaconing, rare-destination, anomalous identity.
4. **Rate / burst primitive over evidence** — feeds ransomware precursor,
   persistence bursts, credential sweeps.

**Isolated features** (valuable, but they compound nothing):
firewall action fields, individual Windows rules, additional response
actions, the buyer-facing evidence page.

---

## 3 · RECOMMENDATION (not ranked by ease)

> **Next gate: X1 — Entity Resolution + Multi-Evidence Incident.**
> Then, *in parallel and owner-side*, one real source (§1.13).

Why this and not the other thirteen:

* It is the **only** item that is a prerequisite for four others. Building
  lateral movement, identity correlation or cross-source attribution first
  means building them twice.
* It needs **no new telemetry and no unblocked environment** — it works on
  evidence already canonical, so it cannot stall the way §1.2, §1.3, §1.6
  and §1.10 would.
* It is where NivXRay stops being "an evidence platform with strong
  ingestion" and becomes an XDR. N1 gave the network chain; N2.1 gave the
  endpoint chain; neither can currently be told as **one incident**.
* It is also the highest-risk item for fabrication, which is precisely why
  it should be built by this codebase, with its existing refusal
  discipline, rather than bolted on later under delivery pressure.

**Smallest X1 gate (proposal only — not started):**
1. One entity resolution service producing typed entities
   (`endpoint`, `process`, `user`, `domain`, `address`, `file_hash`,
   `flow`) from canonical evidence, each carrying an
   `identity_state` (`AUTHORITATIVE` / `DECLARED` / `NOT_OBSERVED`) and its
   provenance. Address and hostname entities may **never** be
   `AUTHORITATIVE`.
2. An incident that aggregates detections *and* correlation matches by
   entity, citing every canonical event id — replacing the one-event
   anchor without removing it.
3. **One** cross-domain proof: an endpoint/process detection and a network
   relationship on the same authoritative entity composing into a single
   incident — and the negative proof that two entities that merely share an
   address or an instant do **not** compose.
4. Nothing else: no UI, no new source, no new detection pack, no merge.

**Explicitly recommended NOT to start now:** endpoint↔Zeek attribution
(§1.2 — highest fabrication risk, both sides unproven), beaconing (§1.3 —
needs real volume), Windows credential/persistence/lateral content
(§1.6–1.8 — the telemetry is the gate, not the rules), firewall enforcement
(§1.10 — needs an appliance), EDR prevention (§1.11 — a separate product
track), response breadth (§1.12 — already the strongest area), and the
buyer-facing evidence page (presentation, per owner).

---

**STOP — awaiting owner review. No implementation was started.**
