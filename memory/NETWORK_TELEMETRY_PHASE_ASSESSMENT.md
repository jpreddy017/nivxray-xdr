# NivXRay XDR — NETWORK / DNS / FIREWALL SECURITY TELEMETRY
## PHASE ASSESSMENT & DESIGN (READ-ONLY · NO IMPLEMENTATION)

Owner decision honoured: assessment/design only. No code written, no DSM,
no rule, no parser, no synthetic replay, no migration, no refactor, no
production change, no merge, no deploy. Nothing outside `/app/memory` was
created or modified. NivXForge EDR / Work Mode untouched.

Capability states used consistently:
`IMPLEMENTED` · `SYNTHETIC/REPLAY PROVEN` · `REAL SOURCE PROVEN` ·
`EXTERNAL_ACCESS_BLOCKED` · `ABSENT`

---

## 1 · EXISTING CAPABILITY (what is already in the tree)

### 1.1 Evidence plane — network-relevant DSMs

| DSM id (declared source) | What it actually interprets | Network evidence it produces | State |
| --- | --- | --- | --- |
| `snort-eve` (`detection_content/xdr_pipeline.py:37-200`) | Suricata/Snort **EVE JSON** alerts. Parser *requires* `event_type`, `timestamp`, `src_ip`, `dest_ip`; rejects `alert` without `alert.signature_id` | `network.src.ip/port`, `network.dst.ip/port`, `network.protocol`, `security.signature.{id,name,severity}`, `event_type="network_alert"`, activity time = EVE `timestamp` (**ACTIVITY_TIME** basis) | Code `IMPLEMENTED`; in-pipeline golden alert `SYNTHETIC/REPLAY PROVEN`; live Suricata sensor `ABSENT` |
| `cef-leef` (`detection_content/telemetry/cef_leef_dsm.py`, 612 lines) | **CEF 0 / LEEF 1.0 / 2.0** carried over syslog — i.e. the real firewall/appliance dialect. Re-parses the verbatim raw line (collector parse is provenance, not authority) | `src`/`spt`/`sourceAddress`/`srcPort`, `dst`/`dpt`/`destinationAddress`/`destinationPort`, `proto`/`protocol`, device identity `dvchost`/`dvc`/`devname`, user `suser`/`duser`, `act`/`action`/`deviceAction` (currently mapped onto **FileEntity.action**, not a network action), `destinationDnsDomain`→`network.dns_query`; D12-correct time handling (`rt` = receipt/OBSERVATION, only `devTime`/`start`/`end` may establish activity) | Code `IMPLEMENTED`; end-to-end over the wire (collector syslog → authenticated ingest → canonical evidence → `DET-EX-001`) `SYNTHETIC/REPLAY PROVEN` (`memory/PREVIEW_COLLECTOR_PROOF.md`) — the sender was **not** a real firewall appliance, so *firewall* telemetry is **not** REAL SOURCE PROVEN |
| `microsoft-sysmon` (`telemetry/sysmon_dsm.py`) | Sysmon EIDs `{1,3,11,12,13,14,22}` — includes **EID 3 network_connect** and **EID 22 dns_query** | `network.src_ip/src_port/dest_ip/dest_port/protocol`, `network.dns_query` (`QueryName`), **plus full process identity** (`Image`, `ProcessGuid`, `pid`, parent) on the same record. `QueryResults` **is parsed (line 103) then dropped** — see GAP-1 | Code `IMPLEMENTED`; `SYNTHETIC/REPLAY PROVEN`; real Windows/Sysmon feed `ABSENT` |
| `nivxforge-linux-sensor` | Sensor activities `PROCESS` / `FILE` / `NETWORK` via `edr_plane.canonical_bridge` | process + network connection, **no DNS activity at all** | Code `IMPLEMENTED`; live host acceptance `EXTERNAL_ACCESS_BLOCKED` (D20) |
| Zeek / Corelight | — | — | `ABSENT` |
| PAN-OS / FortiGate / ASA-FTD **native** (non-CEF) formats | — | — | `ABSENT` (only their CEF dialect is reachable, via `cef-leef`) |
| DNS resolver logs (Windows DNS analytic, BIND, Unbound, protective DNS) | — | — | `ABSENT` |
| Cloud network logs (VPC Flow, Route53 Resolver, Azure NSG Flow) | — | — | `ABSENT` |

### 1.2 Acquisition plane (`/app/apps/nivxray-xdr-collector`)

* `framework/syslog.py` — **UDP + TCP** listener, RFC3164 / RFC5424 / auto,
  with CEF/LEEF payload detection layered on top
  (`payload_formats.detect_and_parse`), `Capability.NETWORK_EVENTS`
  declared, per-instance port binding enforced. `IMPLEMENTED`.
* `framework/rest_poller.py` + `oauth2.py` + `scheduler.py` — pull sources.
  `IMPLEMENTED`.
* `framework/outbox.py` + `acquisition_state.py` — SQLite durable outbox,
  checkpoints, commit-on-authoritative-acceptance, Terminal Record
  quarantine. `IMPLEMENTED` (this is the asset the network phase reuses).
* `framework/runtime.py` — wires syslog/webhook/poller/M365 connectors.
* **Gap**: durability applies to *polled* sources. A syslog/UDP receiver has
  no checkpoint and no replayable upstream — loss is unrecoverable by
  construction. That is a property of the transport, not a defect, but it
  must be stated in any "no silent loss" claim (GAP-5).

### 1.3 Routing / authority plane

`services/source_routing.py` — declared-source routing, one declared source →
exactly one DSM, content may only *validate* a declaration. Network-relevant
catalog keys already present: `snort-eve` (aliases `suricata`,
`suricata-eve`, `snort`), `cef-leef` (aliases `cef`, `leef`),
`microsoft-sysmon` (`sysmon`), `nivxforge-linux-sensor`.
**A Zeek / firewall-native / DNS-resolver declared source does not exist** —
adding one is a catalog + DSM change, not a new pipeline. `IMPLEMENTED`.

### 1.4 Canonical evidence model (`telemetry/models.py:49`)

```
NetworkEntity: src_ip, src_port, dest_ip, dest_port, protocol, direction, dns_query
```

Present today: src/dst IP, src/dst port, protocol, direction (field exists;
**no DSM populates it**), dns_query.
Absent from the canonical contract: allow/deny action, DNS response
IPs/answers, DNS qtype/rcode, bytes/packets/duration, flow/session/community
id, network-device identity as a *network* field, NAT pre/post addresses,
firewall rule name, zone/interface, URL/SNI/JA3.

### 1.5 Detection + correlation plane

* `detection_content/library/rules_enterprise.py` — `lane="network"` rules
  exist: DNS-tunnelling predicate (`network.dns_query` / `dns.query` /
  `query`) and cloud-IMDS access (`network.dest_ip == 169.254.169.254`).
  `IMPLEMENTED`, but the network lane is 2 rules deep.
* `routers/xdr_correlation.py` — **stateful 13-operator engine**:
  `EVENT_MATCH, TEMPORAL, TEMPORAL_ORDERED, SEQUENCE, COUNT, THRESHOLD,
  VALUE_COUNT, GROUP_BY, NEGATIVE_EVIDENCE …`. This is exactly what
  beaconing / repeated-deny / DNS→connection sequencing needs.
  `IMPLEMENTED`. Ships with **zero ENABLED rules** — `xdr_ice` honestly
  returns `NO_RULES_ENABLED` rather than fabricating correlation.
* `detection_content/xdr_ice.py:87` reads **both** canonical network shapes
  (nested `network.src.ip` and flat `network.src_ip`). Correct.
* `services/investigator/capabilities/network_identity_file.py` and
  `historical.py` read **only** the nested `network.{src,dst}.ip` shape →
  network/historical pivots are blind to every model-shaped DSM
  (`cef-leef`, `microsoft-sysmon`, `windows-security-evd`). GAP-2.
* `DnsPivotCapability` reads `canonical["dns"]["query"]`. **No DSM emits a
  `dns` object** — every DSM writes `network.dns_query`. So the DNS pivot can
  only ever fire from incident IOCs, never from canonical DNS evidence.
  GAP-3.

### 1.6 Legacy / parallel fabric — INVENTORY ONLY, TOUCHED NOTHING

* `backend/services/telemetry_adapters/` — second adapter framework
  (`framework.py`, `registry` with explicit registration, `correlation.py`,
  `verdict_bridge.py`, `stores.py`, `pollers.py`, `runner.py`).
  Adapters present: `aws_cloudtrail.py`, `entra_signin_log.py`,
  `okta_system_log.py`. **No network / DNS / firewall adapter exists here**,
  so the network phase has nothing to inherit from it and no reason to touch
  it. Declared `SourceKind` includes `network` — aspirational only.
* `backend/lib/collector_catalog.py` — UI **templates** for
  `NETWORK` (firewall via syslog CEF, recommended profile
  `ecs-network-firewall`) and `DNS` categories. These are catalogue rows,
  not capability: no DSM is bound to them. `ABSENT` as capability,
  `IMPLEMENTED` as catalogue text.
* `backend/v2/ingestion/*` and `backend/nivxforge/investigation/*` carry
  their own `dns_query` / `network_conn` CEM shapes (EDR-side investigation
  fabric). Out of scope by owner boundary — reported, untouched.
* `lib/lane_schemas.py` — Rule Studio network lane vocabulary already lists
  `tcp/udp/icmp/http/tls/dns` protocol values (authoring surface only).

---

## 2 · GAPS (ranked by security consequence)

| # | Gap | Consequence |
| --- | --- | --- |
| GAP-1 | Canonical model has **no DNS answer / response IP** field; Sysmon's `QueryResults` is parsed then discarded | The single most important XDR join — *domain → the IP the host was told to use* — cannot be stored, so DNS→connection correlation is impossible even where the source provides it |
| GAP-2 | Investigator network/historical pivots read only the nested snort shape | Firewall (CEF) and Sysmon network evidence is invisible to IP prevalence / prior-sighting investigation |
| GAP-3 | `dns_pivot` reads `canonical.dns.query`, which no DSM emits | Domain pivot cannot use canonical DNS evidence |
| GAP-4 | No allow/deny action, bytes/packets/duration, flow id, zone/rule name in the canonical contract | Repeated-denied-connection, data-egress-volume and beaconing-by-duration detections have nothing to cite |
| GAP-5 | Syslog/UDP path has no durable checkpoint (unlike the polled sources) | A "no silent loss" claim cannot be made for push-based network telemetry |
| GAP-6 | No network-device / sensor identity as first-class network evidence (`dvchost` lands in `host.hostname`) | Cannot distinguish "the firewall observed it" from "the host observed it" |
| GAP-7 | `network.direction` exists but is never populated | Inbound/outbound reasoning unavailable |
| GAP-8 | Zero ENABLED correlation rules; network lane has 2 detections | The stateful engine capable of beaconing/sequence detection is idle |
| GAP-9 | No IP/domain reputation or known-malicious-infrastructure evidence source bound to the network lane | "Communication with known-malicious infrastructure" is not decidable deterministically today |

---

## 3 · CANDIDATE AUTHORITATIVE SOURCES (evaluated broadly, no vendor lock)

| Candidate | Evidence density | Native DNS? | Allow/deny? | Identity? | Process? | DNS→IP→conn join | Acquisition | Owner cost to make REAL |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Zeek / Corelight** (`conn.log`, `dns.log`, `ssl.log`, `http.log`, JSON) | **Highest.** 5-tuple + bytes/packets both directions + duration + `conn_state` + `uid` + `community_id`; `dns.log` = query, qtype, rcode, **answers**, TTL | **Yes, authoritative** (query *and* response) | No (observer, not enforcer) | No user | No process | **Yes** — `answers` gives domain→IP; `community_id`/5-tuple gives IP→flow | Existing syslog/TCP-JSON receiver, or file/JSON lines | Free OSS sensor on a span/tap or a single Linux box; no vendor contract |
| **PAN-OS** (traffic + threat + **dns-security** logs, CEF or native) | High | Partial (dns-security subscription only) | **Yes** | **Yes** (User-ID) | No | Weak — traffic log gives flow; DNS only as a threat verdict | Existing `cef-leef` path works **today** | Requires the appliance + licence |
| **FortiGate / Cisco ASA-FTD** | Medium-high | Fortinet DNS filter only | **Yes** | Partial | No | Weak | `cef-leef` (Fortinet CEF) / native parser needed for ASA | Requires appliance |
| **DNS resolver logs** (Windows DNS analytic ETW, BIND querylog, Unbound, protective DNS) | Medium | **Yes** | Policy block only (protective DNS) | Client IP only | No | Query side only; BIND/Unbound query logs usually carry **no answers** | Syslog / file / ETW | Cheap, but answer-side often missing → weakens the key join |
| **AWS VPC Flow + Route53 Resolver query logs** | Medium-high | **Yes** (Route53 includes answers) | **Yes** (`ACCEPT`/`REJECT`) | No user | No | Yes, but only inside AWS and joined on ENI/instance, not host | S3/CloudWatch pull — new poller work | Needs an AWS account with real traffic |
| **Azure NSG flow logs** | Medium | No | Yes | No | No | No | Storage-account pull | Needs Azure |
| **NivXForge EDR / Sysmon host network+DNS (EID 3 / 22)** | Medium, but **uniquely process-attributed** | Yes (query; answers available in EID 22 but currently dropped — GAP-1) | No | Yes (user/host) | **Yes** | Host-side only | Already implemented | Sysmon feed = `ABSENT`; NivXForge live host = `EXTERNAL_ACCESS_BLOCKED` |

---

## 4 · RECOMMENDED FIRST SOURCE

> **Zeek (open-source) `dns.log` + `conn.log`, JSON, one sensor,
> delivered over the existing collector syslog/TCP receiver, behind a new
> declared source `zeek-json` with a `zeek-json` DSM.**

Why this and not a firewall:

1. **It is the only candidate that authoritatively closes the join that XDR
   correlation actually needs**: `dns.log.answers` gives *domain → resolved
   IP*, and `conn.log` gives *that IP → a real flow with bytes, duration and
   state*, linked by `uid` / `community_id`. Firewalls give enforcement but
   not the DNS answer; DNS resolvers give the query but usually not the
   answer *and* never the flow.
2. **It is obtainable for real, today, with no vendor contract** — a free
   sensor on hardware the owner already has. That matters more than
   elegance: the phase goal is REAL SOURCE PROVEN, and every firewall
   candidate stalls on "the owner may not have the appliance" (already the
   documented reason auditd was chosen over CEF in
   `PRODUCTION_TELEMETRY_ONBOARDING_RUNBOOK.md`).
3. **Highest evidence-per-field-of-work ratio**: two log types unlock DNS
   *and* flow *and* volume *and* connection state at once. Every other
   candidate needs 2–3 separate sources to reach the same coverage.
4. **It does not lock the product to a vendor.** Firewall coverage already
   has a working path (`cef-leef`) the moment a real appliance exists;
   adding Zeek does not compete with it, and a later `panos` /
   `route53-resolver` source reuses the same canonical network fields this
   phase defines.

Runner-up, if the owner has a licensed PAN-OS box with real traffic:
**PAN-OS traffic + threat over the existing `cef-leef` path** — smaller
build (routing/catalog + action/bytes fields only), gives allow/deny and
User-ID, but leaves the DNS→IP join unproven.

---

## 5 · SECURITY USE CASES UNLOCKED BY THE RECOMMENDED SOURCE

Supportable **deterministically** with Zeek `dns.log` + `conn.log` alone:

| Use case | Evidence it cites | Engine |
| --- | --- | --- |
| Suspicious DNS: long/high-entropy labels, excessive subdomain depth, TXT/NULL-heavy query mix (**DNS tunnelling / exfil**) | `dns.query`, `qtype_name`, per-domain query count | existing rule lane (predicate already exists) + `VALUE_COUNT` |
| **NXDOMAIN burst / DGA behaviour** | `dns.rcode_name=NXDOMAIN` grouped by client | `COUNT`/`THRESHOLD` |
| **Beaconing** — regular-interval, low-variance, small-payload flows to one destination | `conn` start times, `duration`, `orig_bytes`/`resp_bytes` per `id.orig_h`→`id.resp_h:port` | `GROUP_BY` + `TEMPORAL` |
| **Unusual outbound destination / port / protocol** (rare-destination) | `id.resp_h`, `id.resp_p`, `proto`, prevalence across canonical evidence | existing prevalence pivot (after GAP-2 fix) |
| **DNS → IP → connection relationship** (domain resolved, then contacted) | `dns.answers` → `conn.id.resp_h`, same client, bounded window | `SEQUENCE` / `TEMPORAL_ORDERED` |
| **Failed/aborted connection sweeps** (scanning, blocked C2 retries) | `conn_state` (`S0`, `REJ`), destination cardinality | `VALUE_COUNT` |
| **Large egress to a rare destination** | `orig_bytes` + destination prevalence | `THRESHOLD` |
| Network activity **associated with an existing incident/entity** | IP / domain pivots on canonical evidence | investigator pivots (after GAP-2 / GAP-3 fixes) |

**Not** supportable by this source alone — state as ABSENT, do not force in:

* *Repeated denied connections* → needs an **enforcement** source
  (firewall allow/deny). Zeek observes, it does not deny. `ABSENT`.
* *Known-malicious infrastructure / C2 indicator match* → needs an
  authoritative reputation/IOC source bound to the network lane (GAP-9).
  Zeek supplies the observation, not the verdict. `ABSENT` until an
  intel source is authorised.
* *Endpoint process → network relationship* → needs authoritative endpoint
  telemetry (Sysmon EID 3/22 or NivXForge sensor). Currently
  `SYNTHETIC/REPLAY PROVEN` / `EXTERNAL_ACCESS_BLOCKED` respectively.

---

## 6 · CANONICAL EVIDENCE REQUIRED (fields this phase must be able to store)

Extension to `NetworkEntity` (additive only; absent stays absent):

| Field | Source of truth | Available from Zeek? |
| --- | --- | --- |
| `src_ip`, `src_port`, `dest_ip`, `dest_port`, `protocol` | exists today | yes (`id.orig_h/p`, `id.resp_h/p`, `proto`) |
| `direction` | exists, unpopulated | derivable **only** from declared internal ranges → mark as DERIVED, not OBSERVED, or leave absent |
| `action` (allow/deny/reset) | new | **no** — leave absent (firewall-only) |
| `conn_state` / session outcome | new | yes (`conn_state`, `history`) |
| `bytes_sent`, `bytes_received`, `packets_sent`, `packets_received`, `duration_ms` | new | yes (`orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts`, `duration`) |
| `flow_id` (Zeek `uid`), `community_id` | new — **the cross-source join key** | yes |
| `dns_query` | exists | yes (`query`) |
| `dns_query_type`, `dns_rcode`, `dns_response_ips[]`, `dns_ttls[]`, `dns_authoritative`, `dns_rejected` | new — closes GAP-1 | yes (`qtype_name`, `rcode_name`, `answers`, `TTLs`, `AA`, `rejected`) |
| `sensor_device_id` / `sensor_device_name` (which network device observed it) | new — closes GAP-6 | yes (Zeek node / `_path` + sensor identity from the declared collector) |
| `nat_src_ip/port`, `nat_dest_ip/port`, `firewall_rule`, `zone_src/zone_dest`, `url`, `tls_sni`, `ja3` | new | **no** from `conn.log`/`dns.log` — absent (later sources) |
| user identity | `IdentityEntity` (exists) | **no** — Zeek has no user. Absent, never inferred |
| process identity | `ProcessEntity` (exists) | **no** — Zeek has no process. Absent, never inferred |
| `raw_ref` + `provenance` | exists (D11) | yes |

**Timestamps (D12 discipline, non-negotiable):**
`conn.log.ts` = the flow's **first packet** → `ACTIVITY_TIME` (start bound);
`duration` gives the end bound. `dns.log.ts` = the query instant →
`ACTIVITY_TIME`. The collector's receive time → `sensor_observed_at`
(`OBSERVATION_TIME`). A syslog-header time from a relay must **never** be
promoted to activity time — exactly the rule `cef_leef_dsm` already applies
to `rt`.

---

## 7 · ACQUISITION METHOD

* **Transport**: existing `SyslogConnector` (TCP preferred — framing and no
  silent datagram loss) with Zeek's JSON writer, or a file-tail variant if
  the owner prefers not to expose a port. **No new transport class needed.**
* **Payload**: Zeek JSON lines are self-describing via `_path`
  (`conn`, `dns`, …). `payload_formats.detect_and_parse` currently
  recognises CEF/LEEF only → one additional JSON-lines branch, or the DSM
  re-parses the verbatim raw line (which is the existing, stricter pattern:
  the collector's parse is provenance, the backend re-parses for authority).
* **Delivery**: existing authenticated `POST /api/xdr/ingest/telemetry`,
  existing outbox, dedup, Terminal Record Policy. Unchanged.
* **Durability honesty**: push transport → no upstream replay. If the owner
  wants a no-loss claim, the shape is Zeek writes JSON to disk and the
  collector tails with a durable file offset in the existing
  `acquisition_state` — that reuses the durable-checkpoint asset instead of
  inventing one (GAP-5).

---

## 8 · SOURCE-ROUTING REQUIREMENTS

* New catalog key in `services/source_routing.py:SOURCE_CATALOG`:
  `"zeek-json" → "zeek-json"`; aliases `zeek`, `corelight`, `bro`.
* Collector's server-side authorized-source allowlist must include it —
  a declaration alone is not authority (D15).
* `supports()` must be **narrow**: a Zeek record is claimed only on a
  recognised `_path` **plus** Zeek-specific structure (`id.orig_h` /
  `uid`), never on the presence of `src_ip`-like keys — otherwise it
  collides with `snort-eve`, which claims `event_type` + `src_ip`
  (registry position 0). Declared routing prevents accidental capture, but
  `recognize()` mismatch evidence should stay clean.
* Two Zeek log types, one declared source, **one DSM** — the DSM dispatches
  on `_path`. Splitting into `zeek-dns` / `zeek-conn` would multiply
  declared sources for no authority gain.

---

## 9 · CORRELATION KEYS

| Key | Join it enables | Authoritative today? |
| --- | --- | --- |
| `flow_id` (`uid`) | `dns.log` record ↔ `conn.log` flow, within Zeek | **Yes**, once stored (new field) |
| `community_id` | same flow seen by Zeek **and** by a firewall/EDR | Yes from Zeek; other side needs a source that emits it |
| `dest_ip` + time window | domain→IP→flow across sources | Yes (weaker: NAT and CDN re-use break it) |
| `dns_response_ips[]` → `dest_ip` | **domain → contacted IP** (the XDR join) | Yes from Zeek `answers`; from Sysmon EID 22 only after GAP-1 |
| client `src_ip` → `host.host_id` | network observation → endpoint identity | **No** — requires an authoritative IP↔host inventory (DHCP/asset/EDR). Today it is an inference. `ABSENT` |
| `process.guid` → DNS/connection | process → network | **Only** from Sysmon EID 3/22 or NivXForge sensor, on the host itself |

---

## 10 · THE XDR CHAIN — WHERE IT BREAKS TODAY (no manufactured joins)

```
Endpoint → Process → DNS Query → Domain → Destination IP → Network Connection → Detection
```

| Edge | Authoritative evidence | State |
| --- | --- | --- |
| Endpoint → Process | Sysmon EID 1/22 (`Image`, `ProcessGuid`) or NivXForge sensor PROCESS | `IMPLEMENTED` · Sysmon `SYNTHETIC/REPLAY PROVEN` · NivXForge live host `EXTERNAL_ACCESS_BLOCKED` |
| Process → DNS Query | **Sysmon EID 22 only** — same record carries process *and* query | `IMPLEMENTED`, `SYNTHETIC/REPLAY PROVEN`. Zeek can never supply this edge |
| DNS Query → Domain | same record | `IMPLEMENTED` |
| **Domain → Destination IP** | DNS **answers**. Sysmon `QueryResults` is parsed and **dropped** (no canonical field); Zeek `dns.answers` not yet ingested | **BREAK · `ABSENT`** — the decisive gap (GAP-1) |
| Destination IP → Network Connection | Zeek `conn.log` (not ingested yet) · firewall CEF (`cef-leef`, no real appliance) · Sysmon EID 3 (host-side) | Backend-side `IMPLEMENTED` for CEF/Sysmon shapes; network-sensor side `ABSENT` |
| Network Connection → Detection | stateful 13-operator engine + network rule lane | `IMPLEMENTED`, **zero enabled correlation rules** (GAP-8) |
| Endpoint ↔ network observation (`src_ip` → host) | needs an authoritative IP↔host inventory | **BREAK · `ABSENT`** — inference only |

**Honest conclusion:** after this phase's recommended source, the chain is
provable **end-to-end only on a host that also sends Sysmon/NivXForge
telemetry**. Zeek alone proves
`DNS Query → Domain → Destination IP → Network Connection → Detection`
authoritatively (client identified by IP, not by host identity). The
`Endpoint → Process` prefix stays dependent on real endpoint telemetry,
which is `SYNTHETIC/REPLAY PROVEN` (Sysmon) or blocked (NivXForge). This
must not be presented as a full chain until one real endpoint feed exists.

---

## 11 · EXISTING COMPONENTS TO REUSE (adopt, do not rebuild)

| Reuse | Why it is sufficient |
| --- | --- |
| `SyslogConnector` + `SyslogRunner` | TCP/UDP, framing, per-instance binding, `NETWORK_EVENTS` capability already declared |
| `Outbox` / `AcquisitionState` / Terminal Record Policy / `DedupCache` / `DeliveryWorker` | durability + quarantine already proven this phase |
| `POST /api/xdr/ingest/telemetry` + D11 provenance + D13 shape + D14 tenant authority | no new ingest boundary |
| `services/source_routing.py` | one catalog entry + aliases, nothing structural |
| `services/event_time_basis` + `provenance_timestamps` | activity vs observation time already enforced |
| `telemetry/models.py` `CanonicalTelemetryEvent` / `NetworkEntity` | **extend additively**; do not create a second network schema |
| `routers/xdr_correlation.py` (13 operators) | beaconing / sequence / threshold detection engine already exists |
| `detection_content/library` rule contract + `lane="network"` | rule surface exists |
| `cef_leef_dsm.py` | the reference implementation for re-parsing raw lines, honest `UNKNOWN` states and D12 time discipline |
| `routers/xdr_ingest_routing.py` (D21) | routing visibility works for the new source with no UI change |

Explicitly **not** reused: `services/telemetry_adapters/*` (parallel fabric,
inventory only), `backend/v2/ingestion/*`, `backend/nivxforge/*`.

---

## 12 · LIVE-SOURCE (REAL SOURCE PROVEN) REQUIREMENTS — OWNER SIDE

1. One host running **Zeek** (or Corelight) with visibility of real traffic
   — span/tap, or a Linux box whose own interface carries real DNS and
   egress traffic.
2. Zeek configured with the **JSON writer**, with `conn` and `dns` enabled.
3. Network reachability from that host to the preview collector, plus a
   collector API key and a server-side allowlist entry for `zeek-json`.
4. A named, owner-acknowledged **capture window** (start/end) so the first
   accepted evidence is attributable to a real observation period.
5. For the *firewall* runner-up instead: a real PAN-OS/FortiGate with CEF
   syslog export configured to the collector.
6. Until 1–4 exist, network telemetry stays `EXTERNAL_ACCESS_BLOCKED`, and
   any local run must be labelled `SYNTHETIC/REPLAY PROVEN` — the same
   discipline applied to M365.

---

## 13 · WHAT REMAINS IMPOSSIBLE AFTER THIS FIRST SOURCE

* Allow/deny and firewall-policy reasoning (repeated denied connections,
  rule-name attribution) — needs an enforcement source.
* Known-malicious-infrastructure / C2 verdicts — needs an authorised
  reputation/IOC source (GAP-9).
* User identity on network evidence — needs User-ID / identity correlation.
* Process attribution for flows observed on the wire — needs real endpoint
  telemetry; Zeek cannot supply it at any maturity.
* Reliable network-observation → host-identity binding — needs an
  authoritative IP↔host inventory.
* TLS/SNI/JA3, HTTP URL and file-transfer evidence — needs Zeek
  `ssl.log`/`http.log`/`files.log` (deliberately out of the first gate).
* Encrypted-payload content analysis — out of scope at any phase.

---

## 14 · SMALLEST IMPLEMENTATION GATE (proposal only — NOT started)

**Gate N1 — "Real network evidence, one sensor, two log types."**

1. Extend `NetworkEntity` additively with the Zeek-backed fields in §6
   (DNS answers/qtype/rcode, bytes/packets/duration, `conn_state`,
   `flow_id`/`community_id`, sensor device identity). Absent stays absent.
2. One `zeek-json` DSM (parser + normalizer) dispatching on `_path`, with a
   deliberately narrow `supports()`, re-parsing the verbatim raw line, D12
   time bases as in §6.
3. One catalog entry + aliases in `source_routing.py`; collector allowlist
   entry.
4. Transport: existing syslog TCP receiver (or durable file-tail if the
   owner prefers no open port).
5. Fix GAP-1 for Sysmon at the same time (`QueryResults` → canonical DNS
   answers) — it is one field map and it is what makes the cross-domain
   join possible at all.
6. Fix GAP-2 / GAP-3 (pivots read both canonical network shapes; DNS pivot
   reads `network.dns_query`) — small, and without them new network
   evidence is invisible to investigation.
7. Enable **two** deterministic detections only, both citable from a single
   record: NXDOMAIN-burst (`THRESHOLD`) and DNS→IP→connection
   (`SEQUENCE`). Beaconing comes after real volume exists.
8. Proof required: real Zeek output → authenticated ingest → canonical
   evidence with provenance → detection → one correlated relationship,
   with the capability state declared honestly.

Out of Gate N1 by design: firewall-native parsers, cloud network sources,
reputation/IOC binding, TLS/HTTP logs, beaconing, Terminal Record UI,
Cross Domain Story.

---

## 15 · CAPABILITY STATE SUMMARY

| Capability | State |
| --- | --- |
| Suricata/Snort EVE alert ingestion (`snort-eve`) | `IMPLEMENTED` · `SYNTHETIC/REPLAY PROVEN` · real sensor `ABSENT` |
| Firewall/appliance CEF-LEEF ingestion (`cef-leef`) | `IMPLEMENTED` · `SYNTHETIC/REPLAY PROVEN` over a real wire · real appliance `ABSENT` |
| Sysmon network (EID 3) + DNS query (EID 22) | `IMPLEMENTED` · `SYNTHETIC/REPLAY PROVEN` · real feed `ABSENT` |
| DNS **answer / response IP** as canonical evidence | `ABSENT` |
| Zeek / Corelight flow + DNS ingestion | `ABSENT` |
| Firewall-native (PAN-OS/FortiOS/ASA) parsers | `ABSENT` |
| DNS resolver log ingestion | `ABSENT` |
| Cloud network telemetry (VPC Flow / Route53 / NSG) | `ABSENT` |
| Syslog acquisition transport (UDP/TCP, CEF/LEEF aware) | `IMPLEMENTED` |
| Durable acquisition + Terminal Record Policy | `IMPLEMENTED` (push transports uncheckpointed — GAP-5) |
| Declared-source routing + tenant authority + provenance | `IMPLEMENTED` |
| Stateful 13-operator correlation engine | `IMPLEMENTED`, zero enabled rules |
| Network detection lane | `IMPLEMENTED` (2 rules) |
| Network / DNS investigator pivots | `IMPLEMENTED` but shape-blind (GAP-2 / GAP-3) |
| Known-malicious-infrastructure verdicts | `ABSENT` |
| Endpoint→Process→DNS→Domain→IP→Connection full chain | `ABSENT` (two authoritative breaks — §10) |
| Legacy `services/telemetry_adapters` network capability | `ABSENT` (no network adapter exists) |
| Live network source | `EXTERNAL_ACCESS_BLOCKED` (owner prerequisites §12) |

---

**STOP — awaiting owner approval before any implementation.**
No code, no schema change, no rule, no deployment was performed.
