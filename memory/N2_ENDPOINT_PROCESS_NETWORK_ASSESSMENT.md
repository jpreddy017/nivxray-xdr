# GATE N2 — ENDPOINT / PROCESS → NETWORK ATTRIBUTION
## ASSESSMENT & DESIGN (READ-ONLY · NO IMPLEMENTATION)

Owner scope honoured: assessment only. No code, no sensor patch, no new
source, no UI, no Cross Domain Story, no merge, no deployment. Only this
document was created. NivXForge EDR **runtime/agent implementation** was not
entered — the sensor was read strictly as an *evidence producer*
(`agents/nivxforge-linux/nivxforge_sensor.py` emission shape and the
`edr_plane` evidence contracts), which is what N2 must reason about.

Capability states: `IMPLEMENTED` · `SYNTHETIC/REPLAY PROVEN` ·
`REAL SOURCE PROVEN` · `EXTERNAL_ACCESS_BLOCKED` · `ABSENT`

---

## 0 · THE DECISIVE QUESTION

> Can NivXRay XDR prove that **process P on endpoint E caused network/DNS
> activity N** using authoritative evidence, rather than observing that they
> happened around the same time?

**Today: NO.** But the two paths fail for completely different reasons, and
only one of them needs new telemetry.

| Path | Why it fails today | What it needs |
| --- | --- | --- |
| **Windows / Sysmon** | The authoritative key **already exists in the source and is thrown away by NivX.** Sysmon stamps `ProcessGuid` on EID 1 (process create), EID 3 (network connect) **and** EID 22 (DNS query). `sysmon_dsm.py:90,94` parses `ProcessGuid` / `ParentProcessGuid` — and then the value appears **nowhere**: not in `ProcessEntity` (which has no GUID field), not in `additional_fields`, not even in `raw_ref`. Verified by running the DSM: `guid in canonical doc → False`. | **Carrying** the identity the source already gives. No sensor change, no new telemetry, no new source. |
| **Linux / NivXForge sensor** | The sensor resolves the socket's owning PID through the inode map (`collect_network`, `_inode_pid_map`) — genuinely good evidence — but the NETWORK event carries **`pid` with no process start identity**. `ProcessIdentity.mint()` deliberately *refuses* to mint without `start_time`, because "a PID alone is reused by the OS within minutes". So the join key cannot be formed. There is also **no DNS activity at all** on this sensor. | One additive field on the NETWORK event (the start identity the PROCESS lane already collects), plus DNS collection later. Sensor change = recommendation only. |

So the smallest missing primitive is **a carried, lifetime-bound process
identity on network and DNS evidence** — not more telemetry.

---

## 1 · EXISTING CAPABILITY

| Component | What it is | State |
| --- | --- | --- |
| `edr_plane/contracts/identity.py` · `ProcessIdentity.mint(endpoint_id, pid, start_time)` | The correct identity model already exists and already **refuses** a PID-only lifeline. `parent_iid` is populated only when the parent was observed; `lineage_state` records which of three honest cases applies | `IMPLEMENTED` |
| `NetworkIdentity` (contract 5) | Already has `endpoint_id`, **`process_iid`**, `dns_query`, `dns_answers`, local/remote 5-tuple, and states in its own docstring that a remote IP is never an endpoint and never a process | `IMPLEMENTED` — *as a contract*. The runtime canonical evidence path does not populate `process_iid` |
| `EndpointIdentity` | `endpoint_id` minted from `processor_id` / `machine_guid`, stable across hostname and IP change | `IMPLEMENTED` · `REAL SOURCE PROVEN` for enrolment shape |
| `agents/nivxforge-linux` sensor `collect_network()` | `/proc/net/tcp` + `/proc/net/tcp6`, owning PID resolved via socket **inode → pid**, honest `not_observed: ["owning_process"]` when the inode does not resolve, `LISTEN` sockets recorded with remote side `not_observed` | `IMPLEMENTED` · live host acceptance `EXTERNAL_ACCESS_BLOCKED` (D20) |
| `edr_plane/canonical_bridge.py` | Sensor JSON → canonical. NETWORK path sets `process = {"pid": …}` only. PROCESS path carries `process_start_ticks` **and** `process_start_time` | `IMPLEMENTED` |
| `detection_content/telemetry/sysmon_dsm.py` | EID 1/3/11/12/13/14/22; DNS answers now canonical (N1/GAP-1) | `IMPLEMENTED` · `SYNTHETIC/REPLAY PROVEN` · real Sysmon feed `ABSENT` |
| `routers/xdr_correlation.py` | 13-operator stateful engine; `group_by` reads any field from the signal or its `fields` bag — so a process key is usable **the day it exists** | `IMPLEMENTED` |
| `detection_content/telemetry/network_signals.py` (N1) | Canonical network evidence → signals; one signal per DNS answer; entity key carries the join | `IMPLEMENTED` · `SYNTHETIC/REPLAY PROVEN` |
| `services/edr/device_identity.py` | Device attribution from enrolment records; a hostname-only source is `identity_confidence = "inferred"` and can never be promoted | `IMPLEMENTED` |

---

## 2 · EVIDENCE AVAILABLE TODAY

| Evidence | Windows / Sysmon | Linux / NivXForge sensor | Zeek (N1) |
| --- | --- | --- | --- |
| Endpoint / device identity | `Computer` (hostname → INFERRED only) | **`endpoint_id`** (minted, durable) | none — address only |
| Process PID | yes (EID 1/3/22) | yes on PROCESS; yes on NETWORK **when the inode resolves** | none |
| Process start identity (lifetime) | **`ProcessGuid` encodes it** — parsed, then dropped | PROCESS lane: `start_time` + `start_ticks`. **NETWORK lane: absent** | none |
| Process image / command line | yes | yes (PROCESS lane) | none |
| Parent lineage | `ParentProcessGuid` (dropped) | `_proc_parent` with start-ticks verification | none |
| Process ↔ connection link | **EID 3 carries process + 5-tuple in ONE record** | socket inode → pid, in one record | none |
| Process ↔ DNS link | **EID 22 carries process + query + answers in ONE record** | `ABSENT` — the sensor collects no DNS | none |
| Local/source IP of the endpoint | EID 3 `SourceIp` | `local_ip` per connection | `id.orig_h` |
| Sensor identity | provider/channel | `endpoint_id` + `sensor_version` | `_system_name` |
| Activity timestamps | `UtcTime` (ACTIVITY) vs `TimeCreated` (OBSERVATION) | `start_time` (ACTIVITY) vs `observed_at` (OBSERVATION) | `ts` (ACTIVITY) vs `_write_ts` (OBSERVATION) |
| Canonical event id + provenance | yes (D11/D12/D15) | yes | yes |

---

## 3 · MISSING EVIDENCE

| # | Missing | Consequence | Where it must be fixed |
| --- | --- | --- | --- |
| **N2-A** | `ProcessGuid` / `ParentProcessGuid` never reach canonical evidence | The one authoritative Windows join key is discarded at the door. Process→DNS and Process→connection are unprovable **even though the source proved them** | `sysmon_dsm.py` + a canonical field (`models.py`) |
| **N2-B** | Canonical `ProcessEntity` has **no** identity field at all — no `process_guid`, no `process_iid`, no `start_time` | Even a source that supplies process identity has nowhere to put it; correlation can only group on `pid`, which is reused | `detection_content/telemetry/models.py` |
| **N2-C** | Sensor NETWORK events carry `pid` without start identity | `ProcessIdentity.mint()` correctly refuses; Linux process→network stays AMBIGUOUS | sensor emission (**recommendation only**) + `canonical_bridge.py` |
| **N2-D** | NivXForge sensor collects **no DNS** | Linux Process→DNS is `ABSENT` at the source; no code change can conjure it | sensor capability (later gate) |
| **N2-E** | `EndpointIdentity.local_ips` / `mac_addresses` exist in the contract but are **populated by nothing** (grep: one hit, the declaration). Enrolment sends `processor_id`, `machine_guid`, `hostname`, `platform` only | No authoritative IP↔endpoint inventory ⇒ Zeek's `id.orig_h` can never be bound to a device. This is the same break N1 reported, now located precisely | enrolment payload + store (later gate) |
| **N2-F** | Sensor NETWORK collection is a **poll of `/proc/net` state**, deduped by 5-tuple+state | A connection that opens and closes between polls is never observed; absence of a connection event is not evidence of absence | sensor architecture (later gate) |
| **N2-G** | No canonical `process_attribution_state` | "PID resolved from the inode" and "PID unknown" and "GUID-backed identity" all look alike downstream | canonical model |

---

## 4 · AUTHORITATIVE JOIN KEYS

A join is **AUTHORITATIVE** only when a single source record states both
sides of it, or when both records carry the same source-minted identity
whose uniqueness the source itself guarantees for the process lifetime.

| Join | Key | Verdict |
| --- | --- | --- |
| Process → DNS query/answers (Windows) | `ProcessGuid` present on EID 22 **in the same record as** `QueryName` + `QueryResults` | **AUTHORITATIVE** once carried (N2-A/B) |
| Process → network connection (Windows) | `ProcessGuid` on EID 3 **in the same record as** the 5-tuple | **AUTHORITATIVE** once carried |
| Process → parent process (Windows) | `ParentProcessGuid` → `ProcessGuid` | **AUTHORITATIVE** once carried |
| Process lifeline (Linux) | `process_iid = (endpoint_id, pid, start_time)` — the contract's own key | **AUTHORITATIVE** for the PROCESS lane today; for NETWORK only after N2-C |
| Process → connection (Linux) | socket **inode → pid**, resolved inside one collection pass, *plus* that process's start identity | **AUTHORITATIVE after N2-C**; today **AMBIGUOUS** (pid only) |
| Endpoint scoping of any of the above | `endpoint_id` (minted, durable) | **AUTHORITATIVE** |
| Endpoint ← Zeek `id.orig_h` | — | **FORBIDDEN** until an IP↔endpoint inventory exists (N2-E) |
| Endpoint ← hostname (`Computer`) | — | **AMBIGUOUS** — already labelled `identity_confidence: inferred` by `device_identity.py`; must never be promoted |
| DNS answer IP → subsequent connection (N1) | client + resolved address + order (`CORR-NET-002`) | **AUTHORITATIVE for the network relationship**, and it stays a *network* claim — it says nothing about which process |

---

## 5 · UNSAFE / AMBIGUOUS JOINS — named explicitly

| Hazard | Why a join built on it is not attribution | Class |
| --- | --- | --- |
| **PID reuse** | Linux recycles PIDs within minutes; Windows too. Same PID ≠ same process. The contract already refuses a PID-only lifeline — the correlation design must refuse it identically | `FORBIDDEN` as a sole key |
| **Process restart** | Same image, same command line, new lifetime. Without start identity, two lifetimes merge into one fabricated lifeline | `FORBIDDEN` as a sole key |
| **Process lifetime vs window** | A 15-minute correlation window outlives many processes. A join is valid only where the process's observed lifetime **contains** the network activity instant; otherwise it is coincidence | must be an explicit condition |
| **IP + time coincidence** | The core prohibition. "A process was running and a connection existed at the same moment" is not causation, especially on a multi-process host | `FORBIDDEN` |
| **DHCP / IP reassignment** | An address identifies a lease, not a device. Yesterday's `10.8.0.31` is another machine today | `FORBIDDEN` for identity |
| **NAT / PAT** | Zeek behind NAT sees the gateway address; the endpoint sees its own. The two 5-tuples are not equal and must not be equated without a NAT mapping source | `FORBIDDEN` |
| **Proxy / egress gateway** | Every client collapses into one source address; the destination Zeek sees is the proxy's, not the process's peer | `FORBIDDEN` |
| **Container / pod IP reuse** | Pod addresses are recycled within seconds and shared across namespaces; a container's `id.orig_h` may belong to three workloads within a minute | `FORBIDDEN` |
| **Shared host / multi-user** | Many processes share one source IP simultaneously. Address-based attribution picks one arbitrarily | `FORBIDDEN` |
| **DNS cache reuse** | A process may connect to an address resolved minutes or hours earlier — by a *different* process, or before collection began. Absence of a DNS record in-window is not evidence the process did not resolve it, and presence does not prove *this* process resolved it | `AMBIGUOUS` — must be stated on the match, never silently assumed |
| **Clock skew** | Endpoint and network sensor clocks differ. Ordering across sources is only as good as the worse clock; ordering **within** one source's record is not affected | `AMBIGUOUS` — needs a tolerance and a recorded basis |
| **IPv4 / IPv6 dual stack** | The same flow appears as `::ffff:a.b.c.d` on one side and `a.b.c.d` on the other; a process may resolve A and AAAA and connect over either | `AMBIGUOUS` — normalise explicitly or do not join |
| **Sysmon EID 3 sampling / EID 22 exclusions** | Both are commonly filtered by config. A missing record is a collection gap, not an absence of activity | must be reported, never inferred |

**Design rule this section produces:** every N2 relationship must be
grouped on a **process identity + endpoint identity**, bounded by the
process's observed lifetime, and any relationship that would require an
address/time equivalence must be emitted (if at all) at a lower evidential
level with its ambiguity named.

---

## 6 · COMPONENTS TO REUSE (adopt, do not rebuild)

`ProcessIdentity` / `NetworkIdentity` / `EndpointIdentity` contracts ·
`ProcessIdentity.mint` refusal semantics · `lineage_state` ·
`canonical_bridge.parse` (the single sensor→canonical truth) ·
`sysmon_dsm` parser (the GUIDs are already extracted) ·
`event_time_basis` / `provenance_timestamps` · the D15 routing and D11
provenance path · `network_signals.signals_from_canonical` (N1) ·
`routers/xdr_correlation.py` 13 operators and its arbitrary `group_by` ·
`services/edr/device_identity.py` confidence model · the D21 routing
surface. **Nothing new is required at framework level.**

---

## 7 · MINIMUM SENSOR CHANGES (RECOMMENDATION ONLY — not authorised)

1. **NETWORK events carry the owning process's start identity**, not just
   its PID: the same `start_ticks` + `start_time` the PROCESS lane already
   reads from `/proc/<pid>/stat`. One extra read per resolved inode. This
   single field turns Linux process→network from AMBIGUOUS into
   AUTHORITATIVE, because `process_iid` becomes mintable.
2. **Keep the honest negative**: when the inode does not resolve, continue
   emitting `not_observed: ["owning_process"]` — and never fall back to a
   PID guess.
3. *(Later gate, not N2)* DNS activity collection on the sensor, and
   `local_ips` / `mac_addresses` at enrolment for the IP↔endpoint inventory.

---

## 8 · CORRELATION DESIGN (proposed)

**Canonical additions (additive, provenance-tracked, absent stays absent):**
`process.process_guid`, `process.process_iid`, `process.start_time`,
`process.parent_process_guid`, and `process.attribution_state` ∈
`SOURCE_PROCESS_IDENTITY` (GUID or iid present) ·
`PID_ONLY_NOT_AUTHORITATIVE` · `NOT_OBSERVED`.

**Signal projection (extends N1's, same module):** every network/DNS signal
additionally carries `endpoint_id`, `process_key` (GUID or iid) and
`process_attribution_state`. A signal whose state is not
`SOURCE_PROCESS_IDENTITY` **carries no `process_key` at all** — it must not
be group-able by process.

**Rule (disabled by default), one only:**

```
CORR-EP-001  Process → DNS answer → connection to the resolved address
  operator  SEQUENCE  [A_PROC_DNS, B_PROC_CONN]
  group_by  endpoint_id | process_key | network_peer_ip
  window    ≤ process observed lifetime, and ≤ 900 s
  cites     the DNS canonical event id AND the connection canonical event id
```

Because the group-by contains the process identity, the engine **cannot**
produce the match from address coincidence: two different processes on the
same host resolve to two different entity keys, and a signal with no
process identity cannot enter either.

The N1 rule stays exactly as it is and keeps its *network* meaning. The two
are complementary: N1 proves the domain→address→flow chain; N2 proves who
on the endpoint did it. Neither is rewritten to look like the other.

---

## 9 · TEST PLAN

*Attribution correctness* — same PID, different start time ⇒ two
lifelines, never one · PID reuse after exit ⇒ no join · process restart
mid-window ⇒ no join · network activity outside the process's observed
lifetime ⇒ no join · missing `ProcessGuid` ⇒ `PID_ONLY_NOT_AUTHORITATIVE`
and no process-grouped match · unresolved socket inode ⇒ `NOT_OBSERVED`,
no match, and the honest state visible.

*Anti-fabrication* — two processes on one host connecting to the same
address ⇒ two entity keys, no cross-attribution · same PID on two
endpoints ⇒ no join · Zeek connection + endpoint process at the same
instant ⇒ **no** process attribution (the N1 network match only) ·
address+time coincidence alone ⇒ nothing.

*Hazards* — NAT/proxy-shaped 5-tuple mismatch · container/pod address
reuse · DHCP reassignment across the window · IPv4/IPv6 `::ffff:` forms ·
clock skew beyond tolerance · DNS-cache reuse (connection with no
in-window DNS event) ⇒ relationship absent, ambiguity stated.

*Regression* — the N1 suite (62) and the D12 temporal guard must stay
green; the Sysmon GUID carry must not alter any existing canonical field.

---

## 10 · SMALLEST IMPLEMENTATION GATE (proposal — NOT started)

**Gate N2.1 — "carry the identity the source already gave us."**

1. Canonical `ProcessEntity` additions + `attribution_state` (§8).
2. `sysmon_dsm`: carry `ProcessGuid` / `ParentProcessGuid` on EID 1/3/22
   into canonical evidence and `raw_ref`, with field provenance
   (`sysmon:EventData.ProcessGuid`). **No other Sysmon behaviour changes.**
3. `canonical_bridge`: mint `process_iid` for NETWORK **only** when start
   identity is present; otherwise `PID_ONLY_NOT_AUTHORITATIVE`. (Until the
   sensor change, Linux will legitimately report the honest negative — and
   that is the correct N2.1 outcome, not a failure.)
4. Extend the N1 signal projection with the process keys.
5. One rule, `CORR-EP-001`, seeded **DISABLED**.
6. Tests per §9; proof over real HTTP as in N1; capability classified
   honestly (Sysmon remains `SYNTHETIC/REPLAY PROVEN`, live feed `ABSENT`).

Out of N2.1 by design: sensor changes, DNS on Linux, IP↔endpoint
inventory, NAT mapping, Cross Domain Story, UI, any new source.

---

## 11 · CAPABILITY CLASSIFICATION

| Capability | State |
| --- | --- |
| Process identity model (`ProcessIdentity`, refusal without start time) | `IMPLEMENTED` |
| Sysmon `ProcessGuid` in the source | `IMPLEMENTED` at source · **dropped by NivX** ⇒ canonical process identity `ABSENT` |
| Windows Process → DNS / → connection attribution | `ABSENT` today; **AUTHORITATIVE and reachable** via N2.1 |
| Linux sensor socket-inode → PID | `IMPLEMENTED` · live host `EXTERNAL_ACCESS_BLOCKED` |
| Linux Process → network attribution | `ABSENT` (PID-only ⇒ AMBIGUOUS); needs one sensor field |
| Linux Process → DNS | `ABSENT` at source |
| Endpoint identity (`endpoint_id`) | `IMPLEMENTED` |
| IP → endpoint/device binding | `ABSENT` (`local_ips` is a contract field populated by nothing) |
| Network relationship (N1) | `IMPLEMENTED` · `SYNTHETIC/REPLAY PROVEN` |
| Correlation engine + arbitrary group-by | `IMPLEMENTED` |
| Live Sysmon feed · live Zeek sensor | `ABSENT` · `EXTERNAL_ACCESS_BLOCKED` |
| Cross-domain story | `ABSENT` (not started) |

**PCAP position (recorded per owner decision):** an owner-supplied pcap
processed by a genuine Zeek binary would be **parser / source-format
validation only**. It can never close live-sensor acceptance, and N1's
live-source status stays `EXTERNAL_ACCESS_BLOCKED` regardless.

---

**STOP — awaiting owner review before any N2 implementation.**
