# GATE N2.1 — ENDPOINT / PROCESS → NETWORK ATTRIBUTION · COMPLETION REPORT
_preview only · no merge · no deployment · no Investigation UI · no new telemetry domain_

Owner scope executed exactly: A (Sysmon identity preservation), B (sensor
NETWORK start identity), C (canonical attribution state), D (endpoint
address evidence), E (`CORR-EP-001`, seeded DISABLED). No UI was built. No
Cross Domain Story, no new source, no additional detection pack.

---

## 1 · IMPLEMENTATION

| File | Change |
| --- | --- |
| `detection_content/telemetry/models.py` | `ProcessEntity` gains `process_guid`, `parent_process_guid`, `process_iid`, `start_time`, `attribution_state`, `attribution_reason`, `field_provenance`; the three attribution states are defined once, in one place |
| `detection_content/telemetry/sysmon_dsm.py` | **A** — `ProcessGuid` / `ParentProcessGuid` now reach canonical evidence *and* `raw_ref`, with provenance. Nothing else about Sysmon changed |
| `agents/nivxforge-linux/nivxforge_sensor.py` | **B** — `_proc_start_identity()` re-reads field 22 of `/proc/<pid>/stat` for the PID the socket inode resolved to; `collect_network()` emits it. A process that exits between the inode map and the read yields `not_observed: ["owning_process_start_identity"]` |
| `edr_plane/canonical_bridge.py` | **B/C** — NETWORK and PROCESS lanes declare the attribution state; `bind_process_identity()` mints `process_iid` where the authenticated endpoint is known, and downgrades honestly where it is not |
| `detection_content/telemetry/nivxforge_sensor_dsm.py` | same binding on the XDR ingest path, from the authenticated envelope |
| `edr_plane/endpoint_address_observation.py` **(new)** | **D** — endpoint-owned address observations with lifecycle + provenance, and a lookup that structurally refuses to be an identity |
| `server.py` | index for the new observation collection |
| `detection_content/telemetry/network_signals.py` | process keys, endpoint scope **and the basis of that scope** on every signal |
| `detection_content/correlation_library.py`, `routers/xdr_correlation.py` | **E** — `CORR-EP-001`, seeded DISABLED |
| `tests/test_n2_endpoint_process_attribution.py` **(new)** | 33 tests |
| `tests/edr/test_p0_b_linux_sensor.py` | the "no invented process" contract now asserts the *stronger* statement: no process is named **and** the absence says why |
| `scripts/p0_n2_endpoint_process_attribution_proof.py` **(new)** | live HTTP proof, 28 checks |

No new framework, no second identity model, no parallel correlation engine.

---

## 2 · PROVENANCE

Every identity field names the exact wire field that produced it:

```
process.field_provenance
  process_guid        sysmon:EventData.ProcessGuid
  parent_process_guid sysmon:EventData.ParentProcessGuid
  pid                 sensor:/proc/net socket inode → pid
  start_time          sensor:/proc/<pid>/stat field 22
  process_iid         nivx:ProcessIdentity.mint(endpoint_id, pid, start_time)
```

`raw_ref` on Sysmon evidence now carries `process_guid` / `parent_process_guid`
too, so the source's identity is reachable from the evidence reference and
not only from inside the parser. Address observations carry
`provenance.basis = AUTHENTICATED_ENDPOINT_OWN_TELEMETRY` and
`provenance.observed_field = network.src_ip`.

---

## 3 · ATTRIBUTION STATES

| State | Meaning | Produced when |
| --- | --- | --- |
| `SOURCE_PROCESS_IDENTITY` | the source bound process and activity itself | a Sysmon `ProcessGuid` on the same record as the activity, **or** endpoint + pid + start identity all observed |
| `PID_ONLY_NOT_AUTHORITATIVE` | context, never attribution | a PID with no start identity (the process exited between the inode map and the `/proc` read), a Sysmon record with no GUID, **or** start identity present but no authenticated endpoint scope |
| `NOT_OBSERVED` | the owning process was not resolved | the socket inode resolved to nothing; the record names no process at all |

`attribution_reason` always states *why*, so a reader never has to guess
whether an absence is a collection gap or an absence of activity.

One more honesty field came out of the proof: signals carry
`endpoint_identity_basis` — `AUTHENTICATED_ENDPOINT_ID` when the endpoint
came from an authenticated enrolment, `HOSTNAME_INFERRED` when the scope is
only a hostname a log record reported (Sysmon's `Computer`). Sysmon
attribution is still sound because `ProcessGuid` is globally unique on its
own, but the scope is labelled for what it is.

---

## 4 · POSITIVE PROOF (live, over real HTTP — 28/28 checks PASS)

```
1 SYSMON ProcessGuid SURVIVES INGEST
    ProcessGuid on canonical evidence            {n2-…-aaaa}
    field provenance                             sysmon:EventData.ProcessGuid
    attribution state                            SOURCE_PROCESS_IDENTITY
    DNS answer == connection peer                203.0.113.128

2 SENSOR NETWORK EVENT · START IDENTITY DECIDES
    with start identity     → process_iid        proc_251039ae592124dd6275
    without it              → PID_ONLY_NOT_AUTHORITATIVE, no iid, reason given

3 ENDPOINT → PROCESS → NETWORK PEER
    level        CORRELATION_SUPPORTED
    entity_key   WS-N2-PROOF|{n2-…-aaaa}|203.0.113.128
    raw_event_ids {sysmon-22-b228280e…, sysmon-3-e890d0cd…}
                 = the DNS canonical event + the connection canonical event
    capability_not_verdict  true

5 ENDPOINT ADDRESS EVIDENCE (real database)
    own address recorded, peer address NOT recorded
    binding_policy = TIME_BOUNDED_OBSERVATION_NOT_IDENTITY
```

Both lanes converge on one identity model: the same process observed on the
PROCESS lane and on the NETWORK lane mints the **same** `process_iid`.

---

## 5 · NEGATIVE / FALSE-JOIN PROOF

Proven live **and** in-process. None of these produce the relationship:

| Attempt | Result |
| --- | --- |
| A different process on the same host, same address, same window | no join |
| The same process identity on a different endpoint | no join |
| A connection to a different peer | no join |
| A connection **before** the resolution | no join |
| PID-only evidence on either side | cannot even enter the window |
| A process-attributed DNS with an unattributed connection | no join |
| An unanswered (NXDOMAIN) resolution | no join |
| **Address + instant agreeing, with no process identity — the prohibition itself** | **nothing** |

This is structural, not a threshold: both conditions require
`process_attribution_state == SOURCE_PROCESS_IDENTITY`, and the projection
emits **no `process_key` at all** for any weaker state. A signal that cannot
match a condition never enters the window, so there is nothing for address
and time to attach themselves to.

Also proven: PID reuse and process restart mint *different* identities; the
same PID on two endpoints is two processes; `CORR-NET-002` still fires on
the same evidence and its key still names **no** process — the network
claim and the attribution claim stay separate.

---

## 6 · REGRESSIONS

* `test_n2_endpoint_process_attribution.py` — **33 passed**
* `test_n1_zeek_network_telemetry.py` — **62 passed** (unchanged)
* `test_d12_cross_dsm_activity_time.py` — 55 passed / 1 pre-existing red
  (`m365-unified-audit` coverage, Microsoft track, untouched)
* EDR sensor + endpoint-detection suites — **145 passed** together with the
  N1/N2 suites
* Wide targeted regression (routing · telemetry · DSM · sysmon ·
  correlation · investigator · D11–D21 · M365 · CEF · Snort · sensor ·
  endpoint): 1311 passed, 20 failed, 41 errors. Every one of those 20/41
  was verified against a stashed tree and reproduces **identically without
  this gate's changes** — Work-Mode/RBAC-unauthenticated, live-fixture and
  analyzer tracks, all deliberately untouched.
* One test was intentionally updated: the sensor bridge's "no invented
  process" contract, which now asserts the stronger property (no process
  named **and** the absence explained) rather than an empty dict.

---

## 7 · REMAINING EVIDENCE BREAKS (unchanged by design)

* **Client IP → endpoint/device identity** — still `ABSENT`. D adds
  *evidence* (which endpoint was seen using which address, when), never
  identity: `usable_for_attribution` is `False` in every branch of
  `lookup()`, because DHCP, NAT/PAT, VPN, proxy egress, container/pod reuse
  and shared hosts all produce exactly the "single candidate in window"
  shape while being wrong. `CORR-EP-001` does not consult it at all.
* **Zeek-observed flows** carry no process and never will — attribution on
  the wire requires endpoint evidence for the same activity.
* **Linux Process → DNS** — `ABSENT` at source: the NivXForge sensor
  collects no DNS. No code can conjure it.
* **Short-lived connections** — the sensor polls `/proc/net`; a connection
  that opens and closes between polls is not observed, and absence is not
  evidence of absence.
* **Cross-source (endpoint ↔ Zeek) joins** — still not attempted; they
  would need NAT mapping and clock tolerance, and are deliberately outside
  this gate.
* **Clock skew** — irrelevant *within* a source record (where these joins
  are made) and unresolved *across* sources, which is why no cross-source
  join was built.

---

## 8 · CAPABILITY CLASSIFICATION

| Capability | State |
| --- | --- |
| Canonical process identity + attribution states | `IMPLEMENTED` |
| Sysmon `ProcessGuid` preserved into evidence (EID 1/3/22) | `IMPLEMENTED` · `SYNTHETIC/REPLAY PROVEN` |
| Windows Process → DNS / → connection attribution | `IMPLEMENTED` · `SYNTHETIC/REPLAY PROVEN` |
| Sensor NETWORK process start identity → `process_iid` | `IMPLEMENTED` · `SYNTHETIC/REPLAY PROVEN` |
| Honest downgrade (PID-only / not observed) | `IMPLEMENTED` · `SYNTHETIC/REPLAY PROVEN` |
| `CORR-EP-001` Endpoint → Process → Network peer | `IMPLEMENTED`, shipped **DISABLED** · `SYNTHETIC/REPLAY PROVEN` |
| Endpoint address observations (evidence, not identity) | `IMPLEMENTED` · proven against a real database |
| Live Sysmon feed | `ABSENT` |
| Live NivXForge sensor host | `EXTERNAL_ACCESS_BLOCKED` |
| Live Zeek sensor (N1) | `EXTERNAL_ACCESS_BLOCKED` |
| IP → endpoint identity attribution | `ABSENT` — and deliberately unreachable |
| Linux Process → DNS | `ABSENT` at source |
| Cross-domain story | `ABSENT` (not started) |

Full chain status:

```
Endpoint → Process → DNS Query → Domain → Resolved IP → Connection → Detection
   ▲ AUTHENTICATED_ENDPOINT_ID (sensor) or HOSTNAME_INFERRED (Sysmon)
            ▲ SOURCE_PROCESS_IDENTITY, bound inside one source record
```

Proven at implementation/replay level end-to-end **where one source states
both the process and the activity**. It is not proven from live sources,
and it is not proven across sources.

---

**STOP — awaiting owner review.** No Investigation UI, no Cross Domain
Story, no new telemetry domain, no merge, no deployment.
