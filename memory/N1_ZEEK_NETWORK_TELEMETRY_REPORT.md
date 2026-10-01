# GATE N1 — ZEEK NETWORK / DNS TELEMETRY · COMPLETION REPORT
_preview only · no merge · no production deployment · NivXForge EDR / Work Mode untouched_

Owner scope executed exactly: Zeek `dns.log` + `conn.log` as the first
authoritative network source, with **GAP-1, GAP-2 and GAP-3 folded into N1
acceptance**, new content disabled by default, and the truth boundary kept
strict.

---

## 1 · CHANGED FILES

| File | Change |
| --- | --- |
| `backend/detection_content/telemetry/models.py` | `NetworkEntity` extended **additively** with the fields Zeek genuinely supplies, plus `field_provenance` |
| `backend/detection_content/telemetry/zeek_json_dsm.py` **(new)** | One DSM — parser + normalizer — dispatching on Zeek's `_path` |
| `backend/detection_content/telemetry/registry.py` | Registers `zeek-json` through the existing single registry |
| `backend/services/source_routing.py` | Catalog key `zeek-json` + aliases `zeek`, `bro`, `corelight`, `zeek-conn`, `zeek-dns` |
| `backend/detection_content/telemetry/sysmon_dsm.py` | **GAP-1** — `QueryResults` → canonical DNS answers (+ field provenance) |
| `backend/services/investigator/capabilities/network_identity_file.py` | **GAP-2/GAP-3** — both canonical network shapes; DNS pivot reads `network.dns_query` |
| `backend/services/investigator/capabilities/historical.py` | **GAP-2** — prior-sighting lookups read both shapes |
| `backend/detection_content/telemetry/network_signals.py` **(new)** | Canonical network evidence → correlation signals (one signal per DNS answer) |
| `backend/detection_content/correlation_library.py` | Two N1 scenarios, declared `enabled: False` / `state: DISABLED` |
| `backend/routers/xdr_correlation.py` | Seeding honours a pack's own `enabled` / `state` (existing packs unchanged) |
| `backend/tests/test_n1_zeek_network_telemetry.py` **(new)** | 62 tests |
| `backend/tests/test_d12_cross_dsm_activity_time.py` | Zeek added to the platform-wide temporal coverage guard |
| `scripts/p0_n1_zeek_network_live_proof.py` **(new)** | Live HTTP proof + real-source attempt |

No new framework, no second registry, no second rule model, no new ingest
boundary, no new database.

---

## 2 · CANONICAL SCHEMA — ONLY WHAT ZEEK STATES

Added to `NetworkEntity`: `dns_query_type`, `dns_rcode`,
`dns_response_ips`, `dns_response_records`, `dns_response_ttls`,
`dns_authoritative`, `dns_rejected`, `dns_transaction_id`, `bytes_sent`,
`bytes_received`, `packets_sent`, `packets_received`, `duration_ms`,
`conn_state`, `conn_history`, `flow_id`, `community_id`,
`sensor_device_id`, `sensor_device_name`, `field_provenance`.

**Not added**: allow/deny action, NAT addresses, firewall rule name, zones.
Zeek does not supply them, and an empty placeholder is an invitation to
claim them later.

`dns_response_ips` is the field the whole gate turns on: `answers` is split
by what each value IS, so a CNAME never becomes an address. An NXDOMAIN
answers nothing and the record says so
(`additional_fields.dns_answer_absent_reason`).

---

## 3 · PROVENANCE

* **Field level** — `network.field_provenance` maps each populated field to
  the exact wire field: `dns_response_ips → "zeek:dns.log answers (address
  records)"`, `bytes_sent → "zeek:conn.log orig_bytes"`, and for the
  endpoint side `dns_response_ips → "sysmon:EventData.QueryResults"`. A
  field the source did not state is absent from the map, not empty in it.
* **Temporal (D12)** — `ts` is the wire instant → `ACTIVITY_TIME`
  (`event_time_substituted: false`), the same basis Suricata/Snort EVE
  already uses for a packet instant. `_write_ts` → `sensor_observed_at`
  (OBSERVATION). Remove `ts` and the event honestly loses its activity
  time rather than borrowing one — proven by the platform-wide D12 guard,
  which now covers `zeek-json`.
* **Flow end** — `conn.log ts` is the FIRST packet and `duration` measures
  the length; no end timestamp is synthesised, and the record states that.
* **Routing (D15) / ingest (D11) / tenant (D14)** — unchanged paths; the
  routing decision travels on the evidence (`provenance.routing`).

---

## 4 · ROUTING

One declared source → one DSM. Aliases resolve to the same catalog key and
**widen nothing**: a `corelight` declaration from a collector not
authorized for `zeek-json` is still refused. `supports()` requires Zeek's
own `_path` **and** its connection identity (`uid` / `id.*`), so it cannot
absorb another source's payload, and an unsupported log type (`ssl`,
`http`) is refused rather than half-read.

Live refusals proven, each with its own code and **zero** evidence created:
`SOURCE_NOT_AUTHORIZED`, `DECLARATION_REQUIRED`, `SOURCE_FORMAT_MISMATCH`
(unsupported `_path`), `SOURCE_FORMAT_MISMATCH` (no connection identity),
plus a `403 TENANT_ISOLATION_VIOLATION` for a cross-tenant envelope and
`duplicates=1` for a replay.

---

## 5 · DETECTION / CORRELATION CONTENT (both DISABLED by default)

| Rule | Operator | Group-by | Fires on |
| --- | --- | --- | --- |
| `CORR-NET-001` DNS Resolution Failure Burst (NXDOMAIN) | `THRESHOLD` 10 / 300 s | `client_ip` | one client's NXDOMAIN answers reaching the declared threshold |
| `CORR-NET-002` DNS Answer → Connection To The Resolved Address | `SEQUENCE` / 900 s | `client_ip` + `network_peer_ip` | same client, same resolved address, DNS **first** |

Nothing was added to the always-on single-event library lane: a library
rule fires for every tenant the moment it ships, and a single DNS record
cannot evidence a burst. Keeping both in the correlation framework is what
made "disabled by default" actually true.

`_seed_bundled_rules` now honours a pack's own `enabled` / `state`; the
existing packs keep their previous behaviour exactly.

---

## 6 · CORRELATION PROOF — THE RELATIONSHIP, AND ITS CITATIONS

A DNS record with N address answers projects N signals, each carrying
`network_peer_ip` = that answer; a connection projects one with
`network_peer_ip` = its destination. The rule groups on
`client_ip|network_peer_ip`, so the **entity key itself is the join**.

Live result (`p0_n1_zeek_network_live_proof.py`, section 6):

```
level        CORRELATION_SUPPORTED
entity_key   10.77.0.31|198.51.100.143
raw_event_ids {4b58791b-…-8db22ff10bc7,  81ee5c8f-…-842a6c80867c}
             = the DNS canonical event + the connection canonical event
capability_not_verdict  true
```

Negative controls, all proven live and in-process:
a connection **before** the DNS answer, a **different client** on the same
address, a connection to a **different address**, and a DNS record with
**no address answer** each fail to produce the relationship. The NXDOMAIN
burst produces nothing below its declared threshold, and two clients do not
pool into one burst.

---

## 7 · TESTS

* `backend/tests/test_n1_zeek_network_telemetry.py` — **62 passed**.
  Covers: routing and alias authorization; malformed JSON; missing/unknown
  `_path`; missing connection identity; declaration mismatch both ways;
  tenant claim; epoch and ISO timestamps; missing `ts`; `_write_ts`
  separation; single / multiple / non-address / NXDOMAIN answers;
  IPv4 and IPv6; volume, state, duration, `uid`, absent `community_id`;
  direction only when stated; no invented process/user/device; Sysmon
  `QueryResults` parsing incl. `::ffff:` and `-`; GAP-2/GAP-3 pivots;
  the projection; and every correlation true/false-join case.
* `backend/tests/test_d12_cross_dsm_activity_time.py` — **55 passed**,
  `zeek-json` now inside the platform-wide temporal guard.
* Live proof — **PASS** (all 27 checks), preview restored to its prior
  state (both rules disabled again at the end).

### Regression
Targeted regression over every routing / telemetry / DSM / correlation /
investigator / D11–D21 / M365 / CEF / Snort test:
**baseline 8 failed · 849 passed · 32 errors → now 6 failed · 911 passed ·
34 errors** (the +62 are this gate's new tests). The remaining failures and
errors are the known pre-existing Work-Mode / RBAC-unauthenticated and
`REACT_APP_BACKEND_URL`-fixture tracks, unchanged and deliberately not
touched.

One pre-existing red assertion remains and is now **more** accurate: the
D12 coverage guard still fails naming `m365-unified-audit`, which had no
temporal sample before this gate. That belongs to the Microsoft track; it
was not silently fixed here.

---

## 8 · REAL-SOURCE STATUS — ATTEMPTED, THEN REPORTED HONESTLY

The genuine-Zeek attempt was made and is machine-checked on every proof run:

```
zeek_binary        NOT_INSTALLED
apt_candidate      none                 (no zeek in the configured sources)
cap_net_raw        False
cap_net_admin      False
live_capture_probe DENIED: tcpdump: any: You don't have permission to
                   perform this capture on that device (Operation not permitted)
```

`AF_PACKET` raw sockets are refused by the kernel for this container as
well. Zeek cannot observe traffic here at any configuration, so:

> **LIVE SOURCE: `EXTERNAL_ACCESS_BLOCKED`.**
> No preview-environment real-source PASS is claimed.

Still available without a full sensor deployment: if the owner supplies a
**pcap from a real network**, a genuine Zeek binary can produce genuine
`conn.log` / `dns.log` from it — that would be REAL ZEEK / OWNER-SUPPLIED
CAPTURE, and still not SPAN/TAP or Corelight acquisition.

### Capability classification
| Capability | State |
| --- | --- |
| `zeek-json` DSM (conn + dns), routing, canonical schema, provenance | **IMPLEMENTED** |
| End-to-end authenticated delivery → evidence → correlation → cited relationship | **SYNTHETIC/REPLAY PROVEN** (real HTTP, real ingest, real engine; Zeek-shaped TEST records) |
| GAP-1 DNS answers (Zeek **and** Sysmon side) | **IMPLEMENTED** · SYNTHETIC/REPLAY PROVEN |
| GAP-2 network + historical pivots · GAP-3 DNS pivot | **IMPLEMENTED** · SYNTHETIC/REPLAY PROVEN |
| NXDOMAIN burst · DNS→IP→connection content | **IMPLEMENTED**, shipped DISABLED |
| Live Zeek sensor / real network traffic | **EXTERNAL_ACCESS_BLOCKED** |
| Firewall allow/deny, TI verdicts, user/process attribution on the wire | **ABSENT** (by source, not by omission) |

---

## 9 · THE CHAIN AFTER N1 — WHAT IS PROVEN, WHAT IS STILL BROKEN

Proven end-to-end (implementation level):

```
DNS Query → Domain → Resolved IP → Connection → Detection
                     ▲ network identity is the CLIENT ADDRESS
```

Still authoritative **BREAKS**, preserved verbatim:

* **Endpoint → Process** — Zeek supplies neither. Only Sysmon EID 1/22 or
  the NivXForge sensor can, and those are SYNTHETIC/REPLAY PROVEN and
  EXTERNAL_ACCESS_BLOCKED respectively.
* **Client IP → device identity** — needs an authoritative asset / DHCP /
  IP-inventory source. ABSENT; the DSM records
  `endpoint_identity_state: NOT_OBSERVED` on every event so nothing
  downstream can quietly assume otherwise.
* **User attribution on network evidence** — ABSENT.
* **Known-malicious infrastructure verdict** — ABSENT without an
  authoritative TI source.
* **Firewall allow/deny semantics** — ABSENT; Zeek observes, it does not
  enforce.

The "first real relationship" artifact is therefore correctly named a
**network evidence relationship** (domain → resolved IP → actual connection
→ cited detection), not a cross-domain XDR relationship. It becomes the
stronger XDR claim only when genuine endpoint/process evidence joins it.

---

**STOP — awaiting owner review.** No Cross Domain Story, no further
telemetry source, no Microsoft detection expansion, no production change,
no merge, no deployment.
