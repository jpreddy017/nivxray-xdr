# CAT-14 · NDR / Network Capabilities

> STRICT READ-ONLY deep-dive.

## 1 · PRE-AG baseline (proven — and this is where the canonical pipeline was born)

| Artifact | Evidence | Status |
|---|---|---|
| **`SnortEveDSM`** | `backend/detection_content/xdr_pipeline.py:29-48` — `id="snort-eve"`, `vendor="Snort"`, `product="Snort / Suricata EVE"`, `version="1"`, `source_type="NETWORK_IDS"`; `supports()` at `:36-39` matches Suricata-EVE (`event_type` + `src_ip`) | IMPLEMENTED, **PRE-AG** |
| `SnortEveParser` | `xdr_pipeline.py:88` | IMPLEMENTED, PRE-AG |
| `SnortNormalizer` | `xdr_pipeline.py:126` | IMPLEMENTED, PRE-AG |
| Collector bootstrap for Snort | `/api/admin/content-supply-chain/collector-runtime/bootstrap-snort` (live) | IMPLEMENTED, PRE-AG |
| `ndr_stream` source kind | declared in `/api/xdr/data-sources` `kinds[]` | DECLARED only |
| Network response action | `IP_BLOCK` — "Block IP at network edge", domain `network` | IMPLEMENTED, PRE-AG |
| IP/domain/URL enrichment | `/api/osint/lookup`, `/api/ioc/enrich`, `/api/threat-intel/lookup/{value}` | IMPLEMENTED, PRE-AG |
| Correlation operators | `CROSS_HOST`, `CROSS_SOURCE` — implemented per live `/api/xdr/correlation/status` | IMPLEMENTED, PRE-AG |

**Architecturally important:** the *first* DSM in NivXRay XDR is a **network** DSM. The canonical pipeline was built network-first, and it is hard-coded as the first entry of the pipeline registry (`xdr_pipeline.py:53` `self._dsms: list = [SnortEveDSM()]`).

## 2 · AG delta

**NONE for network.** AG's three DSMs are Windows-Security, Linux-Auditd (host) and AWS-CloudTrail (cloud). AG added **no** network DSM, no flow analysis, no PCAP handling, no DNS/HTTP/TLS analytics.

## 3 · Current state (live)

```
$ 733 live API paths matching /network/i  →  0
$ 733 live API paths matching /ndr/i      →  0
$ 733 live API paths matching /flow|pcap|dns|tls/i → 0
```

The only network capability reachable from an API is:
1. the `snort-eve` DSM inside `process_event_through_pipeline` (reachable via `/api/v2/ingestion/*`, `/api/xdr/ingest/telemetry`), and
2. `IP_BLOCK` in the response registry — `capability_available: **false**`.

| Dimension | Verdict |
|---|---|
| Implemented | 🟡 one IDS-alert DSM + parser + normalizer |
| Registered | 🟡 reachable only through generic ingestion; **0 network-named API paths** |
| Executed | ✅ the `dsm`/`parser`/`normalizer` stages execute for Suricata-EVE input |
| Runtime-proven | 🔴 `ndr_stream` declared, **0 configured** (CAT-12) |
| Production-ready | 🔴 **PARTIAL** — IDS-alert ingestion only; this is not NDR |

### What NDR requires vs what exists

| NDR primitive | NivXRay |
|---|---|
Flow records (NetFlow/IPFIX/Zeek conn) | 🔴 absent |
DNS analytics | 🔴 absent |
HTTP/TLS/JA3 fingerprinting | 🔴 absent |
East-west traffic visibility | 🔴 absent |
PCAP retrieval / retro-analysis | 🔴 absent |
Encrypted-traffic analytics | 🔴 absent |
IDS **alert** ingestion | 🟡 `snort-eve` DSM |
Network response (block) | 🟡 registered, unavailable |

## 4 · Industry benchmark

| Vendor | Network capability |
|---|---|
| **Cisco XDR** | Strongest of the set — endpoint, **network**, firewall, email, identity, **DNS** telemetry natively integrated |
| **Cortex XDR** | Network telemetry into the Cortex Native Data Lake; network events participate in causality chains |
| **Microsoft Defender XDR** | Device network events in advanced hunting; external-platform disruption (AWS, Okta) |
| **Trellix** | Dedicated NDR product line with its own console (`docs.trellix.com/.../ndr_4.x_console_pg`) |
| **CrowdStrike** | Network containment on the endpoint; third-party network telemetry via NG-SIEM |
| **SentinelOne** | Network events inside Storyline |
| **Splunk** | Ingests any network source; correlation via SPL |

## 5 · Gap

| Gap | Severity | Justification |
|---|---|---|
| **No flow/DNS/TLS telemetry** | **P1** | Without it, `CROSS_HOST`/`CROSS_SOURCE` correlation operators (already implemented) have no network side to cross to. This is the cheapest route to genuine **cross-domain** correlation (CAT-06's P0) because the DSM/parser/normalizer pattern already exists and was proven network-first |
| **`ndr_stream` kind declared, no DSM behind it** | **P1** | Master DEV-2 family: declaration without capability |
| **`IP_BLOCK` unavailable** | P1 | Registered, `capability_available: false`; needs one firewall/EDR integration |
| No PCAP / retro network analysis | P2 | Requires retention (CAT-09/CAT-12) |
| No encrypted-traffic analytics | P2 | Not justified until flow telemetry exists |
| No network-named API surface | P2 | Consequence of the above, not an independent gap |

**Sequencing note:** connecting a Suricata/Zeek source is arguably the **single cheapest P0-2 candidate** from CAT-12, because the `snort-eve` DSM, parser and normalizer are already written and already the pipeline's default path, and `/api/admin/content-supply-chain/collector-runtime/bootstrap-snort` already exists.

## 6 · UNKNOWN

- U-14.1 — Whether `bootstrap-snort` provisions a functioning collector or only a definition row. `xdr_collectors` = 110 definitions with 0 running instances. Requires execution.
- U-14.2 — Whether `SnortNormalizer` output carries enough network context (5-tuple, direction, bytes) for genuine network correlation. Would require reading and executing the normalizer; **not claimed**.
