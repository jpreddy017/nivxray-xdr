# NivXRay — Universal Threat Investigation Platform
## Master Architecture Design v2.0 · Artefacts 1–8

**Status**: Design · pre-implementation
**Scope**: Prompt 1 (Vision) refined + Prompts 2–4 (adapters, CEM, correlation) + Prompt 7 (graph)
**Companion document**: `/app/memory/ENGINES_UI_PERF.md` — Artefacts 9–15
**Baseline**: freeze current RC5 metrics *before* any Stage-work begins (prerequisite gate)

---

## ARTEFACT 1 — Complete Architecture

### 1.1 Positioning (locked)

NivXRay = **AI-Assisted, Deterministic Threat Investigation & Attack Reconstruction Platform**.
- NOT an EDR / SIEM / XDR / telemetry collector.
- Sits **above** those tools; ingests their output.
- Delivers deterministic investigations, timelines, trajectories, attack graphs, and cited analyst reports.

### 1.2 Locked design principles (13)

| # | Principle | Enforcement |
|---|-----------|-------------|
| 1 | Deterministic-first | Identical input ⇒ byte-identical output |
| 2 | AI-optional | Full functionality with `NIVX_AI=off` |
| 3 | Explainable | Every fact carries a `derivation[]` chain |
| 4 | Evidence-driven | No claim without `evidence_ids[]` |
| 5 | Vendor-agnostic core | Vendor names forbidden past adapter boundary |
| 6 | Streaming-ready | Chunked ingestion, back-pressure aware |
| 7 | Modular | One responsibility per module |
| 8 | Plugin-based | Adapters/behaviors/enrichers/views auto-registered |
| 9 | Horizontally scalable | Stateless workers; state in Mongo/Redis |
| 10 | Enterprise-grade | RBAC + audit + secrets hygiene + offline mode |
| 11 | API-first | Every UI action has a documented REST endpoint |
| 12 | Zero hallucination | AI must cite evidence or refuse |
| 13 | Zero vendor lock-in | Any adapter can be removed without core changes |

### 1.3 15-stage master pipeline (extended from v1)

```
1  INPUT ADAPTERS       ← plugin registry, vendor-agnostic core
2  UNIVERSAL PARSER     ← envelope + schema detection
3  NORMALIZATION        ← → Canonical Event Model (CEM v1)
4  CORRELATION          ← deterministic entity linking + confidence
5  SEMANTIC ENGINE      ← existing RC5 (per command_line entity)
6  BEHAVIOR ENGINE      ← behavior detectors → cited Behavior nodes
7  MITRE ENGINE         ← behavior → technique mapping (versioned tables)
8  RECONSTRUCTION       ← Process / File / Device reconstruction subsystems
9  TIMELINE             ← deterministic time-ordered attack narrative
10 TRAJECTORY ENGINE    ← per-entity state histories (device/file/process/…)
11 INVESTIGATION GRAPH  ← unified graph over entities + evidence
12 THREAT INTEL         ← optional enrichment (cache-first, offline-safe)
13 RISK ENGINE          ← multi-dimensional confidence → risk score
14 EXPLAINABILITY       ← derivation chains + citation resolver
15 REPORT / WORKSPACE   ← analyst UI + exports + AI copilot (opt-in)
```

**Backwards compatibility**: `POST /api/rc5/parse` wraps a raw string into a single-event CEM payload and routes through the pipeline — legacy consumers see no schema change.

---

## ARTEFACT 2 — Module Breakdown

```
/app/backend/
├── adapters/                      # Stage 1
│   ├── base.py                    # Protocol + BaseAdapter
│   ├── registry.py                # decorator + discovery
│   ├── command_line.py            # NEW · wraps legacy /rc5/parse input
│   ├── powershell.py              # NEW · .ps1 file / heredoc / EncodedCommand
│   ├── cmd.py                     # NEW
│   ├── bash.py                    # NEW
│   ├── linux_shell.py             # NEW · sh/zsh/fish common
│   ├── evtx.py                    # NEW · streaming EVTX reader
│   ├── sysmon.py                  # NEW · Sysmon XML + JSON
│   ├── auditd.py                  # NEW
│   ├── syslog.py                  # NEW · RFC-3164 + RFC-5424
│   ├── json_events.py             # NEW · generic JSON-Lines
│   ├── csv_events.py              # NEW
│   ├── xml_events.py              # NEW
│   ├── vendors/                   # vendor-specific families
│   │   ├── crowdstrike_fdr.py
│   │   ├── defender_xdr.py
│   │   ├── sentinelone.py
│   │   ├── carbonblack.py
│   │   ├── cortex_xdr.py
│   │   ├── elastic_defend.py
│   │   ├── sophos.py
│   │   ├── trend_vision_one.py
│   │   ├── cisco_xdr.py
│   │   ├── qradar.py
│   │   ├── splunk.py
│   │   ├── sentinel.py
│   │   ├── arcsight.py
│   │   ├── chronicle.py
│   │   ├── logrhythm.py
│   │   ├── elastic_siem.py
│   ├── cloud/
│   │   ├── aws_cloudtrail.py
│   │   ├── azure_activity.py
│   │   ├── entra_id.py
│   │   ├── o365.py
│   │   ├── exchange.py
│   │   ├── gws.py
│   ├── network/
│   │   ├── zeek.py
│   │   ├── suricata.py
│   │   ├── snort.py
│   │   ├── netflow.py
│   │   ├── firewall.py
│   │   ├── proxy.py
│   │   ├── vpn.py
│   │   ├── dns_logs.py
│   │   ├── pcap_meta.py
│   ├── ti/                        # threat-intel bundles (structured input)
│   │   ├── stix.py
│   │   ├── taxii.py
│   │   ├── yara.py
│   │   ├── sigma.py
│   │   ├── ioc_bundle.py
│   └── infra/
│       ├── kubernetes.py
│       ├── docker.py
│
├── parser/                        # Stage 2
│   ├── universal_parser.py
│   ├── envelope_detect.py
│   └── streaming.py
│
├── normalize/                     # Stage 3
│   ├── cem.py                     # CanonicalEvent dataclass
│   ├── entities.py                # Entity dataclasses (see Artefact 3)
│   ├── coercers.py                # per-field type coercion helpers
│   └── normalizer.py              # dispatch by adapter → normalizer
│
├── correlation/                   # Stage 4
│   ├── engine.py                  # deterministic entity linking driver
│   ├── rules/                     # each rule is a discoverable plugin
│   │   ├── process_key.py         # (pid + logon_id + host_id + start_ts)
│   │   ├── file_hash.py
│   │   ├── network_5tuple.py
│   │   ├── identity.py
│   │   ├── certificate.py
│   │   ├── parent_child.py
│   │   ├── session.py
│   │   └── temporal_window.py
│   ├── scoring.py                 # confidence ∈ [0.0, 1.0]
│   └── graph_bridge.py            # emits nodes+edges into Investigation Graph
│
├── engine/                        # Stage 5 · EXISTING · unchanged interface
│   ├── (all current RC5 files)
│   └── adapter_bridge.py          # NEW · called by /rc5 legacy endpoints
│
├── behavior/                      # Stage 6
│   ├── detectors/
│   │   ├── credential_dumping.py
│   │   ├── persistence_registry.py
│   │   ├── persistence_service.py
│   │   ├── persistence_task.py
│   │   ├── defense_evasion_amsi.py
│   │   ├── defense_evasion_etw.py
│   │   ├── injection_reflective.py
│   │   ├── injection_hollowing.py
│   │   ├── injection_dll.py
│   │   ├── lolbin_execution.py
│   │   ├── discovery_recon.py
│   │   ├── command_and_control.py
│   │   ├── exfiltration.py
│   │   ├── lateral_movement.py
│   ├── engine.py                  # runs all detectors, emits Behavior nodes
│
├── mitre/                         # Stage 7
│   ├── mapper.py
│   └── maps/attack_v15.yaml       # versioned mapping tables
│
├── reconstruction/                # Stage 8
│   ├── process_reconstruction.py  # process tree + LOLBin/injection tags
│   ├── file_reconstruction.py     # download → create → exec → delete chain
│   ├── device_reconstruction.py   # boot → login → activity → current-state
│
├── timeline/                      # Stage 9
│   ├── engine.py                  # deterministic ordering + merging
│   ├── merge_rules.py             # collapse duplicates
│   ├── anomaly.py                 # gap detection, out-of-order
│   └── views.py                   # zoom-level projections (30s/5m/1h/24h/7d/30d)
│
├── trajectory/                    # Stage 10
│   ├── engine.py
│   ├── device.py
│   ├── file.py
│   ├── process.py
│   ├── registry.py
│   ├── identity.py
│   ├── network.py
│   ├── cloud.py
│   ├── service.py
│   └── driver.py
│
├── graph/                         # Stage 11
│   ├── model.py                   # Node / Edge dataclasses
│   ├── store.py                   # Mongo-backed graph storage
│   ├── pivot.py                   # right-click pivot semantics
│   ├── traversal.py               # BFS / shortest-path deterministic
│   └── layout.py                  # deterministic layout hints for UI
│
├── enrichment/                    # Stage 12
│   ├── base.py                    # Enricher Protocol
│   ├── cache.py                   # TTL + offline mode
│   ├── enrichers/
│   │   ├── virustotal.py
│   │   ├── abuseipdb.py
│   │   ├── urlscan.py
│   │   ├── otx.py
│   │   ├── hybridanalysis.py
│   │   ├── shodan.py
│   │   ├── greynoise.py
│   │   ├── ipinfo.py
│   │   ├── abusech.py
│   ├── local_ti.py                # STIX / IOC bundle indexes
│
├── risk/                          # Stage 13
│   ├── dimensions.py              # decode / behavior / ioc / mitre / correlation / context
│   ├── engine.py
│   └── policy.yaml                # weighting knobs — versioned
│
├── explain/                       # Stage 14
│   ├── derivation.py              # dependency-graph of rules
│   └── resolver.py                # inflate evidence IDs → citations
│
├── report/                        # Stage 15 · server-side reporting
│   ├── executive.py
│   ├── analyst.py
│   ├── stix_export.py
│   └── pdf.py
│
├── copilot/                       # AI last-mile
│   ├── prompts.py
│   ├── executor.py                # cites evidence or refuses
│   └── policies.py                # opt-in, per-case boundary
│
├── baselines/                     # PREREQUISITE
│   └── rc5_baseline.json          # frozen metrics
│
├── tests/                         # existing + new hierarchies mirror above
│
└── routers/                       # FastAPI surfaces (Artefact 4)
    ├── rc5_parse.py               # LEGACY — kept, wraps adapter
    ├── cases.py                   # NEW · case CRUD
    ├── ingest.py                  # NEW · adapter-driven ingestion
    ├── timeline.py
    ├── trajectory.py
    ├── graph.py
    ├── enrichment.py
    ├── risk.py
    └── copilot.py
```

**Rules of engagement**:
- Every module owns exactly one responsibility.
- No cross-imports between `adapters/*` and `engine/*` — only via `normalize/` and `correlation/`.
- Legacy RC5 code stays in `engine/` untouched; new code never imports internals.

---

## ARTEFACT 3 — Data Model (Canonical Event Model v1)

### 3.1 Entities (globally unique `iid`)

Every entity: `{ iid, kind, attrs, first_seen, last_seen, case_id }`.

`iid` = ULID-prefixed by kind: `proc_01H...`, `file_01H...`, etc.

| Kind | Primary attrs | Correlation key |
|------|---------------|-----------------|
| `device` | hostname, os, os_version, agent_id, mac | agent_id ∥ (hostname + os) |
| `user` | sid, upn, name, domain | sid ∥ upn |
| `identity` | provider, tenant_id, oid, upn | (provider + oid) |
| `session` | session_id, logon_id, logon_type | (device_iid + logon_id) |
| `process` | pid, name, cmdline_hash, path, start_ts, parent_iid | (device_iid + pid + start_ts) |
| `command_line` | text, decoded, chain_recipe (from RC5) | sha256(text) |
| `script` | path, sha256, language | sha256 |
| `thread` | tid, process_iid | (process_iid + tid) |
| `memory` | process_iid, base_addr, size, protection | (process_iid + base_addr) |
| `kernel_event` | type, subsystem, ts | uuid |
| `registry` | hive, key, value_name, data | (device_iid + hive + key + value_name) |
| `file` | path, sha256, size, mtime, signer | sha256 ∥ (device_iid + path) |
| `directory` | path, device_iid | (device_iid + path) |
| `hash` | algo, value, target_iid | (algo + value) |
| `certificate` | thumbprint, subject, issuer, valid_from, valid_to | thumbprint |
| `service` | name, image_path, start_type | (device_iid + name) |
| `driver` | name, sha256, path | (device_iid + sha256) |
| `scheduled_task` | name, action, trigger | (device_iid + name) |
| `wmi_subscription` | filter, consumer, binding | (device_iid + binding) |
| `named_pipe` | name, endpoints | (device_iid + name) |
| `network_conn` | proto, src_ip, src_port, dst_ip, dst_port, ts | 5-tuple + ts_window |
| `dns_query` | qname, qtype, response, ts | (device_iid + qname + ts) |
| `http_transaction` | method, url, host, status, ts | (device_iid + url_hash + ts) |
| `smb_session` | share, host, user | (device_iid + share + user) |
| `ssh_session` | user, dst, key_fingerprint | (device_iid + dst + key_fingerprint) |
| `rdp_session` | src, dst, user | (device_iid + src + dst + user) |
| `cloud_resource` | provider, kind, arn/urn, region | arn ∥ urn |
| `iam_action` | provider, actor_iid, action, target | (provider + actor + action + ts) |
| `email` | message_id, sender, subject, recipients | message_id |
| `attachment` | email_iid, filename, sha256 | (email_iid + sha256) |
| `url` | url, host, path | sha256(url) |
| `domain` | fqdn | fqdn |
| `ip_address` | value, version | value |
| `port` | number, proto | (proto + number) |
| `ioc` | kind, value, source, confidence | (kind + value) |
| `mitre_technique` | tid, name, tactic | tid |
| `malware_family` | name, aliases | canonical name |
| `threat_actor` | name, aliases | canonical name |
| `campaign` | name, actor_iid | canonical name |
| `detection` | rule_id, product, ts | (product + rule_id + ts) |
| `alert` | source, severity, ts | source uuid |
| `incident` | id, title, status | id |
| `behavior` | technique_iid, evidence_ids, confidence | uuid |
| `evidence` | rule, inputs, output, ts | uuid |

### 3.2 CanonicalEvent (CEM v1)

```jsonc
{
  "iid": "evt_01HXABCD...",
  "case_id": "case_01HXABCD...",
  "adapter": "sysmon",                 // Stage 1 origin
  "adapter_version": "1.0.0",
  "ts": "2026-02-22T09:12:33.481Z",    // UTC ISO-8601 with ms
  "sequence": 17234,                    // adapter-local monotonic
  "kind": "process_create",             // enum, section 3.3
  "device": { "iid": "dev_..." },
  "actor":  { "iid": "usr_..." },       // may be null
  "session": { "iid": "sess_..." },
  "process": {
    "iid": "proc_...",
    "pid": 4288,
    "parent_iid": "proc_...",
    "command_line_iid": "cmd_...",
    "image_iid": "file_..."
  },
  "artefacts": {
    "file":       [{ "iid": "file_...", "action": "created" }],
    "registry":   [{ "iid": "reg_...",  "action": "value_set" }],
    "network":    [{ "iid": "net_...",  "action": "connect" }],
    "dns":        [{ "iid": "dns_...",  "action": "query"   }],
    "http":       [{ "iid": "http_...", "action": "request" }],
    "certificate":[{ "iid": "cert_..." }],
    "email":      [{ "iid": "eml_..."  }]
  },
  "labels": ["persistence", "credential-access"],   // Stage 6 tags
  "mitre": ["T1547.001"],                           // Stage 7 tags
  "raw":   { /* opaque per-adapter — forensic reference */ },
  "trust": { "adapter_confidence": 0.98 }
}
```

### 3.3 CEM event `kind` enum (initial)

`process_create` · `process_exit` · `process_access` · `image_load` · `thread_create` · `remote_thread_create` · `memory_alloc` · `memory_protect` · `handle_open` · `file_create` · `file_write` · `file_delete` · `file_rename` · `directory_create` · `registry_create` · `registry_value_set` · `registry_delete` · `network_connect` · `network_listen` · `dns_query` · `http_request` · `smb_share_access` · `ssh_session_open` · `rdp_session_open` · `named_pipe_create` · `service_install` · `service_start` · `driver_load` · `scheduled_task_create` · `wmi_subscribe` · `kernel_event` · `logon_success` · `logon_failure` · `token_manipulation` · `privilege_escalation` · `mail_delivery` · `mail_read` · `cloud_iam_action` · `cloud_resource_change` · `alert` · `detection`

### 3.4 Relationship model (stored separately)

```jsonc
{
  "iid": "rel_01H...",
  "case_id": "case_01H...",
  "src_iid": "proc_...",
  "dst_iid": "file_...",
  "kind": "downloaded",        // enum (Section 3.5)
  "confidence": 0.92,
  "evidence_ids": ["evt_...", "evt_..."],
  "created_at": "2026-02-22T09:12:34Z"
}
```

### 3.5 Relationship kind enum

`executed` · `spawned` · `injected_into` · `hollowed` · `loaded` · `downloaded` · `uploaded` · `created` · `modified` · `deleted` · `renamed` · `read` · `written` · `connected_to` · `resolved` · `queried` · `authenticated_as` · `assumed_role` · `impersonated` · `persisted_via` · `escalated_via` · `communicated_with` · `sent_email_to` · `received_email_from` · `matched_ioc` · `mapped_to_technique` · `attributed_to`

Every relationship's `confidence` is deterministic (Section 7).

---

## ARTEFACT 4 — API Surface

All endpoints admin-protected (JWT). All prefixed `/api/`. **Legacy `/api/rc5/*` retained.**

### 4.1 Ingestion

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/cases` | Create case (empty) |
| GET | `/api/cases` | List cases (paginated) |
| GET | `/api/cases/{id}` | Case detail |
| DELETE | `/api/cases/{id}` | Soft-delete |
| POST | `/api/cases/{id}/ingest` | Upload artefact(s); multipart or JSON — auto-detect adapter |
| POST | `/api/cases/{id}/ingest/stream` | SSE stream progress (chunk-by-chunk) |
| GET | `/api/adapters` | List registered adapters + capabilities |
| POST | `/api/adapters/detect` | Sniff a sample bytes → suggested adapter |

### 4.2 Query surface

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/cases/{id}/events` | Filtered CEM events (paginated) |
| GET | `/api/cases/{id}/entities` | Filtered entities |
| GET | `/api/cases/{id}/entities/{iid}` | Single entity + relationships |
| GET | `/api/cases/{id}/relationships` | Filtered relationships |
| GET | `/api/cases/{id}/timeline` | Timeline (zoom-aware) — Stage 9 |
| GET | `/api/cases/{id}/trajectory/{kind}/{iid}` | Trajectory for one entity — Stage 10 |
| GET | `/api/cases/{id}/graph` | Investigation graph JSON (paginated by neighborhood) — Stage 11 |
| POST | `/api/cases/{id}/graph/pivot` | Pivot from a node → sub-graph |
| GET | `/api/cases/{id}/behaviors` | Stage 6 output |
| GET | `/api/cases/{id}/mitre` | ATT&CK coverage |
| GET | `/api/cases/{id}/risk` | Dimensional confidence + verdict |
| GET | `/api/cases/{id}/report` | Executive/analyst report (JSON / STIX / PDF) |

### 4.3 Enrichment

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/cases/{id}/enrich/{iid}` | Enrich a single entity |
| POST | `/api/cases/{id}/enrich/bulk` | Enrich all matching entities of a kind |
| GET | `/api/enrichers` | List available enrichers + status |

### 4.4 Copilot (opt-in per case)

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/cases/{id}/copilot/summary` | Executive summary — cites evidence |
| POST | `/api/cases/{id}/copilot/story` | Attack story — cites timeline nodes |
| POST | `/api/cases/{id}/copilot/ask` | Free-form Q&A — must cite or refuse |
| GET | `/api/cases/{id}/copilot/status` | AI on/off, model, key state |

### 4.5 Legacy (unchanged)

`/api/rc5/parse` · `/api/rc5/golden/*` · `/api/decode/smart` · `/api/investigations` · `/api/documents` · `/api/admin/*` · authentication · training-inbox · benchmarks · MITRE heatmap.

---

## ARTEFACT 5 — Database Schema (MongoDB)

New collections (existing ones untouched):

### 5.1 `cases`
```
{ _id (ULID), name, created_at, created_by, status, adapters_used[], event_count, entity_count, risk_score, verdict, tags[] }
```
Indexes: `created_at desc`, `created_by`, `tags`.

### 5.2 `case_events` (CEM store)
```
{ _id, case_id, ts, kind, adapter, sequence, device_iid, actor_iid, process_iid, artefacts_iids[], mitre[], labels[], raw }
```
Indexes:
- `(case_id, ts)` — timeline range scans
- `(case_id, kind, ts)` — kind-filtered views
- `(case_id, device_iid, ts)` — per-device queries
- `(case_id, process_iid, ts)` — process trajectory
- Optional TTL on `raw` for cold-storage tier.

### 5.3 `case_entities`
```
{ _id (iid), case_id, kind, attrs, first_seen, last_seen, correlation_key }
```
Indexes:
- `(case_id, kind)`
- `(case_id, correlation_key)` — dedupe / merge
- Text index on `attrs.hostname`, `attrs.name`, `attrs.path`, `attrs.upn` for entity search

### 5.4 `case_relationships`
```
{ _id (iid), case_id, src_iid, dst_iid, kind, confidence, evidence_ids[], created_at }
```
Indexes:
- `(case_id, src_iid)` — outgoing
- `(case_id, dst_iid)` — incoming
- `(case_id, kind)`

### 5.5 `case_behaviors`
```
{ _id (iid), case_id, technique_iid, confidence, evidence_ids[], detector, ts }
```
Indexes: `(case_id, technique_iid)`, `(case_id, detector)`.

### 5.6 `case_reports`
```
{ _id, case_id, kind, format, sha256, content_ref, generated_at, generated_by }
```

### 5.7 `enrichment_cache`
```
{ _id (sha256(kind+value)), kind, value, source, response, ttl_expires_at }
```
TTL index on `ttl_expires_at`.

### 5.8 `audit_log` (append-only)
```
{ _id, ts, actor, case_id, action, target_iid, before_hash, after_hash }
```

**Partitioning strategy**: shard cases > 1 M events onto a dedicated collection alias (`case_events_YYYYMM`) via a router service, transparent to consumers.

---

## ARTEFACT 6 — Plugin Interfaces

### 6.1 Input adapter Protocol

```python
from typing import Iterator, Protocol, runtime_checkable

@runtime_checkable
class InputAdapter(Protocol):
    name: str                       # unique id, kebab-case
    version: str                    # semver
    supported_formats: list[str]    # ["evtx", "xml", "json-lines"]
    capabilities: set[str]          # {"stream", "resume", "delta"}

    def detect(self, sample: bytes | str) -> float:
        """Return confidence 0.0–1.0 that this adapter can read the sample."""

    def stream(self, source: "Source", *, chunk_size: int = 4096) -> Iterator["RawEvent"]:
        """Yield RawEvent objects. Must be back-pressure friendly."""
```

### 6.2 Normalizer Protocol

```python
class Normalizer(Protocol):
    adapter: str                    # matches InputAdapter.name

    def normalize(self, raw: "RawEvent") -> Iterator["CanonicalEvent"]:
        """One RawEvent may yield 0..N CanonicalEvents (e.g. Sysmon 1 → process+file)."""
```

### 6.3 Correlation rule Protocol

```python
class CorrelationRule(Protocol):
    name: str
    kinds: tuple[str, ...]          # entity kinds this rule links

    def link(self, ent_a: "Entity", ent_b: "Entity", ctx: "CorrCtx") -> "LinkResult | None":
        """Return a LinkResult with a deterministic confidence, or None."""
```

### 6.4 Behavior detector Protocol

```python
class BehaviorDetector(Protocol):
    name: str
    techniques: tuple[str, ...]     # ATT&CK TIDs

    def detect(self, case: "CaseView") -> Iterator["Behavior"]:
        """Return zero or more Behavior nodes, each with evidence_ids."""
```

### 6.5 Enricher Protocol

```python
class Enricher(Protocol):
    name: str
    kinds: tuple[str, ...]          # entity kinds this enricher covers
    offline_safe: bool              # True if pure local

    def enrich(self, entity: "Entity", *, offline: bool = False) -> "EnrichmentResult":
        ...
```

### 6.6 Trajectory view Protocol

```python
class TrajectoryView(Protocol):
    kind: str                       # entity kind rendered

    def render(self, entity: "Entity", events: Iterator["CanonicalEvent"]) -> "Trajectory":
        ...
```

### 6.7 Discovery

All plugin modules under the respective directories are auto-imported at boot. A `@register(kind="...")` decorator adds them to `registry.py`. No hard-coded lists.

---

## ARTEFACT 7 — Correlation Model

### 7.1 Rules (each deterministic, cited)

| Rule | Signal | Confidence formula |
|------|--------|--------------------|
| `process-key` | (device + pid + start_ts ± 1s) match | 1.00 if exact, 0.85 if start_ts within [1s, 10s] |
| `parent-child` | child.parent_iid == parent.iid | 1.00 |
| `file-hash` | sha256 match | 1.00 |
| `file-path-mtime` | (device + path + mtime ± 500ms) match | 0.90 |
| `network-5tuple` | (proto + src+dst tuple + ts_window 5s) match | 0.90 |
| `dns-http` | dns.qname resolves to http.host | 0.85 |
| `dns-connect` | dns.qname’s answer IP == network_conn.dst_ip within 30s | 0.80 |
| `identity-sid` | user.sid match | 1.00 |
| `identity-upn` | user.upn match, sid differs | 0.75 |
| `session-logon` | (device + logon_id) match | 0.95 |
| `certificate-thumbprint` | thumbprint match | 1.00 |
| `command-line-sha` | command_line.sha256 match | 1.00 |
| `ioc-match` | (kind + value) match | 0.90 |
| `mitre-technique` | behavior.technique_iid → mitre_technique | 1.00 |

### 7.2 Composite score

For multi-signal links: `conf = 1 − ∏(1 − conf_i)` (probabilistic OR). Caps at 0.99 to reserve 1.00 for exact-key rules.

### 7.3 Anti-hallucination guardrails

- If a rule fires on only one entity side (e.g. dns query without a matching connect within window), emit a **negative-evidence flag** rather than a link.
- Rules NEVER use time alone. `temporal_window` is always paired with at least one other signal.
- Rule outputs are **derivation-cited** in the `evidence_ids[]` field.

### 7.4 Feature-flag rollout

`NIVX_CORRELATION_ENGINE=sidecar` (Phase 1) → `dual` (Phase 2, dual-write for gate validation) → `primary` (Phase 3, once baselines lock).

---

## ARTEFACT 8 — Investigation Graph Model

### 8.1 Storage

- Nodes: existing `case_entities` collection (an entity **is** a node — no duplication).
- Edges: existing `case_relationships` collection (a relationship **is** an edge).
- No separate graph store. Traversal + layout are computed on demand from Mongo indexes.

### 8.2 Node kinds — see Artefact 3.1 (44 kinds).

### 8.3 Edge kinds — see Artefact 3.5 (27 kinds).

### 8.4 Graph API contract

```
GET /api/cases/{id}/graph?focus={iid}&depth=1&max_nodes=500
→
{
  "focus_iid": "...",
  "depth": 1,
  "nodes": [
    { "iid": "...", "kind": "process", "attrs": { ... }, "risk": 0.72 },
    ...
  ],
  "edges": [
    { "iid": "...", "src": "...", "dst": "...", "kind": "downloaded", "confidence": 0.91 },
    ...
  ],
  "layout_hints": { "algorithm": "hierarchical", "seed": 42 },
  "truncated": false
}
```

### 8.5 Pivot semantics

`POST /api/cases/{id}/graph/pivot` body:
```
{ "iid": "...", "keep_kinds": ["process", "file", "network_conn"], "depth": 2 }
```
Returns a **fresh sub-graph** rooted on `iid`, with only the requested kinds. UI opens this in a new tab and preserves the outer graph state.

### 8.6 Determinism

- Node ordering: by (kind, first_seen, iid).
- Edge ordering: by (src_iid, dst_iid, kind).
- Layout `seed` is derived from `case_id` → identical layouts across reloads.
- Traversal always uses BFS with a stable sort inside each level.

### 8.7 Cross-case boundary

Graph traversal never crosses `case_id`. IOCs / MITRE / threat actors are the only entity kinds allowed to be **cross-case singletons** (their `case_id` is null; every case relates *to* them, not owns them).

---

## Sign-off checkpoint for Artefacts 1–8

Before Artefacts 9–15 are actioned, please confirm:

- [ ] Positioning + 13 principles locked
- [ ] 15-stage pipeline order accepted
- [ ] Module tree accepted (or amend list)
- [ ] Entity kinds + CanonicalEvent shape accepted
- [ ] Event `kind` enum sufficient (or additions)
- [ ] Relationship enum sufficient (or additions)
- [ ] API surface accepted (or amend paths)
- [ ] Mongo collection design + indexes accepted
- [ ] Plugin protocols accepted
- [ ] Correlation rules + confidence formulas accepted
- [ ] Graph storage strategy (no separate DB) accepted
- [ ] Cross-case IOC/MITRE singleton model accepted

→ Companion document `/app/memory/ENGINES_UI_PERF.md` covers Artefacts 9–15.

**No code has been written.**
