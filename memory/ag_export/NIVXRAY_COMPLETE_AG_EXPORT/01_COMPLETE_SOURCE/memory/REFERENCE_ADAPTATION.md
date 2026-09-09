# Reference Adaptation Map
## Commercial EDR/XDR capabilities we should ADOPT (not copy) into NivXRay

**Sources reviewed (Feb-2026):**
- CrowdStrike · Real-Time Response
- Cisco Secure Endpoint · Device Trajectory
- Cisco Secure Endpoint · Automated Forensic Snapshots
- Cisco Secure Endpoint · MITRE ATT&CK Evaluation posture

**Governance boundary:** we are an **investigation platform**, not an EDR. We do NOT run commands on endpoints. We do NOT collect telemetry directly. We DO ingest and reason over evidence produced by these products.

**UI rule:** *Adopt patterns, invent visuals.* Every UI must remain DetectFlow (dark, glass, Chivo 900, cyan-teal accents).

---

## 1 · Device Trajectory — Cisco Secure Endpoint pattern

Capability aspects Cisco surfaces that we adopt:

| Aspect | Their approach | Our adoption |
|---|---|---|
| Timeline scrubber | Zoomable time axis with dot events | ✅ **Shipped** (Fit / 1h / 24h / 7d / 30d) |
| Swimlanes | Fixed vertical categories per event kind | ✅ **Shipped** — SYSTEM / PROCESS / FILES / NETWORK / REGISTRY |
| Entity refs | Every event links to file / process / URL | ✅ **Shipped** — `EntityRef` per frame |
| Retrospective drill-through | Click event → jump to related events on OTHER devices | 🟡 **Phase 4b** — cross-device pivot |
| Process ancestry inline | Parent-child chain shown as a small tree per selected process | 🟡 **Phase 4c** — Process Ancestry Panel |
| SHA / signer badges | Hash / signer status next to file events | 🟡 **Phase 4d** — Enrichment strip on nodes |
| Filter chips (verdict, MITRE) | Filter timeline by verdict / MITRE tactic | 🟢 **Phase 3g** — one-line filter row above the swimlanes (small PR) |
| "New event since" badge | Highlights events added since last view | 🟢 **Phase 3g** — trivially derived from `provenance.ingested_at` |

**Do NOT adopt:** their exact iconography, blue-arrow visual language, or product-branded chrome.

---

## 2 · Forensic Snapshots — Automated evidence capture

Their model: on a detection, automatically capture running-processes + open-network + logged-on users + recent file activity + registry deltas → attach to the alert.

Our adoption (aligned with governance §Artifact Store):

| Cisco snapshot slice | Our v2 storage target |
|---|---|
| Running processes | `v2_shadow_observations` (process_create events already there) |
| Open network connections | `v2_case_events` kind=network_connect |
| Logged-on users | kind=logon_success |
| Recent files | kind=file_write / file_create |
| Registry delta | kind=registry_value_set |
| **Snapshot manifest (immutable)** | 🟡 **NEW · Phase 4a** · `v2_artifact_store` — one document per snapshot, sha256 content-addressed, refers to the CEM events it froze |

**Endpoint we would add (later, additive):**
`POST /api/v2/cases/{id}/snapshots/capture`
`GET  /api/v2/cases/{id}/snapshots`
`GET  /api/v2/cases/{id}/snapshots/{sha256}`

Each snapshot is **immutable** and carries the same Provenance record every CEM event does. Deterministic: identical case-state produces identical snapshot sha256.

---

## 3 · Process Tree — real-time process graph

Cisco / CrowdStrike show a **branching process ancestry** with metrics per node (verdict, telemetry count, MITRE tags).

Our adoption:

| Feature | Adopt? | Where |
|---|---|---|
| Node = process, edge = spawn | ✅ | `v2/graph/process_tree.py` (Phase 4c) |
| Verdict colour per node | ✅ | Cyan/amber/red — deterministic from evidence confidence |
| MITRE chip on node | ✅ | Aggregates all techniques from events under that process |
| Command-line inline | ✅ | Hover reveals raw + rule id |
| Timeline scrub tied to tree | ✅ | Selecting a process highlights its lifetime on the trajectory |
| Live process count | ⛔ | We are not an EDR — we show what was captured, not what's running now |
| Right-click "kill process" | ⛔ | Not our surface area |

---

## 4 · MITRE ATT&CK Evaluation posture

Cisco publishes coverage against MITRE's public adversary emulations (APT29, Carbanak+FIN7). We adopt the *pattern*, not the branding:

| Aspect | Our adoption |
|---|---|
| Public adversary emulations | 🟡 Extend `v2/seed/` with 5+ canonical chains (add Carbanak / FIN7 / Turla / Volt Typhoon / MuddyWater alongside Bumblebee) |
| Per-technique detection scoring | 🟢 **Phase 3g** — coverage summary = MITRE technique count seen / expected in the corpus |
| Public transparency | 🟡 Publish the evaluation summary as `/api/v2/coverage/mitre` (governance-approved endpoint) |
| Vendor-vs-vendor comparisons | ⛔ Not our fight |

---

## Concrete next-slate priorities (derived from the above)

**Phase 3g · Trajectory refinements** *(small PR, additive)*
- MITRE chips per event node (data is already in the frame payload)
- Filter chip row: verdict × MITRE tactic × lane
- "New since last view" badge

**Phase 4a · Artifact Store** *(medium PR, additive)*
- `v2/artifact_store/` + snapshots endpoints
- Immutable, sha256-addressed, provenance-carrying

**Phase 4b · Cross-device Pivot** *(medium PR)*
- `POST /api/v2/graph/pivot?entity_iid=...` returns every case where that entity appears
- UI: hover any file/network entity in trajectory → "seen on 3 devices" link

**Phase 4c · Process Ancestry Panel** *(medium PR)*
- `v2/graph/process_tree.py` builds a tree from `process_create` events + `parent_iid` refs
- New route `/v2/tree/:caseId/:processIid`

**Phase 4d · Enrichment Strip** *(medium PR)*
- Hash / signer / TI hit chip next to file events on the trajectory
- Uses existing `v2/enrichment/` slot; offline-safe

**Phase 5 · MITRE Coverage Endpoint** *(small PR)*
- `GET /api/v2/coverage/mitre` returns technique-count per adversary emulation

---

## Explicit non-adoption

To keep our positioning clean:

- No live-response / interactive endpoint shell.
- No real-time telemetry ingestion.
- No product-vs-product benchmarking marketing.
- No copied iconography, colour palette, or wordmark.
- No AI hallucination anywhere in the fact path.

---

*This document is a design reference. Nothing here is implemented yet unless
marked ✅ Shipped. Every future phase must still pass the RC5 regression gate.*
