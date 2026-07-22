# NivXRay v2 · Release Roadmap
## Dual-Mode DFIR Platform · Locked Feb-2026

Every release must pass its gate before the next begins. Scope
does not migrate between releases — new asks land in a
higher-numbered release.

---

## The Two Operating Modes

NivXRay ships **one deterministic engine** exposed through **two
first-class workflows**. Every release below is scored against
what it unlocks in each mode.

### 🅰️ Mode A · Automated Ingest-and-Report Pipeline (SOAR back-end)
`EDR / SIEM / cloud telemetry → CEM → deterministic engine + enrichment → Investigation Report → ServiceNow / Splunk / webhook`
- Push telemetry in (JSON / syslog / WMI / API / EVTX / CSV)
- NivXRay decodes commands, correlates OSINT / MITRE / NIST IR, writes a full report
- Report is pushed to ServiceNow / SIEM / webhook where the analyst already sits

### 🅱️ Mode B · Interactive Analyst Console (post-alert investigation)
`Alert in SIEM → analyst opens NivXRay → visual trajectory, ancestry, artifacts, on-demand report`
- Same CEM, same engines, same report generator
- Every UI feature is a projection of the shared model

Everything up to and including the Report Generator is shared. That
is why R4 (Report Generator) is prioritised ahead of new UI surfaces
— it multiplies the value of every downstream release in both modes.

---

## R1 · Device Trajectory MVP · **SHIPPED**

Delivered:
- CEM v1 versioned schema + entity-aware Evidence model
- Shadow adapter + semantic parser (18 deterministic rules)
- POST /api/v2/cases/{id}/observations
- GET  /api/v2/cases/{id}/trajectory/device
- Swimlane UI, real DFIR seed (Bumblebee → AdaptixC2 → Akira)
- Feature-flag isolation (TRAJECTORY_ENGINE, CASE_ENGINE, ADAPTERS)
- OpenAPI diff + PIC v2 + versioning tests
- 796/796 fast tests green · zero RC5 files touched

---

## R1.1 · Analyst Experience · **SHIPPED**

Delivered:
- Cisco Secure Endpoint symbol vocabulary (12 activity glyphs)
- Amber-on-Graphite palette, IBM Plex Sans + Mono
- Per-process rows, dashed lifelines, two-tier calendar+hour scrubber
- Filter chips (verdict + lane + MITRE), case selector dropdown
- Glyph legend popover, "new since last view" badge
- Rule-provenance hover cards + Evidence panel with verdict + confidence badges
- Activity feed tab (chronological parent → child pairs)
- GET /api/v2/cases/{id}/mitre/coverage (technique + tactic counts)
- Seed script upserts parent v2_cases doc
- 8/8 backend + 15/15 frontend flows verified by testing agent

Modes served: Mode B primarily; MITRE coverage endpoint also feeds Mode A reports.

---

## 🔴 R4 · Deterministic Investigation Report Generator · **NEXT · P0**

Why now: Report Generator is the **shared capability** that powers
both Mode A and Mode B. Every future adapter or UI feature is
immediately more valuable once it can produce a complete,
deterministic investigation report.

Scope:
- `POST /api/v2/cases/{id}/report` returns JSON + Markdown
- `POST /api/v2/cases/{id}/report.md`  returns Markdown text/plain
- Deterministic hash of inputs on every report (same case → same hash)
- Report sections:
  1. **Executive Summary** (auto-composed narrative from CEM)
  2. **Case Metadata** (id, name, timeline span, sha of observations)
  3. **Verdict Rollup** (malicious / suspicious / observation counts)
  4. **MITRE ATT&CK Coverage** (techniques × tactics matrix)
  5. **Process Ancestry Snapshot** (top spawn chains)
  6. **Top Entities** (files, network destinations, registry keys, users)
  7. **Chronological Timeline** (grouped by lane, with rule provenance)
  8. **Command-line Decoding Evidence** (RC5 outputs on encoded commands)
  9. **Enrichment Section** (stubs for NIST IR + OSINT + CVE — filled in R3)
  10. **Report Signature** (SHA-256 of canonical JSON)
- Frontend: "Generate Report" button on Device Trajectory → modal preview
  with Copy JSON / Copy Markdown / Download .md
- Backing tests: pytest unit tests for determinism, section coverage,
  and hash-stability across two runs on identical input

Gate:
- [ ] `pytest tests/rc5/` still 100% green
- [ ] Two consecutive report generations on the same case return identical hashes
- [ ] Report contains all 10 sections with non-empty data on the seeded case
- [ ] Frontend modal renders and Copy / Download work
- [ ] Testing agent green on backend + frontend

Modes served: **BOTH · Mode A (egress payload) + Mode B (on-demand preview)**

---

## 🟠 R1.2 · Process Ancestry Panel · **P1**

Scope:
- New route `/v2/ancestry/:caseId/:processIid`
- Graph view of parent → child spawn chains for a given process
- Reuses the same CEM store — zero new schema
- Backend: GET /api/v2/cases/{id}/ancestry/process/{iid}

Modes served: Mode B (analyst deep-dive); Mode A pulls the same
ancestry data into the R4 report's "Process Ancestry Snapshot".

---

## 🟠 R2 · Artifact Store · **P1**

Scope:
- Immutable artifact objects (stable IDs) — every observation, rule
  hit, and report generation cites artifact IDs
- Backend: v2_artifacts collection + POST/GET /api/v2/artifacts
- Report Generator (R4) upgrades to cite artifact IDs instead of
  inline event dumps

Modes served: BOTH — foundational for auditability + report citations.

---

## 🔴 R2.5 · Multi-format Ingest Adapters · **P0 · unlocks Mode A ingress**

Scope:
- JSON telemetry adapter (canonical, extends existing shadow adapter)
- Syslog / RFC-5424 adapter
- Windows EVTX adapter (Event Log XML)
- CSV / TSV adapter
- Generic webhook receiver: POST /api/v2/ingest/webhook
- WMI receiver stub (feature-flag gated, real WMI in R7)
- Every adapter emits CEM v1 events, same rules apply downstream

Modes served: **Mode A ingress** (Mode B uses the same adapters
transparently when analysts upload evidence bundles).

---

## 🟡 R3 · Enrichment Kit · **P1**

Scope:
- Complete MITRE technique → tactic mapping (currently 26 entries,
  full ATT&CK matrix v14 = ~700)
- NIST IR mapping (SP 800-61 IR phases per event class)
- OSINT lookup adapter (VirusTotal / abuseipdb / URLhaus — flag-gated)
- CVE correlation (from process image / DLL path where applicable)
- Enrichment cache with TTL

Modes served: BOTH — powers R4 report's enrichment section and the
in-UI provenance hover card.

---

## 🔴 R5 · Egress Adapters · **P0 · closes Mode A loop**

Scope:
- ServiceNow ITSM outbound (create incident from report)
- Splunk HEC outbound
- QRadar API outbound
- Generic webhook egress with HMAC signing
- Email (SendGrid via Emergent LLM key? · TBD)
- Retry queue + delivery receipts

Modes served: Mode A egress — closes the loop from ingest → report → SIEM/ITSM.

---

## 🟢 R6 · Golden Trajectory Corpus · **P2**

Scope:
- Score attack chains for completeness / accuracy / latency
- Nightly gate compares production output vs corpus fingerprints
- Regression catcher for R2.5 adapter additions

Modes served: internal quality bar (not user-visible).

---

## Deferred / Backlog

- R7 · Real WMI receiver (Windows agent)
- R8 · Multi-tenant RBAC (case-level ACLs)
- R9 · Timeline diff (compare two cases)
- R10 · Playbook automation (SOAR rules on report output)

---

## Governance

- RC5 legacy engine: **PERMANENTLY FROZEN**. See /app/memory/GOVERNANCE.md
- Every new endpoint under `/api/v2/`, every new frontend module under `/app/frontend/src/v2/`
- Feature flags default OFF; every release ships behind a flag
- Testing agent must be green before a release is tagged
- The Report Generator (R4) is the **canonical output** — every UI
  screen is a projection of what the report expresses
