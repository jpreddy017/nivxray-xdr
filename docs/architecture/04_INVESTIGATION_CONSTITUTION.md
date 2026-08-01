# 04 · Investigation Constitution

## The Universal Pipeline (SSOT)

Every investigation, regardless of source, MUST flow through this exact sequence:

```
             ─── ingestion sources ───
             PowerShell · CMD · Bash
             URL · IOC list · Script
             Base64 · Hex · Ciphertext
             Cisco XDR · Defender · CrowdStrike
             SentinelOne · QRadar · Splunk · Elastic
             Sysmon · Windows Events · Email · STIX · YARA
                          │
                          ▼
    ┌─────────────────────────────────────────────┐
    │  Investigation Document Intelligence (IDI)  │  ← ingestion adapters
    │  (vendor detect · section parse · normalise)│
    └─────────────────────────────────────────────┘
                          │
                          ▼
    ┌─────────────────────────────────────────────┐
    │   Canonical Investigation Schema (CIO)       │  ← single source of truth
    └─────────────────────────────────────────────┘
                          │
                          ▼
    ┌─────────────────────────────────────────────┐
    │   Investigation Knowledge Graph (IKG)        │  ← evidence graph
    └─────────────────────────────────────────────┘
                          │
                          ▼
    ┌─────────────────────────────────────────────┐
    │   Unified Verdict Engine v1                  │  ← locked by P1-02 CI gates
    └─────────────────────────────────────────────┘
                          │
             ┌────────────┼────────────┐
             ▼            ▼            ▼
       Executive     Attack Story   ATT&CK Mapping
       Summary       Timeline       Report Composer
             ▼            ▼            ▼
        Device Trajectory · Reports · Analyst Workspace (X-Lab)
```

## Locked rules

### 1. IDI is an ingestion adapter, NEVER a parallel pipeline
The Investigation Document Intelligence layer takes vendor-shaped input
(Cisco XDR incident, CrowdStrike detection, Defender alert, QRadar
offense, Splunk notable, Sysmon XML, Windows Event) and produces the
same CIO the decode pipeline produces. Downstream is unchanged.

❌ NO forked verdict engine.
❌ NO forked summary composer.
❌ NO forked evidence graph.
✅ Only a new adapter class per vendor, all writing into the same CIO.

### 2. The Unified Verdict Engine remains the sole authority
`nivxforge.investigation.verdict_engine.compute_verdict()` is the only
implementation. The P1-02 CI gate at
`/app/backend/tests/parity/test_verdict_parity_workspace_vs_xlab.py`
enforces this — any fork breaks CI.

### 3. Every ingestion path produces the same CIO
Whether input is a PowerShell one-liner or a Cisco XDR JSON blob,
the downstream engines see a single canonical shape. The IDI layer's
sole job is to shrink the input distribution to that shape.

## Definition of "IDI adapter"

An IDI adapter is a Python class or function conforming to this contract:

```python
class VendorAdapter:
    name: str                  # "cisco_xdr" | "crowdstrike" | ...
    def detect(self, raw: str | dict) -> float:
        """Return 0..1 confidence this adapter should handle the input."""
    def normalise(self, raw: str | dict) -> NormalisedIncident:
        """Extract entities, events, indicators, timeline, vendor verdict."""
    def quality_report(self, raw: str | dict, normalised: NormalisedIncident) -> NormalizationQualityReport:
        """MANDATORY. See §Normalization Quality Report below."""
```

The universal `AdapterRegistry` picks the adapter with the highest
`detect()` score. The adapter's `normalise()` output is then fed to
the existing `from_analysis_result` → `build_cio` chain, and its
`quality_report()` is attached at `cio.metadata.normalization_quality`.

Consequence: adding a new vendor requires exactly one new adapter,
zero changes to the CIO, evidence graph, verdict engine, summary
composer, or any lens.

## 🔒 Normalization Quality Report (mandatory per adapter)

Every adapter MUST emit a machine-readable + analyst-readable quality
report so parser regressions surface immediately and adapter quality
becomes objectively measurable.

**Shape** (`cio.metadata.normalization_quality`):

```json
{
  "adapter":               "cisco_xdr",
  "normalization_version": "1.2.0",
  "schema_version":        "cio-v4",
  "detect_confidence":     0.99,
  "sections_parsed": {
    "incident_header":       true,
    "threat_detection":      true,
    "event_data":            true,
    "investigation_findings":true,
    "threat_intel":          true,
    "timeline":              true,
    "mitre":                 true,
    "json_payload":          true
  },
  "entity_counts": {
    "hosts": 7, "processes": 5, "files": 3, "hashes": 2,
    "ips":   4, "domains":   3, "urls":  2
  },
  "coverage_pct":     98,
  "correctness_pct":  95,
  "completeness_pct": 92,
  "warnings": [
    "Missing Process IDs",
    "Missing Registry Events",
    "Missing Network Connections"
  ]
}
```

**`normalization_version` + `schema_version`** are mandatory. They
distinguish parser-behaviour changes (adapter update) from canonical-
schema evolution (CIO upgrade), which simplifies regression triage
when historical investigations are reprocessed.

## 🔒 The three CI metrics (not just coverage)

Coverage alone is insufficient — a parser can achieve high coverage
while extracting incorrect data. Every adapter emits three
independent scores:

| Metric | Question it answers | CI floor (default) |
|--------|--------------------|--------------------|
| **Coverage**     | Were the expected sections and entities parsed? | 60 % |
| **Correctness**  | Do parsed values match the golden corpus?       | 90 % |
| **Completeness** | Were all expected entities + relationships extracted? | 80 % |

Any adapter dropping below its floor on any of the three metrics
fails CI.

## 🔒 Golden Corpus (per vendor)

For each supported vendor, maintain a deterministic golden corpus at
`/app/backend/tests/parity/corpora/<vendor>/` with paired
`input_*.json` and `expected_*.json` files. The Parity CI verifies:

1. Adapter detection
2. Section identification
3. Entity extraction
4. Timeline ordering
5. Process hierarchy
6. Relationship graph
7. Threat-intel normalization
8. CIO serialization
9. Executive Summary determinism
10. Attack Story determinism
11. Verdict parity (identical evidence ⇒ identical verdict)
12. Normalization Quality Report contents

## 🔒 Canonical Schema Stability Test (cross-vendor)

Testing each adapter against its own corpus is not enough — the CIO
itself must remain vendor-neutral, otherwise every new adapter
gradually bends the schema toward the assumptions of the first one
implemented.

For every "equivalent-incident" set at
`/app/backend/tests/parity/equivalence/<incident_id>/`
(one folder per synthetic scenario, containing one input file per
vendor), the CI asserts **semantic equivalence** of the resulting
CIOs — NOT byte-for-byte equality.

Equivalence dimensions (all must match across vendors):
- Same affected `host` set
- Same primary detection (top verdict contributor kind + label)
- Same execution chain (process parent→child edges)
- Same ATT&CK techniques (as a set, not necessarily ordered)
- Same normalised entity set (hosts · users · files · hashes · ips · domains · urls)
- Same verdict inputs (same contributors' `kind` + `weight`)
- Same verdict label
- **Evidence Provenance present** — every normalised entity MUST carry
  a traceable `provenance` link to its original vendor source (see
  §Evidence Provenance below). The provenance CONTENT differs by
  vendor; its EXISTENCE and shape must not.

**Consequence**: if Cisco XDR and Defender XDR describe the same
incident, both adapters MUST produce CIOs that lead to the same
verdict, the same MITRE mapping, and the same executive story — even
if the wording of the vendor's own alert differs.

**File layout**

```
tests/parity/
    corpora/                    ← per-adapter golden corpus (P2-05a)
        cisco_xdr/
            input_case_01.json
            expected_case_01.json
        crowdstrike/
            input_case_01.json
            expected_case_01.json
        ...
    equivalence/                ← cross-vendor semantic parity (P2-05b)
        incident_001_bits_downloader/
            cisco_xdr.json
            defender.json
            crowdstrike.json
            expected_semantic.json    ← the vendor-neutral CIO shape
        incident_002_powershell_iex/
            ...
```

## 🔒 Evidence Provenance (mandatory per entity)

Every entity emitted into the CIO evidence graph carries a
`provenance` block so an analyst can always trace a normalised fact
back to its raw vendor evidence:

```json
{
  "id":    "host-AZG51-CHECKIN-1",
  "kind":  "host",
  "value": "AZG51-CHECKIN-1",
  "provenance": {
    "adapter":        "cisco_xdr",
    "vendor_field":   "detection.event_data.hostname",
    "raw_snippet":    "\"hostname\": \"AZG51-CHECKIN-1\"",
    "raw_offset":     [4291, 4340],
    "extraction_rule":"cisco_xdr::host::from_event_data"
  }
}
```

For the same host observed via Defender the provenance differs:

```json
"provenance": {
  "adapter":      "defender",
  "vendor_field": "alertContext.DeviceName"
}
```

**Rules**
- Provenance CONTENT is vendor-specific — never enforce identical fields.
- Provenance EXISTENCE is universal — an entity without a provenance
  block fails the Normalization Quality Report AND the parity CI.
- Provenance is READ-ONLY once written. Downstream engines (verdict,
  summary, MITRE, report) must never modify it.

**UI surfacing** — X-Lab's **Source lens** lets the analyst click any
evidence node and see the original vendor snippet + rule that
extracted it. The **Evidence lens** shows a compact
`⤴ cisco_xdr::event_data.hostname` provenance chip on every entity
card.

## Anti-goals (permanent)

- ❌ No vendor-specific verdict logic outside the shared engine.
- ❌ No vendor-specific summary text outside the shared composer.
- ❌ No vendor-specific UI panels in X-Lab.
- ❌ No feature flag for "auto-investigate mode vs decode mode" —
     the router chooses the adapter transparently based on `detect()`
     scores.
- ❌ **No adapter that stops at "I found a PowerShell command."**
     Every adapter MUST recursively hand embedded commands, scripts,
     encoded payloads, URLs, and hashes back into the pipeline for
     deep investigation. Parse ≠ Investigate — see doctrine below.

## 🔒 IDI Doctrine · "Investigate, don't just parse"

Traditional SIEM parsers (QRadar DSM, ArcSight FlexConnector, Splunk
TA, Microsoft DCR) do:

```
Raw Logs → Parser → Normalize → Correlate → Alert
```

They stop at correlation.  X-Lab MUST do:

```
Raw Input → Parse → Normalize → Investigate → Correlate → Reason → Explain
```

Every adapter is responsible for the FULL chain — not just parsing.
When a Cisco XDR alert carries an embedded PowerShell command line,
the Cisco adapter DOES NOT stop at "extracted command_line=…". It
hands the command back to the pipeline's Deep Command Investigation
layer, which decodes it (Base64 · UTF-16LE · deflate · XOR · RC4 · …),
extracts IOCs, maps ATT&CK, and folds every recovered artefact back
into the same CIO.

**The correlation engine evolves** from event-based (`Event A + Event B → Offense`)
to **semantic** — chains of evidence tie together across process
tree, DNS, hash reputation, VT/AbuseIPDB, registry run keys, and
timeline into a single Attack Story.

**Naming**: the layer is called **IDI** (Investigation Document
Intelligence) for consistency with the backlog and constitution. Its
responsibilities are broader than the name suggests: it parses,
normalises, detects vendors, decodes commands, investigates embedded
artefacts, correlates evidence, builds timelines, constructs the
knowledge graph, and produces the CIO. Any renaming happens ONLY via
a superseding ADR — never inline.

---


## Success criteria (when IDI is "done")

- Every vendor input listed in `INPUT_TYPES` (see
  `nivxforge/investigation/input_understanding.py`) has a matching
  adapter.
- Adapter selection is deterministic on identical inputs.
- Every adapter emits a Normalization Quality Report at
  `cio.metadata.normalization_quality` and X-Lab's Executive lens
  renders the coverage chip.
- The Verdict Parity CI (P1-02) remains green after every adapter
  ships.
- The Investigation Quality Gate (P1-07 · scaffolded at
  `/app/backend/tests/quality/test_investigation_quality.py`) passes
  on the full vendor corpus and asserts
  `coverage_pct >= FLOOR` per adapter (default 60 %; per-adapter
  override allowed).

## 8. Universal Investigation Ingestion (LOCKED)

The IDI architecture shall evolve beyond vendor-specific investigation
reports into a **Universal Investigation Ingestion Platform** capable
of ingesting and investigating **any security-relevant input**.

This is NOT a single parser. It is a deterministic adapter framework.
Every adapter has the same contract:

```
detect(raw) → normalise(raw) → quality_report(raw, normalised)
       │
       ▼
Canonical Investigation Object (CIO)
```

No downstream component knows or cares where the evidence originated.

### 🔒 Terminology · "Adapter" not "Parser"

A parser only extracts fields. An IDI **Adapter** is responsible for:
detect · parse · normalise · **recursively investigate embedded
artefacts** · produce a CIO. From this point forward the constitution
refers exclusively to Adapters.

### 🔒 Four Adapter Categories

1. **Investigation Document Adapters** — Cisco XDR · Cisco Secure
   Endpoint · Defender XDR · CrowdStrike Falcon · SentinelOne ·
   QRadar Offense Export · Splunk ES Investigation · Elastic Security
   · MDR Reports · SOC case notes · Threat reports · Markdown · PDF
   · HTML.
2. **Log Adapters** — Windows Event Logs (.evtx) · Sysmon · RFC3164
   / RFC5424 Syslog · Linux · Unix · macOS Unified Logs · Auditd ·
   Osquery · DNS · DHCP · Apache · Nginx · IIS · Proxy · Firewall ·
   VPN · NetFlow · IPFIX · Zeek · Suricata · Snort · CEF · LEEF · CSV
   · JSON · NDJSON · XML · YAML · Plain Text.
3. **Cloud Adapters** — AWS CloudTrail · GuardDuty · Security Hub ·
   Azure Activity · M365 · Entra ID · GCP Audit · Okta · Duo ·
   Kubernetes · Docker · Container Runtime · S3 Access Logs.
4. **Artifact Adapters** — PowerShell · CMD · Bash · Python ·
   JavaScript · VBScript · Office macros · URLs · Domains · IPs ·
   Hashes · Registry exports · Memory artefacts · Volatility output ·
   Velociraptor collections · YARA results · Sigma rules · PCAP
   metadata · Encoded payloads · Archives · DLL metadata.

### 🔒 Universal Detection Engine (front door)

Every uploaded object first passes through a deterministic detection
engine that identifies vendor · format · content type · encoding ·
compression · nested artefacts — without analyst intervention. It
dispatches to the correct Adapter category.

### 🔒 Recursive Investigation Rules

- Every recovered artefact (URL / hash / script / command / archive /
  DLL / registry key / task / service / memory blob) becomes a new
  investigation target fed back into the Universal Detection Engine.
- Analysts NEVER need CyberChef.
- Adapters that stop after "extract" fail the Investigation Quality
  Gate.

### 🔒 Roadmap phasing (do not implement in one shot)

- **Phase 1** — Windows Event Logs · Sysmon · Syslog · JSON/NDJSON ·
  Cisco XDR · Defender · CrowdStrike · SentinelOne.
- **Phase 2** — Zeek · Suricata · Auditd · CEF · LEEF · QRadar ·
  Splunk · Elastic.
- **Phase 3** — AWS · Azure · GCP · Okta · Duo · Kubernetes · Docker.
- **Phase 4** — Velociraptor · Volatility · Memory · PCAP · Forensics.

### 🔒 Architecture Invariant

Every supported input — whether a Cisco XDR investigation, a Sysmon
event, a Linux syslog, a CloudTrail record, a PowerShell command, or
a memory artefact — produces the **same** CIO. Only the Adapter
changes. Everything downstream (IKG · Verdict · Executive Summary ·
Attack Story · ATT&CK · Reports · Trajectory · Workspace) remains
identical.
