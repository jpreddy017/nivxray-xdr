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
```

The universal `AdapterRegistry` picks the adapter with the highest
`detect()` score. The adapter's `normalise()` output is then fed to
the existing `from_analysis_result` → `build_cio` chain.

Consequence: adding a new vendor requires exactly one new adapter,
zero changes to the CIO, evidence graph, verdict engine, summary
composer, or any lens.

## Anti-goals (permanent)

- ❌ No vendor-specific verdict logic outside the shared engine.
- ❌ No vendor-specific summary text outside the shared composer.
- ❌ No vendor-specific UI panels in X-Lab.
- ❌ No feature flag for "auto-investigate mode vs decode mode" —
     the router chooses the adapter transparently based on `detect()`
     scores.

## Success criteria (when IDI is "done")

- Every vendor input listed in `INPUT_TYPES` (see
  `nivxforge/investigation/input_understanding.py`) has a matching
  adapter.
- Adapter selection is deterministic on identical inputs.
- The Verdict Parity CI (P1-02) remains green after every adapter
  ships.
- The Investigation Quality Gate (P1-07 · scaffolded at
  `/app/backend/tests/quality/test_investigation_quality.py`) passes
  on the full vendor corpus.
