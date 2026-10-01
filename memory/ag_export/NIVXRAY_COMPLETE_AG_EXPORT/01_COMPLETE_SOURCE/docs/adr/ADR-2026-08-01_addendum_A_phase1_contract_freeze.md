# ADR-2026-08-01 · Addendum A · Phase 1 Contract-Freeze Gate

_Locked by operator. Phase 1 implementation is BLOCKED until every
contract below is signed off._

## New pipeline stage: Evidence Validation

Insert between Investigation Graph and Correlation:

```
Parser → Normalizer → CEM → Investigation Graph
      → Evidence Validation
      → Correlation → TI → Root Cause → Hypothesis
      → Confidence → Recommendations → Narrative
```

Evidence Validation resolves conflicting timestamps, duplicate hashes,
conflicting usernames/hosts, inconsistent process trees, malformed
vendor data BEFORE any downstream reasoning runs.

## Ten contracts to freeze before Phase 1 code (in order)

### 1 · Canonical Event Model v1 (VERSIONED, IMMUTABLE)
- Pydantic schema `CEMv1`.
- Every future vendor field addition requires `CEMv2` + migration path.
- Never break older investigations.

### 2 · Investigation Graph schema
- Directed multigraph.
- Node = {id, kind, value, attrs, provenance}.
- Edge = {id, from, to, relation, evidence_ids, confidence}.
- Read-only after construction; every mutation goes through a
  versioned change-set.

### 3 · Standard node taxonomy (FROZEN)
Host · User · Process · Command · Decoded Payload · Registry · Service
· Scheduled Task · File · Hash · URL · IP · DNS · Certificate ·
Network · Alert · Detection · ATT&CK · Threat Family · Recommendation
· Finding · Hypothesis · Timeline Event.

New kinds require ADR amendment.

### 4 · Evidence provenance model
Every node MUST carry:
- `source` (which pipeline stage created it)
- `vendor` (originating vendor, if any)
- `timestamp` (when observed / derived)
- `confidence` (0..1)
- `evidence_refs` (list of upstream node ids)
- `input_offset` (byte-range in the original raw payload when applicable)

### 5 · Investigation object contract
```
Investigation
  ├── raw_input           (bytes / str)
  ├── cem                 (CEMv1)
  ├── graph               (InvestigationGraph)
  ├── timeline            (Timeline)
  ├── findings            (List[Finding])
  ├── hypotheses          (List[Hypothesis])
  ├── recommendations     (List[Recommendation])
  ├── confidence          (ConfidenceReport)
  ├── report              (RenderedNarrative)
```
Not scattered files. One aggregate root, shared by every stage.

### 6 · Knowledge-provider INTERFACES (not implementations)
```
KnowledgeProvider  (abstract)
  ├── LolbinProvider
  ├── AttckProvider
  ├── ThreatFamilyProvider
  ├── PlaybookProvider
  ├── MechanismProvider
  └── OsintProvider
```
Swappable, mockable, versioned. Implementations arrive in later phases.

### 7 · Threat Intelligence interface
```
TIProvider
  ├── ioc_reputation(ioc) → Reputation
  ├── historical_sightings(ioc) → List[Sighting]
  ├── families_for(ioc) → List[FamilyMatch]
  ├── campaigns_for(family) → List[Campaign]
  └── confidence(query) → float
```
Interface exists in P1; implementations arrive in P3.

### 8 · Root Cause engine contract
Given the current Investigation, return a ranked list of root-cause
candidates from a fixed taxonomy: Phishing · Software Deployment ·
Lateral Movement · Credential Theft · Malvertising · Remote
Administration · Supply Chain · Web Exploitation · Insider ·
Misconfiguration · Unknown.

Each candidate carries evidence_for, evidence_against, confidence.

### 9 · Visibility engine contract
For every question the investigation should answer, return one of:
Observed · Not Observed · Cannot Verify · Visibility Gap — plus the
reason. This surface must appear in every report.

### 10 · Recommendation engine contract
Deterministic mapping:
```
(ThreatFamily, Stage, Visibility, ContainmentState, AssetType)
  → Playbook
  → List[Recommendation]
```
Never hardcoded. Rule-driven.

## Phase 1 sequence (only after every contract above is signed off)

1. Implement `CEMv1`.
2. Implement Cisco Secure Endpoint normalizer → `CEMv1`.
3. Implement Sysmon normalizer → `CEMv1`.
4. Implement Investigation Graph (build from CEMv1).
5. Implement Evidence Validation stage.
6. Ship an end-to-end demo: raw payload → CEM → Graph → Validation →
   printable investigation state.

Nothing else in Phase 1. Not the correlation engine, not the narrative,
not knowledge bases, not TI. Those are Phase 2/3.

## Blocking asks (still)

- Four gold-standard analyst investigations pasted into
  `/app/memory/P0_MISSION.md`.
- Sign-off on each of the 10 contracts above (individual approval per
  contract is acceptable; blanket approval is preferred).
