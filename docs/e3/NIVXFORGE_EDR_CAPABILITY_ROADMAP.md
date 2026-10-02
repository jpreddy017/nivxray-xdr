# NivXForge EDR Capability Roadmap (E3)

This roadmap records owner-classified future capabilities only. Nothing here is built or authorized until the owner approves it.

## Device Trajectory backlog

### DT-B1 · Linked XDR Incidents (NEW FEATURE — not built)
- **Classification:** the owner decided (DT-I1D acceptance) that this is a new feature, not a regression. The current Device Trajectory code has no "Linked XDR Incidents" surface.
- **Depends on:** a future incident/XDR linkage contract. That contract must define:
  - incident identity
  - the link basis (evidence refs, rule/behavior attribution, or analyst action)
  - link state (proven, supported, correlated or unknown)
  - provenance
  - tenant isolation
- **Rules:**
  - A link is never inferred from time proximity or shared PID.
  - When no link exists, the UI says so truthfully; it never implies the event is "not in an incident".
- **Status:** BACKLOG. Do not build this until the linkage contract is approved.
