# NivXRay Workspace Architecture Rules (v1.0 · FROZEN)

> Superseded by `/app/memory/NIVXRAY_ARCHITECTURE_V1.md`.
> These are the non-negotiable rules extracted for quick reference.

## The 7 Non-Negotiable Rules

### R1 — Workspace never analyzes
The Workspace only collects evidence (paste · upload · URL · drag & drop).
No OCR button, no PDF mode, no image mode, no EVTX mode, no PCAP mode.
The Workspace shouldn't know those exist.

### R2 — Single entry point
All inputs must enter through the Universal Input Router (`POST /api/investigate`).
No bypasses. No legacy paths. No direct-to-decoder routes.

### R3 — IEP is the universal contract
Every input must become a valid Investigation Evidence Package (IEP).
No downstream engine may consume native file formats (PDF, image, EVTX, PCAP,
DOCX, EML, ZIP, memory dump, malware sample) directly.

### R4 — Orchestrator owns recursion
The Investigation Orchestrator is the ONLY component allowed to recursively
schedule investigations. IDA, DIE, ICE, IOC Intelligence, and the Evidence
Reasoning Engine never call each other directly.

### R5 — Engines are format-agnostic
IDA, DIE, ICE, IOC Intelligence, and the Evidence Reasoning Engine must
remain input-format agnostic. They read IEP.artifacts only.

### R6 — Provenance is mandatory
Every finding must retain provenance back to the originating IEP object.
Every conclusion must be explainable — chain of evidence traceable through
adapter → IEP → validator → engine → SSOT projection.

### R7 — SSOT is the single narrative source
The Evidence Reasoning Engine is the single source of truth for ALL
summaries, reports, and conclusions. There must never be independent
generators for Executive / Analyst / Technical / NIST / PDF outputs —
they are projections of the same SSOT.

### R8 — Adapters extract, they never reason
Adapters may extract evidence and obvious structural relationships
(`curl.exe` → `downloads` → `update_ms.msi`, `Email` → `contains` →
`Attachment`, `ZIP` → `contains` → `EXE`) but must NEVER infer attacker
intent, malware behavior, or analytical conclusions. All reasoning
belongs exclusively to the Evidence Reasoning Engine.

Concrete separation:
- Evidence Adapter → "I found `curl.exe` downloading `update_ms.msi`."
- Investigation Orchestrator → "Investigate both artifacts recursively."
- ICE → "Correlate the results."
- Evidence Reasoning Engine → "This likely represents ingress tool transfer and payload delivery."

## Additionally Retained From Earlier Iterations

- **R22 · Extracted Evidence Becomes Investigation Input** — any executable /
  analyzable artifact IDA extracts is promoted to a new Investigation Input
  and recursively investigated. (Now formally a consequence of R4 recursion.)
