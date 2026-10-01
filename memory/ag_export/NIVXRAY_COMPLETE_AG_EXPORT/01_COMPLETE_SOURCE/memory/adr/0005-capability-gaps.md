# ADR-005 · Capability Coverage Gaps (informational — NOT authorised work)

Recorded 2026-08-10 during Phase 3 closure. **No implementation authorised.**
Owner directive: *"…should be recorded as a future capability gap, not implemented now."*

## Gap 1 · TEXT_EXTRACT_FROM_ARCHIVE

- **Role**: Analyzer (INV-6 classification).
- **Trigger**: Runs after `ARCHIVE_EXTRACT` when the primary_type or an extracted artefact is a `docx`, `pptx`, `xlsx`, `zip_archive`, `apk`, or similar container.
- **Behaviour**: Reads each extracted `archive_member` (e.g. `word/document.xml` for DOCX; slide XML for PPTX) and appends the decoded text as evidence nodes on the authoritative SSOT. Downstream MITRE_MAP / IOC_EXTRACTOR / COMMAND_DETECT capabilities benefit automatically because they scan the raw-text projection.
- **Rationale**: The real Sample.docx's MITRE-relevant content lives inside `word/document.xml`. Today's MITRE_MAP scans the raw ZIP bytes (largely binary noise) and produces 0 matches. Adding this Analyzer would surface the archive's meaningful text without changing any Phase 3 architecture.
- **What this is NOT**: not a projection, not a Phase 4 concern, not an SSOT-shape change. It's a **new Analyzer plug-in** slot on the existing capability registry.
- **When to implement**: When a future phase adds it explicitly. Phase 5 EntryAdapter work is a natural home, but the owner will decide when. Phase 4 must NOT implement it.

## Gap 2 · Additional Analyzers not implemented in Phase 3

Recorded for completeness — these are ADR-005-listed capabilities the registry currently has no plug-in for. Phase 3 executor's status=`skipped` covers them:

- `DECODER` — iterative deterministic decode chain (base64, hex, encoded blobs)
- `SEMANTIC_AST` — per-language semantic AST (PowerShell / CMD / Bash / JS / VBS / Python)
- `DKP_MATCH` — Decoder Knowledge Pack pattern matching
- `ATTACK_CHAIN` (as an Analyzer that seeds graph relationships, not the Phase-4 projection)
- `LOLBAS_MATCH`
- `VENDOR_NORMALISER` (Cisco / CrowdStrike / Defender / QRadar / SentinelOne / Splunk / vendor-JSON)
- `PROCESS_TREE`
- `QUALITY_SCORE`
- `IDA_ACQUIRE` (URL fetcher — must be Enricher role, INV-2 isolated)

Each of these already has a corresponding *existing analyzer module* in the codebase (`services/die/*`, `services/ida/*`, `v2/mdr/*`, etc.). Adding them = writing a thin `(ssot, raw, ctx) -> None` adapter following the Phase 3 pattern. **None authorised at this time.**

## Non-goal for Phase 4

Adding any of the above IS NOT a Phase 4 task. Phase 4 is strictly projections over the authoritative SSOT as it exists today.
