# NivXForge EDR — 360° ARCHITECTURE PARITY DIRECTIVE (owner, 2026-06)

Benchmark: Cisco Secure Endpoint / AMP, **360° architecture parity, not UI
cloning**. Original NivXForge implementation only — no Cisco source, CSS,
JS, markup, fonts, images or proprietary assets. The IP boundary is never a
reason to reduce fidelity or capability.

## Required planes (today NivXForge is strong on the first, thin on the rest)
1. OBSERVATION — sensor → Endpoint Event Journal → raw evidence →
   normalization → canonical evidence. **EXISTS.**
2. DETECTION — deterministic rules exist. Missing: file engine, behaviour
   engine, network engine as a detection *fabric*.
3. PREVENTION — **MISSING.** Cisco chain to benchmark: exclusions → file
   scan/TETRA equivalent → application control → SHA/reputation → exploit
   prevention → malicious activity protection → system process protection →
   network/device flow correlation.
4. RESPONSE — dispatch + approval + independent verification. **PARTIAL.**

## Backend capabilities to build (owner-specified)
- **File intelligence / reputation**: SHA identity → local engine → intel →
  disposition (CLEAN / MALICIOUS / UNKNOWN) → execution relationship →
  trajectory. Control what is escalated for expensive analysis; do not ship
  every file event to a cloud query.
- **Real-time analytics + correlation** producing behavioural findings
  ("Cloud IOC" equivalent) that need no malicious file.
- **Retrospection engine** (Cisco: 7-day window): new intelligence
  re-evaluates already-recorded evidence, finds affected endpoints and
  re-scores surrounding activity. Maps directly onto the existing journal.
- **Intel abstraction layer** (do NOT try to build Talos): IOC router over
  local intel / vendor intel / customer intel → normalised intel →
  evidence graph. No single-provider dependency.
- **Device Trajectory is a BACKEND capability**: endpoint → process
  (parent/child/command/file/registry/DNS/network) + system events +
  detection + response. The UI is a projection over that. Cisco filter
  parity: Activity · System · Disposition · Flags · File Type.
- **Control plane**: tenant → users/roles → groups → endpoints → policies
  (prevention, detection, network, device control, exclusions, updates) →
  IOC lists → response policies → sensor packages → audit. Current
  tenant→group→policy→endpoint direction is confirmed correct.
- **Deployment shapes**: NivXForge Cloud · customer-private · air-gapped,
  all on the same evidence contract.

## ML / intelligence fabric (owner-specified, explicitly NOT "add ML")
Deterministic rules · signatures/IOC · reputation · statistical detection ·
classical ML (gradient boosting, random forest, logistic, isolation/anomaly,
clustering) · neural models (command representation, sequence detection,
behavioural representation, malware classification) · behavioural
correlation · retrospection · OPTIONAL LLM for explanation only.
Models to plan: file (static PE/entropy/imports/signer), process+command
(ancestry + command-line features), behaviour sequence, endpoint baseline /
anomaly, network (destination rarity, beaconing, peer deviation), and
cross-endpoint fleet ML.
Split: lightweight versioned models ON the sensor (offline inference) ·
heavy models in the backend (history, fleet, retrospection).

**Hard rule — ML is never truth.** A model emits a FINDING carrying score,
model id, model version, contributing features and `evidence_refs[]`. The
detection/correlation engine + policy turn findings into verdicts. The
analyst can always ask "why?" and get cited evidence. NivXForge must keep
working with no LLM at all.

## Native advantages to PRESERVE (never removed for Cisco similarity)
Canonical evidence · explicit provenance · Command Intelligence
(raw → decoded → canonical → interpretation → process → effects →
detection → ATT&CK → provenance) · Endpoint Event Journal · deterministic
evidence · tenant isolation · secure bounded enrolment · truthful state
semantics · approval authority · independent response verification.

## Console surfaces (permanent IA)
Dashboard · Computers · Detections · Events · Device Trajectory · File
Trajectory · Command Intelligence · Hunt · Live Query · Outbreak Control ·
Policies · Exclusions · Response · Downloads · Audit.

## Execution order still in force
Phase A real Windows proof → Phase B trajectory ≤2 s (**DONE**) →
Phase C Cisco 360° parity matrix (surface → structure → interactions →
workflow → capability → NivXForge existing/missing → backend dep →
frontend dep → status → acceptance proof) → Phase D surface-by-surface
implementation (research → map → reuse → close backend gap → build UI →
functional test → real SPA → visual + interaction QA → classify).
No placeholders for menu parity. A visually similar page with fake data is
a FAIL. Backend capability without the analyst workflow is PARTIAL.
