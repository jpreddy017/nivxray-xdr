# NivXRay XDR + NivXForge EDR: Unified Platform Engineering Blueprint
Status: DESIGN BASELINE ONLY — not production certified
Branch: feature/unified-xdr-edr-platform-blueprint
Date: 2026-10-11

## Non-negotiable invariants
- Preserve existing production, desktop, canary, Gate 4 HOLD, and unrelated development branches. No deploys or destructive migrations.
- All security findings and AI assertions must link to canonical immutable evidence IDs and provenance. No invented facts.
- Derive tenant, principal, role, and approval authorization server-side. Deny cross-tenant reads and writes by default.
- Response lifecycle: REQUESTED -> APPROVED -> DISPATCHED -> EXECUTED -> VERIFIED (with independent FAILED and EXPIRED terminal outcomes). Never conflate acceptance with containment.
- All privileged response actions require policy checks, signed service-to-service authorization, idempotency, replay protection, tamper-evident audit, and human approval according to policy.
- Treat all telemetry, files, URLs, retrieved content, and AI tool results as untrusted. Agent tool execution must be allowlisted and policy-mediated.
- No assertion of parity with proprietary detection IP; independently implement functional analogues and use official APIs where licensed.

## Product surfaces
1. Incidents: queue, correlated alerts, evidence, timeline, severity, analyst ownership, case management.
2. Devices: inventory, sensor status, exposure, software, device trajectory, process lineage, network and user activity.
3. Files: hash identity, signer, prevalence, first/last seen, file trajectory, quarantine status and verification.
4. Investigations: interactive graph of device, user, process, file, DNS, IP, domain, alert, and incident relationships.
5. Threat hunting: typed query builder, raw query, saved hunts, replayable results.
6. Detections: rules-as-code, versioning, dry-run, FP/FN validation, staged rollout and rollback.
7. Response: host isolation/release, process termination, file quarantine, collection, approval and verification.
8. Intelligence: IOC enrichment, confidence, source provenance, expiration, contextual risk.
9. AI SOC: evidence-grounded summaries, competing hypotheses, next-best investigation, analyst copilot, governed multi-agent workflows.
10. Administration: SSO/OIDC, RBAC/ABAC, tenants, secrets, retention, audit, billing/metering, sensor policy.

## Reference architecture
- UI: React + TypeScript, table-first light default, process-tree and relationship graph (D3).
- Control plane: FastAPI API gateway, authentication, tenant resolution, policy, case management, approval and response services.
- Ingestion: versioned canonical event envelope, authenticated collectors, buffering and backpressure, per-source adapters.
- Streaming: Redis Streams for initial small deployments; Kafka-compatible bus when scale demands it.
- Storage: PostgreSQL for transactional control-plane records; object storage for immutable evidence; ClickHouse/OpenSearch for high-volume event search; Redis for ephemeral state. Existing MongoDB integrations retained via migration adapters, not replaced blindly.
- Endpoint sensor: Windows ETW/Sysmon where available; Linux eBPF/audit; macOS Endpoint Security Framework subject to platform entitlements. Signed installers, secure enrollment, bounded offline queue, updates, and health telemetry.
- Correlation: deterministic entity resolution, temporal joins, attack-chain detection, MITRE mapping, risk scoring with source-specific confidence.
- AI: local/private model option, model gateway, RAG over tenant-scoped evidence, planner/investigator/reviewer roles, no direct privileged execution.
- Observability: metrics, traces, logs, audit, SLOs, queue lag, sensor coverage and data loss accounting.

## Canonical event minimum
event_id, schema_version, tenant_id, source, source_event_id, observed_at, ingested_at, host_id, principal_id, event_type, process_guid, parent_process_guid, file_sha256, command_line, network_5tuple, action, outcome, raw_evidence_ref, provenance, integrity_hash.
Optional fields are explicitly nullable; never invent unavailable data.

## Device / file trajectory requirements
- Time-sorted timeline with activity bands and filterable event types.
- Process tree with PID reuse handling via process GUID, host boot identity, and start time.
- Graph edge types: spawned, wrote, loaded, connected, resolved, authenticated, detected, quarantined.
- Every node and edge opens original evidence; missing links are shown as unknown, not fabricated.
- Separate detected, attempted, blocked, quarantined, removed, and verified outcomes.

## Agentic security requirements
- Agents: triage, evidence correlation, threat intelligence, hunting, detection engineering, reviewer.
- Planner may suggest steps; only an independent policy engine may authorize tools.
- Hard limits on time, tokens, data volume, network egress and action scope.
- Evidence citations on each claim; confidence and alternative explanations; prompt-injection defenses.
- Approval and audit for all impactful actions; agent-generated code/rules must pass testing.

## Implementation gates
G0 Inventory repository and reconcile existing architecture, branches, security findings, HOLDs.
G1 Contracts, authentication, tenant isolation, canonical evidence and ingestion tests.
G2 Device inventory, process tree, file trajectory, timeline and graph APIs/UI.
G3 Detection, correlation, hunt, intelligence and explainable verdicts.
G4 Response gateway, approvals, idempotency, replay prevention, verification.
G5 AI multi-agent investigation and model governance.
G6 Windows/Linux sensor hardening, macOS feasibility and installers.
G7 Adversarial, regression, load, reliability, backup/restore, observability, independent security review.
G8 Staged canary, rollback and explicit production release approval.

## Release evidence required
- Cross-tenant isolation tests, authorization matrix, signed sensor artifacts and verified update chain.
- Data-loss and backpressure measurements; benchmarked search latency and graph performance.
- Detection FP/FN measured on labeled benign and malicious corpora, including regression.
- Full response execution and verification trace, including failure, replay and race tests.
- SAST, SCA, secret scanning, dependency SBOM, DAST, penetration test, DR rehearsal.
- Operational runbooks, SLO dashboards, incident response, rollback, privacy and retention controls.

## Competitor functional benchmarking
CrowdStrike Falcon: device telemetry, EDR investigation, prevention, real-time response.
Microsoft Defender for Endpoint: device timeline, advanced hunting, incident graph, automated investigation.
Sophos Intercept X: anti-exploit, ransomware protection, adaptive defense and response.
Cisco Secure Endpoint (AMP): file trajectory, device trajectory, retrospective detection, quarantine.
Xyner-style agents: task orchestration, memory, governed API tools, review and audit.
Implement only independently designed capabilities; licensed third-party integrations use supported APIs.

## Immediate engineering next steps
1. Read actual source and identify reusable components; do not assume this document matches implementation.
2. Add API contracts and acceptance tests for device and file trajectories.
3. Build a read-only integrated UI using canonical evidence.
4. Run automated tests before requesting merge; do not deploy from this branch.
