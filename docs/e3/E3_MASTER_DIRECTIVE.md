NIVXFORGE EDR — E3 MASTER ENGINEERING DIRECTIVE. COMMERCIAL-GRADE EDR + DETERMINISTIC EVIDENCE INTELLIGENCE. STATUS: AUTHORITATIVE FOR E3. Baseline: feature/e3-edr-engines @ cd5b4e1bd5d3e376073d37ec90c09108f79b9895 (owner-verified on GitHub).

0. MISSION
Build NivXForge EDR into a genuinely operational, technically defensible, commercially credible EDR.
The target is NOT:
- a dashboard that only resembles an EDR
- an AI chatbot attached to telemetry
- disconnected detections
- a Cisco/Falcon/Sophos UI clone
- frontend cards claiming capabilities the backend can't prove
- correlation treated as causality
- "no alert" treated as "clean"
- verdicts that can't be reproduced from evidence
The target is BOTH (A) mature commercial EDR capability depth AND (B) NivXForge deterministic, evidence-driven investigation intelligence.
Use publicly documented capabilities of Cisco Secure Endpoint/AMP, CrowdStrike Falcon, Sophos Intercept X, Microsoft Defender for Endpoint, SentinelOne, Elastic Security and other credible public/open research as engineering references. Study: capability, analyst workflow, sensor requirements, detection, investigation, response semantics, operational expectations, scale, and public architecture.
Do NOT copy: proprietary code, private APIs, detection content, ML models, trade secrets, undocumented internals, copyrighted UI assets, or vendor implementation details that aren't public. Understand the problem and engineer the NivXForge implementation independently.

1. PRODUCT EQUATION
NIVXFORGE EDR = commercial-grade EDR foundation + deep telemetry + immutable raw evidence + universal decoding + canonical evidence + provenance + identity resolution + temporal/causal evidence graph + deterministic detection + behavioral/sequence intelligence + threat intelligence + ML/anomaly signals + retrospection + hypothesis evaluation + negative explainability + investigation intelligence + Second Human Brain + continuous evidence reassessment + human-verifiable reasoning + authorized response + execution & verification + operational/fleet engineering.
Commercial capability is the FLOOR. NivXForge investigation intelligence is the DIFFERENTIATOR. We require BOTH.

2. NON-NEGOTIABLE INVARIANTS
2.1 DETERMINISTIC-FIRST. Use deterministic mechanisms before probabilistic reasoning for: decoding, canonicalization, normalization, process/entity identity, parent/child, hashes, signer facts, timestamps, event relationships, rules, sequence rules, evidence refs and response state. Probabilistic systems may augment, never silently replace.
2.2 EVIDENCE-DRIVEN. Every material claim must be traceable to concrete evidence: detection, verdict, severity, ATT&CK, behavioral finding, sequence match, ML signal, TI, reputation, causal claim, summary, hypothesis, recommendation, retrospective change, response justification, verification. Use immutable evidence refs/provenance. Nothing unsupported may masquerade as fact.
2.3 SECOND HUMAN BRAIN is an ENGINEERING REQUIREMENT, NOT logs→LLM→answer. The platform reconstructs, remembers, compares, challenges, explains and guides an investigation using verifiable evidence. It should eventually answer:
- what happened, what came before, what came after
- who/what initiated it; what it created, modified, contacted; what executed next
- what caused what, and what is only correlated
- why it matters; what detection fired and why; what behavioral sequence was seen
- what TI says; what ML says, and what ML doesn't know
- what supports the malicious hypothesis, what contradicts it, what expected evidence is absent, what telemetry is missing, what cannot be concluded
- has it occurred elsewhere; what changed the assessment; what to investigate next; what response is justified
- was the response approved, accepted, executed; did it succeed; was containment verified
Every factual answer must be evidence-backed.
2.4 CONTINUOUS REASSESSMENT LOOP: acquire → persist raw → decode → normalize → canonicalize → identify entities → build relationships → establish supported causality → deterministic detection → behavioral → TI → ML → assess → contradictions → missing evidence → hypotheses → guide → new evidence → course-correct → reassess → analyst decision → authorized response → execution → verification → new evidence → reassess. This is NOT one synchronous transaction. Implement it as durable, bounded, independently testable services.
2.5 CAUSALITY OVER COINCIDENCE. Never claim "A caused B" because A preceded B. Relationship states: PROVEN_CAUSAL / SUPPORTED_RELATIONSHIP / CORRELATED / UNKNOWN. Edge types include process→child, process→file write, file→process exec, process→network, process→DNS, process→registry, user/session→process, service→process, task→process. Every causal edge identifies its evidence. Missing linkage = UNKNOWN, never an invented edge.
2.6 NEGATIVE EXPLAINABILITY. Answer both "why did we alert?" and "why did we NOT conclude malicious?". Each hypothesis preserves SUPPORTING, CONTRADICTING, MISSING EXPECTED, UNAVAILABLE TELEMETRY, FAILED CONDITIONS and UNKNOWN CONDITIONS. Example: "credential dumping": LSASS access ✓; dump-file telemetry ?; expected sequence ✗; memory telemetry ?; signed binary + admin workflow are contradicting context → INSUFFICIENT_EVIDENCE, not BENIGN/CLEAN/FP unless evidence independently supports that.
2.7 CANONICAL EVIDENCE + PROVENANCE lineage: RAW → DECODED → NORMALIZED/CANONICAL → ENTITY/RELATIONSHIP → DERIVED → DETECTION/BEHAVIOR/TI/ML → ASSESSMENT → HYPOTHESIS → CONCLUSION → RESPONSE JUSTIFICATION. Each stage answers: origin, transformation, version, supporting evidence, when, superseded? Do NOT silently resolve the canonical authority question. E3 stays store-independent.
2.8 UNKNOWN IS FIRST-CLASS. UNKNOWN / INSUFFICIENT_EVIDENCE / UNAVAILABLE / NOT_ASSESSED never silently become CLEAN/BENIGN/FALSE_POSITIVE. No detection ≠ clean; no TI hit ≠ clean; low ML ≠ clean; signed ≠ clean; no ATT&CK ≠ benign.
2.9 AI/ML IS AUGMENTATION. NEVER Telemetry→AI→Verdict. Evidence graph → (rules, behavior, TI, ML, retrospective state, analyst evidence) → ASSESSMENT → AI reasoning/explanation → human-verifiable output.
- AI MAY: summarize, organize, explain relationships, identify gaps, generate hypotheses, suggest pivots, help build hunts, prioritize, explain detections, compare hypotheses.
- AI MUST NOT: manufacture evidence, fabricate relationships or TI, infer missing events as facts, convert UNKNOWN→CLEAN, bypass response authorization, or be the sole malicious-verdict authority.
2.10 RETROSPECTION. Triggers: RULE_CHANGE, INTEL_CHANGE, MODEL_CHANGE, REPUTATION_CHANGE, ANALYST_CHANGE; extensible without redesign. Retrospection is tenant-scoped, bounded, indexed, idempotent, deterministic where applicable, version-aware, observable and auditable. NO unbounded historical scan; affected evidence is found via bounded indexed lookup.
2.11 HISTORY IS NEVER REWRITTEN. V4 never overwrites V1. Example: 09:00 UNKNOWN → 09:02 SUSPICIOUS → 09:07 SUSPICIOUS + behavior → 11:41 MALICIOUS (reputation) → 11:43 ISOLATION ACCEPTED → EXECUTED → 11:44 CONTAINMENT VERIFIED. Preserve: version, timestamp, trigger, rule/model/TI versions, evidence refs, actor, analyst input, superseding assessment.
2.12 HUMAN-VERIFIABLE. Support: why? show me the evidence; what supports or contradicts this; uncertainty; what's missing; what changed; which version; what next.
2.13 AUTHORITY: deterministic where possible, probabilistic where valuable, AI where useful, HUMAN where required (especially consequential response).

3. TARGET ARCHITECTURE
Sensor → authenticated ingest → immutable raw evidence store → durable processing obligation → async processing → universal decoder (+provenance) → canonical evidence (store-independent contract) → identity/entity resolution (process/file/user/host/network) → temporal + causal evidence graph → {deterministic detection, behavioral/sequence engine → ML/anomaly signal engine, TI broker} → ASSESSMENT ENGINE → supporting / contradicting evidence → HYPOTHESIS ENGINE (proven/rejected/unknown/insufficient) → INVESTIGATION INTELLIGENCE ("Second Human Brain": what happened / what's missing / what next) → analyst decision → response policy + approval → response execution → verification → new evidence → retrospective replay → assessment engine.

4. SENSOR/TELEMETRY TARGET (keep a capability matrix per source; never claim support merely because a schema field exists). Status values: SUPPORTED_AND_PROVEN / SUPPORTED_PARTIAL / COLLECTED_NOT_WIRED / NOT_COLLECTED / PLANNED.
- PROCESS: create/terminate, PID, stable instance identity, image, command line, parent PID/identity, user/session, integrity/elevation, hash, signer, cert, image metadata.
- FILE: create/write/rename/delete/execute, hash, path, responsible process, signer, first/last seen, prevalence.
- NETWORK: process-associated connections, src/dst, protocol, port, direction, lifecycle, DNS association where provable.
- DNS: query, response, domain, resolved IP, requesting process.
- REGISTRY: create/modify/delete, key/value, responsible process, persistence relevance.
- IDENTITY: user, session, logon, endpoint, service accounts, privilege.
- PERSISTENCE: services, scheduled tasks, startup, registry, others.
- MODULE/SCRIPT: image/DLL loads, PowerShell/script, interpreters, encoded content.
- SECURITY: sensor status, policy, protection state, tamper, exclusions, version, telemetry health.

5. PROCESS IDENTITY. PID alone is insufficient because PIDs are reused. A process instance = tenant + endpoint + boot/session + PID + start time + other stable discriminators. The current E3 M1 identity is process_iid. Unresolved links stay UNKNOWN; never connect events because PIDs match. Every edge carries: type, source, target, evidence_refs, time, relationship state, provenance.

6. DETECTION is multi-engine: rules, behavior sequences and TI reputation, plus ML and anomaly signals, all feeding ASSESSMENT. Don't force them into one binary verdict. Each engine publishes an inspectable EngineResult {engine, engine_version, tenant_id, endpoint_id, subject, status, score?, confidence?, evidence_refs[], explanation, unknowns[], generated_at, provenance}.

7. BEHAVIORAL ENGINE (exists; foundational). Preserve MATCH / NO_MATCH / INSUFFICIENT_EVIDENCE. Missing evidence never yields NO_MATCH. Continue toward: multi-stage sequences, temporal constraints, entity binding, lineage, file/network/registry stages, bounded windows, reusable primitives, attack-chain patterns, explainable matches, versioning, retro compatibility. No eval; rules stay data.

8. ML (exists). The starter models stay TESTING until validated on real telemetry; never promote them because synthetic tests pass. Feature families: parent/child and process-tree rarity, command entropy, encoding, first-seen binary/domain/IP, outbound patterns, registry persistence, child bursts, off-hours, prevalence, execution novelty, endpoint- and tenant-relative baselines. A missing value = UNKNOWN. MLSignal keeps id, version, lifecycle, feature version, score, explanation, evidence_refs, baseline state, timestamp, provenance. Cold start = INSUFFICIENT_BASELINE. ML alone never creates a malicious verdict.

9. TI BROKER. No new isolated provider client; inventory and consolidate existing ones. IOC → TI broker → providers + internal TI → normalized result → reputation history → INTEL_CHANGE event → retrospection.
- Normalize: hash, IP, domain, URL, certificate, signer, others.
- States: MALICIOUS / SUSPICIOUS / BENIGN / UNKNOWN / NO_DATA / UNAVAILABLE / RATE_LIMITED / ERROR. NO_DATA ≠ BENIGN. Preserve provider provenance.
- Behaviour: cache, TTL, quota, rate limiting, routing, retry, failure and stale semantics, re-enrichment, reputation transitions. Changed intelligence triggers bounded retrospection.

10. RETROSPECTIVE REPLAY ENGINE (core differentiator). Pipeline: CHANGE EVENT → trigger normalization → affected-evidence selector → bounded tenant-scoped lookup → re-evaluation → new assessment (old preserved; new evidence refs, trigger, engine versions and provenance recorded) → course correction. Requirements: tenant isolation, idempotency, deterministic job IDs, bounded lookup, no full scans, checkpointing, retry, metrics, auditability, version compatibility.

11. ASSESSMENT ENGINE. Don't reduce everything to a score. Synthesize deterministic findings, behavioral findings, TI, ML, causal context, negative and missing evidence, history and analyst evidence, while preserving each source. Assessment {assessment_id, version, tenant_id, subject, disposition, confidence, supporting_evidence[], contradicting_evidence[], unknowns[], missing_evidence[], detections[], behavior_results[], ti_results[], ml_signals[], attack_mappings[], previous_assessment, supersedes, trigger, generated_at, provenance}. Never hide engine disagreement; e.g. Deterministic: NO DETECTION / Behavior: SUSPICIOUS / TI: UNKNOWN / ML: ELEVATED (TESTING) / Signer: VALID / Causal: PARTIAL stays visible.

12. HYPOTHESIS ENGINE. Explicit hypotheses (e.g. H1 credential dumping, H2 legitimate admin tooling, H3 persistence). Each carries supporting, contradicting and missing expected evidence, unavailable telemetry, causal requirements and confidence (only if calibrated). States: SUPPORTED / REJECTED / UNKNOWN / INSUFFICIENT_EVIDENCE.

13. DEVICE TRAJECTORY = the investigation convergence surface, not a decorative timeline. It eventually combines: timeline, process tree, causal relationships, file/network/DNS/registry, user/session, services/persistence, detections, behavior, ML, TI, MITRE, retro history, analyst disposition, response state, provenance.
Layout:
- endpoint header: hostname, OS, sensor, user, isolation, health, last seen
- an investigation summary row (machine assessment, analyst disposition)
- search/filters/time/event types/detections
- trajectory pane (process tree with file/DNS/network/registry)
- Activity Details pane: what happened, why it matters, detection attribution, behavior, ML, TI, causal context, MITRE, supporting/contradicting/missing evidence, retro history, response state, provenance, suggested pivots
FIX: NO attributed tactic/technique = NEUTRAL styling, not red. Red requires supported threat attribution.

14. MACHINE ASSESSMENT ≠ ANALYST DISPOSITION.
- Machine: MALICIOUS / SUSPICIOUS / BENIGN / UNKNOWN / NOT_ASSESSED / INSUFFICIENT_EVIDENCE.
- Analyst: TRUE_POSITIVE / FALSE_POSITIVE / EXPECTED_ACTIVITY / AUTHORIZED_TEST / NEEDS_INVESTIGATION / other controlled values.
An analyst disposition is auditable human input. It may influence future retrospection per policy, and it never erases machine assessments.

15. ACTIVITY DETAIL CONTRACT per selected event/entity:
1. Observation
2. Causal context (producer, what followed, which links are proven)
3. Detection attribution (if none: "No detection engine claimed this observation." — never "clean")
4. Behavioral intelligence
5. TI
6. ML/anomaly (signals, baseline, TESTING/ACTIVE)
7. Supporting evidence
8. Contradicting evidence
9. Missing evidence
10. MITRE (evidence-backed only)
11. Retrospection (changed? why?)
12. Response requested
13. Verification
14. Provenance
15. Evidence-driven next pivots

16. RESPONSE invariant: ACCEPTED ≠ EXECUTED ≠ CONTAINED ≠ VERIFIED. Lifecycle: REQUESTED → AUTHORIZED → ACCEPTED → DISPATCHED → EXECUTED → OBSERVED EFFECT → VERIFIED. Failures stay visible. Never show "contained" because a request was accepted. Future actions (isolate, release, terminate, quarantine, block indicator, collect artifact, forensic package, live query, live response) all require authorization boundaries.

17. HUNTING. Hunt query → canonical evidence layer → endpoint/process/IOC/file/network/DNS → results → investigation pivot or saved hunt → future detection. Never depend on vendor raw schemas where canonical evidence can abstract them.

18. FORENSICS (later; design for compatibility now): file collection, process and persistence artifacts, investigation packages, memory acquisition where safe, chain of custody, hash verification, artifact provenance, authorized acquisition.

19. SENSOR HARDENING (long-term): secure enrollment, sensor identity, credential lifecycle, policy, tamper resistance, signed updates, versions, health, offline behaviour, queue durability, resource limits, backpressure, telemetry-gap reporting, recovery. Don't weaken security to accelerate features.

20. OFFLINE/LOCAL INTELLIGENCE where feasible: decoding, normalization, rules, behavior sequences, local reputation cache, local ML inference, policy, basic containment subject to authorization. Online enhances: fresh TI, fleet prevalence, global reputation, enrichment, larger AI reasoning, central correlation. Offline ≠ unintelligent; online ≠ authority over evidence.

21. OPERATIONAL ENGINEERING. Every production candidate must consider: tenant isolation, durability, idempotency, backpressure, bounded memory and CPU, timeouts, retry, dead-letter, caching, rate limits, storage growth, retention, latency, concurrency, observability, metrics, structured logs, versioning, upgrade compatibility, rollback.
Track latencies: ingest, processing, detection, replay, TI, ML inference, response, verification.
Track queue and failure health: queue depth and age, dropped evidence, decode/normalization/identity failures, TI errors and rate limits, replay failures.

22. PERFORMANCE.
Prefer: incremental graph construction, indexed lookup, bounded windows, lazy and cached enrichment, async processing, pagination, virtualized UI, safe precomputed summaries, background retrospection.
Avoid: unbounded scans, N+1 TI calls, recomputing history on page load, blocking ingest on enrichment or ACK on detection, loading the whole trajectory into the browser.

23. MULTI-TENANCY. Every capability proves isolation. Never accept tenant_id blindly when authoritative backend context exists. Queries, caches (where data is sensitive) and replay jobs are tenant-scoped. TI separates globally shareable intelligence from tenant-private evidence. No default-tenant fallback.

24. BASELINE: feature/e3-edr-engines @ cd5b4e1b… (behavioral engine + ML foundation + TESTING models). Do NOT branch from bcb8d766.

25. ML SAFETY: ml.rarity.process_tree and ml.weighted.exec_behavior stay TESTING. Promotion requires real telemetry, calibration, FP analysis, FN analysis where measurable, distribution analysis, baseline validation, performance validation and documented acceptance.

26. DT-I1 EXECUTION ORDER (incremental):
- DT-I1A INVENTORY/CONTRACT: inventory the existing DT, APIs, telemetry, assessment fields, behavioral engine, ML, TI clients, canonical sources, process identity, response state, MITRE and provenance. Classify EXISTS_AND_PROVEN / EXISTS_PARTIAL / EXISTS_NOT_WIRED / MISSING / DUPLICATED / DEFERRED. No behaviour change yet.
- DT-I1B INVESTIGATION VIEW MODEL: store-independent contracts for event, entity, assessment, causal relationship, detection attribution, behavior result, ML signal, TI result, MITRE, provenance, response, retro history, analyst disposition and missing evidence. Synthetic fixtures + contract tests.
- DT-I1C ACTIVITY DETAILS: namespaced components with minimal, documented edits to existing UI. Truthful rendering of machine assessment, analyst disposition, detection, behavior, ML, TI, causal, MITRE, evidence, negative evidence, unknowns and provenance.
- DT-I1D CAUSAL CONTEXT: process identity/relationship representation; no inferred links presented as fact.
- DT-I1E TI CONTRACT: normalize current providers behind one view contract; don't rewrite every provider.
- DT-I1F SECOND-BRAIN MODEL: deterministic synthesis of what happened, what preceded, what followed, supporting, contradictions, unknowns, missing evidence and next pivots. NO LLM required for correctness; AI sits above later.
- DT-I1G RETROSPECTIVE REPLAY: RULE/INTEL/MODEL/REPUTATION/ANALYST_CHANGE, bounded replay, append-only assessments, never rewrite.
- DT-I1H RESPONSE STATE: requested/authorized/accepted/executed/verified/failed, truthfully, using the existing hardened authority. No new response authority.
- DT-I1I PERFORMANCE/OPS: pagination, bounded queries, cache semantics, metrics, failure handling, perf tests, large synthetic trajectories.
- DT-I1J ACCEPTANCE/HANDOFF: test evidence, changed-file inventory, architecture docs, limitations, gaps, deferred items, real-telemetry validation plan, Git handoff artifact. No deployment without owner approval.

27. UI CHANGE POLICY: new namespaced components + backend view-model/API contracts + minimal, explicitly listed DT edits. No free refactor.

28. SCREENSHOTS: the owner will attach the current NivXForge DT baseline. Inspect: KUSHU trajectory, timeline, rows, Activity Details, Unknown/not assessed, "No detection engine claimed this observation", Observables, Observed Activity, the red MITRE styling with no attribution, search/filter, endpoint context. Never infer functionality from appearance; verify the code and backend wiring.

29. COMPETITOR RESEARCH METHOD. For each useful public capability record: capability; problem solved; analyst experience; sensor, backend and data-model requirements; detection, investigation and response requirements; security boundary; scale implications; NivXForge current state, gap and proposed implementation; tests; acceptance. Status: EXISTS_AND_PROVEN / EXISTS_PARTIAL / EXISTS_NOT_WIRED / MISSING / DEFERRED. No parity claims from visual similarity.

30. LIVING ROADMAP: docs/e3/NIVXFORGE_EDR_CAPABILITY_ROADMAP.md, organized by telemetry, detection, behavior, ML, TI, retrospection, investigation, DT, process tree, file trajectory, evidence graph, Second Human Brain, hunting, response, forensics, endpoint security, policy, tamper protection, fleet, operations, performance, multi-tenancy, offline intelligence, AI/agentic.
Each item records: status, existing implementation, required telemetry, backend and frontend, dependencies, security, tests, acceptance, metrics, limitations, next milestone.
Owner minimum list:
- Telemetry: process create/terminate, cmdline, parent/child identity, file create/write/rename/delete/execute, hashes, signer, registry, DNS, network, user/logon/session, services, scheduled tasks, modules/DLL, script/interpreter, security-control events, endpoint health/tamper.
- Investigation: DT, Process Tree, File Trajectory, network/DNS/registry/user context, evidence graph, causal chain, first/last seen, prevalence, search/filter, pivot-to-hunt, XDR linkage.
- Detection: rules, behavior, Sigma, YARA, TI, ML, anomaly, correlation, attack-chain, MITRE, suppression/exclusions, lifecycle.
- TI: normalized IOC model, VT, AbuseIPDB, OTX, future providers, internal TI, cache/TTL/quota, provenance, transitions.
- Retrospection: the 5 triggers, bounded replay, history preservation.
- Response: isolate/release, terminate, quarantine/block, indicator block, investigation package, Live Query/Response, approval, execution, verification, rollback.
- Hunting: event search, advanced query, IOC/process/file/network hunts, historical and saved hunts, detection-from-hunt.
- Endpoint security: health, tamper, policy, exclusions, offline detection, update lifecycle, enrollment, credential lifecycle.
- Operations: fleet, telemetry, queue/backpressure, processing and detection latency, gaps, storage/retention, replay, TI provider and model health.
- Forensics (later): acquisition, file collection, process and persistence artifacts, memory, chain of custody.
DO NOT implement this whole roadmap in DT-I1. DT-I1 builds the investigation architecture the roadmap plugs into, with no later DT rewrite.

31. ENGINE COMPLETION CONTRACT. Code existing, a 200 response, a rendered UI or passing synthetic/unit tests do NOT make an engine complete. Where applicable, prove: real evidence consumption, evidence refs, provenance, determinism, tenant isolation, UNKNOWN semantics, causal correctness, negative explainability, versioning, idempotency, bounded resources, failure semantics, retro compatibility, metrics, human-verifiable output, security compliance. Synthetic tests prove engineering behaviour, not production effectiveness; capabilities that depend on endpoint behaviour need controlled real-telemetry validation.

32. TESTING PYRAMID:
- L1 schema/unit
- L2 deterministic engine
- L3 synthetic attack/benign sequences
- L4 cross-engine (evidence → behavior → ML → assessment → view)
- L5 retrospection (old evidence + new rule/TI/model → new assessment)
- L6 tenant isolation
- L7 failure (TI or ML unavailable, partial telemetry, duplicate/out-of-order/replayed evidence, missing parent, PID reuse, late events)
- L8 perf/load
- L9 controlled real-endpoint telemetry
- L10 production acceptance
Never jump from synthetic tests to production claims.

33. REQUIRED FAILURE CASES: missing/partial evidence; duplicate, late or out-of-order events; PID reuse; missing parent; endpoint or sensor restart; TI timeout, quota exceeded or no data; ML cold start; ML TESTING lifecycle; duplicate or interrupted replay; rule or model version changes; analyst disposition changes; tenant mismatch; unauthorized response; response accepted but not executed; response executed but verification missing.

34. EVIDENCE GRAPH: every node is evidence-backed. Every relationship is evidence-backed or explicitly labelled CORRELATED/UNKNOWN. Example: USER → launched WINWORD → spawned POWERSHELL → {FILE.DLL loaded by RUNDLL32 → NETWORK; DOMAIN resolved → IP:443; REGISTRY modified → PERSISTENCE}.

35. INVESTIGATION FLOW: raw events → facts → relationships → causal chain → {detections, behavior, TI, ML} → assessment → supporting/contradicting → hypotheses (supported/unknown/rejected) → missing evidence → pivots → new evidence → reassess. This is the Second Human Brain foundation.

36. FUTURE AI/AGENTIC: AI consumes structured, tenant-scoped investigation contracts (evidence, unknowns, hypotheses), not raw database access. It explains, guides and summarizes for the analyst. Agentic actions obey the same response authorization; no autonomous bypass.

37. PROTECTED E1/GATE-4: do not modify processing_queue.py, ACK/ingest, canonical_bridge, response authorization, tenant or auth authority, Gate-4, enrollment, installer, or protected Windows config. If DT-I1 finds a required E1 change: DOCUMENT it, don't implement it.

38. DEVICE SAFETY: DESKTOP-A9HGFJJ is protected; no revoke, rotate, re-enroll, stop, restart, uninstall or config change. KUSHU (canary) stays STOPPED while Gate-4 is on HOLD. DT-I1 needs no endpoint action, and neither endpoint may be touched for test data.

39. DEPLOYMENT: without owner approval, no production deploy, merge, PR, endpoint rollout, sensor restart, KUSHU/DESKTOP action, response execution or credential rotation. Develop, test, document, hand off.

40. AUTONOMY: decide reversible, bounded matters yourself (filenames, helpers, fixtures, package layout). Interrupt the owner only for: irreversible decisions; security-boundary changes; canonical-authority or shared-architecture authority; production deployment; endpoint action; credential/key operations; response-authority changes; destructive migrations; work materially out of scope.

41. Gate-4 is a separate lane; don't chase Gate-4 failures.

42. DOCS: maintain the roadmap, DT-I1 architecture and contracts, Second Human Brain design, retrospection design, TI normalization contract, assessment/causal/unknown semantics, negative explainability, performance and security assumptions, limitations, and the real-telemetry validation plan. Document implemented reality only.

43. OWNER ACCEPTANCE QUESTIONS (answer before declaring a phase complete):
1. What was implemented?
2. What real problem does it solve?
3. What evidence does it consume?
4. Where does that evidence originate?
5. Is provenance preserved?
6. What happens when evidence is missing?
7. Can UNKNOWN become CLEAN?
8. Are causal claims supported?
9. Can the analyst see why?
10. Can the analyst see contradicting evidence?
11. Can the analyst see missing evidence?
12. Are historical assessments reproducible?
13. Can new knowledge trigger bounded reassessment?
14. Is tenant isolation proven?
15. Is it deterministic where intended?
16. Are ML lifecycle and limits visible?
17. Does failure degrade safely?
18. Are resources bounded?
19. Are metrics available?
20. What is synthetic-only?
21. What is validated on real telemetry?
22. What is still missing versus commercial EDR?
23. Was protected E1 code touched?
24. Any deployment or endpoint side effects?
25. What exact git diff represents the work?

44. "REAL EDR": a capability is real only with the appropriate sensor, telemetry, durable ingest, normalization, identity, evidence, engine, security boundary, investigation surface, tests, observability and real-world validation. Counter-examples:
- Process Tree that guesses parentage — not real.
- TI with hard-coded reputation — not real.
- ML with random scores — not real.
- Containment that only means a request was accepted — not real.
- MITRE labels without evidence — not real.
- Retrospection that overwrites results — not real.
- AI that invents telemetry — not real.

45. NORTH STAR: architecture before decoration; telemetry before unsupported capability; evidence before verdict; identity before relationship; causality before causal claims; detection before red styling; UNKNOWN before invented certainty; negative evidence before one-sided conclusions; provenance before confidence; deterministic truth before probabilistic inference; ML as signal, not oracle; AI as augmentation, not evidence authority; history before overwrite; authorization before response; execution before containment claims; verification before "contained"; real telemetry before effectiveness claims; operational engineering before production-ready. Commercial EDR capability + NivXForge deterministic evidence intelligence — WE REQUIRE BOTH.

46. EXECUTE NOW:
1. Confirm the baseline.
2. Delete the temp bundle and verify it's gone.
3. Do DT-I1A before changing DT behaviour.
4. Inspect screenshots when provided.
5. Inspect the existing DT and its real backend wiring.
6. Inventory TI, behavioral, ML, process identity, MITRE, response and provenance.
7. Produce the status matrix.
8. Define contracts before broad UI work.
9. Continue autonomously.
10. Stop only for genuine owner decisions.
DO NOT: deploy, merge, modify protected E1 code, touch KUSHU/DESKTOP, promote TESTING models, silently resolve canonical authority, fake capability, or substitute AI inference for evidence.
At each milestone report: IMPLEMENTED, TESTED, PROVEN, PARTIAL, NOT WIRED, MISSING, DEFERRED, LIMITATIONS, FILES CHANGED, TEST RESULTS, SECURITY IMPACT, PERFORMANCE IMPACT, NEXT STEP.

ORCHESTRATOR ADDENDA (binding):
- Same workspace rules as before: work only in the clone. Tests run in .e3venv with the network guard, synthetic data only, no real Mongo or services.
- Frontend: the NivXForge frontend can't run against a backend here. Write the components plus unit/render tests if the repo has a JS test runner; if it doesn't, document that and don't install heavy toolchains globally (an isolated local install inside the clone, excluded from git, is fine).
- No push. Each milestone ends with a commit. The final handoff includes the full SHA list and diff vs cd5b4e1b and vs 1800aeea, with every modified pre-existing file listed and justified.
