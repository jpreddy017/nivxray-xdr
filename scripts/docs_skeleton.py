#!/usr/bin/env python3
"""Build the authoritative NivXRay XDR documentation skeleton.

Owner directive: every SPEC_PENDING document must carry purpose, owner,
dependencies, required source inputs, known current reality, unresolved
questions, completion criteria and the release stage by which it must be
complete.  No generic filler, no empty placeholders.

Also emits DOC_PROVENANCE_LEDGER.md, reconciling every pre-existing
/app/memory/*.md so no previous architecture decision is orphaned.

Idempotent: never overwrites a file whose status is AUTHORED or ADOPTED.
"""
from __future__ import annotations

import pathlib
import re
from datetime import datetime, timezone

ROOT = pathlib.Path("/app")
DOCS = ROOT / "docs" / "nivxray-xdr"
MEMORY = ROOT / "memory"
STAMP = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")

# ── SPEC_PENDING specifications ─────────────────────────────────────
# rel_path: (title, layer, purpose, owner, deps, inputs, reality,
#            questions, criteria, stage)
S = "SPEC_PENDING"
T = "TARGET_SPEC"
H = "HISTORICAL_RECORD"

PENDING: dict[str, tuple] = {
 "00_PRODUCT/PRODUCT_VISION.md": (
  "Product Vision", T,
  "State what NivXRay XDR is for, who it serves and what it refuses to be, "
  "so that scope arguments are settled by a document instead of by taste.",
  "Owner",
  "CAPABILITY_CATALOG.md · PRODUCT_BOUNDARIES.md",
  "Owner positioning material; memory/NivXRay_Strategic_Master_Positioning.md "
  "(1164 lines); memory/NORTH_STAR_PRODUCT_GOAL.md",
  "Positioning exists in memory but has never been reconciled against the "
  "REALITY_MATRIX, so the vision currently describes a broader product than "
  "the one that runs.",
  "Is the near-term commercial unit NivXForge EDR alone, or only the pair? "
  "Which buyer is primary — SOC team, MSSP, or design partner?",
  "Vision reconciled line-by-line with CAPABILITY_CATALOG; every claim "
  "traceable to a capability or explicitly marked as future.",
  "INTERNAL_ALPHA"),
 "00_PRODUCT/PRODUCT_BOUNDARIES.md": (
  "Product Boundaries — XDR vs EDR", T,
  "Fix the boundary between NivXRay XDR and NivXForge EDR so neither "
  "duplicates the other, and record which side owns each capability.",
  "Architecture",
  "COMPONENT_ARCHITECTURE.md · memory/MASTER_OWNERSHIP_AUDIT.md",
  "memory/MASTER_OWNERSHIP_AUDIT.md (1207 lines); memory/"
  "XDR_EDR_PARITY_AUDIT.md; memory/XDR_SEPARATION_HANDOFF.md",
  "The ownership audit is complete and the two consoles are separated with "
  "distinct logins, shells and rails. The ARCHITECTURE LOCK is honoured in "
  "code today.",
  "Does XDR ever execute an endpoint action directly, or must it always "
  "orchestrate through EDR? (Current implementation: always orchestrate.)",
  "Every capability in CAPABILITY_CATALOG carries exactly one owning "
  "product; zero capabilities owned by both.",
  "INTERNAL_ALPHA"),
 "00_PRODUCT/TERMINOLOGY.md": (
  "Terminology", T,
  "One vocabulary for evidence, observation, canonical event, detection, "
  "correlation, incident, case, verdict, security state and response, so "
  "that documents and APIs stop drifting apart.",
  "Architecture",
  "EVIDENCE_ARCHITECTURE.md · INCIDENT_ARCHITECTURE.md",
  "Existing field names across 865 routes; memory/ARCHITECTURE.md; "
  "memory/CAPABILITIES_HLD_LLD.md",
  "The same concept appears as `case`, `incident` and `workspace_case` in "
  "different layers; `observation`, `raw event` and `canonical event` are "
  "three genuinely different objects that are often conflated in prose.",
  "Do we rename `workspace_cases` to `incidents` at the storage layer, or "
  "keep the collection name and fix only the vocabulary?",
  "Every term used in an authoritative doc appears here exactly once with "
  "its owning SSOT and its API field name.",
  "INTERNAL_ALPHA"),
 "01_REFERENCE/CISCO_WORKFLOW_CATALOG.md": (
  "Cisco XDR Workflow Catalog", T,
  "Catalogue the analyst workflows Cisco XDR supports end to end, so "
  "NivXRay screens are designed around operations rather than pages.",
  "Product + Design",
  "CISCO_COMPONENT_CATALOG.md · SOURCE_REGISTER.md",
  "Cisco public product documentation; owner-supplied Cisco training "
  "material and XDR.pptx (76 slides, already partly mined in "
  "memory/MASTER_CISCO_DELTA.md)",
  "memory/MASTER_CISCO_DELTA.md and memory/Y0_CISCO_XDR_REFERENCE_INTAKE.md "
  "capture a first pass from the owner's deck. Workflow-level detail "
  "(step order, decision points, hand-offs) is NOT yet captured.",
  "Which Cisco workflows can be evidenced from public docs versus only "
  "from owner-held training material? Everything unevidenced must be "
  "REFERENCE_CAPTURE_REQUIRED.",
  "Every workflow has: trigger, actor, ordered steps, objects touched, "
  "decision points, exit states, and a NivXRay equivalent or a declared gap.",
  "LAB_VALIDATED"),
 "01_REFERENCE/CISCO_UI_REFERENCE_CATALOG.md": (
  "Cisco XDR UI Reference Catalog", T,
  "Inventory every Cisco reference screen we legitimately hold, so UI "
  "parity work is evidence-driven rather than memory-driven.",
  "Design",
  "SOURCE_REGISTER.md · 03_DESIGN/VISUAL_PARITY_MATRIX.md",
  "Owner-supplied Cisco screenshots and training decks only. No scraping "
  "of Cisco's product; no proprietary asset reuse.",
  "Only two owner images are attached to the current session (a NivXRay "
  "mockup and a NivXForge EDR screenshot). NO Cisco screen captures are "
  "currently in the repository.",
  "Which Cisco screens can the owner legally supply for internal "
  "reference? Everything else stays REFERENCE_CAPTURE_REQUIRED.",
  "Every first-class NivXRay screen has either a reference capture or an "
  "explicit REFERENCE_CAPTURE_REQUIRED marker; zero screens designed from "
  "recollection.",
  "CLOSED_BETA"),
 "02_ARCHITECTURE/DATA_ARCHITECTURE.md": (
  "Data Architecture", T,
  "Define every store, its SSOT role, retention, tenancy key and the one "
  "component allowed to write it.",
  "Architecture",
  "EVIDENCE_ARCHITECTURE.md · GENERATED_ENGINE_REGISTRY.md",
  "Live MongoDB collection inventory; the response service SQLite SSOT; "
  "backend/services/edr/endpoint_query.py store contract",
  "Endpoint-keyed stores and their identity fields are declared and "
  "guarded (P0-2C). Retention, archival and tenancy keys are NOT "
  "documented for most collections.",
  "Which collections are authoritative versus derived projections that "
  "could be rebuilt? What is the retention obligation per store?",
  "Every collection has: owner, SSOT/derived classification, writer, "
  "tenancy key, retention, rebuild procedure.",
  "CLOSED_BETA"),
 "02_ARCHITECTURE/DETECTION_ARCHITECTURE.md": (
  "Detection Architecture", T,
  "Document how a canonical event becomes a detection: rule sources, "
  "evaluation, attribution to evidence, and what a detection may claim.",
  "Detection",
  "EVIDENCE_ARCHITECTURE.md · CORRELATION_ARCHITECTURE.md",
  "xdr_detection_rules (98 rules, 5 sources); detection_content/ package; "
  "scripts/p0_detection_attribution_proof.py",
  "98 rules are loaded and 64 detections are attributed to REAL sensor "
  "events with raw_id + canonical_event_id. Rule provenance, licensing and "
  "coverage-by-platform are only partly documented.",
  "How many of the 98 rules can actually fire against Linux-shaped "
  "telemetry versus assuming Windows/Sysmon fields?",
  "Rule inventory with per-rule platform applicability, required fields, "
  "and a fired/never-fired status backed by runtime evidence.",
  "LAB_VALIDATED"),
 "02_ARCHITECTURE/CORRELATION_ARCHITECTURE.md": (
  "Correlation Architecture", T,
  "Define cross-source correlation: grouping keys, time semantics, "
  "confidence, and the honest limits while only one telemetry domain exists.",
  "Detection",
  "DETECTION_ARCHITECTURE.md · INCIDENT_ARCHITECTURE.md",
  "xdr_correlation_rules (10 rules); backend correlation engine; "
  "memory/ROADMAP.md G-16/FLOW 5 notes",
  "A correlation engine and 10 rules exist. Genuine CROSS-DOMAIN "
  "correlation is not demonstrable: only the endpoint domain has a real "
  "producer, so today's correlation is within-domain.",
  "Does any current correlation rule require a second domain, and does it "
  "therefore silently never fire?",
  "Each rule declares required domains; a runtime proof shows which fire "
  "with one domain and which are blocked pending a second.",
  "CLOSED_BETA"),
 "02_ARCHITECTURE/INVESTIGATION_ARCHITECTURE.md": (
  "Investigation Architecture", T,
  "Document the investigation plane: observables, pivots, graph, timeline, "
  "sightings and the evidence contract behind each.",
  "Investigation",
  "EVIDENCE_ARCHITECTURE.md · INTELLIGENCE_ARCHITECTURE.md",
  "IUE/IKG engines; 15 catalogued investigation capabilities; "
  "memory/IUE_ARCHITECTURE_V2.md; memory/IUE_INVESTIGATION_SSOT_"
  "RECONCILIATION.md",
  "An investigation workspace, evidence graph and process ancestry exist "
  "and render from real evidence. The SSOT reconciliation memo flags "
  "unresolved authority questions between IUE and the investigation store.",
  "Which store is authoritative for an investigation: the IUE record or "
  "workspace_cases? (The SSOT reconciliation memo does not close this.)",
  "One declared SSOT per investigation object; every pivot documented with "
  "its authoritative API and failure states.",
  "CLOSED_BETA"),
 "02_ARCHITECTURE/INTELLIGENCE_ARCHITECTURE.md": (
  "Intelligence Architecture", T,
  "Document reputation/disposition sourcing, caching, provenance and how "
  "third-party intelligence is prevented from becoming a verdict.",
  "Intelligence",
  "INVESTIGATION_ARCHITECTURE.md · 07_SECURITY/SECRETS_MANAGEMENT.md",
  "7 live IOC providers (abuseipdb, hybrid-analysis, malwarebazaar, "
  "threatfox, urlhaus, urlscan, virustotal); threat-intel routes",
  "Seven providers report live at startup. Provenance and cache-age "
  "disclosure on analyst surfaces is not fully specified.",
  "What is the disclosure contract when a provider is down or a "
  "disposition is stale? Must never silently degrade to 'clean'.",
  "Per-provider contract: auth, rate limits, cache TTL, staleness "
  "disclosure, failure state, and never-infer-clean rule proven by test.",
  "CLOSED_BETA"),
 "02_ARCHITECTURE/AUTOMATION_ARCHITECTURE.md": (
  "Automation Architecture", T,
  "Define workflows, triggers, approvals and the boundary between "
  "automation and response execution.",
  "Response",
  "RESPONSE_ARCHITECTURE.md · 07_SECURITY/RESPONSE_SAFETY.md",
  "Existing automation/webhook routes; approval lifecycle in the response "
  "service",
  "Approval gating is real inside the response lifecycle. A general "
  "workflow/playbook engine comparable to the reference product is NOT "
  "implemented.",
  "Do we build a workflow engine or expose only fixed, audited playbooks? "
  "A general engine is a large security surface.",
  "Trigger taxonomy, workflow object model, approval binding, audit "
  "contract, and a proof that no workflow can bypass response approval.",
  "DESIGN_PARTNER_PILOT"),
 "02_ARCHITECTURE/ASSET_ARCHITECTURE.md": (
  "Asset Architecture", T,
  "Define the asset/device model: identity, deduplication, ownership, "
  "criticality and how asset value feeds prioritisation.",
  "Architecture",
  "EVIDENCE_ARCHITECTURE.md · INCIDENT_ARCHITECTURE.md",
  "edr_endpoints registry; services/edr/device_identity.py; P0-2C alias "
  "invariant",
  "Endpoint identity resolution is now a structural invariant with a "
  "validated alias set and tenant-constrained reverse lookup. Asset "
  "criticality, ownership and business context do NOT exist.",
  "Where does asset value come from with no CMDB integration — manual "
  "tagging, or deferred until an integration exists?",
  "Asset object model with identity, alias set, dedup rule, criticality "
  "source and its effect on incident priority, all evidence-backed.",
  "CLOSED_BETA"),
 "02_ARCHITECTURE/IDENTITY_TENANCY_ARCHITECTURE.md": (
  "Identity & Tenancy Architecture", T,
  "Document principals, tenants, scopes and the object-level authorisation "
  "rule that every route must satisfy.",
  "Security",
  "07_SECURITY/TENANT_ISOLATION.md · 07_SECURITY/RBAC_MATRIX.md",
  "RBAC routes (19); resolve_tenant_scope; scripts/"
  "p0_w_incident_tenant_authorization_proof.py",
  "Tenant scoping is enforced and proven for incidents and endpoint "
  "evidence; a cross-tenant IDOR was found and closed. Coverage across all "
  "865 routes is not systematically proven.",
  "Is there a route-level guard that fails a new route lacking tenant "
  "scoping, comparable to the P0-2C alias guard?",
  "Every tenant-scoped route enumerated and covered by an authorisation "
  "test; a structural guard prevents adding an unscoped route.",
  "CLOSED_BETA"),
 "02_ARCHITECTURE/SECURITY_STATE_CAUSAL_ARCHITECTURE.md": (
  "Security State & Causal Architecture", T,
  "Document the security-state model, causal FSM and what a counterfactual "
  "or intervention claim is permitted to assert.",
  "Reasoning",
  "EVIDENCE_ARCHITECTURE.md · INCIDENT_ARCHITECTURE.md",
  "14 security-state routes; 8 reasoning-fabric capabilities; owner's "
  "34-point technology directive (deferred)",
  "Security-state and causal surfaces exist and render in the "
  "investigation workspace. The owner's technology-adoption audit that "
  "would formalise the causal claims is explicitly DEFERRED until the P0s "
  "close.",
  "What is the evidentiary standard for a causal or counterfactual claim? "
  "Without one, these surfaces risk asserting more than the evidence "
  "supports.",
  "Claim taxonomy with required evidence per claim class, and a rule that "
  "no causal claim may exceed its evidence, proven by test.",
  "DESIGN_PARTNER_PILOT"),
 "03_DESIGN/DESIGN_SYSTEM.md": (
  "Design System", T,
  "The token set, type scale, colour system, spacing, elevation and motion "
  "rules every NivXRay surface must use.",
  "Design",
  "INFORMATION_ARCHITECTURE.md · COMPONENT_LIBRARY.md",
  "memory/NIVXRAY_VISUAL_GRAMMAR.md (617 lines); memory/VISUAL_LANGUAGE.md "
  "(514 lines); /app/design_guidelines.json",
  "Two substantial visual-language documents already exist and the shipped "
  "consoles follow them. They have not been reconciled with each other or "
  "with the owner's Cisco-parity target.",
  "Do NIVXRAY_VISUAL_GRAMMAR and VISUAL_LANGUAGE conflict? Which is "
  "authoritative after adoption?",
  "One token source of truth referenced by code; both memory documents "
  "ADOPTED or SUPERSEDED with no third variant surviving.",
  "CLOSED_BETA"),
 "03_DESIGN/NAVIGATION_SPEC.md": (
  "Navigation Specification", T,
  "Define both product rails, their order, grouping, badges, deep-link "
  "behaviour and the XDR to EDR pivot contract.",
  "Design",
  "INFORMATION_ARCHITECTURE.md",
  "App.jsx route table (generated); memory/Y1_STATUS_REPORT.md rail work; "
  "owner mockup (15-item rail) versus shipped 8-primary rail",
  "The shipped rail is the 8-primary reference structure. The owner has "
  "supplied a mockup with a 15-item rail; the conflict is OPEN and was "
  "raised but not resolved.",
  "Authoritative rail: the shipped 8-primary structure, or the owner's "
  "15-item mockup, or Cisco IA plus a new Home landing page?",
  "One rail specification, per-item route, RBAC visibility rule, badge "
  "data source, and reconciliation with the generated UI route inventory.",
  "CLOSED_BETA"),
 "03_DESIGN/PAGE_TEMPLATES.md": (
  "Page Templates", T,
  "The small set of page archetypes (queue, detail, canvas, matrix, "
  "settings) every screen must instantiate.",
  "Design",
  "DESIGN_SYSTEM.md · NAVIGATION_SPEC.md",
  "Existing 60 frontend routes; shipped page structures",
  "Templates are implicit in the code and mostly consistent, but are not "
  "written down, so each new page re-derives its layout.",
  "How many archetypes actually exist across the 60 shipped routes?",
  "Each of the 60 routes mapped to exactly one archetype; deviations "
  "justified in writing.",
  "CLOSED_BETA"),
 "03_DESIGN/COMPONENT_LIBRARY.md": (
  "Component Library", T,
  "Catalogue every shared UI component with props, states and the "
  "data-testid contract.",
  "Design + Frontend",
  "DESIGN_SYSTEM.md · 04_DEVELOPMENT/FRONTEND_GUIDE.md",
  "apps/nivxray-xdr/src/**/components; shadcn/ui base set",
  "Shared components exist (including the new EndpointNotResolved honest "
  "empty state) and carry data-testids, but there is no catalogue.",
  "Which components are genuinely shared between the XDR and EDR shells "
  "versus duplicated per product?",
  "Every shared component documented with props, states, testids and its "
  "consuming routes; duplicates identified for consolidation.",
  "CLOSED_BETA"),
 "03_DESIGN/INTERACTION_PATTERNS.md": (
  "Interaction Patterns", T,
  "Standardise selection, filtering, drawer versus page, bulk action, "
  "keyboard navigation and pivot behaviour.",
  "Design",
  "PAGE_TEMPLATES.md · COMPONENT_LIBRARY.md",
  "Shipped console behaviour; 14 audited frontend pivots (P0-2C)",
  "Pivot contracts were audited and one defect fixed. Broader interaction "
  "patterns are unwritten.",
  "Is there a keyboard model at all today? Cisco-grade consoles are "
  "keyboard-driven; ours is largely mouse-driven.",
  "Each pattern specified once with acceptance tests, including the full "
  "keyboard model.",
  "CLOSED_BETA"),
 "03_DESIGN/STATES_AND_ERRORS.md": (
  "States & Errors", T,
  "The mandatory state vocabulary — loading, empty-real, no-integration, "
  "stale, partial, unavailable, unauthorized, not-resolved, error — and the "
  "rule that an empty result may never imply absence of evidence.",
  "Design + Architecture",
  "COMPONENT_LIBRARY.md · EVIDENCE_ARCHITECTURE.md",
  "P0-2C ENDPOINT_NOT_RESOLVED contract; the WINDOW_HONESTY_GAP finding; "
  "existing epistemic_state envelopes",
  "This is the most mature honesty mechanism in the product: "
  "ENDPOINT_NOT_RESOLVED is enforced backend-side and now rendered by "
  "three EDR surfaces. Coverage is not universal — the process-tree window "
  "gap is a live example of a true-but-misleading empty state.",
  "Is there any surface that still renders an empty collection where the "
  "backend supplied a named absence?",
  "Every state has one component, one API contract and one test; a sweep "
  "proves no surface converts a named absence into a bare empty state.",
  "LAB_VALIDATED"),
 "03_DESIGN/ACCESSIBILITY.md": (
  "Accessibility", T,
  "Contrast, focus order, keyboard operability, screen-reader semantics "
  "and motion-reduction requirements.",
  "Design",
  "DESIGN_SYSTEM.md · INTERACTION_PATTERNS.md",
  "WCAG 2.2 AA; shipped console markup",
  "No accessibility audit has been performed. The dark, dense console "
  "style carries real contrast risk on faint text.",
  "Is AA a commitment for GA, and is any customer contractually likely to "
  "require it?",
  "AA audit passed on every first-class screen with an automated check in "
  "CI.",
  "RELEASE_CANDIDATE"),
 "03_DESIGN/RESPONSIVE_BEHAVIOR.md": (
  "Responsive Behaviour", T,
  "Breakpoints and degradation rules for dense analyst surfaces.",
  "Design",
  "PAGE_TEMPLATES.md",
  "Shipped CSS; console is designed for wide displays",
  "The consoles are built for wide desktop use. Narrow-viewport behaviour "
  "is untested and likely broken on the matrix and canvas surfaces.",
  "Is tablet or mobile a real requirement for a SOC console, or "
  "explicitly out of scope?",
  "Per-archetype breakpoint behaviour specified and verified, or "
  "out-of-scope recorded as a product decision.",
  "RELEASE_CANDIDATE"),
 "04_DEVELOPMENT/FRONTEND_GUIDE.md": (
  "Frontend Guide", T,
  "How to add a screen: routing, data access, state vocabulary, testids, "
  "and the rule that no component may invent data.",
  "Frontend",
  "DEVELOPMENT_GUIDE.md · COMPONENT_LIBRARY.md",
  "Shipped frontend conventions; edrApi/api clients",
  "Conventions are consistent in practice but unwritten; the no-invented-"
  "data rule is enforced by review rather than by tooling.",
  "Can a lint rule detect a hard-coded metric or a client-side severity "
  "decision?",
  "A new screen can be added correctly by following this document alone, "
  "and a lint or test rule catches invented data.",
  "LAB_VALIDATED"),
 "04_DEVELOPMENT/BACKEND_GUIDE.md": (
  "Backend Guide", T,
  "How to add a capability: contract, SSOT, tenant scoping, evidence "
  "provenance, engine identity and proof obligations.",
  "Backend",
  "DEVELOPMENT_GUIDE.md · API_GUIDE.md",
  "865 live routes; the P0-2C alias invariant as the reference pattern",
  "The P0-2C endpoint-identity invariant is the model to generalise: a "
  "declared contract plus an AST guard plus a runtime proof. Nothing else "
  "is guarded this way yet.",
  "Which other invariants deserve the same treatment — tenant scoping "
  "first?",
  "A new capability can be added correctly from this document, and its "
  "invariants are guarded rather than reviewed.",
  "LAB_VALIDATED"),
 "04_DEVELOPMENT/API_GUIDE.md": (
  "API Guide", T,
  "Route naming, versioning, error taxonomy, pagination, idempotency and "
  "the named-absence response contract.",
  "Backend",
  "BACKEND_GUIDE.md · GENERATED_ROUTE_INVENTORY.md",
  "Generated route inventory; existing error shapes",
  "865 routes with several competing conventions and no published error "
  "taxonomy; ENDPOINT_NOT_RESOLVED is the first properly specified "
  "absence contract.",
  "Do we version the API before a design partner, and can the OpenAPI "
  "schema be served (it is currently not exposed at /api/openapi.json)?",
  "One naming and error convention, published error taxonomy, and route "
  "inventory reconciled with zero undocumented live routes.",
  "CLOSED_BETA"),
 "04_DEVELOPMENT/INTEGRATION_SDK_GUIDE.md": (
  "Integration SDK Guide", T,
  "How a new source or control plane implements the NivXRay integration "
  "contract without touching platform internals.",
  "Integrations",
  "INTEGRATION_ARCHITECTURE.md",
  "Existing collector and vendor-wizard routes; the reference product's "
  "capability model",
  "Collector and vendor-wizard surfaces exist, and a standalone collector "
  "runs on :8055, but there is no declared integration contract an "
  "external source could implement.",
  "Is the first third-party integration written by us or by a partner? "
  "That decides how strict the SDK must be.",
  "A new integration can be built from this guide alone and declares its "
  "capabilities, health and provenance without core changes.",
  "DESIGN_PARTNER_PILOT"),
 "04_DEVELOPMENT/SENSOR_DEVELOPMENT_GUIDE.md": (
  "Sensor Development Guide", T,
  "How to build a NivXForge sensor for a new platform: enrolment, "
  "transport, event contracts, identity, command execution and "
  "verification probes.",
  "Endpoint",
  "INTEGRATION_ARCHITECTURE.md · RESPONSE_ARCHITECTURE.md",
  "agents/nivxforge-linux/nivxforge_sensor.py (the only existing "
  "producer); edr_plane/enrollment/*; edr_plane/contracts/telemetry.py",
  "One Linux sensor exists and has delivered real telemetry. The enrolment "
  "and ingest APIs are platform-agnostic, but three parts of the platform "
  "are Linux-shaped: trajectory lanes cover only PROCESS/FILE/NETWORK, "
  "kill verification requires a /proc start_ticks identity basis, and no "
  "Windows or macOS producer exists.",
  "Windows process identity basis (PID plus creation time) must be a "
  "first-class alternative to start_ticks — does that change the command "
  "target contract?",
  "A Windows sensor can be built from this guide, its events land in "
  "declared lanes, and its kill verification is accepted by the response "
  "verifier without weakening the proof standard.",
  "LAB_VALIDATED"),
 "04_DEVELOPMENT/DETECTION_CONTENT_GUIDE.md": (
  "Detection Content Guide", T,
  "How rules are authored, licensed, tested against real telemetry and "
  "promoted, including per-platform field requirements.",
  "Detection",
  "DETECTION_ARCHITECTURE.md",
  "xdr_detection_rules (98 rules, 5 sources); rule-studio routes; "
  "memory/UNIVERSAL_DECODER_LICENSE_MATRIX.md",
  "98 rules load and a rule studio exists. Licence posture is partly "
  "documented; per-rule platform applicability is not.",
  "How many of the 98 rules assume Windows or Sysmon fields and therefore "
  "cannot fire on current Linux telemetry?",
  "Every rule declares required fields, platform applicability, licence "
  "and a real-telemetry test result.",
  "LAB_VALIDATED"),
 "04_DEVELOPMENT/RESPONSE_ADAPTER_GUIDE.md": (
  "Response Adapter Guide", T,
  "How a control plane implements a response action with approval, "
  "execution and independent verification.",
  "Response",
  "RESPONSE_ARCHITECTURE.md · 07_SECURITY/RESPONSE_SAFETY.md",
  "apps/nivxray-xdr-response (:8056); edr_plane/response.py lifecycle",
  "The lifecycle is real and refuses to claim success: 5 commands reached "
  "VERIFIED, 1 VERIFICATION_FAILED, 8 CAPABILITY_UNAVAILABLE. 16 of 18 "
  "catalogued actions are NON_OPERATIONAL stubs.",
  "For each of the 16 stubs: adopt, wire, or deprecate? Publishing 18 "
  "actions where 2 work is a product-honesty problem.",
  "Each action either has a real adapter with a verification probe or is "
  "removed from the catalogue; no action is listed without a state.",
  "CLOSED_BETA"),
 "04_DEVELOPMENT/CONTRIBUTION_RULES.md": (
  "Contribution Rules", T,
  "The non-negotiable engineering rules: evidence first, no synthetic "
  "operational data, no parallel SSOT, no invented UI data, proof before "
  "claim.",
  "Owner + Architecture",
  "DEVELOPMENT_GUIDE.md · TESTING_GUIDE.md",
  "memory/GOVERNANCE_RULES.md (1039 lines); memory/MASTER_GATE.md; "
  "memory/GOVERNANCE.md",
  "Extensive governance rules already exist and have been enforced in "
  "practice across this programme. They are spread across three memory "
  "documents with overlapping authority.",
  "Which of the three governance documents is authoritative after "
  "adoption?",
  "One rule set, each rule paired with the automated guard that enforces "
  "it or an explicit note that it is review-enforced.",
  "INTERNAL_ALPHA"),
 "05_OPERATIONS/DEPLOYMENT_GUIDE.md": (
  "Deployment Guide", T,
  "How NivXRay is deployed, which services exist, their ports, "
  "dependencies and start order.",
  "Operations",
  "SYSTEM_ARCHITECTURE.md",
  "Supervisor configuration; backend :8001, frontend :3000, collector "
  "ial :8055, response service :8056",
  "The platform runs as supervisor-managed services in a single "
  "environment. There is no documented deployment topology, and the "
  "preview environment is not a production topology.",
  "What is the target production topology — single tenant per install, or "
  "multi-tenant SaaS? This changes almost everything downstream.",
  "A clean environment can be brought up from this document alone, with "
  "verified health on every service.",
  "CLOSED_BETA"),
 "05_OPERATIONS/INSTALLATION_GUIDE.md": (
  "Installation Guide", T,
  "Operator-facing installation, including sensor deployment at scale.",
  "Operations",
  "DEPLOYMENT_GUIDE.md · SENSOR_DEVELOPMENT_GUIDE.md",
  "Linux sensor enrolment flow; agent credential lifecycle",
  "Sensor enrolment works one machine at a time via a token. There is no "
  "packaged installer and no fleet deployment mechanism.",
  "Do we need an MSI/service installer before a design-partner pilot? "
  "Almost certainly yes for Windows.",
  "An operator can install the platform and enrol a fleet without "
  "engineering help.",
  "DESIGN_PARTNER_PILOT"),
 "05_OPERATIONS/CONFIGURATION_GUIDE.md": (
  "Configuration Guide", T,
  "Every configuration key, its default, its blast radius and where it "
  "lives.",
  "Operations",
  "DEPLOYMENT_GUIDE.md · 07_SECURITY/SECRETS_MANAGEMENT.md",
  "backend/.env, frontend/.env, feature flags (including shadow-mode "
  "engine flags)",
  "Feature flags exist including shadow-mode engine toggles. There is no "
  "consolidated configuration reference.",
  "Which flags are safe for an operator to change versus engineering-only?",
  "Every key documented with type, default, effect and owner; no "
  "undocumented key read at runtime.",
  "CLOSED_BETA"),
 "05_OPERATIONS/INTEGRATION_ADMIN_GUIDE.md": (
  "Integration Administration Guide", T,
  "How an administrator configures, credentials, tests and monitors an "
  "integration.",
  "Operations",
  "INTEGRATION_ARCHITECTURE.md",
  "Collector routes (22); vendor wizard (17); data-source routes (10)",
  "Administration surfaces exist. The collector pipeline has a known "
  "split-brain between reported and actual status (P0-4, open).",
  "Until P0-4 closes, can any integration health status be trusted for "
  "administration decisions?",
  "Health shown to an administrator is the authoritative health, proven by "
  "a reconciliation test.",
  "CLOSED_BETA"),
 "05_OPERATIONS/OBSERVABILITY_GUIDE.md": (
  "Observability Guide", T,
  "Logs, metrics, traces and the alerts that tell an operator the platform "
  "has gone blind.",
  "Operations",
  "DEPLOYMENT_GUIDE.md",
  "Structured JSON logging; existing health routes",
  "Structured logging exists. Critically, the platform went telemetry-"
  "blind for over 24 hours and NOTHING alerted — that is the strongest "
  "evidence this document is needed.",
  "What is the staleness threshold at which sensor silence becomes an "
  "alert rather than a quiet empty screen?",
  "Sensor silence, ingest failure, collector failure and integration "
  "failure each raise an operator-visible alert with a proven trigger.",
  "LAB_VALIDATED"),
 "05_OPERATIONS/BACKUP_RECOVERY_GUIDE.md": (
  "Backup & Recovery Guide", T,
  "What must be backed up, how it is restored and what is rebuildable.",
  "Operations",
  "DATA_ARCHITECTURE.md",
  "MongoDB collections; response-service SQLite SSOT",
  "No backup or restore procedure exists or has ever been tested.",
  "Which stores are authoritative and must be backed up versus derived "
  "projections that can be rebuilt?",
  "A restore has been performed successfully in a test environment with a "
  "measured RPO and RTO.",
  "RELEASE_CANDIDATE"),
 "05_OPERATIONS/UPGRADE_ROLLBACK_GUIDE.md": (
  "Upgrade & Rollback Guide", T,
  "How the platform and the sensor fleet are upgraded and rolled back "
  "safely.",
  "Operations",
  "DEPLOYMENT_GUIDE.md · SENSOR_DEVELOPMENT_GUIDE.md",
  "memory/RC2.1a_ROLLBACK_PLAN.md; memory/RC2.2_ROLLBACK_PLAN.md",
  "Point-in-time rollback plans exist for two past releases. There is no "
  "general procedure and no sensor upgrade mechanism at all.",
  "Can a sensor self-update, and what happens to in-flight telemetry and "
  "pending commands during an upgrade?",
  "An upgrade and a rollback both performed in test, including a sensor "
  "fleet, with no evidence loss.",
  "RELEASE_CANDIDATE"),
 "05_OPERATIONS/HA_SCALING_GUIDE.md": (
  "HA & Scaling Guide", T,
  "Availability targets, scaling limits and measured capacity.",
  "Operations",
  "DEPLOYMENT_GUIDE.md · 08_VALIDATION/PERFORMANCE_MATRIX.md",
  "Current single-instance topology",
  "Single instance of every service; no HA; no load testing. Observed "
  "corpus is roughly 8k events from 2 endpoints, so nothing is known about "
  "behaviour at fleet scale.",
  "What fleet size must the first pilot support? That number drives every "
  "capacity decision.",
  "Measured throughput and latency at a stated fleet size, with a "
  "documented scaling path and no single point of failure.",
  "RELEASE_CANDIDATE"),
 "05_OPERATIONS/TROUBLESHOOTING_GUIDE.md": (
  "Troubleshooting Guide", T,
  "Symptom-to-cause runbooks for the failures that actually occur.",
  "Operations",
  "OBSERVABILITY_GUIDE.md",
  "This programme's own incident history: telemetry blindness, collector "
  "split-brain, alias resolution failures, empty-state ambiguity",
  "The real failure modes are known and documented in memory reports; they "
  "are not yet expressed as operator runbooks.",
  "Which failures can an operator fix versus which require engineering?",
  "Every known failure mode has a runbook with a detection signal and a "
  "verified remedy.",
  "CLOSED_BETA"),
 "06_USER_GUIDES/SOC_ANALYST_GUIDE.md": (
  "SOC Analyst Guide", T,
  "The analyst's day: triage, investigate, decide, respond, verify, close.",
  "Product",
  "INFORMATION_ARCHITECTURE.md · INCIDENT_ARCHITECTURE.md",
  "Shipped console behaviour; owner's workflow description",
  "The console supports a substantial part of this loop against real "
  "evidence. A user guide must describe only what is usable today, so it "
  "cannot be written honestly until the incident-provenance question is "
  "resolved.",
  "Can an analyst currently tell a real incident from a seeded one? Today, "
  "no — 0 of the incidents carry a provenance label.",
  "Every documented step performable in the shipped product against real "
  "evidence, with screenshots from a real endpoint.",
  "CLOSED_BETA"),
 "06_USER_GUIDES/THREAT_HUNTER_GUIDE.md": (
  "Threat Hunter Guide", T,
  "Hypothesis-driven hunting across available evidence.",
  "Product",
  "INVESTIGATION_ARCHITECTURE.md",
  "Search and hunting routes; fleet spread index",
  "Search and spread surfaces exist over one telemetry domain, which "
  "sharply limits genuine hunting.",
  "Is hunting credible with a single domain, or does this guide wait for a "
  "second source?",
  "Documented hunts are reproducible on real data and return real results.",
  "DESIGN_PARTNER_PILOT"),
 "06_USER_GUIDES/INCIDENT_RESPONDER_GUIDE.md": (
  "Incident Responder Guide", T,
  "Containment and eradication using verified response actions.",
  "Product",
  "RESPONSE_ARCHITECTURE.md",
  "Response lifecycle; verification probes",
  "Only KILL_PROCESS is genuinely verifiable today, and only on Linux. "
  "Isolation is BLOCKED_ENVIRONMENT.",
  "What does a responder do when the only verified action is process "
  "termination?",
  "Every documented action is operational and independently verified in "
  "the shipped product.",
  "CLOSED_BETA"),
 "06_USER_GUIDES/ADMINISTRATOR_GUIDE.md": (
  "Administrator Guide", T,
  "Tenants, users, roles, integrations, sensors, retention and audit.",
  "Product",
  "IDENTITY_TENANCY_ARCHITECTURE.md · INTEGRATION_ADMIN_GUIDE.md",
  "Administration routes; RBAC surfaces",
  "Administration surfaces exist for RBAC, API keys, secrets and audit. "
  "Retention and lifecycle administration do not.",
  "Which administrative actions are self-service versus engineering-only "
  "today?",
  "An administrator can run the platform from this guide without "
  "engineering support.",
  "CLOSED_BETA"),
 "06_USER_GUIDES/MSSP_GUIDE.md": (
  "MSSP / Multi-Tenant Guide", T,
  "Operating many customers from one console without cross-customer leakage.",
  "Product",
  "07_SECURITY/TENANT_ISOLATION.md",
  "MSS routes (8); tenant scoping; cross-tenant proofs",
  "Multi-tenant scoping is real and proven at the incident and endpoint-"
  "evidence layers, including a cross-tenant denial that discloses nothing. "
  "MSSP operational workflows are not documented.",
  "Is MSSP a launch market or a later one? It materially changes isolation "
  "and reporting priorities.",
  "Multi-customer operation documented and proven with an isolation test "
  "per surface.",
  "DESIGN_PARTNER_PILOT"),
 "06_USER_GUIDES/INVESTIGATION_GUIDE.md": (
  "Investigation Guide", T,
  "How to drive an investigation from observable to conclusion.",
  "Product",
  "INVESTIGATION_ARCHITECTURE.md",
  "Investigation workspace; pivots; evidence graph",
  "The workspace renders real evidence, including process ancestry and the "
  "evidence graph, on the one real endpoint.",
  "Which pivots return real results with one telemetry domain, and which "
  "always return a named absence?",
  "Every documented pivot demonstrated on real evidence with its honest "
  "limits stated.",
  "CLOSED_BETA"),
 "06_USER_GUIDES/AUTOMATION_GUIDE.md": (
  "Automation Guide", T,
  "Building and operating automation safely.",
  "Product",
  "AUTOMATION_ARCHITECTURE.md",
  "Existing automation and webhook routes",
  "No general workflow engine exists, so there is nothing an analyst can "
  "be taught to automate yet.",
  "Deferred until AUTOMATION_ARCHITECTURE settles the engine question.",
  "A user can build, test and operate an automation that performs a real "
  "action with approval.",
  "DESIGN_PARTNER_PILOT"),
 "06_USER_GUIDES/RESPONSE_GUIDE.md": (
  "Response Guide", T,
  "Choosing, approving, executing and verifying a response.",
  "Product",
  "RESPONSE_ARCHITECTURE.md",
  "Response lifecycle states; approval gating",
  "The lifecycle is honest about every state, including refusing to call "
  "an unverified action successful. Only 2 of 18 catalogued actions are "
  "operational.",
  "How is the action catalogue presented so an analyst is never offered an "
  "action that cannot execute?",
  "Documented actions are operational, verified and RBAC-gated in the "
  "shipped product.",
  "CLOSED_BETA"),
 "07_SECURITY/SECURITY_ARCHITECTURE.md": (
  "Security Architecture", T,
  "Trust boundaries, service identities and the platform's own attack "
  "surface.",
  "Security",
  "IDENTITY_TENANCY_ARCHITECTURE.md · THREAT_MODEL.md",
  "Service topology; auth implementation; 865-route surface",
  "Auth, RBAC and tenant scoping are implemented and partly proven. "
  "Service-to-service identity between the platform and the response "
  "service on :8056 needs documenting, and a cross-tenant IDOR was found "
  "in this programme — evidence that systematic review is required.",
  "Is the response service's trust in the platform authenticated, or "
  "network-trusted?",
  "Every trust boundary documented with its authentication mechanism and "
  "a test proving it cannot be bypassed.",
  "CLOSED_BETA"),
 "07_SECURITY/RBAC_MATRIX.md": (
  "RBAC Matrix", T,
  "Every permission, the roles holding it and the routes enforcing it.",
  "Security",
  "IDENTITY_TENANCY_ARCHITECTURE.md",
  "require_permission decorators across the route surface; RBAC routes",
  "Permission enforcement exists via decorators and is proven for response "
  "and incident surfaces. There is no complete matrix across 865 routes.",
  "How many live routes have no permission requirement at all?",
  "Every route mapped to a permission, every permission to roles, with an "
  "automated check for unprotected routes.",
  "CLOSED_BETA"),
 "07_SECURITY/TENANT_ISOLATION.md": (
  "Tenant Isolation", T,
  "The isolation model and the proof that no surface leaks across "
  "customers.",
  "Security",
  "IDENTITY_TENANCY_ARCHITECTURE.md",
  "scripts/p0_w_incident_tenant_authorization_proof.py; P0-2C cross-tenant "
  "gates; the tenant-constrained alias reverse lookup",
  "Isolation is proven for incidents and all endpoint evidence surfaces, "
  "including the requirement that a foreign identifier is indistinguishable "
  "from an unknown one. A resolver-level cross-customer alias bleed was "
  "found and closed in P0-2C.",
  "Which of the 865 routes have never been isolation-tested?",
  "Every tenant-scoped surface has an isolation test; a structural guard "
  "prevents adding an unscoped one.",
  "LAB_VALIDATED"),
 "07_SECURITY/AUTHENTICATION_AUTHORIZATION.md": (
  "Authentication & Authorization", T,
  "Login, sessions, tokens, agent credentials and object-level "
  "authorisation.",
  "Security",
  "SECURITY_ARCHITECTURE.md · RBAC_MATRIX.md",
  "Auth implementation; agent enrolment credentials; session context routes",
  "Analyst auth and agent credential issuance both work, including single-"
  "use enrolment tokens and revocation.",
  "Password policy, session lifetime, MFA and credential rotation are "
  "undefined.",
  "Full authn/authz specification with tests for expiry, revocation, "
  "reuse and privilege escalation.",
  "CLOSED_BETA"),
 "07_SECURITY/SECRETS_MANAGEMENT.md": (
  "Secrets Management", T,
  "How secrets are stored, rotated, scoped and audited.",
  "Security",
  "CONFIGURATION_GUIDE.md",
  "xdr_secrets routes (7); .env files; IOC provider keys",
  "A secrets surface exists and provider keys are configured. Rotation and "
  "audit of secret access are not specified.",
  "Are any secrets currently in .env that belong in the secrets store?",
  "Every secret has a store, an owner, a rotation period and an access "
  "audit trail.",
  "CLOSED_BETA"),
 "07_SECURITY/AUDIT_ARCHITECTURE.md": (
  "Audit Architecture", T,
  "What is audited, immutably, and how an auditor reconstructs an action.",
  "Security",
  "RESPONSE_ARCHITECTURE.md",
  "xdr_audit_log; incident_state_history append-only worklog",
  "Response executions and incident state changes are audited, with the "
  "worklog held append-only in incident_state_history as the single source "
  "of truth.",
  "Is the audit log tamper-evident, and what is its retention?",
  "Every privileged action audited with actor, time, target and outcome; "
  "tamper evidence proven.",
  "CLOSED_BETA"),
 "07_SECURITY/RESPONSE_SAFETY.md": (
  "Response Safety", T,
  "The guarantees preventing a wrong, duplicate or unauthorised action on "
  "a production machine.",
  "Security + Response",
  "RESPONSE_ARCHITECTURE.md · AUDIT_ARCHITECTURE.md",
  "Response lifecycle invariants; target identity binding; approval "
  "separation",
  "The strongest safety property already holds: a command binds to a "
  "process START IDENTITY, so a recycled PID cannot be killed by mistake, "
  "and verification refuses to accept a probe without that identity basis.",
  "Is there a blast-radius limit — could one request isolate an entire "
  "fleet?",
  "Idempotency, target binding, approval separation, rate and blast-radius "
  "limits all specified and tested.",
  "LAB_VALIDATED"),
 "07_SECURITY/THREAT_MODEL.md": (
  "Threat Model", T,
  "Threats against the platform itself, including a compromised sensor and "
  "a malicious tenant.",
  "Security",
  "SECURITY_ARCHITECTURE.md",
  "STRIDE over the documented trust boundaries",
  "No formal threat model exists. A security tool that can terminate "
  "processes on managed hosts is itself a high-value target.",
  "What happens if an agent credential is stolen — can it read other "
  "endpoints' evidence or issue commands?",
  "Threat model complete with mitigations mapped to tests for every high "
  "and critical threat.",
  "RELEASE_CANDIDATE"),
 "08_VALIDATION/REQUIREMENTS_TRACEABILITY_MATRIX.md": (
  "Requirements Traceability Matrix", T,
  "Trace every requirement to its capability, API, test and proof.",
  "Architecture",
  "CAPABILITY_CATALOG.md · GENERATED_PROOF_INVENTORY.md",
  "Owner directives across this programme; memory/PRD.md (12209 lines)",
  "Requirements are recorded chronologically in PRD.md rather than as a "
  "traceable set, so coverage cannot be computed.",
  "Can requirements be extracted from PRD.md mechanically, or must they be "
  "restated?",
  "Every requirement traced to capability, API, test and proof, with "
  "coverage reported by the reconciliation gate.",
  "CLOSED_BETA"),
 "08_VALIDATION/CISCO_PARITY_MATRIX.md": (
  "Cisco Parity Matrix", T,
  "Observable-capability parity against the reference product, per screen "
  "and per workflow.",
  "Product + Design",
  "CISCO_TO_NIVXRAY_MAPPING.md · CISCO_UI_REFERENCE_CATALOG.md",
  "memory/MASTER_PARITY_MATRIX.md; memory/MASTER_CISCO_DELTA.md; "
  "memory/AMP_TRAJECTORY_CONFORMANCE.md",
  "A parity matrix already exists at the capability level and an AMP "
  "trajectory conformance study is complete. Screen-level parity is not "
  "evidenced because no Cisco screen captures are held.",
  "Which parity items can be judged without Cisco reference captures? "
  "Most cannot.",
  "Every parity row carries reference evidence or "
  "REFERENCE_CAPTURE_REQUIRED, and a state backed by a proof.",
  "CLOSED_BETA"),
 "08_VALIDATION/E2E_ACCEPTANCE_MATRIX.md": (
  "End-to-End Acceptance Matrix", T,
  "The end-to-end chains that must pass for each maturity stage.",
  "QA",
  "MATURITY_MODEL.md · LAB_VALIDATION_PLAN.md",
  "Existing proof scripts; the chain from collection to verified response",
  "Individual stages are proven in isolation. No single test walks "
  "collection to canonical evidence to detection to incident to "
  "investigation to response to verification on real data.",
  "What is the minimum acceptable end-to-end chain for LAB_VALIDATED?",
  "One executable end-to-end acceptance chain per stage, passing on real "
  "evidence only.",
  "LAB_VALIDATED"),
 "08_VALIDATION/PERFORMANCE_MATRIX.md": (
  "Performance Matrix", T,
  "Measured throughput, latency and capacity with stated conditions.",
  "QA",
  "HA_SCALING_GUIDE.md",
  "memory/V1_6_0_BASELINE_METRICS.md; memory/"
  "RC4.6_PIPELINE_PERF_INVESTIGATION.md",
  "Some historical pipeline performance work exists. Nothing has been "
  "measured at fleet scale; the real corpus is roughly 8k events from 2 "
  "endpoints.",
  "What is the target events-per-second per endpoint and per fleet?",
  "Measured numbers for ingest, detection, query and UI render at a "
  "declared fleet size, reproducible by script.",
  "RELEASE_CANDIDATE"),
 "08_VALIDATION/SECURITY_TEST_MATRIX.md": (
  "Security Test Matrix", T,
  "Every security control paired with the test proving it.",
  "Security + QA",
  "07_SECURITY/*",
  "Existing tenant and authorisation proofs; the P0-2C cross-tenant gates",
  "Tenant isolation and object-level authorisation have real tests, "
  "including a proof that a foreign identifier is indistinguishable from an "
  "unknown one. Coverage of authn, secrets, audit and response safety is "
  "partial.",
  "Do we need an external penetration test before a design-partner pilot?",
  "Every control in 07_SECURITY has an automated test; no control is "
  "review-only.",
  "RELEASE_CANDIDATE"),
 "09_RELEASE/ALPHA_PLAN.md": (
  "Internal Alpha Plan", T,
  "Entry and exit criteria for INTERNAL_ALPHA.",
  "Owner",
  "MATURITY_MODEL.md · REALITY_MATRIX.md",
  "Current reality baseline; open P0 list",
  "The platform is at ENGINEERING. The nearest blockers are telemetry "
  "recovery and incident provenance labelling.",
  "Does INTERNAL_ALPHA require the Windows sensor, or is a recovered Linux "
  "pipeline plus labelled provenance sufficient?",
  "Exit criteria met and evidenced by proof scripts, with no synthetic "
  "operational data in the environment.",
  "INTERNAL_ALPHA"),
 "09_RELEASE/BETA_PLAN.md": (
  "Closed Beta Plan", T,
  "Entry and exit criteria for CLOSED_BETA.",
  "Owner",
  "LAB_VALIDATION_PLAN.md",
  "Owner's stated beta bar: multiple real Windows endpoints, continuous "
  "operation, real detections, upgrade and rollback, response "
  "verification, tenant isolation, no synthetic operational dataset",
  "None of the beta criteria are met today; no Windows producer exists and "
  "there is no upgrade mechanism.",
  "How many endpoints and how many days of continuous operation "
  "constitute the beta bar?",
  "Every criterion evidenced, with continuous operation measured over a "
  "declared window.",
  "CLOSED_BETA"),
 "09_RELEASE/PILOT_PLAN.md": (
  "Design Partner Pilot Plan", T,
  "Running the product on a real network with a real partner.",
  "Owner",
  "BETA_PLAN.md · 05_OPERATIONS/*",
  "Beta exit evidence; operational documentation",
  "Not reachable until beta closes; installation, upgrade, observability "
  "and backup are all absent today.",
  "What support commitment can a solo team make to a design partner?",
  "Pilot entry criteria met with an operational runbook and a support "
  "model.",
  "DESIGN_PARTNER_PILOT"),
 "09_RELEASE/RC_PLAN.md": (
  "Release Candidate Plan", T,
  "Hardening, performance, DR and documentation completeness for RC.",
  "Owner",
  "PILOT_PLAN.md · 08_VALIDATION/*",
  "Pilot findings; performance and security matrices",
  "Not reachable yet. HA, backup, DR and performance are all undone.",
  "What is the smallest credible RC scope — Linux plus Windows EDR only, "
  "deferring broader XDR?",
  "All RC gates evidenced with no open P0 or P1.",
  "RELEASE_CANDIDATE"),
 "09_RELEASE/GA_PLAN.md": (
  "GA Plan", T,
  "The complete GA bar and the evidence required for each item.",
  "Owner",
  "GA_READINESS_MATRIX.md",
  "memory/GA_BLOCKERS.md (323 lines); owner's GA requirements",
  "A GA blocker list already exists in memory and predates the current "
  "reality baseline, so it needs reconciling rather than rewriting.",
  "Is GA scoped to NivXForge EDR first, with NivXRay XDR GA later? That "
  "would be a much shorter path.",
  "Every GA gate in GA_READINESS_MATRIX evidenced; the reconciliation gate "
  "passes; no synthetic operational data anywhere.",
  "GA"),
 "09_RELEASE/RELEASE_CHECKLIST.md": (
  "Release Checklist", T,
  "The per-release mechanical checklist.",
  "Owner",
  "GA_PLAN.md",
  "memory/RELEASE_NOTES_*; historical rollback plans",
  "Releases have been performed with ad-hoc checklists recorded per "
  "release in memory.",
  "Who signs off a release when the team is one person plus agents?",
  "One checklist used for every release, with recorded sign-off.",
  "CLOSED_BETA"),
}

TEMPLATE = """<!-- NIVX-DOC
layer: {layer}
status: SPEC_PENDING
generated_by: scripts/docs_skeleton.py
generated_at: {stamp}
-->

# {title}

**STATUS: `SPEC_PENDING`** — this document is a declared gap, not a
placeholder. It must be completed by **{stage}**.

## Purpose
{purpose}

## Owner
{owner}

## Dependencies
{deps}

## Required source inputs
{inputs}

## Known current reality
{reality}

> Authoritative current-state numbers live in
> [`08_VALIDATION/REALITY_MATRIX.md`](../08_VALIDATION/REALITY_MATRIX.md),
> which is generated from the running system. Nothing in this section may
> contradict it.

## Unresolved questions
{questions}

## Completion criteria
{criteria}

## Release stage by which this must be complete
`{stage}`
"""


def main() -> None:
    written, skipped = [], []
    for rel, (title, layer, purpose, owner, deps, inputs, reality,
              questions, criteria, stage) in PENDING.items():
        p = DOCS / rel
        if p.exists():
            txt = p.read_text()
            if re.search(r"^status:\s*(AUTHORED|ADOPTED|GENERATED)", txt,
                         re.M):
                skipped.append(rel)
                continue
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(TEMPLATE.format(
            layer=layer, stamp=STAMP, title=title, purpose=purpose,
            owner=owner, deps=deps, inputs=inputs, reality=reality,
            questions=questions, criteria=criteria, stage=stage))
        written.append(rel)
    print(f"SPEC_PENDING written: {len(written)}   preserved: {len(skipped)}")
    for r in written:
        print(f"  · {r}")


if __name__ == "__main__":
    main()
