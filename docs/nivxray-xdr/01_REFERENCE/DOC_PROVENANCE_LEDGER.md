<!-- NIVX-DOC
layer: HISTORICAL_RECORD
status: GENERATED
generated_by: scripts/docs_provenance.py
generated_at: 2026-09-07T18:00Z
-->

# DOC PROVENANCE LEDGER

Every pre-existing document under `/app/memory/` reconciled against the
authoritative tree at `/app/docs/nivxray-xdr/`. **157 documents.**

**Nothing is deleted.** A `SUPERSEDED` document keeps its content and
gains a `SUPERSEDED_BY:` pointer. An `ADOPTED` document's decisions are
carried into the named authoritative document; the original is retained
as the provenance record of *when and why* the decision was made.

> Why this matters: `/app/memory/CAPABILITY_REGISTRY.md` was a
> hand-maintained capability list that had drifted from the runtime
> inventory. That is precisely the failure mode the generated matrix plus
> the reconciliation gate now make impossible. The ledger exists so that
> replacing it does not lose the reasoning that produced it.

## Classification

| Class | Count | Meaning |
|---|---:|---|
| `ADOPTED` | 73 | content becomes part of an authoritative document |
| `SUPERSEDED` | 8 | replaced — usually by a GENERATED document that cannot drift |
| `OPERATIONAL` | 10 | still live working state; not documentation |
| `HISTORICAL_REFERENCE` | 66 | point-in-time record, retained, never edited |

## Ledger

| Legacy document | Class | Absorbed into | Note |
|---|---|---|---|
| `memory/AMP_TRAJECTORY_CONFORMANCE.md` | `ADOPTED` | `08_VALIDATION/CISCO_PARITY_MATRIX.md` | Secure Endpoint device-trajectory conformance study |
| `memory/ANALYST_OPERATIONS_ARCHITECTURE.md` | `ADOPTED` | `02_ARCHITECTURE/INCIDENT_ARCHITECTURE.md` | analyst operations phase-0 architecture |
| `memory/ANALYST_OPERATIONS_MANDATE.md` | `ADOPTED` | `02_ARCHITECTURE/INCIDENT_ARCHITECTURE.md` | locked build mandate |
| `memory/ANALYST_WORKSPACE_BLUEPRINT.md` | `ADOPTED` | `02_ARCHITECTURE/INVESTIGATION_ARCHITECTURE.md` | workspace blueprint |
| `memory/ARCHITECTURAL_DIRECTION_IEDDE.md` | `ADOPTED` | `02_ARCHITECTURE/EVIDENCE_ARCHITECTURE.md` | ratified ARB direction |
| `memory/ARCHITECTURE.legacy-v1.md` | `HISTORICAL_REFERENCE` | — | pre-XDR platform architecture, retained for lineage |
| `memory/ARCHITECTURE.md` | `ADOPTED` | `02_ARCHITECTURE/SYSTEM_ARCHITECTURE.md` | master architecture v1.1 — folded into the new system architecture |
| `memory/ARCHITECTURE_v2.md` | `ADOPTED` | `02_ARCHITECTURE/SYSTEM_ARCHITECTURE.md` | 828-line v2 design; the richer source for the target architecture |
| `memory/AUTONOMOUS_INVESTIGATION.md` | `ADOPTED` | `02_ARCHITECTURE/INVESTIGATION_ARCHITECTURE.md` | autonomous investigation operating model |
| `memory/BACKLOG.md` | `OPERATIONAL` | — | post-v1.5.7 backlog |
| `memory/BEE_ARCHITECTURE.md` | `ADOPTED` | `02_ARCHITECTURE/SECURITY_STATE_CAUSAL_ARCHITECTURE.md` | frozen behaviour explanation engine |
| `memory/CAPABILITIES_HLD_LLD.md` | `ADOPTED` | `00_PRODUCT/CAPABILITY_CATALOG.md` | 514-line HLD/LLD |
| `memory/CAPABILITIES_SKELETON.md` | `SUPERSEDED` | `00_PRODUCT/CAPABILITY_CATALOG.md` | earlier skeleton of the same |
| `memory/CAPABILITY_REGISTRY.md` | `SUPERSEDED` | `08_VALIDATION/GENERATED_CAPABILITY_MATRIX.md` | hand-maintained registry replaced by generation from the runtime inventory — this is exactly the drift the gate now prevents |
| `memory/CHANGELOG.md` | `OPERATIONAL` | — | 7292-line release history |
| `memory/CHECKPOINT_v1_3_0_preview.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/COCKPIT_AUDIT_R44.md` | `ADOPTED` | `03_DESIGN/INFORMATION_ARCHITECTURE.md` | incident cockpit UX audit |
| `memory/CORPUS_VERSIONING.md` | `ADOPTED` | `04_DEVELOPMENT/TESTING_GUIDE.md` | evidence benchmark discipline |
| `memory/CURRENT_STATE_AUDIT.md` | `SUPERSEDED` | `08_VALIDATION/REALITY_MATRIX.md` | 605-line hand audit (2026-02) |
| `memory/CURRENT_STATE_AUDIT_RECONCILIATION.md` | `SUPERSEDED` | `08_VALIDATION/REALITY_MATRIX.md` | audit reconciliation (2026-08) |
| `memory/DECISION_LOG.md` | `OPERATIONAL` | — | chronological decision index — remains the index of record |
| `memory/DEMO_PAYLOAD_BATTERY.md` | `ADOPTED` | `04_DEVELOPMENT/TESTING_GUIDE.md` | demo payload battery — TEST-ONLY, must never seed the operational environment |
| `memory/DEPLOYMENT_EVIDENCE.md` | `HISTORICAL_REFERENCE` | — | RC2.0 deployment evidence pack |
| `memory/DESIGN_NIVXFORGE_ANALYST_PLATFORM.md` | `ADOPTED` | `00_PRODUCT/PRODUCT_BOUNDARIES.md` | design memo, awaiting decision |
| `memory/DEVELOPING_V2.md` | `ADOPTED` | `04_DEVELOPMENT/DEVELOPMENT_GUIDE.md` | contributor onboarding for v2 |
| `memory/DIAGNOSTIC_RC4_SHELLCODE_2026-02-28.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/DOCX_L2_DIAGNOSTIC.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/DOCX_WORKSPACE_GAP_REPORT.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/ENGINES_UI_PERF.md` | `ADOPTED` | `08_VALIDATION/PERFORMANCE_MATRIX.md` | engines/UI/perf/security notes |
| `memory/EVIDENCE_INVENTORY_2026-02-28.md` | `HISTORICAL_REFERENCE` | — | point-in-time evidence inventory |
| `memory/FUNDRAISING_PACK.md` | `HISTORICAL_REFERENCE` | — | commercial, out of scope for the engineering tree |
| `memory/GA_BLOCKERS.md` | `ADOPTED` | `08_VALIDATION/GA_READINESS_MATRIX.md` | P0 GA blocker list; must be reconciled against the reality baseline |
| `memory/GOLDEN_CASE_SAMPLE1.md` | `ADOPTED` | `04_DEVELOPMENT/TESTING_GUIDE.md` | golden diagnostic case |
| `memory/GOVERNANCE.md` | `ADOPTED` | `04_DEVELOPMENT/CONTRIBUTION_RULES.md` | RC5 preservation + platform governance directive |
| `memory/GOVERNANCE_RULES.md` | `ADOPTED` | `04_DEVELOPMENT/CONTRIBUTION_RULES.md` | 1039-line ARB rules — the largest single input to contribution rules |
| `memory/IDA_ARCHITECTURE.md` | `ADOPTED` | `02_ARCHITECTURE/EVIDENCE_ARCHITECTURE.md` | frozen intelligent document analyzer |
| `memory/IMPLEMENTATION_ROADMAP.md` | `OPERATIONAL` | `09_RELEASE/LAB_VALIDATION_PLAN.md` | active NivXForge roadmap |
| `memory/IR_REPORT_CONTRACT.md` | `ADOPTED` | `02_ARCHITECTURE/INCIDENT_ARCHITECTURE.md` | frozen report contract |
| `memory/IUE_ARCHITECTURE_TRACE.md` | `HISTORICAL_REFERENCE` | — | read-only track-A trace |
| `memory/IUE_ARCHITECTURE_V2.md` | `ADOPTED` | `02_ARCHITECTURE/INVESTIGATION_ARCHITECTURE.md` | frozen IUE v2 |
| `memory/IUE_INVESTIGATION_SSOT_RECONCILIATION.md` | `ADOPTED` | `02_ARCHITECTURE/INVESTIGATION_ARCHITECTURE.md` | unresolved IUE/investigation SSOT authority question — carried forward as an open question, NOT silently closed |
| `memory/IVE_ARCHITECTURE.md` | `ADOPTED` | `02_ARCHITECTURE/INVESTIGATION_ARCHITECTURE.md` | frozen IVE |
| `memory/L1_INVESTIGATION_API_PLAYBOOK.md` | `ADOPTED` | `04_DEVELOPMENT/API_GUIDE.md` | L1 investigation API playbook |
| `memory/LAUNCH_CONTENT_PACK.md` | `HISTORICAL_REFERENCE` | — | marketing copy |
| `memory/LAYER2_FINAL_EXECUTION_CONTRACT.md` | `HISTORICAL_REFERENCE` | — | layer 2 execution contract |
| `memory/LAYER2_QUEUE_REBUILD_MANDATE.md` | `ADOPTED` | `03_DESIGN/INFORMATION_ARCHITECTURE.md` | incident queue rebuild mandate |
| `memory/LLM_TRAINING_SCHEMA.md` | `HISTORICAL_REFERENCE` | — | LLM fine-tune schema |
| `memory/MASTER_CISCO_DELTA.md` | `ADOPTED` | `01_REFERENCE/CISCO_XDR_REFERENCE_MODEL.md` | delta mined from the owner's XDR.pptx (76 slides) |
| `memory/MASTER_GATE.md` | `ADOPTED` | `04_DEVELOPMENT/CONTRIBUTION_RULES.md` | binding master gate, read-first rules |
| `memory/MASTER_OWNERSHIP_AUDIT.md` | `ADOPTED` | `02_ARCHITECTURE/COMPONENT_ARCHITECTURE.md` | 1207-line ownership+wiring audit — the primary input for component ownership |
| `memory/MASTER_PARITY_MATRIX.md` | `ADOPTED` | `08_VALIDATION/CISCO_PARITY_MATRIX.md` | matrix 1, capability parity |
| `memory/MATURITY_ASSESSMENT_2026-09-02.md` | `ADOPTED` | `00_PRODUCT/MATURITY_MODEL.md` | 444-line maturity assessment |
| `memory/MIGRATION_DEPENDENCIES.md` | `ADOPTED` | `02_ARCHITECTURE/INTEGRATION_ARCHITECTURE.md` | what XDR must eventually own itself |
| `memory/NIVXFORGE_EDR_ROADMAP.md` | `ADOPTED` | `09_RELEASE/LAB_VALIDATION_PLAN.md` | EDR-only track roadmap |
| `memory/NIVXFORGE_PLATFORM_VISION.md` | `ADOPTED` | `00_PRODUCT/PRODUCT_VISION.md` | frozen platform vision |
| `memory/NIVXMACHINES_REDIRECT_FIX_HANDOFF.md` | `HISTORICAL_REFERENCE` | — | unrelated website SEO task |
| `memory/NIVXRAY_ARCHITECTURE_V1.md` | `HISTORICAL_REFERENCE` | — | frozen 1186-line investigation architecture; superseded by the two-product split but load-bearing for IUE lineage |
| `memory/NIVXRAY_CT_SCAN_REVIEW.md` | `HISTORICAL_REFERENCE` | — | honest CT-scan review, v1.3.0-preview |
| `memory/NIVXRAY_CURRENT_STATE_TRUTH.md` | `SUPERSEDED` | `08_VALIDATION/REALITY_MATRIX.md` | hand-written current-state truth audit — now generated, so it can no longer drift |
| `memory/NIVXRAY_ENTERPRISE_UX_GAP_ANALYSIS.md` | `ADOPTED` | `03_DESIGN/INFORMATION_ARCHITECTURE.md` | enterprise UX gap analysis |
| `memory/NIVXRAY_VISUAL_GRAMMAR.md` | `ADOPTED` | `03_DESIGN/DESIGN_SYSTEM.md` | 617-line locked visual grammar |
| `memory/NIVXRAY_XDR_360_AUDIT.md` | `SUPERSEDED` | `08_VALIDATION/REALITY_MATRIX.md` | 360 production-readiness audit |
| `memory/NORTH_STAR.md` | `ADOPTED` | `00_PRODUCT/PRODUCT_VISION.md` | aspirational north star — explicitly not a roadmap |
| `memory/NORTH_STAR_PRODUCT_GOAL.md` | `ADOPTED` | `00_PRODUCT/PRODUCT_VISION.md` | adopted product goal |
| `memory/NivXRay_360_Architecture.md` | `ADOPTED` | `02_ARCHITECTURE/COMPONENT_ARCHITECTURE.md` | current+target component view |
| `memory/NivXRay_360_Audit_Spec.md` | `HISTORICAL_REFERENCE` | — | audit execution brief |
| `memory/NivXRay_360_Evidence_Matrix.md` | `SUPERSEDED` | `08_VALIDATION/REQUIREMENTS_TRACEABILITY_MATRIX.md` | flat citation table of capability evidence |
| `memory/NivXRay_360_Product_Market_Posture.md` | `HISTORICAL_REFERENCE` | — | 1171-line market posture, commercial |
| `memory/NivXRay_Investor_Due_Diligence.md` | `HISTORICAL_REFERENCE` | — | self-declared superseded |
| `memory/NivXRay_Stage1_STEP1_Architecture_Audit.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/NivXRay_Stage1_STEP2_Reuse_Matrix.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/NivXRay_Stage1_STEP3_Compatibility.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/NivXRay_Stage1_STEP4_DataFlows.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/NivXRay_Stage1_STEP5_Regression.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/NivXRay_Stage1_STEP6_LaneA_Review.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/NivXRay_Strategic_Master_Positioning.md` | `ADOPTED` | `00_PRODUCT/PRODUCT_VISION.md` | 1164-line locked positioning |
| `memory/OFFLINE_LLM_DEPLOYMENT.md` | `ADOPTED` | `05_OPERATIONS/DEPLOYMENT_GUIDE.md` | offline LLM deployment |
| `memory/OPERATIONAL_LOOP.md` | `ADOPTED` | `05_OPERATIONS/OBSERVABILITY_GUIDE.md` | standing operational feedback loop |
| `memory/P0_1B_SCOPE.md` | `ADOPTED` | `04_DEVELOPMENT/DETECTION_CONTENT_GUIDE.md` | deobfuscation scope |
| `memory/P0_2C_ALIAS_SITE_SWEEP.md` | `ADOPTED` | `02_ARCHITECTURE/EVIDENCE_ARCHITECTURE.md` | the endpoint-identity invariant — the reference pattern for every future platform invariant |
| `memory/P0_2_EDR_RESPONSE_SURFACE.md` | `ADOPTED` | `02_ARCHITECTURE/RESPONSE_ARCHITECTURE.md` | EDR response surface |
| `memory/P0_MISSION.md` | `HISTORICAL_REFERENCE` | — | locked X-LAB P0 mission |
| `memory/P0_P1_BUG_BASELINE.md` | `HISTORICAL_REFERENCE` | — | pre-migration bug baseline |
| `memory/PHASE0_COMPLETION.md` | `HISTORICAL_REFERENCE` | — | permanent audit record, do not edit |
| `memory/PHASE4_ORCHESTRATION_SPEC.md` | `ADOPTED` | `02_ARCHITECTURE/AUTOMATION_ARCHITECTURE.md` | auto-investigation orchestration preview spec |
| `memory/PLATFORM_POSITIONING.md` | `ADOPTED` | `00_PRODUCT/PRODUCT_BOUNDARIES.md` | NivXForge vs Workspace positioning |
| `memory/PRD.md` | `OPERATIONAL` | — | 12209-line master requirements + progress log; the live working document for this programme |
| `memory/PRODUCT_CHARTER.md` | `ADOPTED` | `00_PRODUCT/PRODUCT_VISION.md` | product charter + v1.6.0 roadmap |
| `memory/PR_2_1_2_DIRECTIVE.md` | `HISTORICAL_REFERENCE` | — | ARB directive |
| `memory/RC1_READINESS.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/RC2.1a_ROLLBACK_PLAN.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/RC2.2_ROLLBACK_PLAN.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/RC2_ROADMAP.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/RC4.5.6_DEPLOYMENT_NOTE.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/RC4.5.6_INFRA_REPORT_FOR_EMERGENT.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/RC4.5_ARCHITECTURE_AUDIT.md` | `HISTORICAL_REFERENCE` | — | 729-line RC4.5 architecture + capability audit |
| `memory/RC4.5_RELEASE_NOTES.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/RC4.6_PIPELINE_PERF_INVESTIGATION.md` | `ADOPTED` | `08_VALIDATION/PERFORMANCE_MATRIX.md` | pipeline perf investigation |
| `memory/RC5_CORRECTNESS_OBSERVABILITY_SPRINT_COMPLIANCE.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/RC5_EVIDENCE_GRAPH_ROADMAP.md` | `ADOPTED` | `02_ARCHITECTURE/INVESTIGATION_ARCHITECTURE.md` | IKG roadmap |
| `memory/RC5_PHASE_11_0_COMPLIANCE.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/RC5_PHASE_11_1_11_2_COMPLIANCE.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/RC5_PHASE_2_COMPLIANCE.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/RC5_PHASE_3_COMPLIANCE.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/RC5_PHASE_4_5_COMPLIANCE.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/RC5_PHASE_4_COMPLIANCE.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/RC5_PHASE_5_COMPLIANCE.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/RC5_PHASE_6_COMPLIANCE.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/RC5_PHASE_7_COMPLIANCE.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/RC5_PHASE_8_COMPLIANCE.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/RC5_PHASE_9_5B_COMPLIANCE.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/RC5_PHASE_9_5C_COMPLIANCE.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/RC5_PHASE_9_5C_PLUS_COMPLIANCE.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/RC5_PHASE_9_5D_COMPLIANCE.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/RC5_PHASE_9_5_COMPLIANCE.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/RC5_PHASE_9_COMPLIANCE.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/RC5_PLUGIN_API.md` | `ADOPTED` | `04_DEVELOPMENT/INTEGRATION_SDK_GUIDE.md` | frozen plugin API |
| `memory/RC5_SEMANTIC_ENGINE_SPEC.md` | `ADOPTED` | `02_ARCHITECTURE/DETECTION_ARCHITECTURE.md` | 709-line semantic execution engine spec |
| `memory/REAL_WORLD_LOG.md` | `OPERATIONAL` | — | real SOC case log |
| `memory/REASONING_ENGINE_VISION.md` | `ADOPTED` | `02_ARCHITECTURE/SECURITY_STATE_CAUSAL_ARCHITECTURE.md` | analyst reasoning vision |
| `memory/REFERENCE_ADAPTATION.md` | `ADOPTED` | `01_REFERENCE/CISCO_TO_NIVXRAY_MAPPING.md` | commercial EDR/XDR capabilities to adopt, not copy |
| `memory/RELEASE_NOTES_v1.0.0-RC2.1a.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/RELEASE_NOTES_v1.0.0-RC2.2.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/REMINDERS.md` | `OPERATIONAL` | — | durable pending-work ledger |
| `memory/RESEARCH_REFERENCES.md` | `ADOPTED` | `01_REFERENCE/SOURCE_REGISTER.md` | saved research sources |
| `memory/ROADMAP.md` | `OPERATIONAL` | `09_RELEASE/LAB_VALIDATION_PLAN.md` | 1462-line live roadmap — stays live until the release plans absorb it |
| `memory/SPRINT_1_CHECKPOINT.md` | `HISTORICAL_REFERENCE` | — | sprint checkpoint |
| `memory/STEP1_DIFF_REPORT.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/STEP1_PHASE3_REPORT.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/STEP1_WORKLOG_ADOPTION_CHECK.md` | `ADOPTED` | `02_ARCHITECTURE/INCIDENT_ARCHITECTURE.md` | worklog SSOT decision: incident_state_history is the only worklog |
| `memory/STEP2_RESPONSE_SERVICE_DEPLOY.md` | `ADOPTED` | `02_ARCHITECTURE/RESPONSE_ARCHITECTURE.md` | response service deploy |
| `memory/UNIVERSAL_DECODER_COVERAGE_MATRIX.md` | `ADOPTED` | `04_DEVELOPMENT/DETECTION_CONTENT_GUIDE.md` | decoder coverage |
| `memory/UNIVERSAL_DECODER_LICENSE_MATRIX.md` | `ADOPTED` | `04_DEVELOPMENT/DETECTION_CONTENT_GUIDE.md` | decoder licensing |
| `memory/UNIVERSAL_DECODER_SOURCE_INVENTORY.md` | `ADOPTED` | `04_DEVELOPMENT/DETECTION_CONTENT_GUIDE.md` | decoder sources |
| `memory/V1_6_0_BASELINE_METRICS.md` | `ADOPTED` | `08_VALIDATION/PERFORMANCE_MATRIX.md` | captured baseline metrics |
| `memory/V1_6_0_PLANNING.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/VISION_ENTERPRISE_INTEGRATION.md` | `ADOPTED` | `02_ARCHITECTURE/INTEGRATION_ARCHITECTURE.md` | enterprise integration vision and scope |
| `memory/VISUAL_LANGUAGE.md` | `ADOPTED` | `03_DESIGN/DESIGN_SYSTEM.md` | 514-line visual language system — must be reconciled with the visual grammar; two design authorities cannot both survive |
| `memory/WAKE_UP_REMINDER.md` | `HISTORICAL_REFERENCE` | — | session note |
| `memory/WORKSPACE_ARCHITECTURE_RULES.md` | `SUPERSEDED` | `02_ARCHITECTURE/INVESTIGATION_ARCHITECTURE.md` | already self-declared superseded inside the file |
| `memory/WORKSPACE_USER_JOURNEY.md` | `ADOPTED` | `06_USER_GUIDES/SOC_ANALYST_GUIDE.md` | workspace user journey |
| `memory/WORKSPACE_VALIDATION_MATRIX.md` | `ADOPTED` | `08_VALIDATION/E2E_ACCEPTANCE_MATRIX.md` | workspace validation package |
| `memory/XDR_EDR_PARITY_AUDIT.md` | `ADOPTED` | `00_PRODUCT/PRODUCT_BOUNDARIES.md` | two-product parity audit |
| `memory/XDR_SEPARATION_HANDOFF.md` | `ADOPTED` | `00_PRODUCT/PRODUCT_BOUNDARIES.md` | application-separation directive |
| `memory/Y0_CISCO_XDR_REFERENCE_INTAKE.md` | `ADOPTED` | `01_REFERENCE/CISCO_COMPONENT_CATALOG.md` | first Cisco reference intake + gap matrices |
| `memory/Y1_STATUS_REPORT.md` | `ADOPTED` | `03_DESIGN/NAVIGATION_SPEC.md` | product separation + rail information architecture — the origin of the shipped 8-primary rail |
| `memory/_archive_ARCHITECTURAL_DIRECTION_ICUE_superseded.md` | `HISTORICAL_REFERENCE` | — | already archived and self-superseded |
| `memory/agent_learnings.md` | `OPERATIONAL` | — | agent learnings |
| `memory/evaluation_rubric.md` | `ADOPTED` | `04_DEVELOPMENT/TESTING_GUIDE.md` | permanent payload evaluation rubric |
| `memory/lab-2.0-api-contract.md` | `ADOPTED` | `04_DEVELOPMENT/API_GUIDE.md` | Lab 2.0 API governance artefact |
| `memory/lab-2.0-design-specification.md` | `ADOPTED` | `03_DESIGN/PAGE_TEMPLATES.md` | 541-line workspace design spec |
| `memory/phase-0-parity-guard-report.md` | `HISTORICAL_REFERENCE` | — | parity guard completion |
| `memory/test_credentials.md` | `OPERATIONAL` | — | live test credentials |
| `memory/v1.4.1_P0_brief.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/v1.4.2_refinement_brief.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/v1.5.0_resource_nodes_brief.md` | `HISTORICAL_REFERENCE` | — | point-in-time release/phase/diagnostic record — retained unedited |
| `memory/xlab_parity_audit.md` | `HISTORICAL_REFERENCE` | — | X-Lab capability parity audit |

## Open reconciliation risks

1. **Two design authorities.** `NIVXRAY_VISUAL_GRAMMAR.md` (617 lines) and `VISUAL_LANGUAGE.md` (514 lines) are both ADOPTED into `03_DESIGN/DESIGN_SYSTEM.md`. They have never been diffed. One must become authoritative.
2. **Three architecture documents.** `ARCHITECTURE.md`, `ARCHITECTURE_v2.md` and `NIVXRAY_ARCHITECTURE_V1.md` describe overlapping but different systems. v2 is the richest source; V1 is frozen and still load-bearing for IUE lineage.
3. **Three governance documents.** `GOVERNANCE_RULES.md`, `GOVERNANCE.md` and `MASTER_GATE.md` all assert binding rules.
4. **An unresolved SSOT question is carried forward, not closed.** `IUE_INVESTIGATION_SSOT_RECONCILIATION.md` leaves the investigation authority question open; it is now recorded as an explicit unresolved question in `02_ARCHITECTURE/INVESTIGATION_ARCHITECTURE.md` rather than quietly dropped.
5. **Two live roadmaps.** `ROADMAP.md` (1462 lines) and `IMPLEMENTATION_ROADMAP.md` both claim to be active. Both stay OPERATIONAL until `09_RELEASE/` absorbs them.
6. **Test-only corpora must never leak.** `DEMO_PAYLOAD_BATTERY.md` and `GOLDEN_CASE_SAMPLE1.md` are adopted into the testing guide explicitly as TEST-ONLY. The operational environment defaults to real evidence only.
