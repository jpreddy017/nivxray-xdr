# NivXRay 360° Audit Spec — MANDATORY EXECUTION BRIEF
**For:** Fresh E2 session (post-fork)
**Status:** Verbatim customer specification, 2026-02-13
**Priority:** This spec supersedes the §5-31 scope described in `NivXRay_Investor_Due_Diligence.md`. Execute the full 40-section audit.

---

## READ FIRST · non-negotiables
1. **Truth first · Strategy second · Marketing last.** The customer explicitly said this in the spec.
2. **Every claim MUST cite** repository file/path, module/class/function, API endpoint, test command, runtime evidence, or benchmark. Anything else = ❓ UNKNOWN.
3. **Three-truth discipline**: A = TODAY (verified only), B = TARGET (PRD/ADRs), C = MARKET VISION. Never represent B or C as A.
4. **Six-class classification**: ✅ VERIFIED · 🟡 PARTIAL · 🟠 IMPLEMENTED BUT NOT PRODUCTION-READY · 🔵 PLANNED · ❌ NOT IMPLEMENTED · ❓ UNKNOWN.
5. **Do NOT inflate scores** in the Executive Scorecard to make NivXRay investable.
6. **Existing PRD/README/roadmap/comments/mocks/UI-labels do NOT prove implementation.** Only executable code + reproducible commands do.
7. **Do NOT stop at documentation** — run tests, hit APIs, query the DB when uncertain.

---

## Required deliverables (create ALL three files)
1. `/app/memory/NivXRay_360_Product_Market_Posture.md` (primary, ~40 sections, with TOC)
2. `/app/memory/NivXRay_360_Evidence_Matrix.md` (all evidence citations flattened into a lookup table)
3. `/app/memory/NivXRay_360_Architecture.md` (current + target architecture diagrams)

## Existing seed (build on it, do not discard)
- `/app/memory/NivXRay_Investor_Due_Diligence.md` — v0.1 seed with 5 verified honesty items already flagged. Preserve those rows unless fresh evidence contradicts them.

## 40 sections (execute in order — verbatim from customer)

1. Executive NivXRay Definition
2. Product Boundary (is / is-not)
3. Complete Current Architecture (current + target diagrams)
4. Data / Evidence Flow (trace one piece of evidence end-to-end)
5. Universal Input / Log-Type Capability (endpoint · network · identity · cloud · application · security-products)
6. Artifact Analysis (recursive, artifact-first)
7. Decoding Engine (every codec, defect list, confidence)
8. Canonical Evidence Model (schemas + provenance)
9. Processing Architecture (workers · queues · async · distributed)
10. Correlation Engine (deterministic vs heuristic vs LLM)
11. Investigation Knowledge Graph (nodes · edges · SSOT status)
12. Semantic Engine (raw vs semantic evidence)
13. MITRE ATT&CK (multi-technique per evidence)
14. Verdict Engine (traceability, negative explainability)
15. Investigation Outputs (Summary · Attack Story · Timeline · Evidence · Graph · Trajectory · Process Tree · Verdict · Report)
16. Analyst Workspace (functional vs placeholder UI)
17. Detection Capability (malware · endpoint · identity · network · cloud · app · exfil · C2 · persistence · lateral · credential · LOLBAS)
18. Threat Hunting (hypothesis · IOC · behavioral · ATT&CK · timeline · cross-device · cross-user · historical · graph · query lang · automated)
19. Integrations (real vs simulated vs planned)
20. Security of NivXRay itself (auth · RBAC · SSRF · injection · secrets · dependency vulns · encryption · retention · evidence integrity)
21. Scalability (events/sec · investigations/sec · concurrent · p50/p95/p99 · endpoint scaling tiers)
22. Testing / Quality (exact test counts, gaps)
23. Production Readiness (deployment · observability · HA · DR · upgrades · rollback)
24. Current Demo / Customer Experience (best-possible reproducible flow, honest about breaks)
25. Competitive Landscape (SIEM · XDR · EDR · MDR · SOAR · CNAPP · CSPM · NDR · TIP · sandbox · AI SOC · IR platforms)
26. Market Opportunity (per-category evaluation)
27. Ideal Customer Profile (per-segment pain · buyer · champion · objection · proof)
28. Business Model (hypotheses only — do not pick a final price without evidence)
29. Technology Moat (current vs future)
30. AI Strategy (where LLM should + should NOT be used)
31. Product Gaps (P0/P1/P2/P3 ranked)
32. Roadmap (0-3 / 3-6 / 6-12 / 12-24 months with business + technical + investor reasons)
33. NivXRay vs Giants (wedge · first battle · 3-year expansion)
34. NivXRay Category (existing category vs new category, own-it argument)
35. Investor Truth Layer (10 impressive · 10 incomplete · 5 differentiators · 5 do-not-claim · 10 metrics · 5 gaps · 5 future moats · 1-sentence honest description · 3-year vision · demo)
36. Customer Truth Layer (what we can sell today · required proof · required features · objections · CISO approval · procurement rejection triggers)
37. Investor Due-Diligence Checklist (every question an investor asks + current answer + evidence + unknowns)
38. Pitch Deck Fact Base (green/yellow/red per potential claim)
39. Final NivXRay Posture (strongest asset · biggest weakness · strongest differentiator · biggest competitive threat · best wedge · most important next investment · potential moat · 3-year vision · why-win · why-fail)
40. Final Executive Summary

## Executive Scorecard (MANDATORY final deliverable)
Score /10 with evidence + major-gap column, for:
- Product maturity · Detection · Investigation · Correlation · Artifact analysis · Semantic analysis · ATT&CK · Verdict · Analyst UX · Integrations · Scalability · Security · Reliability · AI capability · Enterprise readiness · Competitive differentiation · Technology moat · Market readiness · Investor readiness

Scores must be evidence-based. Do NOT inflate.

## Estimated effort
6–10 hours of systematic inspection. Budget ~180K tokens on a fresh E2 session.

## Final principle (verbatim from customer)
> The purpose of this audit is NOT to prove that NivXRay is already a giant.
> The purpose is to determine: what has actually been built, what is technically special, where the product can win, what must be built to compete at enterprise scale, and whether there is a credible path for NivXRay to become a major cybersecurity platform.
> Be exhaustive. Be skeptical. Be technically precise. Be commercially realistic. Be investor-ready.
> Truth first. Strategy second. Marketing last.
