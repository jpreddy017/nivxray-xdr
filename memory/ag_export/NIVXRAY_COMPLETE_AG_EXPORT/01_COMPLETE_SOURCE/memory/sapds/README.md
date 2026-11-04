# NivXRay Investigation Workspace (Lab 2.0) — Software Architecture & Product Design Specification (SAPDS)

> **Status**: v1.0 · Living document set
> **Purpose**: The complete engineering blueprint for NivXRay Lab 2.0.
> **Rule**: No implementation code lands until the relevant volume(s) are reviewed and approved.
> **Governance**: Every volume is a superseding artefact — changes require an ADR reference or an operator-approved amendment.

## Reading order

For a new engineer joining the project:

1. **Vol 0** · Vision — *why we're building this*
2. **Vol 1** · Enterprise Architecture — *the 10,000-foot picture*
3. **Vol 5** · CIO Architecture — *the object every subsystem revolves around*
4. **Vol 2 / Vol 3** · Backend / Frontend — *the two sides of the platform*
5. **Vol 7** · Data Flow — *how the CIO travels*
6. **Vol 4** · Workspace Architecture — *the analyst experience*
7. **Vol 9** · Lens Architecture — *the eight views*
8. **Vol 24** · Roadmap — *the sequence of implementation*
9. All other volumes on demand

## Volume Index

| # | Title | Owner | Status |
|---|---|---|---|
| 0 | Vision & Product Philosophy | Product | Draft |
| 1 | Enterprise Architecture | Platform | Draft |
| 2 | Backend Architecture | Backend | Draft |
| 3 | Frontend Architecture | Frontend | Draft |
| 4 | Workspace Architecture | Frontend | Draft |
| 5 | CIO Architecture | Backend | Ratified (Slice-A/B/C/D shipped) |
| 6 | State Architecture | Frontend | Draft |
| 7 | Data Flow Architecture | Platform | Draft |
| 8 | Component Architecture | Frontend | Draft |
| 9 | Lens Architecture (×8) | Frontend | Draft |
| 10 | Graph Architecture | Frontend | Draft |
| 11 | Design System Architecture | Design | Draft |
| 12 | Theme Architecture | Design | Draft |
| 13 | Interaction Architecture | Frontend/UX | Draft |
| 14 | Motion Architecture | Design | Draft |
| 15 | Accessibility Architecture | Frontend | Draft |
| 16 | Performance Architecture | Frontend | Draft |
| 17 | Security Architecture | Platform | Draft |
| 18 | Plugin Architecture | Platform | Draft |
| 19 | Deployment Architecture | Ops | Draft |
| 20 | Testing Architecture | QA/Eng | Draft |
| 21 | Release Architecture | Ops | Draft |
| 22 | AI Architecture | Product/Eng | Draft |
| 23 | Future Evolution Architecture | Product | Draft |
| 24 | Implementation Roadmap | Engineering | Draft |
| 25 | UI & Experience Specification | Design | Draft |

## Companion specifications (not part of SAPDS but binding)

- **ADR-0014** · `/app/memory/adr/0014-canonical-investigation-object.md` · Canonical Investigation Object binding principles (§1.1.1-19)
- **Lab 2.0 API Contract** · `/app/memory/lab-2.0-api-contract.md` · Field-by-field CIO/Summary contract
- **Lab 2.0 Design Specification** · `/app/memory/lab-2.0-design-specification.md` · Critical review of the HTML prototype + preliminary architecture

## Change control

Every volume ends with a **Change Log** section. Any material amendment is entered there with date + rationale. Structural amendments require a superseding ADR referenced in the log.
