# ADR-0015 · Workspace Architecture

**Status**: Accepted (Phase -1 · Architecture Lock)
**Date**: 2026-02-28
**Supersedes**: none · **Superseded by**: none
**Related**: ADR-0014, Lab 2.0 Constitution, Lab 2.0 API Contract

## Context

Lab 2.0 is not a page or a dashboard. It is an Investigation Workspace — a single-context environment where one CIO is loaded and every panel synchronises to it (Constitution §4).

## Decision

The Workspace has a fixed structural anatomy:

```
TopBar · VerdictRibbon · Command Palette trigger · Live/Static · Presence
─────────────────────────────────────────────────────────────────────────
CaseSpine │  LensCanvas (one active lens at a time OR split view)  │ Findings
          │                                                         │  Panel
          │                                                         │
          │                                                         │
─────────────────────────────────────────────────────────────────────────
                    EvidenceBar (always-visible; bound to selection)
```

- Exactly one CIO is loaded per Workspace instance.
- LensCanvas hosts one of eight lenses (Story · Source · Behavior · Timeline · ATT&CK · Entity · Report · Knowledge).
- Split view = two lenses side-by-side synchronised on the same CIO + same selection.
- Workspace layout is persistable per user (Phase B.5).
- Multi-monitor spans via `BroadcastChannel` sync of the Selection Store.

## Consequences

- Any component that does not fit this anatomy must justify its position in an ADR amendment.
- No modal that competes with the LensCanvas is allowed. The Command Palette and Help Overlay are the only sanctioned overlays.
- `AutoInvestigatePage.jsx` (current Workspace) remains untouched; Lab 2.0 lives under `/nivxforge/*` routes.
