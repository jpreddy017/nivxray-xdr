# NivXForge · North Star (Product Goal)

**Status:** Adopted 2026-02-28 · Final · Overrides all lower-level roadmaps when in tension

---

## The single product goal

> **Build the analyst experience until an analyst can investigate a real
> SOC case from ingestion to report without leaving NivXForge.**

Everything else — engines, ADRs, dashboards, sections, placeholders — is a
supporting task to that goal.

---

## The two workflows we are choosing between

### Option A · Current SOC workflow (what analysts do today)

```
Alert arrives
   │
   ├── Open XDR
   ├── Copy command / artifact
   ├── Open CyberChef             (decode)
   ├── Open VirusTotal            (IOC lookup)
   ├── Open ATT&CK Navigator      (technique mapping)
   ├── Google PowerShell fragment (context)
   ├── Write notes                (analyst memory)
   └── Create report              (manual write-up)

Time: 15–30 minutes · 6–8 tools · high cognitive load
```

### Option B · NivXForge (what we are building toward)

```
Alert arrives
   │
   └── Open NivXForge → paste artifact
        │
        ├── Decode
        ├── IOC extraction
        ├── Threat intelligence
        ├── Investigation Brain
        ├── Attack Story
        ├── Evidence Explorer
        ├── MITRE ATT&CK
        └── Report

Time: 3–5 minutes · 1 tool · reasoning visible
```

**Success is when analysts naturally choose Option B over Option A.**

---

## What this North Star naturally prioritises

Anything that reduces the time or cognitive load in Option B:

- Investigate page depth (Investigation Brain, Attack Story, Evidence Explorer)
- Analyst-facing explanations that cite evidence
- Threat intelligence inline (no external tab-switching)
- One-click reports (no manual write-up)
- Ask NivXForge (follow-up questions without leaving the case)

## What this North Star naturally de-prioritises

Anything that doesn't materially help the analyst in Option B:

- Additional governance surfaces beyond what engineering needs
- Platform metrics that only measure the platform, not analyst outcomes
- Feature-for-feature parity with existing SOC tools
- Speculative capabilities without evidence of analyst need

Both categories retain their legitimate homes (engine work, governance,
regressions) — they just do not compete for Investigate-surface investment.

---

## The identity shift this creates

If we stay focused on this goal, NivXForge stops being *"another
cybersecurity tool"* and becomes *"the analyst's workspace."*

That identity is a much stronger product vision than trying to compete
feature-for-feature with CyberChef, VirusTotal, ATT&CK Navigator, and every
other tool in Option A individually. Instead of matching each one, we replace
the *switching between them*.

---

## Relationship to prior governance

This North Star does not repeal anything. It **prioritises** what already
exists:

- `PRODUCT_CHARTER.md` — immutable principles (unchanged)
- `CORPUS_VERSIONING.md` — evidence baseline (unchanged)
- `OPERATIONAL_LOOP.md` — daily process (unchanged)
- `CAPABILITY_REGISTRY.md` — traceability (unchanged)
- `NIVXFORGE_PLATFORM_VISION.md` — IA + outcome framework (unchanged)
- `PLATFORM_POSITIONING.md` — Workspace vs NivXForge (unchanged)
- `REASONING_ENGINE_VISION.md` — long-horizon reasoning shape (unchanged)

When any of these documents is in tension with the North Star, the
North Star wins. But in practice, all of them were written to support this
goal — the North Star simply names it.

---

## What comes next

- Track A (engine): complete ADR-0008 → ADR-0007 → parity → Phase 2.
- Track B (product): every future capability in Investigate is judged by
  whether it moves Option A toward Option B.
- No new governance documents. No new vision documents. No new roadmaps.
- The next artifact worth producing is not a document. It is an analyst
  completing a real case start-to-report in NivXForge and having that
  outcome logged.
