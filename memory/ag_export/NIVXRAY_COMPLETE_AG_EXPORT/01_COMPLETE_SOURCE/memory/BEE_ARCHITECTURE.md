# NivXRay · Behavior Explanation Engine (BEE)

## FROZEN ARCHITECTURE — 2026-03-01

> This document is the single source of truth for the BEE.  BEE is
> now a first-class deterministic engine, elevated from the earlier
> "behavior_explainer" module.  It is reusable across every domain
> engine (DIE · IDA · CIA · IOCE · MITE · LBE · Domain analyzers).

---

## Definition

**BEE — Behavior Explanation Engine**
A deterministic reusable subsystem that transforms structured
findings from any engine into evidence-backed analyst explanations.
Every explanation carries three sections — **What This Does**,
**Why It Matters**, and **Evidence** — with each sentence traceable
to concrete captures against the artifact's normalized form.

BEE is deterministic (no LLM), template-driven, and reads exclusively
from the SSOT — no engine hands data directly to BEE.

---

## Rule R18 — Explanation Everywhere, Deterministically

- Every engine's structured finding SHOULD ship a BEE template so
  the SSOT carries an explanation for it.
- Templates capture concrete substrings from the artifact's
  normalized form so the explanation reflects **this** paste, not
  just the family.
- Every explanation writes into `SSOT.explanations[]` as a
  first-class array (Rule R11 · consumers read from the SSOT only).
- Templates are additive.  Adding a new template never removes an
  existing one.

---

## Universal Explanation Object

```jsonc
{
  "id":              "expl-001",
  "target_kind":     "command" | "ioc" | "mitre" | "lolbas" |
                     "registry" | "process" | "yara" | "sigma" |
                     "cve" | "threat_actor" | "document_finding",
  "target_id":       "cmd-3",          // stage.id / ioc.id / …
  "family":          "browser-extension-load",
  "what_this_does":  ["...", "..."],
  "why_it_matters":  "...",
  "evidence":        ["--load-extension", "--user-data-dir",
                      "--headless=new"],
  "coverage":        1.0,               // 0–1 template match strength
  "template_id":     "bee.browser.extension-load.v1"
}
```

---

## Where BEE Runs

```
                     SSOT slices
                     ────────────
      commands[]  ─────┐
      iocs{}      ─────┤
      mitre[]     ─────┤   ┌─────┐   SSOT.explanations[]
      lolbas[]    ─────┼──▶│ BEE │──────────────▶ ▲
      knowledge_  ─────┤   └─────┘                │
      graph                                       │
      ida.document_findings[] ──▶                 IVE Evidence Projection
                                                  IVE Report Projection
                                                  Workspace Node Inspector
```

BEE never mutates the source slices.  It writes only to
`SSOT.explanations[]`.

---

## Templates

Templates live in `services/die/bee_templates/` — one file per
subject area.  Every template exports:

```python
{
    "id":            "bee.browser.extension-load.v1",
    "target_kind":   "command",
    "family":        "browser-extension-load",
    "intro":         "Launches a Chromium-family browser with a custom unpacked extension.",
    "bullets":       [(regex, template_string), ...],
    "why":           "...",
    "evidence_regex":[regex, regex, ...]     # extracted verbatim
}
```

Adding new coverage = adding a new file.  No existing code changes.

---

## Explanation Coverage Contract

The Investigation Quality Gate enforces:

- Every stage with a recognised `command_family` MUST have a BEE
  explanation.
- Every IOC cluster with ≥ 5 members MUST have a BEE explanation.
- Every ATT&CK technique appearing in `mitre[]` SHOULD have a BEE
  explanation (soft gate for v1).
- `SSOT.explanation_coverage.percentage` MUST be ≥ 90% for every
  fixture in the Quality Gate to pass.

Emitted as `SSOT.explanation_coverage`:

```jsonc
{
  "recognised_targets": 10,
  "explained":          10,
  "percentage":         100,
  "gaps":               []                   // list of missing target_ids
}
```

---

## Roadmap

| Slice | Description | Priority |
|-------|-------------|----------|
| BEE-1 | Elevate `behavior_explainer.py` → `bee/` package with template registry, `SSOT.explanations[]`, and `SSOT.explanation_coverage{}` | P0 |
| BEE-2 | Add explanation coverage to the Investigation Quality Gate; fail release if coverage < 90% for any fixture | P0 |
| BEE-3 | IOC-cluster explanations (5+ IPs from same ASN, 5+ hashes of same malware family, etc.) | P1 |
| BEE-4 | MITRE technique explanations pulled from a deterministic canonical table | P1 |
| BEE-5 | Registry / process / YARA / Sigma / CVE templates | P2 |
| BEE-6 | IDA document-finding explanations (Quick Assist · UNC6692 · Edgecution · …) | P2 |
| BEE-7 | Threat-actor context template pulled from a deterministic actor table | P3 |
