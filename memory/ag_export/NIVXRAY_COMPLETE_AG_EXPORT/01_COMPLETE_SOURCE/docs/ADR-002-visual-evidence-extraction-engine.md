# ADR-002 · Visual Evidence Extraction Engine (VEEE)

**Status:** Accepted · 2026-02-08
**Supersedes:** — (extends ADR-001 semantic-contracts)
**Applies to:** NivXRay Investigation Architecture v1.0+

---

## 1 · Context

Threat-report publishers (Kaspersky Securelist, Talos, Unit42, Mandiant,
Volexity, Microsoft) increasingly render command-line IOCs as
**embedded images** (PNG/WebP) rather than `<pre>`/`<code>` HTML.  On
the Securelist Octlurk article (2026-02-08) our pipeline sees 0 of
14 attacker commands because they live only inside `<img>` tags
with empty `alt`.

Even when the text does become visible, the current classifier stops
at `head == "cmd.exe"` — every attacker pattern wrapped as
`cmd.exe /S /C "<real command>"` collapses to a generic
"Command execution" label.  Both gaps together mean whole
categories of real-world reports produce empty behavior graphs.

## 2 · Decision

Introduce a new subsystem — the **Visual Evidence Extraction Engine
(VEEE)** — and a companion **Evidence Canonicalizer**, positioned
between the Universal Input Router and the Behavior Classifier.
The Behavior Classifier is **not** modified.

```
                Universal Input Router
                         │
      ┌──────────────────┼──────────────────┐
      │                  │                  │
   HTML Adapter      PDF Adapter      Image Adapter
                                            │
                                            ▼
                     Visual Evidence Extraction Engine
                    ┌──────────────────────────────────┐
                    │ Image Classifier                 │
                    │ OCR Engine                       │
                    │ Evidence Extractor               │
                    └──────────────────────────────────┘
                                            │
                                            ▼
                              Normalized Evidence
                                            │
                                            ▼
                             Evidence Canonicalizer
                                            │
                                            ▼
                               Behavior Classifier
                                            │
                                            ▼
                       Projections / Recommendations / SSOT
```

## 3 · Responsibilities

### 3.1 · Visual Evidence Extraction Engine (VEEE)
* **Input**  · Image bytes + acquisition context (host, image URL, page).
* **Output** · `NormalizedEvidence[]` records — never Behaviors, MITRE
  tids, or Recommendations.
* **Stages** (in order):
  1. **Image Classifier** — decides whether the image is a
     code-screenshot, chart, diagram, logo, or noise.  Only
     code-screenshots proceed.
  2. **OCR Engine** — Tesseract 5 via `--tsv` output so per-word
     bounding boxes are preserved.  Engine is pluggable behind a
     `VEEEOCRAdapter` interface (Tesseract now; future providers
     may register additional adapters).
  3. **Evidence Extractor** — groups OCR tokens into command
     lines, IOCs (IPs, domains, hashes, paths), and free-text
     captions.

### 3.2 · Evidence Canonicalizer
* **Input**  · Raw command strings from any adapter (paste,
  HTML `<pre>`, PDF text layer, VEEE OCR output).
* **Output** · `CanonicalCommand{launcher_chain[], effective_command,
  payload}`.
* **Contract** · Runs before every classifier call; the
  Behavior Classifier receives ONLY canonical form.

### 3.3 · Behavior Classifier
* **Unchanged.** Consumes `CanonicalCommand`, never raw strings.

## 4 · Data Contracts

### 4.1 · NormalizedEvidence
```jsonc
{
    "type":         "commandline" | "ioc" | "caption",
    "text":         "schtasks /create /tn AnyDesk ...",
    "provenance": {
        "source":              "image",
        "acquisition_level":   "P3",
        "image_url":           "https://media.kasperskycontenthub.com/.../octlurk-silklurk1.png",
        "image_sha256":        "…",
        "bounding_box":        { "x": 184, "y": 52, "w": 721, "h": 91 },
        "ocr_engine":          "tesseract-5",
        "ocr_confidence":      0.98
    }
}
```

### 4.2 · CanonicalCommand
```jsonc
{
    "raw":                "cmd.exe /S /C \"schtasks /create /tn AnyDesk ...\"",
    "launcher_chain":     ["cmd.exe"],
    "effective_command":  "schtasks",
    "effective_head":     "schtasks.exe",
    "payload":            "schtasks /create /tn AnyDesk /tr ... /sc onlogon",
    "unwrap_depth":       1,
    "canonicalizer_version": "1.0"
}
```

## 5 · Evidence Provenance Levels

| Level | Source                          | Confidence   |
|:-----:|:--------------------------------|:-------------|
| P1    | Native parser (HTML, JSON, XML) | Highest      |
| P2    | Structured document parser (PDF text-layer, DOCX text) | High |
| P3    | OCR extraction                  | Medium–High (confidence-based) |
| P4    | Heuristic reconstruction        | Lower        |

Every NormalizedEvidence record MUST carry `provenance.acquisition_level`.
Downstream consumers (Behavior classifier, Recommendation engine, UI)
may weight by level but MUST NOT reject P3 evidence on level alone —
confidence is the arbiter.

## 6 · Failure Modes

| Failure | Behaviour |
|:--|:--|
| Tesseract binary missing | VEEE emits a single `NormalizedEvidence` of type `caption` with `acquisition_level="P4"` and `note="ocr_unavailable"`; downstream pipeline continues unaffected. |
| Corrupt image | Skipped with a provenance record `{"skipped": true, "reason": "corrupt"}`. |
| Image `< 200×80 px` OR `> 8000×8000 px` | Skipped (`reason=below_min_size` / `above_max_size`). |
| OCR confidence `< 0.30` on all tokens | Skipped (`reason=ocr_low_confidence`). |
| Image classifier says "logo/chart/diagram" | Skipped (`reason=not_code_screenshot`). |
| CDN unreachable / 5xx / >5s timeout | Skipped (`reason=fetch_failed`). |

**Golden rule** — VEEE never crashes the acquisition. Every
failure produces a provenance breadcrumb so the Acquisition
Summary panel can render "Images: 37 · OCR candidates: 11 ·
Processed: 9 · Skipped Logos: 18 · Skipped Charts: 6".

## 7 · Extension Points

* **New OCR provider** — register a class implementing
  `VEEEOCRAdapter.recognize(image_bytes) → OCRResult`.
* **New adapter** (e.g. screenshot upload, mobile capture) — plug
  into the Universal Input Router; if the payload is an image
  it flows into VEEE unchanged.
* **New launcher** — append to `LAUNCHER_RULES` in the
  Canonicalizer; the classifier is untouched.
* **New provenance level** — extend the P1-P4 table; existing
  records remain valid (levels are additive).

## 8 · Non-goals

* VEEE will NOT run LLM vision models — architecture stays
  deterministic and offline (ADR-001).
* VEEE will NOT attempt to reconstruct diagrams / flowcharts /
  network topology graphs. Only code-screenshots.
* The Canonicalizer will NOT recurse infinitely — a hard
  `unwrap_depth ≤ 4` limit prevents pathological inputs from
  looping.
* Neither subsystem emits Behaviors, MITRE, or Recommendations
  directly. Those remain the exclusive output of the semantic
  pipeline downstream.

## 9 · Rollout

* **P0.15A · Evidence Canonicalizer** — ship first, benefits
  every existing ingestion path (no OCR needed).
* **P0.15B · VEEE** — plug into the Universal Input Router
  behind an `NVX_VEEE_ENABLED` env flag; ship in follow-up.
* **P0.15C · Acquisition Summary UI + bounding-box overlay** —
  after VEEE is stable and produces provenance records.

## 10 · CI Invariants

The following AST-level invariants MUST hold once VEEE ships
(companion tests will live under `tests/test_veee_ci_invariants.py`):

1. `services/veee/**` MUST NOT import from `services/mitigation/**`
   nor from `services/ida/behaviors.py` (VEEE never touches semantics).
2. Every classifier call site MUST route through
   `Canonicalizer.canonicalize()` — direct calls to
   `_classify_command_purpose(raw)` with un-canonicalized input
   are a CI violation.
3. Every `NormalizedEvidence` record produced by VEEE MUST
   carry `provenance.acquisition_level` and (if `source="image"`)
   an `image_sha256` — enforced by a schema validator.

---

**Frozen:** 2026-02-08.  Any change to §3 (Responsibilities) or
§4 (Data Contracts) requires an ADR revision and a
schema-version bump (per ADR-001).
