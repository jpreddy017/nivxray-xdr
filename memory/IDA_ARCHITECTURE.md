# NivXRay · Intelligent Document Analyzer (IDA)

## FROZEN ARCHITECTURE — 2026-03-01

> This document is the single source of truth for the IDA engine.
> IDA is the universal Content Acquisition + Document Intelligence
> engine and is a **first-class investigation engine**, on par with
> DIE.  Any agent modifying URL / document / image handling must
> read and honour this document.

---

## Definition

**IDA — Intelligent Document Analyzer**
A universal content acquisition and document intelligence engine
that understands structured and unstructured human-readable
artifacts.  It acquires, parses, extracts, interprets, and converts
documents, web pages, images, screenshots, emails, reports, logs,
diagrams, and other textual artifacts into normalized investigation
evidence for the Canonical Investigation Object (SSOT).

OCR is **one module inside IDA**, not IDA itself.

---

## Architectural Principle (Rule R14)

> **IUE decides.  IDA acquires.  DIE decodes.  Domain engines
> analyze.  The SSOT unifies.  IVE visualizes.**

The IUE never fetches, OCRs, or parses documents.  The decoder never
fetches a webpage.  Each engine has a single responsibility.

---

## Layer 6 — Investigation Engine Router

```
Layer 6 · Investigation Engines

├── DIE   Decoder Intelligence Engine
├── IDA   Intelligent Document Analyzer  ⭐ NEW first-class engine
├── CIA   Command Intelligence Analyzer
├── BIA   Binary Intelligence Analyzer
├── PIA   PCAP Intelligence Analyzer
├── IOCE  IOC Correlation Engine
├── MITE  MITRE Engine
├── LBE   LOLBAS Engine
├── DKP   Decoder Knowledge Pack
├── OSINT OSINT Correlator
├── Story Attack Story Engine
├── Evidence Evidence Engine
├── Report  Report Engine
└── IVE     Investigation Visualization Engine
```

---

## IDA — Internal Modules

```
IDA
│
├── URL Fetcher            (HTTP client · TLS · redirects · UA)
├── HTML Parser            (readability · boilerplate removal)
├── Main Article Extractor
├── Code Block Extractor
├── Table Extractor
├── Image Extractor
├── OCR Engine             (Tesseract · pluggable)
├── PDF Parser
├── DOCX Parser
├── TXT Parser
├── CSV / JSON / XML Parser
├── Email (EML / MSG) Parser
├── Diagram Analyzer       (box + arrow detection)
├── Screenshot Analyzer    (OCR + UI element detection)
├── Threat Report Extractor
├── Command Extractor
├── IOC Extractor
├── MITRE Extractor
├── LOLBAS Extractor
├── Threat-Actor Extractor
├── Timeline Extractor
├── Relationship Extractor
└── Evidence Builder
```

Every IDA output writes into the same SSOT the DIE writes into.

---

## Universal Content-Acquisition Matrix

| Input                       | IDA Modules Activated                                              |
| --------------------------- | ------------------------------------------------------------------ |
| **Threat Report URL**       | URL Fetcher · HTML Parser · Main-Article · Code · IOC · MITRE      |
| **PDF Threat Report**       | PDF Parser · Text · Table · Image · OCR · IOC · MITRE              |
| **DOCX / DOC**              | DOCX Parser · Text · Embedded Images · OCR · Table · IOC           |
| **TXT / Markdown**          | TXT Parser · Command / IOC / MITRE Extractors                      |
| **CSV / JSON / XML**        | Structured Parser · Tabular IOC Extractor                          |
| **PNG / JPG Screenshot**    | Image Loader · OCR · Command / IOC Extractors                      |
| **Architecture Diagram**    | Image Loader · OCR · Box + Arrow Detector · Relationship Extractor |
| **Email (EML / MSG)**       | Email Parser · Header · Body · Attachment · IOC                    |
| **GitHub Repository URL**   | URL Fetcher · Repo Structure · README Parser · Code Block          |
| **Pastebin URL**            | URL Fetcher · Text Parser · Command Extractor                      |
| **VirusTotal / URLhaus URL**| URL Fetcher · Threat Intel Report Extractor                        |

---

## Example Pipelines

### 1 · Threat Report URL
```
User pastes: https://www.esentire.com/blog/…
       ↓
IUE   → classifies input_type = "Threat Report URL"
       ↓
Plan  → { acquire, extract-article, extract-iocs, extract-mitre,
          extract-commands, extract-lolbas, extract-timeline }
       ↓
IDA   → URL Fetcher → HTML Parser → Boilerplate Removal
       → Main Article → Code Blocks → Image Extractor
       → OCR Images (only if present) → IOC Extractor
       → MITRE Extractor → LOLBAS Extractor → Timeline
       → Threat-Actor Extractor → Evidence Builder
       ↓
SSOT  ← merged into Canonical Investigation Object
       ↓
Workspace surfaces (Attack Story · Trajectory · Report · Threat
Analysis · Confidence Explanation) read from SSOT only.
```

### 2 · Screenshot
```
User uploads:  alert.png
IUE → "Screenshot"
IDA → Image Loader → OCR → Recover Text → Command / IOC / Registry
      Extractors → Evidence
SSOT ← merged.
```

### 3 · Mixed Paste
```
User pastes:
  powershell -e JAB…
  https://esentire.com/blog/UNC6692
  d41d8cd98f00b204e9800998ecf8427e
  HKCU\Software\Microsoft\…

IUE → classifies "Mixed Investigation Input"
    → Artifact Splitter separates into 4 artifacts

  Artifact 1 (PowerShell) → DIE → Command Analyzer
  Artifact 2 (URL)        → IDA → URL Fetcher → …
  Artifact 3 (Hash)       → IOCE → OSINT lookup
  Artifact 4 (Registry)   → CIA / Registry Analyzer

All findings merge into ONE Canonical Investigation Object.
```

---

## Contract with the IUE

- IUE MUST NOT fetch, OCR, or parse.  It only classifies +
  produces the investigation plan.
- The plan tells the router which engines to activate.
- IDA is the ONLY engine allowed to acquire content from external
  sources (URLs, files, images, archives).
- All extracted content lands in the SSOT.  No other engine reads
  IDA's intermediate output — they read the SSOT (Rule R13).

---

## Roadmap

| Slice | Description | Priority |
|-------|-------------|----------|
| IDA-1 | Input Classifier extension: recognise URL / PDF / DOCX / PNG / JPG / EML / archive as first-class artifact types | P0 |
| IDA-2 | Artifact Splitter for mixed pastes | P0 |
| IDA-3 | URL Fetcher + HTML Parser + Main Article Extractor + boilerplate removal | P1 |
| IDA-4 | Threat Report IOC / MITRE / LOLBAS / Timeline extractors | P1 |
| IDA-5 | PDF Parser + Text + Table + Image extraction | P2 |
| IDA-6 | DOCX / EML / CSV / JSON / XML parsers | P2 |
| IDA-7 | OCR Engine (Tesseract) + Screenshot Analyzer | P2 |
| IDA-8 | Diagram Analyzer (box + arrow detection → relationship graph) | P3 |
| IDA-9 | GitHub / Pastebin / VirusTotal / URLhaus specialised extractors | P3 |

---

## Non-negotiables

1. IDA emits into the Canonical Investigation Object.  It never
   returns partial state to a UI panel directly.
2. IDA extractors are deterministic — same fetched content → same
   extraction.
3. IDA never trusts the URL; every fetch respects
   safe-download + size limits + timeouts + follow-redirects
   configuration surfaced in `/api/admin/ida-config`.
4. Every IDA fetch decision is analyst-visible in the SSOT
   (`content_acquisition.trace` records fetch URL, status,
   content-type, size, duration).
5. IDA never runs client-side code from fetched pages (no JS eval,
   no shell exec).
