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
| IDA-2 | Artifact Splitter for mixed pastes (PowerShell + URL + Hash + Registry + YARA → parallel routing) | P0 |
| IDA-3 | Content Acquisition — URL Fetcher + HTML Parser + Main-Article Extractor + boilerplate removal + PDF/DOCX/EML/image loaders + archive unpackers | P1 |
| **IDA-3.5** | **Content Understanding — build a `Document Profile` before any extractor runs.**  See "Content Understanding Contract" below. ⭐ | **P1** |
| IDA-4 | Threat Report IOC / MITRE / LOLBAS / Timeline / malware / threat-actor / victim / CVE / YARA / Sigma extractors | P1 |
| IDA-5 | Evidence Normalizer — canonicalise every extracted artifact so duplicates collapse and correlation strengthens.  See "Evidence Normalization Contract" below. | P1 |
| IDA-6 | Semantic Relationship Builder — turn extracted artifacts into a directed graph (Quick Assist → launches → PowerShell → downloads → Python → installs → Edge Extension) and write it to `SSOT.knowledge_graph`.  Feeds Trajectory + IVE + Story engines automatically. | P2 |
| **IDA-7** | **Citation & Provenance** — every artifact IDA writes to the SSOT carries `source = {document, url, section, paragraph, page, offset}` so Workspace features like "Show source paragraph" / "Jump to document" / "Highlight evidence" work without re-parsing.  See "Provenance Contract" below. | **P1** |
| IDA-8 | PDF Parser + Text + Table + Image extraction | P2 |
| IDA-9 | DOCX / EML / CSV / JSON / XML parsers | P2 |
| IDA-10 | OCR Engine (Tesseract) + Screenshot Analyzer | P2 |
| IDA-11 | Diagram Analyzer (box + arrow detection → relationship graph) | P3 |
| IDA-12 | GitHub / Pastebin / VirusTotal / URLhaus specialised extractors | P3 |

---

## Provenance Contract (IDA-7)

Every artifact IDA emits into the SSOT carries a `source` object
so consumers can jump back to the exact evidence location without
re-parsing the source document.

```jsonc
{
  "indicator":  "powershell.exe",
  "type":       "command",
  "normalized": "powershell.exe",
  "source": {
    "document":   "esentire-blog-unc6692",
    "url":        "https://www.esentire.com/…",
    "section":    "Execution",
    "heading":    "Native Messaging Host",
    "paragraph":  5,
    "page":       null,           // only for PDF/DOCX
    "offset":     12034,           // byte offset in acquired content
    "length":     28,
    "extractor":  "ida.command"    // which module produced this
  }
}
```

### Rules

1. Every artifact type — IOC, command, MITRE, LOLBIN, YARA, Sigma,
   registry, file path, service, threat-actor, victim, CVE — carries
   its own `source` object.
2. Fields that don't apply are `null` (e.g. `page` for HTML pages,
   `paragraph` for tabular data).
3. Provenance is used by the Evidence projection (IVE-4) to render
   "Jump to source" affordances in the Workspace.
4. Provenance participates in the Evidence Normalizer (IDA-5) —
   deduplicating artifacts merges their `source[]` arrays so the
   analyst sees every location an indicator appeared.

---

## Content Understanding Contract (IDA-3.5)

Acquisition (IDA-3) tells us *what bytes we have*.  Extraction
(IDA-4) tells us *what those bytes contain*.  Between the two,
Content Understanding tells us *what kind of document we've fetched
and where its interesting parts live* — so the extractor pipeline
runs only what's necessary.

Emitted as `SSOT.document_profile`:

```jsonc
{
  "document_type":     "Threat Report",
  "vendor":            "Mandiant",
  "language":          "English",
  "sections":          ["Campaign", "IOCs", "Detection",
                        "YARA", "Timeline"],
  "contains_commands": true,
  "contains_iocs":     true,
  "contains_sigma":    false,
  "contains_yara":     true,
  "contains_images":   4,
  "contains_tables":   2,
  "section_map":       [
    { "id": "iocs",      "heading": "Indicators of Compromise",
      "offset": 12034, "length": 4210 },
    { "id": "yara",      "heading": "YARA Signatures",
      "offset": 22876, "length": 1802 },
    …
  ]
}
```

### Deterministic Section Discovery

- Header-based (Markdown / HTML heading walk).
- Table-of-contents parse when present.
- Vendor fingerprints — a small deterministic table mapping known
  vendor CSS classes / URL patterns / boilerplate strings to a
  vendor id (Mandiant · Talos · CrowdStrike · Microsoft ·
  eSentire · Huntress · Red Canary · Palo Alto Unit 42 ·
  SentinelOne · Kaspersky · GTIG).
- Feature-flag scan: presence of ``BEGIN YARA``, MITRE
  technique-code regex, table row density, image count, code-block
  count → boolean capability flags.

### Capability Routing

Downstream extractors read the Document Profile and skip work when
the profile says the artifact is not present:

| Capability flag       | Runs when true / skipped when false |
|-----------------------|-------------------------------------|
| contains_commands     | Command Extractor                    |
| contains_iocs         | IOC Extractor                        |
| contains_yara         | YARA Extractor                       |
| contains_sigma        | Sigma Extractor                      |
| contains_tables       | Table Extractor                      |
| contains_images > 0   | OCR Engine (image contents)          |
| contains_timeline     | Timeline Extractor                   |
| contains_mitre        | MITRE Extractor                      |
| contains_lolbas       | LOLBAS Extractor                     |

### Rules

1. Content Understanding is deterministic — no LLM, no fuzzy match.
2. It writes `SSOT.document_profile` once, then never re-parses.
3. Every downstream extractor reads the profile; if a flag is
   false, that extractor MUST NOT be invoked.
4. When acquisition returned bytes that cannot be understood
   (unknown vendor / opaque binary / malformed HTML), the profile
   records `document_type = "Unknown"` and every capability flag
   remains false — the pipeline still runs the generic extractors
   but the analyst sees the honest verdict in the Investigation
   Results pane.

---

## Evidence Normalization Contract (IDA-5)

Every artifact IDA writes to the SSOT MUST pass through a
normalization step so duplicate evidence collapses and correlation
across sections strengthens.  Rules:

| Artifact Type | Normalization Rule |
|---------------|-------------------|
| Executable / LOLBIN | Lowercase, canonical `.exe` suffix, drop path prefix (`powershell` · `PowerShell.exe` · `pwsh` → `powershell.exe`) |
| URL | Lowercase scheme + host, drop trailing slash, drop fragment, keep path + query, punycode host if IDN |
| Domain | Lowercase, drop trailing dot |
| IP | Canonical form (IPv6 compressed / IPv4 dotted-quad) |
| Hash | Lowercase hex; kind auto-derived from length (32 → MD5, 40 → SHA-1, 64 → SHA-256, 128 → SHA-512) |
| Registry Path | Expand `HKLM` → `HKEY_LOCAL_MACHINE`, canonicalise separators, keep case for value names |
| File Path | Expand env vars (`%LOCALAPPDATA%` etc.), preserve case, canonicalise slashes |
| MITRE Technique | Canonical Technique Object `{id, name, tactic, sub_technique_of}` |
| Email Address | Lowercase local + domain, drop plus-tags for correlation only |
| Command String | Preserve verbatim in `raw`; normalized copy in `normalized_command` (whitespace collapsed, backtick joins resolved, `-EncodedCommand` decoded) |

Deduplication happens by `(type, canonical_value)`.  Every duplicate
carries its provenance (the artifact ID and source URL / file it
came from) so evidence is never lost.

---

## Semantic Relationship Builder Contract (IDA-6)

Emits `SSOT.knowledge_graph` — an Investigation Knowledge Graph
(IKG) shaped as:

```jsonc
{
  "nodes": [
    { "id": "n1", "kind": "process",    "value": "powershell.exe" },
    { "id": "n2", "kind": "file",       "value": "python-3.13.zip" },
    { "id": "n3", "kind": "url",        "value": "https://s3.aws/…"},
    { "id": "n4", "kind": "component",  "value": "Edge Extension" }
  ],
  "edges": [
    { "from": "n1", "to": "n3", "relation": "downloads",     "evidence": "…" },
    { "from": "n1", "to": "n2", "relation": "extracts",      "evidence": "…" },
    { "from": "n1", "to": "n4", "relation": "installs",      "evidence": "…" },
    { "from": "quickassist", "to": "n1", "relation": "launches", "evidence": "…" }
  ]
}
```

The Trajectory + IVE + Story engines consume the graph directly
from the SSOT — never rebuild it themselves (Rule R13).

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
