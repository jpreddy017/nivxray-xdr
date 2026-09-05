# NivXRay · Input Understanding Engine (IUE) v2.0

## FROZEN ARCHITECTURE — 2026-03-01

> This document is the single source of truth for the IUE v2.0
> architecture.  It supersedes any prior "decoder-first" thinking.
> Any agent (or human) modifying the Workspace must read and honour
> this document.

---

## GOLDEN RULE

> **The Investigation Results pane must never duplicate the input.**
> Its sole purpose is to present the deterministic understanding
> produced by the Input Understanding Engine and downstream
> investigation engines.  If no decoding is required, the decoder is
> skipped, but the Investigation Results must still contain
> structured findings, extracted artifacts, command analysis, IOC
> correlation, MITRE mappings, LOLBAS analysis, evidence, and an
> investigation summary.  The analyst always receives NEW
> intelligence — never a transformed copy of what they pasted.

---

## Rule 9 — No engine may consume raw user input directly

Every engine (Attack Story, Trajectory, Threat Analysis, MITRE,
LOLBAS, OSINT, IDA, IVE, Report, Narrative, Confidence, …) must
consume the **Canonical Investigation Object** produced by the IUE
or subsequent deterministic transformations.  This guarantees:

* single source of truth
* consistent evidence
* deterministic behaviour
* zero duplicate parsing logic
* no engine can silently reshape the analyst's data

---

## Layered Pipeline

```
USER INPUT
    │
    ▼
[Stage 0]  Input Health Check
    │       — corrupt / empty / password-protected / truncated / OCR-needed
    ▼
[Stage 1]  Input Understanding
    │       — What is this?  (type + confidence + language + encoding)
    ▼
[Stage 2]  Content Profiling
    │       — What exists inside?  (commands, IOCs, registry, files,
    │         URLs, IPs, hashes, CVEs, MITRE, LOLBAS, users, hosts, …)
    ▼
[Stage 3]  Decode Decision
    │       — Encoded → Decoder → re-classify (loop back into IUE)
    │       — Plain  → skip decoder
    ▼
[Stage 4]  Investigation Plan
    │       — deterministic execution plan
    ▼
[Stage 5]  Dynamic Investigation Routing
    │       — enable only the engines required for THIS input type
    ▼
[Stage 5.5] Investigation Context Builder
    │       — build relationships (powershell → downloads → payload
    │         → creates service → contacts 8.8.8.8)
    ▼
[Stage 6]  Canonical Investigation Object (SSOT)
    │
    ├── Attack Story
    ├── Timeline
    ├── Trajectory
    ├── Threat Analysis  (GRAPH · MITRE · LOLBAS · RULES · IOCs ·
    │                      TI-HITS · OSINT · AI · FLOW · CHAIN)
    ├── Evidence
    ├── MITRE Matrix
    ├── LOLBAS
    ├── OSINT Correlator
    ├── Report
    ├── IDA (Intelligent Document & Image Analyzer)
    └── IVE (Investigation Visualization Engine)
```

---

## Canonical Investigation Object

Every engine downstream of the IUE receives ONE object of this shape:

```jsonc
{
  "metadata":            { "input_type", "confidence", "language", "encoding",
                           "engine_version", "created_at", "input_bytes" },
  "input":               { "raw", "normalized" },
  "profiling":           { "input_type", "content_summary", "reasoning" },
  "health":              { "ok", "issues": ["truncated", "password-protected", …] },
  "decoded_layers":      [ /* per-layer trace */ ],
  "commands":            [ /* command objects */ ],
  "scripts":             [ /* PS/JS/VBS/Bash blocks */ ],
  "iocs":                { "ips", "urls", "domains", "hashes", "emails" },
  "registry":            [ /* HKLM/HKCU keys */ ],
  "services":            [ /* sc create / New-Service */ ],
  "processes":           [ /* extracted process names */ ],
  "scheduled_tasks":     [ /* schtasks / Register-ScheduledTask */ ],
  "file_paths":          [ /* paths + UNC */ ],
  "artifacts":           [ /* every raw preprocessor artifact */ ],
  "lolbas":              [ /* LOLBAS entries with legit / abuse */ ],
  "mitre":               [ /* T-codes + tactic + evidence */ ],
  "dkp":                 [ /* DKP families with commonly-observed-in */ ],
  "osint":               { /* per-IOC reputation, country, ASN, sources */ },
  "confidence":          { /* per-signal + overall */ },
  "execution_plan":      [ /* PlanStep[] */ ],
  "engine_outputs":      { /* per-engine result */ },
  "timeline":            [ /* stage timeline */ ],
  "attack_story":        { /* deterministic narrative */ },
  "report":              { /* 12-section report */ }
}
```

---

## Universal Input Matrix

| Input                | Decode | Analyze | IDA | IVE | Final                 |
| -------------------- | :----: | :-----: | :-: | :-: | --------------------- |
| Plain Text           |   ❌   |    ✅   |  ❌ |  ✅ | Investigation         |
| Plain PowerShell     |   ❌   |    ✅   |  ❌ |  ✅ | Investigation         |
| CMD                  |   ❌   |    ✅   |  ❌ |  ✅ | Investigation         |
| Bash                 |   ❌   |    ✅   |  ❌ |  ✅ | Investigation         |
| Vendor Report        |   ❌   |    ✅   |  ❌ |  ✅ | Investigation         |
| TXT                  |   ❌   |    ✅   |  ❌ |  ✅ | Investigation         |
| PDF                  |   ❌   |    ✅   |  ❌ |  ✅ | Investigation         |
| DOC/DOCX             |   ❌   |    ✅   |  ❌ |  ✅ | Investigation         |
| JSON/XML/CSV         |   ❌   |    ✅   |  ❌ |  ✅ | Investigation         |
| PNG/JPG/JPEG         |   OCR  |    ✅   |  ✅ |  ✅ | Investigation         |
| Diagram / Screenshot |   OCR  |    ✅   |  ✅ |  ✅ | Investigation         |
| Encoded PowerShell   |   ✅   |    ✅   |  ❌ |  ✅ | Investigation         |
| Base64               |   ✅   |    ✅   |  ❌ |  ✅ | Investigation         |
| ZIP/7Z/TAR           | Extract|    ✅   |  ❌ |  ✅ | Investigation         |
| EXE/DLL/ELF          |   ❌   |    ✅   |  ❌ |  ✅ | Artifact Investigation|
| PCAP                 |   ❌   |    ✅   |  ❌ |  ✅ | Network Investigation |

---

## The Rename

The workspace no longer has an "OUTPUT" pane.  The pane is:

> **INVESTIGATION RESULTS**

(alternately: "Investigation Findings" — but never "Output" or
"Decoded Output").  The word *Output* belongs to CyberChef; the
word *Investigation* belongs to NivXRay.

---

## Roadmap

| Slice | Description | Status |
|-------|-------------|--------|
| 1 | Investigation Results pane (deterministic renderer replacing OUTPUT) | 🚧 in progress |
| 2 | IUE v2.0 stage-0 input health check | ⏳ next |
| 3 | Canonical Investigation Object (SSOT) — schema + emitter | ⏳ next |
| 4 | Investigation Context Builder — deterministic relationship graph | ⏳ next |
| 5 | Migrate every engine to consume SSOT (Attack Story · Trajectory · Report · Threat Analysis) | ⏳ next |
| 6 | Dynamic Investigation Routing — engine activation from IUE plan | ⏳ next |
| 7 | IDA (image / OCR / diagram) | 🔜 |
| 8 | IVE (Investigation Visualization Engine) | 🔜 |
| 9 | PCAP / Binary / Archive first-class inputs | 🔜 |

---

## Non-negotiables

1. Never damage the current Workspace surfaces — Threat Analysis
   sidebar (GRAPH · MITRE · LOLBAS · RULES · IOCs · TI-HITS · OSINT ·
   AI · FLOW · CHAIN), Attack Story, Trajectory, Report, Narrative,
   Plan checklist, Global Filter Bar — remain fully functional at
   all times.
2. Every enhancement is additive.  No rewrite / redesign / removal
   of validated capabilities.
3. Zero LLM in the deterministic paths.  Same paste → same result.
4. Every conclusion links back to extracted evidence.
5. Every decode / classification / route decision is analyst-visible
   and reproducible.
