# Read-only Diagnostic · Why `processes = 0` and `ti = 0` on Sample.docx

_No code changes. No L2 implementation. No engine A / scoring / ADR-004 changes._
_Answers the owner question: "Is the missing processes/ti data actually present in the normalized DOCX input, and does the existing DOCXAdapter correctly extract it?"_

---

## TL;DR

**L2 (swap in DOCXAdapter) is NOT justified as-scoped.** The DOCXAdapter would in theory unlock the 2 tables in Sample.docx, but three separate limitations conspire to make the `processes=0` / `ti=0` gap independent of the extractor swap:

1. `DOCXAdapter.extract()` currently returns `info = {}` on this file (empty) — its own table/hyperlink/relationship scan is not populating structures even though the DOCX contains them. Something in the adapter's zip walk is not wired to write into `info`.
2. Even if `info["tables"]` were populated, the MDR pipeline's `_extract_entities` builds `MDREvent`s from **paragraph prose**, not table rows. It has no table-schema rule.
3. The two specific gaps we need to close (parent/child process chain + VirusTotal/Talos/AbuseIPDB TI attribution) are actually visible in the current paragraph-loop text — just not extracted into structured `ProcessChain` / `TIItem` records by the current MDR entity extractor.

The right next step is a **targeted MDR entity-extractor improvement**, not a wholesale adapter swap.

---

## What the current extractor sees (routers/documents.py:453-459)

Naive `python-docx` paragraph-loop.

| Signal | Count |
|---|---:|
| Chars | 11,341 |
| Lines | 285 |
| exe / cmd tokens | 33 |
| SHA-256 hashes | 18 |
| URLs | 19 |
| IPs | 17 |
| Hostnames (`XX-YY-N`) | 38 |
| MITRE tactics (`TA0000`) | 2 |
| MITRE techniques (`T0000`) | 0 (source truly has none) |
| Process-chain arrows | 2 |
| Parent/child prose tokens | 8 |

**The evidence IS in the text**. E.g.:
- `fondue.exe /enable-feature:DirectPlay /show-caller /top-most /caller-name:menu_En.exe` — the parent/child relationship is right there
- `Virustotal Results:` · `Talos Intelligence Results:` · `AbuseIPDB Results:` · `Talos Web Reputation: Neutral` — TI section markers present

## What the current extractor DISCARDS

The `Sample.docx` file's structural profile:

| Structure | Count in file | Extracted by paragraph-loop? |
|---|---:|---|
| `w:p` paragraphs | 183 | ✅ Yes |
| `w:tbl` tables | **2** | ❌ Dropped |
| `w:hyperlink` | 0 | (n/a) |
| Comments | 0 | (n/a) |
| Macros (vbaProject.bin) | absent | (n/a) |
| OLE / embedded packages | absent | (n/a) |
| Zip members | 19 | (n/a) |

The 2 tables are the concrete loss. These almost certainly contain the Cisco XDR event grid (parent/child columns + hash/host/action columns).

## What DOCXAdapter would additionally extract — **measured, not assumed**

Running the existing `services/adapters/docx_adapter.py::DOCXAdapter` **against the actual Sample.docx bytes**:

### Stage 1 · `extract() → IEPContent`
```
info keys: []     ← the adapter's rich extraction produced ZERO structured info

  paragraphs        : 0        (should be 183)
  tables            : 0        (should be 2)
  hyperlinks        : 0
  comments          : 0
  tracked_changes   : 0
  custom_properties : 0 keys
  macros_vba        : None
  embeddings        : 0
  external_targets  : 0
  relationships     : 0
```

**⚠️ Finding**: `DOCXAdapter.extract()` returns an empty `info` on real DOCX bytes. Its internal `_scan_tables()`, `_scan_hyperlinks()`, `_parse_rels()`, `_parse_comments()`, `_parse_tracked_changes()` methods either aren't being called or aren't writing to `info`. This is a defect **in the adapter itself**, separate from the routing question.

### Stage 2 · `normalize(content) → 81 IEPArtifacts`
Despite `info` being empty, the adapter's fallback text extraction still produces:

| Kind | Count |
|---|---:|
| hash | 20 |
| url | 20 |
| ip | 15 |
| file_path | 12 |
| domain | 10 |
| command | 4 |

**Comparison vs paragraph-loop + current MDR pipeline** (after L1):

| Bucket | Paragraph-loop → MDR pipeline | DOCXAdapter → normalize | Delta |
|---|---:|---:|---:|
| hashes | already surfaced | 20 | ~parity |
| urls | 20 in observed_iocs | 20 | ~parity |
| ips | already surfaced | 15 | ~parity |
| domains | already surfaced | 10 | ~parity |
| **file paths** | **2** (MDR) | **12** (adapter) | +10 |
| **commands** | 0 structured | 4 structured | +4 |

So DOCXAdapter DOES win on file_paths and commands — but on **paragraph text**, not on tables. The adapter isn't currently unlocking anything the tables contain.

## Would DOCXAdapter's additional artifacts map into `.processes` / `.ti`?

**No — not with today's InvestigationModel builder.**

- `InvestigationModel.processes` is populated by `v2/investigation/model.py::build_model` from `MDREvent` objects that have `.parent_process` / `.child_process` / `.command_line` fields already parsed. DOCXAdapter emits `command` artifacts as flat strings (e.g. `CMD: C:\abcfiles\TSP100 FuturePrint\Autorun.exe`), not as parent/child pairs. The pipeline would still record `processes = 0` because there is no parent/child pair-extractor between the adapter's `command` artifact and the `MDREvent.parent_process` field.
- `InvestigationModel.ti` is populated only when `MDREvent.detection_source` matches known TI providers (VirusTotal / Talos / AbuseIPDB). Neither the current paragraph-loop nor the DOCXAdapter emits `TI section headers → TIItem` mappings; both stop at URLs.

So even if L2 fully worked, `.processes` and `.ti` would still be `0` for this DOCX.

## The real bottlenecks (each is small, targeted, and independent)

| # | Bottleneck | Fix scope | Files touched | Effort |
|---|---|---|---|---:|
| A | `DOCXAdapter.extract()` returns empty `info` — its own scanners aren't wiring output | Bug fix in `services/adapters/docx_adapter.py` `_scan_tables()` / `_parse_*` methods | 1 | small |
| B | Prose "X /caller-name:Y" → `ProcessChain(parent=X, child=Y)` | New rule in `v2/jobs/pipeline.py::_extract_entities` | 1 | small |
| C | Prose "Virustotal Results: …" / "AbuseIPDB Results: …" → `TIItem` | New rule in `v2/jobs/pipeline.py::_extract_entities` | 1 | small |
| D | Table-row structured extraction (parent/child + TI provider + hash columns) | Extend `_extract_entities` to consume `info["tables"]` after (A) is done | 1 | medium |

**None of these is "add a new feature". Each is a targeted extractor rule closing a measured gap.**

## Why L2 (bulk adapter swap) is not justified today

- L2 as-scoped ("swap paragraph-loop for DOCXAdapter") does not close the specific `processes=0` / `ti=0` gaps because DOCXAdapter has its own bugs preventing table extraction (bottleneck A), and the MDR pipeline doesn't consume tables even if provided (bottleneck D).
- The measurable wins from DOCXAdapter on Sample.docx today are `+10 file_paths` and `+4 structured commands` — both nice-to-have, neither closes the `.processes` / `.ti` completeness gap.
- Doing L2 without also doing (A), (B), (C), (D) would burn scope on the wrong problem.

## Recommendation (per the CTO's read-only mandate — not executed)

- **Do not L2 yet.**
- **Do not immediately fix A/B/C/D either** — Wave 1 is still open and the observation store will show whether these gaps are systemic across multiple DOCX cases or specific to Cisco XDR reports.
- **When Wave 1 shows enough real DOCX cases** and completeness clusters at moderate (40-60%), the (A)/(B)/(C)/(D) work becomes evidence-driven rather than speculation-driven. Do them then, in that order, one at a time.

## Zero code-change status of this diagnostic

Confirmed. Only reads:
- `services/adapters/docx_adapter.py` (invoked in isolation for measurement, no persistence)
- `routers/documents.py` (already-shipped L1 version)
- `v2/jobs/pipeline.py::_extract_entities` / `v2/investigation/model.py::build_model`
- `Sample.docx` bytes

Backend / consumer / scoring / ADR-004 untouched.

_END OF READ-ONLY DIAGNOSTIC · AWAITING OWNER DECISION._
