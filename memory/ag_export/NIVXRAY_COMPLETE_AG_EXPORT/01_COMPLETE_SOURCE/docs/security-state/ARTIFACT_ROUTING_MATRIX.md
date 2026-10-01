# NivXRay XDR — Artifact Routing & Content Triage Matrix

## 1. Objective & Design Pattern

The **Artifact Intelligence Layer** (`services/artifact_intelligence/`) and **Recipe Planner** (`services/recipe_planner.py`) act as the authoritative routing fabric for all evidence payloads in NivXRay XDR.

The design pattern mirrors the Technique Detector registry (Rule 26):
$$\text{Unknown Payload} \xrightarrow{\text{Magic + Heuristics}} \text{Classifier} \xrightarrow{\text{Ranked Confidence}} \text{Authoritative Analyzer / Codec} \xrightarrow{\text{Canonical Evidence}}$$

---

## 2. Decision Tree Architecture

```mermaid
flowchart TD
    IN["Input Payload (Bytes or String)"] --> CLAS{"Content Triage Classifier"}
    
    CLAS -->|Printable ASCII / Unicode String| TXT{"Text & Script Classifier"}
    TXT -->|CLI Invocation cmd/powershell/bash| R_CMD["Path: Canonicalizer / CRE / DDO"]
    TXT -->|PowerShell / VBS / JS Script| R_SCR["Path: Script AST Deobfuscator & DDO"]
    TXT -->|Base64 / Hex / URL Text Blob| R_DEC["Path: Universal Decoder / DDO"]
    
    CLAS -->|Binary Buffer (Non-printable > 15%)| BIN{"Binary Magic & Structural Scan"}
    
    BIN -->|'MZ' + e_lfanew 'PE\0\0'| R_PE["Path: PE Analyzer (services/analyzers/pe.py)"]
    BIN -->|'\x7fELF'| R_ELF["Path: ELF Analyzer (services/artifact_intelligence/analyzers/elf.py)"]
    BIN -->|'\xfe\xed\xfa\xce' / '\xfe\xed\xfa\xcf'| R_MAC["Path: Mach-O Analyzer"]
    BIN -->|'PK\x03\x04' / '7z\xbc' / 'Rar!' / '**ACE**'| R_ARC["Path: Archive Analyzer (ZIP, 7z, RAR, ACE, CAB)"]
    BIN -->|'PK\x03\x04' + '[Content_Types].xml'| R_OFF["Path: Office Document Analyzer"]
    BIN -->|'%PDF-'| R_PDF["Path: PDF Document Analyzer"]
    BIN -->|Entropy ≥ 6.0 OR Known Shellcode Prologue| R_SC["Path: Shellcode Analyzer (services/analyzers/shellcode.py)"]
    BIN -->|No Signature Matches| R_UNK["Path: Binary Triage Analyzer (Entropy + Strings + Hashes)"]
```

---

## 3. Comprehensive Artifact Routing Matrix

| Route ID | Content Classification | Magic Bytes / Header | Structural Markers | Authoritative Destination | Output Evidence Type | Graceful Fallback |
|:---|:---|:---|:---|:---|:---|:---|
| `ROUTE_CMD` | Windows / Linux Command | Starts with `cmd`, `powershell`, `pwsh`, `bash`, `sh` | CLI argument syntax, pipe operators, redirection | `services/canonicalizer` | `CanonicalCommand` | Identity string |
| `ROUTE_SCRIPT` | Script File / Block | `function`, `param(`, `var `, `Sub `, `Dim ` | AST grammar matching (PowerShell, VBS, JS) | `services/canonicalizer` + `DDO` | `ScriptIntelligence` | Raw script text |
| `ROUTE_ENCODED` | Encoded Text Blob | High base64/hex character ratio | Strict regex matching `[A-Za-z0-9+/=]{16,}` | `services/decoder_bridge` | `DecodedTrace` | Stop reason logged |
| `ROUTE_SHELLCODE`| Raw Machine Shellcode | `\xfc\xe8`, `\xfc\xeb`, `\x31\xc0\x50`, `\x65\x48\x8b`, `\xff\xb5`, `\xfd\x7b` | Shannon entropy $\ge 6.0$, valid instruction ratio $\ge 60\%$ | `services/analyzers/shellcode.py` | `ShellcodeAnalysis` | `BinaryTriage` |
| `ROUTE_PE` | Windows Executable | `MZ` (`0x4d 0x5a`) | `e_lfanew` at `0x3c` $\to$ `PE\0\0` | `services/analyzers/pe.py` | `PEAnalysis` | `ShellcodeAnalysis` |
| `ROUTE_ELF` | Linux Binary | `\x7fELF` (`0x7f 0x45 0x4c 0x46`) | 32/64-bit ELF class, ET_EXEC/ET_DYN | `services/artifact_intelligence/analyzers/elf.py` | `ELFAnalysis` | `BinaryTriage` |
| `ROUTE_MACHO` | macOS Mach-O Binary | `\xfe\xed\xfa\xce` (32), `\xfe\xed\xfa\xcf` (64), `\xca\xfe\xba\xbe` (Fat) | MH_MAGIC markers, load commands | `services/artifact_intelligence/analyzers/macho.py` | `MachOAnalysis` | `BinaryTriage` |
| `ROUTE_OFFICE` | MS Office Document | `PK\x03\x04` or OLE Compound `\xd0\xcf\x11\xe0` | Contains `word/`, `xl/`, `ppt/`, or VBA macros | `services/artifact_intelligence/analyzers/office.py` | `OfficeAnalysis` | `ArchiveAnalysis` |
| `ROUTE_PDF` | Adobe PDF Document | `%PDF-` | `trailer`, `xref`, `/ObjStm` | `services/artifact_intelligence/analyzers/pdf.py` | `PDFAnalysis` | `BinaryTriage` |
| `ROUTE_ARCHIVE`| Compressed Archive | `PK\x03\x04` (ZIP), `7z\xbc\xaf\x27\x1c`, `Rar!\x1a\x07`, `MSCF` (CAB), `**ACE**` | Valid compression headers & table of contents | `services/artifact_intelligence/analyzers/archive.py` | `ArchiveAnalysis` | `BinaryTriage` |
| `ROUTE_UNKNOWN`| Unrecognized Binary | Any binary stream | Non-printable ratio $> 0.15$ | `services/artifact_intelligence/analyzers/triage.py` | `TriageReport` | Hashes + hex dump |
