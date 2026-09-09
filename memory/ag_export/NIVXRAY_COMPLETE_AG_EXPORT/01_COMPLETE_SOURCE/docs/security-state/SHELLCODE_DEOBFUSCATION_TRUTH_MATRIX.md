# NivXRay XDR — Shellcode Deobfuscation & Analysis Capability Truth Matrix

## Executive Summary

This matrix provides the verified, itemized capability breakdown for **Shellcode Analysis, Static Deobfuscation, and Artifact Extraction** in NivXRay XDR. 

In accordance with enterprise governance, no capability is marked as complete unless verified across all nine lifecycle dimensions:
1. **DISCOVERED**: Capability pattern identified and mapped in codebase.
2. **REGISTERED**: Formally registered in `DecoderRegistry`, `Artifact Intelligence`, or `operations`.
3. **ROUTED**: Authoritatively directed from ingestion/artifact router to the capability.
4. **RUNTIME_REACHABLE**: Fully callable during production execution paths.
5. **TESTED**: Validated via automated unit or regression test suites.
6. **OUTPUT_RETAINED**: Stage evidence retained with SHA-256 hashes and bounded output.
7. **API_EXPOSED**: Exposed in `/decode/smart`, `/api/artifacts/`, or canonical command models.
8. **UI_VISIBLE**: Rendered in `DecodingTracePanel.jsx` or Analyst Workspace cards.
9. **SEMANTICALLY_ANALYZED**: Connected to ATT&CK, LOLBAS, IOC extraction, or Security State.

---

## Authoritative Capability Truth Matrix

| Capability | DISCOVERED | REGISTERED | ROUTED | RUNTIME_REACHABLE | TESTED | OUTPUT_RETAINED | API_EXPOSED | UI_VISIBLE | SEMANTICALLY_ANALYZED | Current Status |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| **Raw Shellcode Detection (Prologue & Entropy)** | ✓ | ✓ | ⚠️ Partial | ⚠️ Partial | ✓ | ✓ | ✓ | ✓ | ✓ | Active in analyzer; missing router trigger in `recipe_planner.py` |
| **x86 Architecture Detection** | ✓ | ✓ | ⚠️ Partial | ⚠️ Partial | ✓ | ✓ | ✓ | ✓ | ✓ | Implemented via Capstone instruction density |
| **x64 Architecture Detection** | ✓ | ✓ | ⚠️ Partial | ⚠️ Partial | ✓ | ✓ | ✓ | ✓ | ✓ | Implemented via Capstone instruction density |
| **ARM / Thumb Architecture Detection** | ✓ | ✓ | ⚠️ Partial | ⚠️ Partial | ✓ | ✓ | ✓ | ✓ | ⚠️ Partial | Implemented via Capstone instruction density |
| **ARM64 Architecture Detection** | ✓ | ✓ | ⚠️ Partial | ⚠️ Partial | ✓ | ✓ | ✓ | ✓ | ⚠️ Partial | Implemented via Capstone instruction density |
| **Capstone Instruction Disassembly** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Full instruction listing (`addr`, `hex`, `op`, `args`) |
| **Instruction Statistics & Entropy Windows** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ⚠️ Partial | Shannon entropy calculated; basic block counters queued |
| **PEB/TEB Access Indicators (fs:[30]/gs:[60])** | ✓ | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | Pattern mapped; static detector stub queued |
| **API Hashing Recognition (ROR13/DJB2)** | ✓ | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | Signatures defined; offline dictionary mapping queued |
| **Binary Strings & IOC Extraction (ASCII/UTF16)**| ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `services.analyzers.shellcode.extract_iocs` |
| **Single-Byte XOR Shellcode Deobfuscation** | ✓ | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | Generic XOR in DDO; binary shellcode unrolling queued |
| **Rolling XOR Shellcode Deobfuscation** | ✓ | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | Architecture planned; implementation queued |
| **ADD / SUB / NOT Transform Deobfuscation** | ✓ | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | Mapped; arithmetic unroller queued |
| **ROL / ROR Bit Shift Deobfuscation** | ✓ | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | Mapped; bitwise unmasker queued |
| **Embedded PE Carving (Reflective Loaders)** | ✓ | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | `_is_valid_pe` exists; parent-child slicing queued |
| **Embedded .NET / Script Carving** | ✓ | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | Architecture planned; carver queued |
| **Staged Payload Recognition (Meterpreter/CS)** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | `_SHELLCODE_FAMILIES` active in shellcode analyzer |
| **Cobalt Strike Beacon Config Extraction** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `cobaltstrike_beacon_config.py` |
| **Analyst Shellcode Investigation Card** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active via `annotate_shellcode()` |

---

## Gap Summary & Implementation Target

- **Currently Production-Complete (5 Capabilities)**:
  Capstone Disassembly, Binary String/IOC Extraction, Staged Payload Recognition, Cobalt Strike Beacon Config Extraction, and Analyst Investigation Card.
- **Partially Integrated (5 Capabilities)**:
  Raw Shellcode Detection, x86, x64, ARM, and ARM64 Architecture Detection (active in `shellcode.py` and UAIE, but missing top-level dispatch from `recipe_planner.py`).
- **Target Implementation Gaps (9 Capabilities)**:
  PEB/TEB Access Detection, API Hashing Recognition, Single-Byte XOR Shellcode Unrolling, Rolling XOR Unrolling, ADD/SUB/NOT Transforms, ROL/ROR Shifts, Embedded PE Carving, Embedded .NET/Script Carving, and Basic Block Profiling.
