# Native Dynamic Sandbox Architecture & Execution Boundary Design

**Category Directory**: `08_SANDBOX/`  
**Authoritative Source Reference**: All source files referenced herein reside authoritatively in [`../01_COMPLETE_SOURCE/`](../01_COMPLETE_SOURCE/).  
**Total Associated Files**: 17 files  
**Total Category Size**: 0.41 MB  
**Total Lines of Code / Documentation**: 8,491 lines  

---

## Purpose & Scope

Architectural specifications for the native detonation hypervisor, microVM orchestrator, dynamic evidence pipeline, and anti-evasion instrumentation.

## Architectural Boundary & Invariant

**CRITICAL INVARIANT**: The Native Dynamic Sandbox is strictly an **evidence-producing execution subsystem**. It must NEVER build a parallel reasoning, IKG, or verdict engine.

### Subsystem Architecture:
1. **Detonation Environment**: Ephemeral microVMs / Windows containers running suspected binaries, scripts, and documents.
2. **Instrumentation Planes**:
   - Kernel API tracing (hooking `NtCreateProcess`, `NtWriteVirtualMemory`, `NtMapViewOfSection`)
   - Network simulation (DNS fake responder, HTTP sinkhole, TLS inspection)
   - In-memory behavioral monitors (AMSI hooks, ETW telemetry)
3. **Dynamic Evidence Attachment**:
   - Process lineage graphs
   - Dropped file payloads (forwarded to the 59-decoder pipeline)
   - Network PCAPs and connection logs (forwarded to Canonical Evidence)
   - Microsecond-level execution timeline
4. **Convergence Bridge**: Telemetry flows into NivXRay Core (`POST /api/v2/evidence/ingest`), where IUE, ICE, and Security State reason over the observations.


---

## Associated File Index (Authoritative Paths in `01_COMPLETE_SOURCE/`)

| Relative Source Path | Size (Bytes) | Lines | Type | Status |
| :--- | :---: | :---: | :---: | :---: |
| [`01_COMPLETE_SOURCE/backend/services/artifact_intelligence/__init__.py`](../01_COMPLETE_SOURCE/backend/services/artifact_intelligence/__init__.py) | 8,571 | 237 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/artifact_intelligence/analyzers/__init__.py`](../01_COMPLETE_SOURCE/backend/services/artifact_intelligence/analyzers/__init__.py) | 944 | 28 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/artifact_intelligence/analyzers/archive.py`](../01_COMPLETE_SOURCE/backend/services/artifact_intelligence/analyzers/archive.py) | 4,593 | 120 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/artifact_intelligence/analyzers/elf.py`](../01_COMPLETE_SOURCE/backend/services/artifact_intelligence/analyzers/elf.py) | 13,566 | 335 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/artifact_intelligence/analyzers/office.py`](../01_COMPLETE_SOURCE/backend/services/artifact_intelligence/analyzers/office.py) | 17,459 | 440 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/artifact_intelligence/analyzers/pdf.py`](../01_COMPLETE_SOURCE/backend/services/artifact_intelligence/analyzers/pdf.py) | 17,446 | 464 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/artifact_intelligence/analyzers/pe.py`](../01_COMPLETE_SOURCE/backend/services/artifact_intelligence/analyzers/pe.py) | 1,477 | 44 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/artifact_intelligence/analyzers/shellcode.py`](../01_COMPLETE_SOURCE/backend/services/artifact_intelligence/analyzers/shellcode.py) | 1,274 | 43 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/tests/test_bits_and_sandbox_evasion.py`](../01_COMPLETE_SOURCE/backend/tests/test_bits_and_sandbox_evasion.py) | 3,813 | 92 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/docs/emergent-handoff-package/03_EDR_ARCHITECTURE/NIVXFORGE_EDR_SANDBOX_INDUSTRY_BENCHMARK.md`](../01_COMPLETE_SOURCE/docs/emergent-handoff-package/03_EDR_ARCHITECTURE/NIVXFORGE_EDR_SANDBOX_INDUSTRY_BENCHMARK.md) | 22,729 | 278 | `documentation` | `AG_CREATED` |
| [`01_COMPLETE_SOURCE/docs/emergent-handoff-package/04_EDR_UIUX/NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html`](../01_COMPLETE_SOURCE/docs/emergent-handoff-package/04_EDR_UIUX/NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html) | 90,149 | 1,855 | `documentation` | `AG_CREATED` |
| [`01_COMPLETE_SOURCE/docs/emergent-handoff-package/04_EDR_UIUX/NIVXFORGE_EDR_SANDBOX_UIUX_SPEC.md`](../01_COMPLETE_SOURCE/docs/emergent-handoff-package/04_EDR_UIUX/NIVXFORGE_EDR_SANDBOX_UIUX_SPEC.md) | 16,349 | 189 | `specification` | `AG_CREATED` |
| [`01_COMPLETE_SOURCE/docs/security-state/NIVXFORGE_EDR_SANDBOX_INDUSTRY_BENCHMARK.md`](../01_COMPLETE_SOURCE/docs/security-state/NIVXFORGE_EDR_SANDBOX_INDUSTRY_BENCHMARK.md) | 22,729 | 278 | `documentation` | `AG_CREATED` |
| [`01_COMPLETE_SOURCE/docs/security-state/NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html`](../01_COMPLETE_SOURCE/docs/security-state/NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html) | 90,149 | 1,855 | `documentation` | `AG_CREATED` |
| [`01_COMPLETE_SOURCE/docs/security-state/NIVXFORGE_EDR_SANDBOX_UIUX_SPEC.md`](../01_COMPLETE_SOURCE/docs/security-state/NIVXFORGE_EDR_SANDBOX_UIUX_SPEC.md) | 16,349 | 189 | `specification` | `AG_CREATED` |
| [`01_COMPLETE_SOURCE/docs/uiux/NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html`](../01_COMPLETE_SOURCE/docs/uiux/NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html) | 90,149 | 1,855 | `documentation` | `AG_CREATED` |
| [`01_COMPLETE_SOURCE/docs/uiux/NIVXFORGE_EDR_SANDBOX_UIUX_SPEC.md`](../01_COMPLETE_SOURCE/docs/uiux/NIVXFORGE_EDR_SANDBOX_UIUX_SPEC.md) | 16,349 | 189 | `specification` | `AG_CREATED` |
