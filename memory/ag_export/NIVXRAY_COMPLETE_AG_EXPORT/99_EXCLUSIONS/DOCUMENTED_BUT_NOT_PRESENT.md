# Capabilities Documented in Specifications but NOT Yet Implemented in Code

In strict adherence to the project integrity directive (*"If something claimed in documentation does not physically exist, put it in 99_EXCLUSIONS/ with an explicit explanation: DOCUMENTED_BUT_NOT_PRESENT"*), the following items are cataloged:

---

### 1. Phase 1 Kernel-Level EDR Sensor Agent & Driver
- **Status**: `DOCUMENTED_BUT_NOT_PRESENT`
- **Referenced In**:
  - `docs/handoff/NIVXFORGE_EDR_CODE_CAPABILITY_MAP.md`
  - `docs/security-state/NIVXFORGE_EDR_TARGET_ARCHITECTURE_AND_IMPLEMENTATION_PLAN.md`
  - `docs/uiux/NIVXFORGE_EDR_SANDBOX_UIUX_SPEC.md`
- **Reason**: The EDR sensor agent (Windows kernel mini-filter driver, eBPF Linux probe, macOS Endpoint Security framework client) is part of **Phase 1 engineering backlog**. The current engagement strictly froze production sensor work to establish Truth Contracts, UI/UX specifications, and integration contracts first.
- **Physical Code Presence**: `0` sensor agent source files exist in the repository.

---

### 2. Phase 4 Native Dynamic Sandbox MicroVM Hypervisor Runner
- **Status**: `DOCUMENTED_BUT_NOT_PRESENT`
- **Referenced In**:
  - `docs/security-state/NIVXFORGE_EDR_SANDBOX_INDUSTRY_BENCHMARK.md`
  - `docs/handoff/NIVXFORGE_EDR_INTEGRATION_CONTRACT.md` (Section 8)
- **Reason**: The microVM hypervisor detonation runner (QEMU/KVM orchestration, ephemeral snapshot restore, in-guest API hook DLL injection) is specified in target architecture for **Phase 4 engineering backlog**.
- **Physical Code Presence**: `0` hypervisor daemon files exist. Current workspace contains evidence parsers (`backend/services/artifact_intelligence/`) and interactive UI prototypes only.

---

### 3. Local Git Version Control Repository (`.git/`)
- **Status**: `DOCUMENTED_BUT_NOT_PRESENT`
- **Referenced In**:
  - `docs/truth-contract/README.md`
- **Reason**: `git.exe` is absent from system PATH and no `.git/` working tree exists on the disk. File integrity is maintained via cryptographic SHA-256 manifests.
