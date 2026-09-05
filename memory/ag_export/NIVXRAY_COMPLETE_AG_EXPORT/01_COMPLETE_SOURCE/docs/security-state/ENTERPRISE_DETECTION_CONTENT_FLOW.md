# NivXRay XDR — Enterprise Detection Content Flow

## 1. End-to-End Operational Lifecycle Flow

The lifecycle of detection content flows deterministically from discovery through canonical validation to live execution and Security State mutation:

```mermaid
sequenceDiagram
    autonumber
    participant Feed as External/Native Sources
    participant Acq as Acquisition Engine
    participant Model as Canonical Model
    participant Dedup as Deduplication Engine
    participant Gate as Quality Gate
    participant Reg as Content Registry
    participant Engine as Native Execution Runtime
    participant State as Security State Ledger

    Feed->>Acq: Ingest Raw Rule (Sigma/YARA/EQL/SPL/KQL)
    Acq->>Acq: Verify License & Provenance
    Acq->>Acq: Parse & Normalize Fields
    Acq->>Model: Translate to Canonical IR (NIR)
    Model->>Dedup: Evaluate Semantic Equivalence
    alt Duplicate Detected
        Dedup-->>Acq: Mark DUPLICATE (Skip duplicate index)
    else Unique Content
        Dedup->>Dedup: Index Semantic Fingerprint
    end
    Model->>Gate: Execute 15 Programmatic Quality Gates
    alt Gate Failure (Score < 80% or Fatal Failure)
        Gate-->>Acq: Mark UNSUPPORTED / REJECTED
    else Gate Pass
        Gate->>Reg: Register in SHADOW State
        Reg->>Engine: Bind to Execution Runtime
        Reg->>Reg: Verify Canary Telemetry (Pass)
        Reg->>Reg: Promote to ACTIVE State
        Engine->>Engine: Stream Execution over Events
        Engine->>State: Emit Canonical Evidence -> Mutate Security State
    end
```

---

## 2. Artifact-First Analysis Workflow

For file artifacts (executables, scripts, office files, PDFs, archives), detection follows an **Artifact-First Analysis Routing** model:

```mermaid
graph TD
    A[Downloaded / Attached File Artifact] --> B[Artifact Router]
    B --> C{Determine Artifact Type}
    C -->|PE Binary| D[PE Analyzer + Shannon Entropy]
    C -->|ELF Binary| E[ELF Analyzer]
    C -->|Office Doc| F[Macro & VBA Extractor]
    C -->|Script| G[Script Tokenizer]
    C -->|PDF| H[PDF Structure Inspector]
    
    D --> I[YARA Native Byte Scanner]
    E --> I
    F --> I
    G --> I
    H --> I

    I --> J{Embedded Encoded Payload Found?}
    J -->|Yes: Base64/XOR/Hex Stream| K[Frozen Universal Decoder Invocation]
    J -->|No| L[Semantic Intent Analysis]
    K --> L
    L --> M[Security State Impact Assessment]
    M --> N[Canonical Evidence -> IKG -> Verdict Engine]
```

### Invariant: Universal Decoder Integration Boundary
- The **Universal Decoder** (`services/decoder/engine.py`) is **frozen**.
- The Artifact Router evaluates whether an encoded command or payload exists before invoking the decoder.
- The decoder is called **only when encoded payloads are discovered**, preventing CPU churn and preserving decoder determinism.

---

## 3. Strict Lifecycle State Transitions

NivXRay enforces a strict, directed state machine for all canonical content objects:

```
[DISCOVERED] ──> [PARSED] ──> [LICENSE_VERIFIED] ──> [NORMALIZED] ──> [TRANSLATED]
                                                                            │
[ACTIVE] <── [SHADOW] <── [ENGINE_BOUND] <── [VALIDATED] <── [DEDUPLICATED] ┘
   │
   ├──> [SUPERSEDED] ──> [RETIRED]
   ├──> [ROLLED_BACK] ──> [DEPRECATED] ──> [RETIRED]
   └──> [DEPRECATED] ──> [RETIRED]

Any Stage: [REJECTED] / [UNSUPPORTED] (Terminal)
```

### Transition Rule Constraints
1. **Zero Silent Skips**: Any transition must record the actor, timestamp, previous state, target state, and justification within `obj.provenance["transitions"]`.
2. **Deterministic Promotion**: An object cannot transition to `ACTIVE` without passing through `SHADOW` mode and validating that zero syntax, execution, or false-positive regressions occur.
3. **No Unbinding**: Once an object reaches `ENGINE_BOUND`, its runtime engine assignment cannot be modified without re-entering the `VALIDATING` gate.
