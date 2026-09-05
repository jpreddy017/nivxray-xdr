# Causal Security State Machine & Security Ledger Architecture

**Category Directory**: `03_SECURITY_STATE/`  
**Authoritative Source Reference**: All source files referenced herein reside authoritatively in [`../01_COMPLETE_SOURCE/`](../01_COMPLETE_SOURCE/).  
**Total Associated Files**: 197 files  
**Total Category Size**: 1.89 MB  
**Total Lines of Code / Documentation**: 33,855 lines  

---

## Purpose & Scope

Next-generation causal security computing layer replacing probability-based risk scores with deterministic security states.

## Architectural Overview & Security State Invariants

The NivXRay Security State engine establishes a mathematical foundation for cyber reasoning based on Pearl's Structural Causal Models (SCM) and Directed Acyclic Graphs (DAGs).

### Key Components Implemented:
1. **Security State Contracts**: `backend/security_state/contracts.py` — Authoritative dataclasses defining `SecurityStateRecord`, `StateTransition`, `CausalIntervention`, and `VerificationProof`.
2. **State Transition Engine**: `backend/security_state/state_engine/` & `transitions/` — Deterministic state machines transitioning between authoritative states (`BENIGN_BASELINE`, `SUSPICIOUS_UNMANAGED`, `CONTAINED_HOST`, `CRITICAL_REACHABLE`, `ACTIVE_ATTACK`).
3. **Causal Engine**: `backend/security_state/causal/` — Pearl causal do-calculus and counterfactual reasoning over attack graphs.
4. **Trusted Capability Abuse Engine (TCAE)**: `backend/security_state/capability/` — Contextual discrimination between authorized administrative tool usage and adversary abuse.
5. **Dynamic Reachability Engine**: `backend/security_state/reachability/` — Computes lateral movement reachability and critical crown jewel asset exposure in real time.
6. **Counterfactual Engine**: `backend/security_state/counterfactual/` — Simulates counterfactual worlds ("What if port 445 were blocked?") to evaluate blast radius and containment safety.
7. **Impact & Intervention Optimizer**: `backend/security_state/impact/` & `intervention/` — Calculates minimal effective containment interventions with lowest operational friction.
8. **Response Safety & Verification**: `backend/security_state/response_safety/` & `validation/` — Fails closed to prevent isolating critical infrastructure (e.g. Domain Controllers, ICU medical assets).
9. **Security State Ledger**: `backend/security_state/ledger/` & `persistence/` — Tamper-evident, append-only log of all state transitions and intervention receipts.


---

## Associated File Index (Authoritative Paths in `01_COMPLETE_SOURCE/`)

| Relative Source Path | Size (Bytes) | Lines | Type | Status |
| :--- | :---: | :---: | :---: | :---: |
| [`01_COMPLETE_SOURCE/backend/security_state/__init__.py`](../01_COMPLETE_SOURCE/backend/security_state/__init__.py) | 287 | 8 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/adapters/__init__.py`](../01_COMPLETE_SOURCE/backend/security_state/adapters/__init__.py) | 123 | 4 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/adapters/ssot_adapter.py`](../01_COMPLETE_SOURCE/backend/security_state/adapters/ssot_adapter.py) | 5,679 | 138 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/attack_state/__init__.py`](../01_COMPLETE_SOURCE/backend/security_state/attack_state/__init__.py) | 150 | 4 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/attack_state/machine.py`](../01_COMPLETE_SOURCE/backend/security_state/attack_state/machine.py) | 6,902 | 158 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/benchmarks/__init__.py`](../01_COMPLETE_SOURCE/backend/security_state/benchmarks/__init__.py) | 102 | 4 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/benchmarks/benchmark.py`](../01_COMPLETE_SOURCE/backend/security_state/benchmarks/benchmark.py) | 5,160 | 115 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/capability/__init__.py`](../01_COMPLETE_SOURCE/backend/security_state/capability/__init__.py) | 303 | 14 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/capability/engine.py`](../01_COMPLETE_SOURCE/backend/security_state/capability/engine.py) | 16,067 | 351 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/causal/__init__.py`](../01_COMPLETE_SOURCE/backend/security_state/causal/__init__.py) | 281 | 16 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/causal/engine.py`](../01_COMPLETE_SOURCE/backend/security_state/causal/engine.py) | 30,055 | 539 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/contracts.py`](../01_COMPLETE_SOURCE/backend/security_state/contracts.py) | 23,206 | 502 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/counterfactual/__init__.py`](../01_COMPLETE_SOURCE/backend/security_state/counterfactual/__init__.py) | 225 | 12 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/counterfactual/engine.py`](../01_COMPLETE_SOURCE/backend/security_state/counterfactual/engine.py) | 22,711 | 434 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/detection_bridge.py`](../01_COMPLETE_SOURCE/backend/security_state/detection_bridge.py) | 7,510 | 176 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/hydration/__init__.py`](../01_COMPLETE_SOURCE/backend/security_state/hydration/__init__.py) | 293 | 9 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/hydration/case_hydrator.py`](../01_COMPLETE_SOURCE/backend/security_state/hydration/case_hydrator.py) | 12,949 | 287 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/hydration/provenance.py`](../01_COMPLETE_SOURCE/backend/security_state/hydration/provenance.py) | 6,962 | 163 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/impact/__init__.py`](../01_COMPLETE_SOURCE/backend/security_state/impact/__init__.py) | 155 | 4 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/impact/engine.py`](../01_COMPLETE_SOURCE/backend/security_state/impact/engine.py) | 7,310 | 174 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/intervention/__init__.py`](../01_COMPLETE_SOURCE/backend/security_state/intervention/__init__.py) | 180 | 4 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/intervention/optimizer.py`](../01_COMPLETE_SOURCE/backend/security_state/intervention/optimizer.py) | 6,264 | 157 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/ledger/__init__.py`](../01_COMPLETE_SOURCE/backend/security_state/ledger/__init__.py) | 125 | 4 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/ledger/ledger.py`](../01_COMPLETE_SOURCE/backend/security_state/ledger/ledger.py) | 3,350 | 103 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/model/__init__.py`](../01_COMPLETE_SOURCE/backend/security_state/model/__init__.py) | 278 | 14 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/model/security_state.py`](../01_COMPLETE_SOURCE/backend/security_state/model/security_state.py) | 4,967 | 138 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/orchestration/__init__.py`](../01_COMPLETE_SOURCE/backend/security_state/orchestration/__init__.py) | 725 | 36 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/orchestration/engine.py`](../01_COMPLETE_SOURCE/backend/security_state/orchestration/engine.py) | 10,419 | 215 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/orchestration/library.py`](../01_COMPLETE_SOURCE/backend/security_state/orchestration/library.py) | 29,239 | 701 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/orchestration/models.py`](../01_COMPLETE_SOURCE/backend/security_state/orchestration/models.py) | 4,050 | 131 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/persistence/__init__.py`](../01_COMPLETE_SOURCE/backend/security_state/persistence/__init__.py) | 301 | 9 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/persistence/models.py`](../01_COMPLETE_SOURCE/backend/security_state/persistence/models.py) | 2,313 | 69 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/persistence/repository.py`](../01_COMPLETE_SOURCE/backend/security_state/persistence/repository.py) | 20,591 | 421 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/progression/__init__.py`](../01_COMPLETE_SOURCE/backend/security_state/progression/__init__.py) | 175 | 4 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/progression/engine.py`](../01_COMPLETE_SOURCE/backend/security_state/progression/engine.py) | 23,335 | 404 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/reachability/__init__.py`](../01_COMPLETE_SOURCE/backend/security_state/reachability/__init__.py) | 277 | 14 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/reachability/engine.py`](../01_COMPLETE_SOURCE/backend/security_state/reachability/engine.py) | 27,937 | 569 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/response_safety/__init__.py`](../01_COMPLETE_SOURCE/backend/security_state/response_safety/__init__.py) | 312 | 10 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/response_safety/safety_gate.py`](../01_COMPLETE_SOURCE/backend/security_state/response_safety/safety_gate.py) | 4,171 | 110 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/response_safety/verification.py`](../01_COMPLETE_SOURCE/backend/security_state/response_safety/verification.py) | 5,697 | 141 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/routers/__init__.py`](../01_COMPLETE_SOURCE/backend/security_state/routers/__init__.py) | 154 | 4 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/routers/router.py`](../01_COMPLETE_SOURCE/backend/security_state/routers/router.py) | 19,110 | 468 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/simulation/__init__.py`](../01_COMPLETE_SOURCE/backend/security_state/simulation/__init__.py) | 193 | 8 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/simulation/simulator.py`](../01_COMPLETE_SOURCE/backend/security_state/simulation/simulator.py) | 5,468 | 144 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/state_engine/__init__.py`](../01_COMPLETE_SOURCE/backend/security_state/state_engine/__init__.py) | 103 | 4 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/state_engine/engine.py`](../01_COMPLETE_SOURCE/backend/security_state/state_engine/engine.py) | 19,064 | 379 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/streaming/__init__.py`](../01_COMPLETE_SOURCE/backend/security_state/streaming/__init__.py) | 1,137 | 38 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/streaming/adapter.py`](../01_COMPLETE_SOURCE/backend/security_state/streaming/adapter.py) | 20,540 | 469 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/streaming/auth.py`](../01_COMPLETE_SOURCE/backend/security_state/streaming/auth.py) | 6,860 | 165 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/streaming/coalescer.py`](../01_COMPLETE_SOURCE/backend/security_state/streaming/coalescer.py) | 5,555 | 136 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/streaming/dedup.py`](../01_COMPLETE_SOURCE/backend/security_state/streaming/dedup.py) | 6,327 | 173 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/streaming/dlq.py`](../01_COMPLETE_SOURCE/backend/security_state/streaming/dlq.py) | 6,097 | 165 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/streaming/fingerprint.py`](../01_COMPLETE_SOURCE/backend/security_state/streaming/fingerprint.py) | 3,571 | 105 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/streaming/models.py`](../01_COMPLETE_SOURCE/backend/security_state/streaming/models.py) | 10,236 | 240 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/streaming/replay.py`](../01_COMPLETE_SOURCE/backend/security_state/streaming/replay.py) | 8,735 | 202 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/streaming/watermark.py`](../01_COMPLETE_SOURCE/backend/security_state/streaming/watermark.py) | 2,944 | 75 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/tests/__init__.py`](../01_COMPLETE_SOURCE/backend/security_state/tests/__init__.py) | 40 | 1 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/tests/api_endpoint_audit.py`](../01_COMPLETE_SOURCE/backend/security_state/tests/api_endpoint_audit.py) | 6,496 | 159 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/tests/phase2_audit_runner.py`](../01_COMPLETE_SOURCE/backend/security_state/tests/phase2_audit_runner.py) | 22,265 | 464 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/security_state/tests/phase2c_real_replay_runner.py`](../01_COMPLETE_SOURCE/backend/security_state/tests/phase2c_real_replay_runner.py) | 17,614 | 312 | `test` | `PRE_EXISTING` |

*... and 137 more files. Refer to [`SECURITY_STATE_MANIFEST.json`](./SECURITY_STATE_MANIFEST.json) for the exhaustive JSON catalog.*
