# RC5 · Phase 4 · Recommendation Compliance Report

**Phase:** 4 — Behavior Extractor
**Date:** Feb 24, 2026
**Spec:** `/app/memory/RC5_SEMANTIC_ENGINE_SPEC.md` v2
**Plugin API:** `/app/memory/RC5_PLUGIN_API.md` v1
**Previous:** `RC5_PHASE_2_COMPLIANCE.md`, `RC5_PHASE_3_COMPLIANCE.md`

## 1 · Previously approved recommendations — status this phase

| # | Recommendation                                                   | Status |
|---|------------------------------------------------------------------|--------|
| 1 | Deterministic-first (§ 0.1)                                      | **Implemented** |
| 2 | Evidence-driven (§ 0.2)                                          | **Implemented** — every `Behavior.evidence_nodes` is a `(node_id,)` tuple with ≥ 1 element (model-enforced) |
| 3 | Semantic reconstruction before detection (§ 0.7)                 | **Implemented** — extractor reads `ExecNode.reconstructed`, never re-parses raw output |
| 4 | Immutable ExecGraph (§ 12.1)                                     | **Preserved** — extractor is read-only |
| 5 | **Detectors consume ExecGraph only, no raw-output parsing (§ 12.2)** | **Implemented + test-locked** — `test_extractor_does_not_read_raw_output` proves the extractor never infers behaviors from `reconstructed` text alone. It reads structured `args`. |
| 6 | Confidence propagation (§ 6)                                     | **Implemented** — `Behavior.confidence = ExecNode.confidence` per rule 6.4 |
| 7 | Plugin API frozen (§ 12.5)                                       | **Implemented** — `BehaviorExtractor(Detector)` uses ONLY public ABCs + `register_detector` |
| 8 | `--no-ai` byte-identity (§ 12.6)                                 | **Implemented** — extractor skips `origin="advisor"` nodes; `test_advisor_origin_nodes_ignored` locks this |
| 9 | No keyword-based verdicts (§ 0.8)                                | **Not applicable** — Verdict engine is Phase 7 |
|10 | Semantic IR precedes ExecGraph (§ 3)                             | **Preserved** — extractor doesn't touch SIR |
|11 | Never guess — emit UnresolvedNode when incomplete                | **Not applicable** — the extractor only reads; unresolved emission is the interpreter's job (Phase 2/3) |
|12 | Language-agnostic downstream (§ 0.5)                             | **Implemented** — extractor works on CMD or PS graphs identically |
|13 | Frozen enums (§ 4/5/7)                                           | **Implemented** — extractor uses only existing `NodeKind`/`SideEffectVerb`/`TacticKind` |
|14 | Kill-list clean (§ 13)                                           | **Preserved** — no keyword-map imports |
|15 | Feature flag safety (§ 14)                                       | **Implemented** — extractor registers at import; `/api/decode/smart` still returns `behaviors: []` until Phase 5+ wires the pipeline |
|16 | AI persona is advisor-only (§ 13)                                | **Preserved** — extractor has ZERO `emergentintegrations` import |
|17 | Regression tests for every capability (§ 15)                     | **Implemented** — 35 new tests, **280 total RC5 tests green** |
|18 | Every historical bug → permanent test                            | **Not applicable this phase** |
|19 | Full backward compatibility                                      | **Preserved** — verified via live smoke test |
|20 | CI invariants (§ 12)                                             | **Preserved** — all 6 Phase-1 invariant tests still green |
|21 | Frozen plugin API — new plugins extend, never modify core        | **Implemented** — extractor is the first real `Detector` plugin, code lives in `engine/detectors/behavior_extractor.py`, zero core touches |
|22 | 100% invariant pass                                              | **Green** |

## 2 · User directives — Phase-4 approval

| Directive                                                           | Status |
|---------------------------------------------------------------------|--------|
| "✅ Phase 4 → Behavior Extractor"                                   | **Complete** |
| "Best time [for /api/rc5/parse]: Immediately after Phase 4"         | **Next up — Phase 4.5** |
| Recommended order (2+3 → deploy → 4 → 4.5 → 5 …)                    | **On track — deploy of 2+3 queued, Phase 4 shipped this session** |

## 3 · Deliverables

- `backend/engine/detectors/__init__.py` — new plugin dir.
- `backend/engine/detectors/behavior_extractor.py` — reads ExecGraph, emits `Behavior[]` with evidence Node IDs. Frozen rule table (documented in module docstring). 5 image-name sets + Run-key marker registry.
- `backend/tests/rc5/unit/behavior_extractor/test_behaviors.py` — 35 tests.
- URL tokenization added to `powershell_parser.py` (side improvement enabling URL-hint capture in download behaviors).

## 4 · Behaviors emitted today (mapping to MITRE tactics)

- `execution/process_spawn` — every ProcessNode
- `command_and_control/download` — iwr/curl/wget/Invoke-WebRequest/Invoke-RestMethod/bitsadmin/certutil/Start-BitsTransfer
- `command_and_control/http` — HttpNode
- `exfiltration/upload` — ftp/scp/sftp/tftp
- `persistence/create_task` — schtasks/at/*ScheduledTask*
- `persistence/install_service` — sc/new-service
- `persistence/write_registry` — reg/Set-ItemProperty/New-ItemProperty
- `persistence/autorun_registration` — reg writes to HKCU|HKLM\...\Run
- `credential_access/dump_credentials` — mimikatz/procdump/Get-Credential/ntdsutil/vaultcmd
- `defense_evasion/bypass_amsi` — semantic-tag from parser
- `defense_evasion/bypass_etw` — semantic-tag from parser
- `defense_evasion/obfuscation` — encoded_command flag
- `defense_evasion/reflection` — AssemblyLoadNode / ReflectionNode
- `defense_evasion/memory_alloc` — MemoryNode
- `execution/shellcode_exec` — ShellcodeNode
- `execution/dll_load` — DllLoadNode
- `collection/file_create`, `impact/file_delete` — FileNode + side-effect verbs
- `dns_query`, `clipboard`, `named_pipe`, `wmi_subscription` — supporting behaviors

## 5 · Deferred to Phase 4.1

- Behaviors from `NativeApiNode` (VirtualAlloc/WriteProcessMemory/CreateRemoteThread specifics) — needs Phase 3.1 reflection.
- Behaviors from `COMNode` (ScriptControl abuse).
- Behaviors from `CloudStorageNode`/`IdentityNode` — needs cloud-specific parsers.
- Sub-classification of `T1055` (injection) — needs multi-node pattern matching (Phase 5 MITRE will handle).

## 6 · Live proof

Obfuscated PS input `powershell.exe -NoP -Enc <b64 of Invoke-WebRequest -Uri http://c2/…>`:
- 2 ExecNodes emitted (inner + outer processes)
- 4 Behaviors emitted, all evidence-referenced:
  - `execution/process_spawn` (inner iwr)
  - `command_and_control/download` (correctly attributed to inner)
  - `execution/process_spawn` (outer powershell)
  - `defense_evasion/obfuscation` (encoded_command)

**Zero architectural invariant weakened.** Ready for Phase 4.5.
