# RC5 Post-Cutover Roadmap: Evidence Knowledge Graph

**Date recorded:** 2026-07-21 · Not scheduled until AFTER Phase 10 cutover.

Captured from user architectural review. The current fix
(`_apply_obfuscation_only_cap` in `rc22_adapter.py` + GC-291..GC-296 +
`test_obfuscation_only_benign.py`) is a **targeted, corpus-locked
surgical patch**. The direction below is the strategic evolution.

## Target 8-layer architecture (post-cutover)

1. **Decode Engine** — Base64, Hex, Gzip, Deflate, RC4, AES, JWT, ROT, XOR (existing rc2 orchestrator)
2. **Language Detection** — PowerShell, CMD, JS, VBS, VBA, HTA, Batch, Office, XML, MSBuild, YAML, Terraform
3. **Semantic Engine** — AST + variables + control flow + reflection + dynamic invocation → Semantic IR (existing RC5)
4. **Specialized Detectors** — Regex, IOC, YARA, Sigma, LOLBIN, API, Crypto, Persistence, Network, Memory, Registry, File, Behavior, MITRE, Threat Intel, ML (optional)
5. **Evidence Knowledge Graph** — Nodes (Process, Command, Script, File, Registry, Network, URL, IP, Domain, User, Cred, Token, Service, Task, Cert, COM, Pipe, MemObj); Edges (executes, creates, reads, writes, downloads, uploads, injects, spawns, contacts, persists, uses, loads, reflects, encodes, decodes, decrypts, dependsOn, derivedFrom, observedVia)
6. **Correlation Engine** — Temporal reasoning, dependency reasoning, confidence aggregation, behavior fusion, FP suppression, contradiction detection
7. **Verdict Engine** — Evidence + risk scoring + MITRE + family + confidence — with rule dependency graph (e.g. `EncodedCommand → NEEDS: Execution OR Persistence OR CredAccess OR Download; ELSE Informational only`)
8. **Explainability** — Why malicious / Why NOT malicious / Evidence Tree / Timeline / Decode Recipe / Semantic Reconstruction / Confidence Breakdown / Alternative Interpretations

## Key principles to bake in

- **Negative evidence** as a first-class citizen. Explicitly collect "no execution", "no network", "no persistence" as signals that REDUCE suspicion.
- **Rule dependency scoring** — no isolated signal can escalate a verdict on its own; escalation requires a supporting evidence chain.
- **Dimensional confidence** — separate confidence per stage (decode / semantic / behavior / IOC / threat-intel / verdict) rather than a single opaque number.
- **Explicit Unknown** — when the engine can't resolve (runtime-only decryption / missing key / packed payload / unsupported language / incomplete context), surface `Unknown` with a reason. Never guess.

## Migration plan (post-cutover)

- Phase 11 · introduce the `EvidenceKnowledgeGraph` data model alongside the existing `ExecGraph`.
- Phase 12 · migrate one detector at a time (Behavior first) to emit graph nodes/edges instead of flat evidence lists.
- Phase 13 · introduce the Correlation Engine as a separate layer.
- Phase 14 · retire the `rc22_adapter._apply_obfuscation_only_cap` bolt-on once the Verdict Engine's rule-dependency graph makes it redundant.
- Every migration step must be gated by ≥95% Golden Corpus pass-rate and zero regressions.

## Current state (2026-07-21)

- Layers 1–2 exist (rc2 orchestrator + language routers).
- Layer 3 (RC5 Semantic Engine) is production-ready.
- Layer 4 is partial — Regex, IOC, LOLBIN, MITRE, Behavior exist; YARA, Sigma, API, Crypto, Threat Intel are stubs or missing.
- Layer 5 (Knowledge Graph) — does NOT exist yet. Currently a flat `ExecGraph`.
- Layer 6 (Correlation Engine) — does NOT exist yet. Correlation is implicit in the verdict math.
- Layer 7 exists as `verdict_v2`.
- Layer 8 exists as the Explainability compiler.

The `_apply_obfuscation_only_cap` hotfix is a **temporary corrective**
until Layer 6/7 implement rule-dependency scoring natively.
