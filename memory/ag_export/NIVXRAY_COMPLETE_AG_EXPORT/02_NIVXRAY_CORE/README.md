# NivXRay Core Security-Intelligence & Detection Engines

**Category Directory**: `02_NIVXRAY_CORE/`  
**Authoritative Source Reference**: All source files referenced herein reside authoritatively in [`../01_COMPLETE_SOURCE/`](../01_COMPLETE_SOURCE/).  
**Total Associated Files**: 397 files  
**Total Category Size**: 3.56 MB  
**Total Lines of Code / Documentation**: 87,677 lines  

---

## Purpose & Scope

Authoritative core reasoning, correlation, parsing, normalization, and detection engines of NivXRay XDR.

## Architectural Overview & Active Engines

NivXRay Core is the primary security reasoning plane. It processes raw and canonical evidence through a strict, deterministic causal pipeline:

1. **IUE (Implicit Unknown Extraction)**: `services/iue/` — Discovers unmanaged, unmodeled, and novel entities, anomalous parent-child relationships, and stealth attack pivots.
2. **ICE (Implicit Correlation Engine)**: `services/ice/` & `detection_content/xdr_ice.py` — High-throughput temporal correlation engine chaining atomic alerts into contextual attack stories.
3. **IEDDE (Implicit Entity & Dynamic Discovery Engine)**: Resolves dynamic identities across multi-cloud and enterprise environments.
4. **UAIE (Unified Adversary Intent Engine)**: `services/uaie/` — Projects observed actions onto MITRE ATT&CK techniques, tactics, and adversary objectives.
5. **DIE (Deobfuscation & Intelligence Engine)**: `services/die/` — Semantic command understanding, LOLBAS discrimination, and behavior explanations.
6. **IDA (Identity & Domain Analytics)**: `services/ida/` — Domain entity tracking and behavioral anomaly projection.
7. **Canonicalizer & Ingress Gate**: `services/canonicalizer/` — Launcher peeling, environment variable expansion, and canonical command projection.
8. **Attack Graph & Story Engines**: `services/attack_graph/` & `services/attack_story/` — Construct causal directed acyclic graphs (DAGs) representing incident progression.
9. **Stage 2 Verdict Engine**: `services/verdict_stage2/` — Secondary deterministic evaluation of composite attack graphs.


---

## Associated File Index (Authoritative Paths in `01_COMPLETE_SOURCE/`)

| Relative Source Path | Size (Bytes) | Lines | Type | Status |
| :--- | :---: | :---: | :---: | :---: |
| [`01_COMPLETE_SOURCE/backend/engine/__init__.py`](../01_COMPLETE_SOURCE/backend/engine/__init__.py) | 2,557 | 75 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/config.py`](../01_COMPLETE_SOURCE/backend/engine/config.py) | 1,395 | 41 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/correlation_engine.py`](../01_COMPLETE_SOURCE/backend/engine/correlation_engine.py) | 8,472 | 223 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/decoder_base.py`](../01_COMPLETE_SOURCE/backend/engine/decoder_base.py) | 2,730 | 77 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/detectors/__init__.py`](../01_COMPLETE_SOURCE/backend/engine/detectors/__init__.py) | 0 | 0 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/detectors/behavior_extractor.py`](../01_COMPLETE_SOURCE/backend/engine/detectors/behavior_extractor.py) | 13,680 | 286 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/detectors/explainability.py`](../01_COMPLETE_SOURCE/backend/engine/detectors/explainability.py) | 16,108 | 393 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/detectors/lolbin_v2.py`](../01_COMPLETE_SOURCE/backend/engine/detectors/lolbin_v2.py) | 15,720 | 383 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/detectors/mitre_mapper.py`](../01_COMPLETE_SOURCE/backend/engine/detectors/mitre_mapper.py) | 30,244 | 651 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/detectors/mitre_navigator_export.py`](../01_COMPLETE_SOURCE/backend/engine/detectors/mitre_navigator_export.py) | 4,997 | 134 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/detectors/mitre_stix_export.py`](../01_COMPLETE_SOURCE/backend/engine/detectors/mitre_stix_export.py) | 6,177 | 166 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/detectors/verdict_v2.py`](../01_COMPLETE_SOURCE/backend/engine/detectors/verdict_v2.py) | 17,635 | 421 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/entity_classifier.py`](../01_COMPLETE_SOURCE/backend/engine/entity_classifier.py) | 13,953 | 352 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/evidence_graph.py`](../01_COMPLETE_SOURCE/backend/engine/evidence_graph.py) | 21,477 | 569 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/evidence_graph_builder.py`](../01_COMPLETE_SOURCE/backend/engine/evidence_graph_builder.py) | 15,388 | 382 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/evidence_graph_config.py`](../01_COMPLETE_SOURCE/backend/engine/evidence_graph_config.py) | 1,810 | 60 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/evidence_graph_observability.py`](../01_COMPLETE_SOURCE/backend/engine/evidence_graph_observability.py) | 4,234 | 132 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/exec_graph.py`](../01_COMPLETE_SOURCE/backend/engine/exec_graph.py) | 14,182 | 371 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/explain_export.py`](../01_COMPLETE_SOURCE/backend/engine/explain_export.py) | 15,695 | 366 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/fingerprint_util.py`](../01_COMPLETE_SOURCE/backend/engine/fingerprint_util.py) | 3,094 | 93 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/golden_corpus.py`](../01_COMPLETE_SOURCE/backend/engine/golden_corpus.py) | 20,791 | 536 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/golden_corpus_categories.py`](../01_COMPLETE_SOURCE/backend/engine/golden_corpus_categories.py) | 6,328 | 128 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/golden_corpus_expansion.py`](../01_COMPLETE_SOURCE/backend/engine/golden_corpus_expansion.py) | 15,220 | 400 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/golden_corpus_expansion_r2.py`](../01_COMPLETE_SOURCE/backend/engine/golden_corpus_expansion_r2.py) | 11,524 | 286 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/golden_corpus_obfuscation_family.py`](../01_COMPLETE_SOURCE/backend/engine/golden_corpus_obfuscation_family.py) | 4,436 | 117 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/golden_corpus_taxonomy.py`](../01_COMPLETE_SOURCE/backend/engine/golden_corpus_taxonomy.py) | 2,390 | 51 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/interpreters/__init__.py`](../01_COMPLETE_SOURCE/backend/engine/interpreters/__init__.py) | 0 | 0 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/interpreters/cmd_interpreter.py`](../01_COMPLETE_SOURCE/backend/engine/interpreters/cmd_interpreter.py) | 19,462 | 421 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/interpreters/powershell_interpreter.py`](../01_COMPLETE_SOURCE/backend/engine/interpreters/powershell_interpreter.py) | 38,472 | 790 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/models.py`](../01_COMPLETE_SOURCE/backend/engine/models.py) | 16,382 | 377 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/normalizers_ps/__init__.py`](../01_COMPLETE_SOURCE/backend/engine/normalizers_ps/__init__.py) | 0 | 0 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/normalizers_ps/alias_map.py`](../01_COMPLETE_SOURCE/backend/engine/normalizers_ps/alias_map.py) | 3,056 | 101 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/orchestrator.py`](../01_COMPLETE_SOURCE/backend/engine/orchestrator.py) | 69,713 | 1,475 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/parsers/__init__.py`](../01_COMPLETE_SOURCE/backend/engine/parsers/__init__.py) | 0 | 0 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/parsers/cmd_parser.py`](../01_COMPLETE_SOURCE/backend/engine/parsers/cmd_parser.py) | 20,275 | 482 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/parsers/powershell_parser.py`](../01_COMPLETE_SOURCE/backend/engine/parsers/powershell_parser.py) | 32,356 | 705 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/plugin_api.py`](../01_COMPLETE_SOURCE/backend/engine/plugin_api.py) | 4,725 | 139 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/registry.py`](../01_COMPLETE_SOURCE/backend/engine/registry.py) | 4,741 | 130 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/report.py`](../01_COMPLETE_SOURCE/backend/engine/report.py) | 8,165 | 206 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/report_pdf.py`](../01_COMPLETE_SOURCE/backend/engine/report_pdf.py) | 11,529 | 284 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/semantic_ir.py`](../01_COMPLETE_SOURCE/backend/engine/semantic_ir.py) | 3,746 | 110 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/shadow.py`](../01_COMPLETE_SOURCE/backend/engine/shadow.py) | 19,077 | 495 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/stix_exporter.py`](../01_COMPLETE_SOURCE/backend/engine/stix_exporter.py) | 2,506 | 84 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/models/__init__.py`](../01_COMPLETE_SOURCE/backend/models/__init__.py) | 584 | 32 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/models/iep.py`](../01_COMPLETE_SOURCE/backend/models/iep.py) | 15,244 | 421 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/__init__.py`](../01_COMPLETE_SOURCE/backend/services/__init__.py) | 257 | 6 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/activity/__init__.py`](../01_COMPLETE_SOURCE/backend/services/activity/__init__.py) | 0 | 0 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/activity/model.py`](../01_COMPLETE_SOURCE/backend/services/activity/model.py) | 4,825 | 118 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/activity/projector.py`](../01_COMPLETE_SOURCE/backend/services/activity/projector.py) | 14,740 | 372 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/adapters/__init__.py`](../01_COMPLETE_SOURCE/backend/services/adapters/__init__.py) | 1,929 | 60 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/adapters/base.py`](../01_COMPLETE_SOURCE/backend/services/adapters/base.py) | 8,195 | 199 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/adapters/docx_adapter.py`](../01_COMPLETE_SOURCE/backend/services/adapters/docx_adapter.py) | 21,014 | 485 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/adapters/eml_adapter.py`](../01_COMPLETE_SOURCE/backend/services/adapters/eml_adapter.py) | 18,512 | 390 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/adapters/image_adapter.py`](../01_COMPLETE_SOURCE/backend/services/adapters/image_adapter.py) | 22,372 | 499 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/adapters/pdf_adapter.py`](../01_COMPLETE_SOURCE/backend/services/adapters/pdf_adapter.py) | 20,983 | 479 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/adapters/text_adapter.py`](../01_COMPLETE_SOURCE/backend/services/adapters/text_adapter.py) | 5,647 | 132 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/adapters/url_adapter.py`](../01_COMPLETE_SOURCE/backend/services/adapters/url_adapter.py) | 12,648 | 276 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/adapters/zip_adapter.py`](../01_COMPLETE_SOURCE/backend/services/adapters/zip_adapter.py) | 21,189 | 454 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/analyzers/__init__.py`](../01_COMPLETE_SOURCE/backend/services/analyzers/__init__.py) | 1,442 | 41 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/analyzers/pe.py`](../01_COMPLETE_SOURCE/backend/services/analyzers/pe.py) | 22,541 | 499 | `implementation` | `PRE_EXISTING` |

*... and 337 more files. Refer to [`CORE_CAPABILITY_MANIFEST.json`](./CORE_CAPABILITY_MANIFEST.json) for the exhaustive JSON catalog.*
