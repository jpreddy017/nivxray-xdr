# User & Behavioral Analytics Engine (UBAE) & Entity 360

**Category Directory**: `09_UBAE/`  
**Authoritative Source Reference**: All source files referenced herein reside authoritatively in [`../01_COMPLETE_SOURCE/`](../01_COMPLETE_SOURCE/).  
**Total Associated Files**: 119 files  
**Total Category Size**: 0.86 MB  
**Total Lines of Code / Documentation**: 20,424 lines  

---

## Purpose & Scope

Behavioral baseline profiling, identity parsing, anomaly detection, and entity resolution.

## Behavioral Intelligence Architecture

The UBAE subsystem models normal user and entity behavior to detect account takeover, insider threat, credential theft, and privilege escalation:

### Implemented Modules:
1. **Behavior Graph Schema**: `BEHAVIOR_GRAPH_SCHEMA.md` — Graph model defining entity nodes, behavioral edges, and baseline windows.
2. **Entity Classifier**: `backend/engine/entity_classifier.py` — Classifies identities (human, service account, machine, cloud role).
3. **Behavior Extractor**: `backend/engine/detectors/behavior_extractor.py` & `services/reasoning/behavior_extractor.py` — Extracts behavioral primitives from raw telemetry.
4. **Entity Resolution Pipeline**: `backend/nivxforge/investigation/pipeline/entity_resolution.py` — Correlates IP addresses, MACs, Kerberos tickets, and hostnames to unique identities.
5. **Identity Parser**: `backend/nivxforge/investigation/pipeline/identity_parser.py` — Extracts structured principal tokens from auth logs.
6. **Behavioral Timeline UI**: `frontend/src/components/investigation/BehavioralTimeline.jsx` — Visual timeline of user actions against baseline distributions.


---

## Associated File Index (Authoritative Paths in `01_COMPLETE_SOURCE/`)

| Relative Source Path | Size (Bytes) | Lines | Type | Status |
| :--- | :---: | :---: | :---: | :---: |
| [`01_COMPLETE_SOURCE/BEHAVIOR_GRAPH_SCHEMA.md`](../01_COMPLETE_SOURCE/BEHAVIOR_GRAPH_SCHEMA.md) | 6,934 | 161 | `documentation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/design/Entity.jsx`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/src/xdr/design/Entity.jsx) | 1,778 | 63 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/corpus/behavioral_correlation_corpus.py`](../01_COMPLETE_SOURCE/backend/detection_content/corpus/behavioral_correlation_corpus.py) | 12,883 | 215 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/detection_content/translation/behavioral_translator.py`](../01_COMPLETE_SOURCE/backend/detection_content/translation/behavioral_translator.py) | 4,701 | 118 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/detectors/behavior_extractor.py`](../01_COMPLETE_SOURCE/backend/engine/detectors/behavior_extractor.py) | 13,680 | 286 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/engine/entity_classifier.py`](../01_COMPLETE_SOURCE/backend/engine/entity_classifier.py) | 13,953 | 352 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/entity_resolution.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/entity_resolution.py) | 14,019 | 365 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/identity_parser.py`](../01_COMPLETE_SOURCE/backend/nivxforge/investigation/pipeline/identity_parser.py) | 6,320 | 201 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/routers/behavior_provenance.py`](../01_COMPLETE_SOURCE/backend/routers/behavior_provenance.py) | 10,146 | 249 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/routers/behavior_registry.py`](../01_COMPLETE_SOURCE/backend/routers/behavior_registry.py) | 1,067 | 39 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/routers/behavioral.py`](../01_COMPLETE_SOURCE/backend/routers/behavioral.py) | 13,085 | 329 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/behavioral/__init__.py`](../01_COMPLETE_SOURCE/backend/services/behavioral/__init__.py) | 382 | 8 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/behavioral/evtx_reader.py`](../01_COMPLETE_SOURCE/backend/services/behavioral/evtx_reader.py) | 6,207 | 163 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/behavioral/sysmon_adapter.py`](../01_COMPLETE_SOURCE/backend/services/behavioral/sysmon_adapter.py) | 23,952 | 539 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/die/behavior_explainer.py`](../01_COMPLETE_SOURCE/backend/services/die/behavior_explainer.py) | 11,961 | 195 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/ida/behavior_registry.py`](../01_COMPLETE_SOURCE/backend/services/ida/behavior_registry.py) | 12,964 | 252 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/ida/behaviors.py`](../01_COMPLETE_SOURCE/backend/services/ida/behaviors.py) | 24,148 | 512 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/investigator/capabilities/network_identity_file.py`](../01_COMPLETE_SOURCE/backend/services/investigator/capabilities/network_identity_file.py) | 20,363 | 467 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/knowledge/behavior_registry.py`](../01_COMPLETE_SOURCE/backend/services/knowledge/behavior_registry.py) | 28,504 | 532 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/reasoning/behavior_extractor.py`](../01_COMPLETE_SOURCE/backend/services/reasoning/behavior_extractor.py) | 27,007 | 585 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/__init__.py`](../01_COMPLETE_SOURCE/backend/services/uaie/__init__.py) | 1,755 | 36 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/adapters/__init__.py`](../01_COMPLETE_SOURCE/backend/services/uaie/adapters/__init__.py) | 1,360 | 31 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/adapters/_base.py`](../01_COMPLETE_SOURCE/backend/services/uaie/adapters/_base.py) | 5,930 | 144 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/adapters/_registry.py`](../01_COMPLETE_SOURCE/backend/services/uaie/adapters/_registry.py) | 817 | 16 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/adapters/commandline.py`](../01_COMPLETE_SOURCE/backend/services/uaie/adapters/commandline.py) | 2,710 | 78 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/adapters/docx.py`](../01_COMPLETE_SOURCE/backend/services/uaie/adapters/docx.py) | 5,256 | 125 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/adapters/eml.py`](../01_COMPLETE_SOURCE/backend/services/uaie/adapters/eml.py) | 4,852 | 115 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/adapters/html.py`](../01_COMPLETE_SOURCE/backend/services/uaie/adapters/html.py) | 2,944 | 73 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/adapters/json_adapter.py`](../01_COMPLETE_SOURCE/backend/services/uaie/adapters/json_adapter.py) | 4,454 | 106 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/adapters/pdf.py`](../01_COMPLETE_SOURCE/backend/services/uaie/adapters/pdf.py) | 3,182 | 82 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/adapters/plain_text.py`](../01_COMPLETE_SOURCE/backend/services/uaie/adapters/plain_text.py) | 1,622 | 46 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/adapters/url.py`](../01_COMPLETE_SOURCE/backend/services/uaie/adapters/url.py) | 2,745 | 77 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/adapters/zip_archive.py`](../01_COMPLETE_SOURCE/backend/services/uaie/adapters/zip_archive.py) | 2,844 | 72 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/artifact.py`](../01_COMPLETE_SOURCE/backend/services/uaie/artifact.py) | 2,613 | 80 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/behavior_extractor.py`](../01_COMPLETE_SOURCE/backend/services/uaie/behavior_extractor.py) | 8,489 | 201 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/capability.py`](../01_COMPLETE_SOURCE/backend/services/uaie/capability.py) | 4,023 | 91 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/capability_adapter.py`](../01_COMPLETE_SOURCE/backend/services/uaie/capability_adapter.py) | 11,455 | 265 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/capability_profiles.py`](../01_COMPLETE_SOURCE/backend/services/uaie/capability_profiles.py) | 2,177 | 66 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/contract.py`](../01_COMPLETE_SOURCE/backend/services/uaie/contract.py) | 14,126 | 291 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/discovery_report.py`](../01_COMPLETE_SOURCE/backend/services/uaie/discovery_report.py) | 13,542 | 301 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/evidence.py`](../01_COMPLETE_SOURCE/backend/services/uaie/evidence.py) | 2,357 | 60 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/ledger.py`](../01_COMPLETE_SOURCE/backend/services/uaie/ledger.py) | 5,740 | 136 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/legacy_ssot_adapter.py`](../01_COMPLETE_SOURCE/backend/services/uaie/legacy_ssot_adapter.py) | 6,084 | 137 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/lifecycle.py`](../01_COMPLETE_SOURCE/backend/services/uaie/lifecycle.py) | 7,649 | 197 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/migration_gate.py`](../01_COMPLETE_SOURCE/backend/services/uaie/migration_gate.py) | 19,989 | 420 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/orchestrator.py`](../01_COMPLETE_SOURCE/backend/services/uaie/orchestrator.py) | 55,513 | 1,035 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/planner.py`](../01_COMPLETE_SOURCE/backend/services/uaie/planner.py) | 4,644 | 118 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/planner_v2.py`](../01_COMPLETE_SOURCE/backend/services/uaie/planner_v2.py) | 4,806 | 120 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/plugins/__init__.py`](../01_COMPLETE_SOURCE/backend/services/uaie/plugins/__init__.py) | 6,682 | 132 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/plugins/_shared.py`](../01_COMPLETE_SOURCE/backend/services/uaie/plugins/_shared.py) | 2,824 | 83 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/plugins/analyzer_magic_byte_retyper/__init__.py`](../01_COMPLETE_SOURCE/backend/services/uaie/plugins/analyzer_magic_byte_retyper/__init__.py) | 7,287 | 179 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/plugins/base64_bare/__init__.py`](../01_COMPLETE_SOURCE/backend/services/uaie/plugins/base64_bare/__init__.py) | 5,046 | 124 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/plugins/base64_frombase64string/__init__.py`](../01_COMPLETE_SOURCE/backend/services/uaie/plugins/base64_frombase64string/__init__.py) | 4,068 | 106 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/plugins/crypto_aes_cbc/__init__.py`](../01_COMPLETE_SOURCE/backend/services/uaie/plugins/crypto_aes_cbc/__init__.py) | 793 | 23 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/plugins/crypto_rc4/__init__.py`](../01_COMPLETE_SOURCE/backend/services/uaie/plugins/crypto_rc4/__init__.py) | 812 | 23 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/plugins/crypto_shape_detector/__init__.py`](../01_COMPLETE_SOURCE/backend/services/uaie/plugins/crypto_shape_detector/__init__.py) | 1,193 | 28 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/plugins/cs_beacon_config_parser/__init__.py`](../01_COMPLETE_SOURCE/backend/services/uaie/plugins/cs_beacon_config_parser/__init__.py) | 8,983 | 217 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/plugins/extractor_binary_configuration/__init__.py`](../01_COMPLETE_SOURCE/backend/services/uaie/plugins/extractor_binary_configuration/__init__.py) | 5,758 | 149 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/plugins/family_universal_recognizer/__init__.py`](../01_COMPLETE_SOURCE/backend/services/uaie/plugins/family_universal_recognizer/__init__.py) | 5,004 | 142 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/services/uaie/plugins/gzip_inflate/__init__.py`](../01_COMPLETE_SOURCE/backend/services/uaie/plugins/gzip_inflate/__init__.py) | 3,729 | 100 | `implementation` | `PRE_EXISTING` |

*... and 59 more files. Refer to [`UBAE_MANIFEST.json`](./UBAE_MANIFEST.json) for the exhaustive JSON catalog.*
