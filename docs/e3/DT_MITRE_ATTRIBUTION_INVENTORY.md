# DT MITRE attribution inventory: how the OLD NivXForge EDR and the HeatMap attribute ATT&CK, and how the Device Trajectory reuses them

E3 adds **no new mapper**. The Device Trajectory (DT) reads the attribution that E1 has already attached to each trajectory row. It then decorates those ids from the single vendored catalogue.

## 1. Existing E1 attribution sources (unchanged by E3)
| Source (backend/) | Kind | Output | Where it surfaces |
|---|---|---|---|
| `v2/ingestion/mitre_map.py` | Heuristic ingest keyword tag | `event.mitre[]`, basis `SOURCE_NORMALIZER_TAG_NOT_VALIDATED_DETECTION` | Old `AmpEventDetails` MITRE box; DT row `mitre` |
| `engine/detectors/mitre_mapper.py` | Behavior mapper v2 (`MITRE_RULES`) | incident mappings | Incidents, HeatMap coverage |
| `operations.py` | `MITRE_HEURISTICS` regex | `incident.mitre` | HeatMap via `workspace_cases` |
| `canonical/projections/attck.py` | Static `_TECHNIQUE_META` table | tactic + kill-chain per id | Canonical projections |
| Detection rules (E1 `DeterministicRuleAnalyzer`) | Rule-declared | `findings[].attck`, basis `RULE_DECLARED_BY_MATCHED_DETECTION` | DT row `findings` + `mitre_basis` (`edr_plane.trajectory_window._project`) |

Old UI precedent: `apps/nivxray-xdr/src/nivxforge/trajectory/AmpEventDetails.jsx` L114-115 splits `event.mitre` into tactics (`/^TA/`) and techniques. It renders the red "MITRE | ATT&CK" box with ◇ empty states.

## 2. Adapter (reuse, not fork)
- `backend/edr_trajectory/attack.py` `annotate_row(row)` reads only E1's `mitre`, `mitre_basis` and `findings[].attck`. It returns `e3_attack{type, techniques[], tactics[], tactic_ids[], severity, sources[], catalogue_version}`.
- E1's `mitre_basis` maps to the on-screen attribution type:
  - `RULE_DECLARED_BY_MATCHED_DETECTION` → **Rule-mapped**
  - `TI_DERIVED` → **Intel-derived**
  - Normalizer tag, text pattern or behavior mapper → **Heuristic**. Heuristic is never shown as a detection, and is excluded from the strip by default.
- `device_summary()` builds the per-tactic strip in the official kill-chain order.
- Semantics: a mapping is not a verdict; an observed technique is not a confirmed attack; no mapping is not proof of no attack. MITRE, IOC, ML and behavioral matches **never** make a file Malicious. Only the signature / hash-reputation engine does that (`disposition.py`).

## 3. One catalogue
- Official MITRE `attack-stix-data` Enterprise **v19.2**, vendored as `backend/mitre_catalogue/enterprise_v19_2.compact.json`, with a meta file holding the sha256. See `backend/mitre_catalogue/README.md`.
- Revoked ids surface their replacement (`revoked → T1059.001`); deprecated ids are labelled; unknown ids are labelled "not in ATT&CK Enterprise v19.2". Nothing is dropped.
- The HeatMap and DT import the same `xdr/mitre/attackNameIndex.generated.js`, enforced by `tools/e3ui/attack_catalog.test.mjs` and `backend/tests/edr_trajectory/test_attack_catalog.py`.
- MITRE terms-of-use attribution: catalogue README plus the HeatMap footer.

## 4. Known E1 mapper drift vs v19.2 (E1-owned, E3 did not change these)
| Mapper | Retired ids still emitted |
|---|---|
| `v2/ingestion/mitre_map.py` | T1562.001 |
| `operations.py` | T1070.001, T1562, T1562.001, T1562.004, T1562.008 |
| `engine/detectors/mitre_mapper.py` | T1562, T1562.001, T1562.006 |
| `canonical/projections/attck.py` | T1070.001, T1562.001, T1562.004 |

Lint: `python3 tools/e3ui/mitre_mapping_diff.py`. The test `test_rule_mapping_lint` fails if new drift appears.

## 5. Regression: old vs new show identical attributions
`backend/tests/edr_trajectory/test_attack_old_new_parity.py` (7 cases) checks that, for the same E1 row, the old box's tactic/technique ids equal the new `MitreBox` ids, and that both show ◇ when nothing is attributed. This is a data-level test. The DOM-level check is `tools/e3ui/mitre_test.py` (`/e3/mitre-compare` side-by-side, 72 checks).
