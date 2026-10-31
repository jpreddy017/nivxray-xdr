# MITRE ATT&CK Enterprise catalogue (vendored, offline)

This is the single catalogue used by **both** the ATT&CK HeatMap (`services/mitre_catalogue`, `/api/mitre/catalogue/*`) and Device Trajectory (`edr_trajectory/attack.py`, `xdr/mitre/attackNameIndex.generated.js`). There is no second copy, and nothing is fetched at runtime.

| | |
|---|---|
| Source | MITRE official `mitre-attack/attack-stix-data`, release **v19.2** (published 2026-08-05; checked as the latest Enterprise release tag at fetch time) |
| URL | https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v19.2/enterprise-attack/enterprise-attack-19.2.json |
| SHA-256 of raw bundle | `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4` |
| Raw bundle | about 54 MB, **not committed**; it is fetched once at build time |
| Derived | `enterprise_v19_2.compact.json`: 15 tactics (x-mitre-matrix order), 222 techniques + 475 sub-techniques (active), `retired[]` (deprecated/revoked, with `revoked_by` from the "revoked-by" relationships), version, modified date |
| Frontend | `apps/nivxray-xdr/src/xdr/mitre/attackNameIndex.generated.js` (`CATALOGUE_VERSION`, `ATTACK_TACTICS`, name index) |

Rebuild (build-time only, outside the network-guarded tests):

```bash
curl -fLo /tmp/ea.json https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v19.2/enterprise-attack/enterprise-attack-19.2.json
python3 backend/mitre_catalogue/build_catalogue.py /tmp/ea.json v19.2
# point services/mitre_catalogue/service.py CATALOGUE_PATH at the new file, then:
python3 backend/mitre_catalogue/build_name_index.py
```

ATT&CK v19 split Defense Evasion into **Stealth** (TA0005) and **Defense Impairment** (TA0112). Mappers that still name "Defense Evasion", or that map to the revoked T1562.* / T1070.001, are listed by `tools/e3ui/mitre_mapping_diff.py` and the lint test `tests/edr_trajectory/test_attack_catalog.py`.

## Terms of use / attribution

© The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation. See the ATT&CK Terms of Use: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/
