# Golden Investigation Corpus (Phase 4 · P6)

**Master architecture reference:** `/app/memory/ARCHITECTURE.md` §10.

Every release replays this corpus and verifies each investigation
produces byte-identical Canonical Artifacts, CEM, Threat Summary, Attack
Chain, Evidence Flow, Timeline, MITRE mappings, and Reports.

**Any drift is a P0 release blocker.**

---

## Layout

```
tests/golden_corpus/
├── README.md                       ← this file
├── manifest.yaml                   ← list of entries + baselines
├── samples/                        ← raw sample inputs (bytes or text)
│   └── <entry_slug>.<ext>
├── baselines/                      ← expected canonical outputs
│   └── <entry_slug>.json           ← baseline CEM + signature + verdict
└── test_investigation_replay.py    ← the replay harness (pytest)
```

## Adding a new golden entry

1. Drop the sample under `samples/<slug>.<ext>`.
2. Add an entry in `manifest.yaml`:
   ```yaml
   - slug: docm_ps_pe
     description: ".docm → PowerShell → PE recursive chain"
     source_kind: file_upload           # file_upload | workspace_input
     sample: samples/docm_ps_pe.docm
     expected_artifact_types: [office, pe]
     expected_min_mitre: [T1059]
   ```
3. Run the harness once to generate the baseline:
   ```bash
   cd /app/backend && python -m pytest tests/golden_corpus/ --update-baseline
   ```
4. Commit both the sample AND `baselines/<slug>.json`.

## Failure modes

- **Baseline missing**: harness fails loudly and prints the current
  fingerprint so an owner can approve it via `--update-baseline`.
- **Baseline drift**: harness fails with a unified diff highlighting
  exactly which canonical field changed.
- **Sample missing**: harness fails with a helpful "sample file expected"
  message and skips the entry from the replay (does NOT auto-pass).

## Interaction with nivxmachines.com (§9 / §9.1)

Golden samples SHOULD be sourced from nivxmachines.com when analyst-safe,
but the harness must remain fully functional using in-tree synthetic
samples if the external source is unavailable. See ARCHITECTURE.md §9.1.
