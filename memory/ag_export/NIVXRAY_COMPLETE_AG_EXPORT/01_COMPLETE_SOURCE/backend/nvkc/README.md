# NVKC — NivXRay Validation & Knowledge Corpus

**Status:** Phase D · Stage 1 (owner-locked 2026-02-16)
**Governance:** Same tier as the Golden Corpus (`backend/tests/golden_corpus/`)
**Master architecture reference:** `/app/memory/ARCHITECTURE.md` v1.1 (FROZEN)

## Purpose

NVKC is **permanent engineering infrastructure**, not a feature and not
AI training. Every future analyzer, analytical consumer, and
deterministic-engine improvement is validated against this corpus.

It provides:

| Track | Purpose | Growth target |
|-------|---------|---------------|
| `command_line/`  | Deterministic scripts, LOLBins, encoders, decoders  | 10 000+ |
| `artifact/`      | PE · PDF · Office · ELF · Mach-O · Email · Archive · APK · IPA · Memory | growing |
| `investigation/` | End-to-end regressions (input → verdict → fingerprint → report) | growing |
| `image/`         | IDA training/regression targets (diagrams, IOC tables, screenshots) | Phase C |
| `malware_family/`| Deterministic family markers for campaign clustering | Phase B/C |
| `benign_enterprise/` | Intune · SCCM · Defender · Cisco · VMware · Windows Update · Exchange · Azure · enterprise PS. False-positive guard. | growing |
| `benchmarks/`    | Regression + performance (RTE iterations, analyzer latency, memory ceilings) | continuous |

## Governance rules

1. **Owner-approved baselines only.** No auto-updates. Any diff must
   go through the same review gate the Golden Corpus uses.
2. **Analyst-safe / synthetic samples first.** External real-world
   samples are strictly optional.
3. **Deterministic fingerprint per sample.** Attack Fingerprint hash
   is pinned so drift is CI-detectable.
4. **NVKC is the primary quality gate.** Every future analyzer +
   feature must pass NVKC before merge.

## Sample metadata schema (v1.0)

Each sample lives in its track's directory and is described by a
YAML file next to it (`<slug>.nvkc.yaml`). Schema:

```yaml
slug:            unique-id                     # required, kebab-case
version:         "1.0"                          # NVKC schema version
track:           command_line | artifact | investigation | image | malware_family | benign_enterprise
description:     one-line human description
input:
  kind:          text | file | b64 | hex
  path:          relative/path/to/payload      # or:
  inline:        "..."                          # for very short payloads
tags:            [powershell, base64, gzip, T1059]   # free-form
expected:
  terminal_state:  binary_artifact_recovered   # RTE terminal state
  artifact_types:  [pe]                        # sorted list
  mitre:           [T1059.001, T1027]          # sorted list
  attack_fingerprint_hash: "<sha256>"          # pinned Attack DNA
  behavior_codes:  [no_imports, invalid_timestamp]
  ioc_kinds:       []                          # or e.g. [url, ip]
  benign:          false                       # true for benign corpus
```

## Validation harness

`backend/nvkc/harness/nvkc_runner.py` loads every `*.nvkc.yaml` under
`backend/nvkc/corpus/`, replays each sample through the frozen v1.1
pipeline, and asserts every field of `expected` matches. Attack
Fingerprint hash drift is treated as a P0 regression identical to
the Golden Corpus contract.

Run locally:

```bash
cd /app/backend
python -m pytest nvkc/harness/ -v
```

Update baseline (owner-only, requires review of the diff):

```bash
python -m pytest nvkc/harness/ --nvkc-update-baseline
```

## Growth stages (owner-locked)

| Stage | Sample count | Milestone |
|-------|--------------|-----------|
| 1     | ~10 seeds     | **Current** — schema + harness landed |
| 2     | 500           | After Compare Cases + Confidence Provenance |
| 3     | 2 000         | After Mach-O + Email + Archives analyzers |
| 4     | 5 000         | After APK + IPA + Memory + IDA |
| 5     | 10 000+       | Continuous coverage expansion |

The stages are **not** blockers — coverage grows continuously as
features ship.
