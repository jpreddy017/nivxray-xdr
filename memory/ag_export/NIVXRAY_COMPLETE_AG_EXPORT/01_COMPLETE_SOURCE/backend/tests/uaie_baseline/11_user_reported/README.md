# uaie_baseline/11_user_reported/

## Philosophy (frozen)

Files under this folder are **regression samples**, not decode targets.

> **NivXRay is a capability-driven investigation engine, not a sample-specific decoder.**
> Every sample here is valuable because it exercises a specific chain of *generic capabilities*.  The sample's name / family / origin is metadata; the acceptance criterion is that the engine reaches its declared **Fixed-Point Termination Certificate** deterministically given the currently-registered capabilities.

## Success criterion (per-sample)

For every sample directory:

1. The engine runs to its fixed point without hanging, crashing, or non-determinism (same input → same `determinism_hash`).
2. The engine exercises the capabilities listed in `metadata.json → capabilities_exercised` that are ALREADY REGISTERED.
3. `metadata.json → capability_gap_report` explicitly documents which capabilities would extend the peel further — these are FUTURE work, not test failures.

## What this folder is NOT

- ❌ **Not** a target list of families the engine should hard-code.
- ❌ **Not** a place for sample-specific "if Sophos then decode_xor()" hacks.
- ❌ **Not** a benchmark that grades success by "reaches C2".

## What this folder IS

- ✅ A permanent corpus of **real inputs** users have pasted into the workspace.
- ✅ A **capability-composition regression suite** — each sample exercises N generic capabilities; adding a new capability should never regress an existing sample.
- ✅ A **capability-gap tracker** — the `capability_gap_report` field in each sample's `metadata.json` tells you which generic capabilities would unlock more peels.  When the same gap appears across many samples, that's your Phase-6-priority capability.

## Adding a new sample

```
mkdir uaie_baseline/11_user_reported/00N_short_slug/
├── input.txt          # raw paste, exactly as the user provided
├── metadata.json      # capabilities_exercised + capability_gap_report + acceptance
└── slo.json           # generic SLOs only — max_ms, expect_fixed_point, minimum stages
```

**Do not** add `expected.json` with sample-specific decoded output unless the engine has already reached its declared fixed-point through generic capabilities.  Freezing outputs from sample-specific hacks defeats the entire architecture.
