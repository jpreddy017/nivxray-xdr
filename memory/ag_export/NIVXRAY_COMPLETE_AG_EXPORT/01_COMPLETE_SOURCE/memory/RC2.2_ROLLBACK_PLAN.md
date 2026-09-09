# RC2.2 Rollback Plan — Safepoint 2026-07-19 12:26 UTC

## Safepoint tag
`v1.0.0-RC2.2-safepoint-20260719-122658` → commit `ff245b2`

## What this safepoint contains
- RC2.0 + RC2.1a (already in Prod)
- RC2.2 decoder pack (7 new plugins: utf16, ps-reconstruct, data-uri, ioc-extractor, base58, jwt, reverse-string)
- RC2.2 universal file ingest (`/api/batch/test/mine`, `/api/batch/test/mine/preview`)
- 194/194 engine tests green
- Deployed to Prod (https://nivxray.nivxforge.com)

## Rollback commands (preview environment)

```bash
# Full revert to safepoint
cd /app
git reset --hard v1.0.0-RC2.2-safepoint-20260719-122658

# Just view what changed since the safepoint
git diff v1.0.0-RC2.2-safepoint-20260719-122658 -- backend/ frontend/

# List all safepoints
git tag | grep safepoint
```

## Rollback for Production
1. Open the Emergent chat's "Rollback" option in the top-right (free, no code changes required)
2. Pick the last stable checkpoint from the timeline
3. Prod will revert without needing a re-deploy

## What NOT to touch
- `.emergent/` directory (platform-managed)
- `.git/` directory (required for rollback)
- `backend/.env`, `frontend/.env` (protected configs)
- Existing RC2.0 + RC2.1a plugin files under `backend/decoders/families/`

## Verification after rollback
```bash
cd /app/backend
python -m pytest tests/test_rc22_decoder_pack.py tests/test_file_ingest_and_miner.py \
                 tests/test_engine_phase_a.py tests/test_family_plugins.py -q --tb=line
# Expected: all green
```
