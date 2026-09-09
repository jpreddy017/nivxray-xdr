# User-Reported Corpus (Rule R24 · Never Break)

Every `.txt` file in this folder is a **real analyst-reported
payload** that must permanently pass R23 + R24 performance SLOs
on every commit.

## To add a payload

1. Save the exact raw input as `<slug>.txt` in this folder
   (e.g. `missing_decoding_75kb.txt`).
2. Optionally create `<slug>.slo.json` next to it with custom SLO
   overrides:
   ```json
   {
     "max_ms":        5000,
     "max_behaviors": 60,
     "min_tactics":   4,
     "expect_decode": ["base64", "gzip", "powershell"]
   }
   ```
3. `pytest tests/test_user_reported_corpus.py` will pick it up
   automatically — no test code changes needed.

## Contract enforced per file

- Backend total render        ≤ `max_ms` (default 3000 ms)
- Behaviors emitted           ≤ `max_behaviors` (default 60)
- MITRE tactics identified    ≥ `min_tactics` (default 1)
- `metadata.performance`      populated
- `decode_status.failed`      MUST be false
- Deterministic               same input → byte-identical SSOT

If any of these fail, CI blocks the merge. A payload that once
broke the platform can never silently break it again.
