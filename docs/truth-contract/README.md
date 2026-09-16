# NivXRay · Immutable Truth Contract Snapshot

This directory holds the read-only forensic audit artifacts pinned as the
authoritative pre-Antigravity snapshot of the NivXRay XDR platform's
current implementation state.

## Files

| File | Purpose | Bytes |
|---|---|---|
| `NIVXRAY_CURRENT_STATE_TRUTH.md` | Human-readable 57-point audit + domain narrative + 8-state component truth table | 50,970 |
| `NIVXRAY_CURRENT_STATE.json` | Machine-readable canonical model (valid JSON, 30 top-level keys, 57 audit-point index, 14 stable integration boundaries, 7 candidate-for-new-technology areas) | 22,465 |
| `NIVXRAY_XDR_SOURCE_EXPORT.html` | Self-contained offline-readable single-file source export of the entire NivXRay repo — 4,347 files · 971,264 lines · 43.2 MB source · 49.9 MB HTML. Left-side nav grouped by top-level directory; every file rendered inside `<pre>` with byte-count + line-count. **Excludes:** `.env` (secrets), `test_credentials.md`, `node_modules`, `__pycache__`, `.git`, `dist`/`build`, lockfiles, uploads, binaries, and any single file > 2 MB. Everything else is included byte-for-byte. | 52,284,442 |
| `NIVXRAY_XDR_SOURCE_EXPORT.html.gz` | Gzipped variant of the export (~19% of raw size) for faster downloads. SHA-256 of the raw HTML is `540f6b52d519578fad684f81e995e754a2bc99b3fb9fffcb6869fd0d49366553`. | 10,047,578 |

Both files are byte-identical mirrors of the originals at
`/app/memory/NIVXRAY_CURRENT_STATE_TRUTH.md` and
`/app/memory/NIVXRAY_CURRENT_STATE.json` — copied here solely so the
Emergent **"Save to GitHub"** feature can persist them (it commits
`/app/backend`, `/app/frontend`, `/app/docs`, `/app/deploy`, etc., but
does **NOT** commit `/app/memory/`).

## Rules

- These artifacts are **read-only truth**. Do NOT edit after commit.
- Runtime + code + live-pod curl evidence is authoritative over documentation.
- The commit SHA that first contains both files becomes the immutable
  Antigravity truth-contract anchor.

## Generation

- Mode: strict READ-ONLY forensic audit
- Date: 2026-02 (post-Sprint 1 · post-B3 decoder migration)
- Governance: absolute UI freeze · no decoder scope creep · no P0-C /
  P0-D authorized during audit
- No application code, tests, configs, or UI were modified.
