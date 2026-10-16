# Stage 2B Part 3 — bundle transfer record

Date: 2026-06
Bundle: `/app/rocket-evidence/e3/nivxray-e3-stage2b-part3.bundle`
Disposition: published for download only. Nothing deployed, merged, pushed or
published to a registry. Production untouched. Release status **NO-GO**.

## Published artefact

| Item | Value |
|---|---|
| Branch | `engineering/e3-stage2b-package` |
| Packaging HEAD | `cd2b8b92d785bee2f88432d3202367bbd51508c0` |
| Packaging tree | `15a13aa6a5fe562895efaecabc11b4e434c8505f` |
| Pinned application commit | `593b3e9fdd6008b67e5cc353c29e413560778fda` |
| Pinned application tree | `54d6e4c28ac564af32f4e0dca59a90214cb0b1bc` |
| Size | 23,532,611 bytes |
| SHA-256 | `98e4adba8ec497411e21b6fa3e9ad11aebcd5d5a2b915e592f2aa42c6747fdfa` |

Verified from the bytes served over HTTPS, not the local file: round-trip SHA
identical, clone yields the expected commit/tree, 12 commits, no alternates,
`fsck` clean, working tree clean, acceptance scripts `100755`, and
`prepare.py --verify-only` prints "Pinned source verified" inside the clone.

## Transfer mechanism

`GET /api/transfer/{name}?token=…` on the preview backend, allowlisted to
`stage2b-part2` and `stage2b-part3`. Token held in `backend/.env`, compared
with `compare_digest`. **The Part 2 token was rotated**; the previous value now
returns 404, as does any unknown bundle name.

Revoke by deleting `STAGE2B_TRANSFER_TOKEN` from `backend/.env` and restarting
the backend.

## Content review

Scanned all 5,666 blobs across all 12 commits.

- **No tracked `.env`, private key, certificate, token or credential file** in
  the HEAD tree or in any ancestor commit.
- Pattern hits were reviewed individually and are all benign: AWS's published
  documentation example key `AKIAIOSFODNN7EXAMPLE` used as a leak-detection
  fixture, `xoxb-…` UI placeholders, negative-test connection strings in
  `test_package.py`, and a `<pwd>` docs template.
- **Disclosed, not omitted:** `apps/nivxray-xdr-response/data/executions.db`
  exists in two ancestor commits (`1dc4e358`, `e6d7efb9`) and is therefore in
  the bundle. It is an **empty SQLite file** — 24,576 bytes, one `executions`
  table, **0 rows**. Untracked since `b30497f8`; absent from the HEAD tree and
  from every exported build context.
- History begins at the sanitized snapshot `b1240bba`; no pre-sanitization
  history, and no alternate object references.

Truncating history to drop the empty database was rejected: `prepare.py`
requires descent from E3 `1dc4e358…`, so a re-rooted bundle would fail
provenance verification on the host.

## Private integration wheel — supply chain

| Item | Value |
|---|---|
| Artefact | `emergentintegrations-0.2.0-py3-none-any.whl` |
| SHA-256 | `1822c409e24817689541891784b8ec3ff4dfed845ce8cd09fd4feb91ba3a4bdd` |
| Size | 29,463 bytes, pure Python (`py3-none-any`) |
| Source | `https://d33sy5i8bnduwe.cloudfront.net/simple/` — Emergent's private index, **not PyPI** |
| Declared in | `backend/requirements-integrations.txt`, pinned with `--hash=sha256:` |

**The wheel itself is NOT in this bundle.** Only the hash-pinned declaration
ships; the artefact is fetched at build time.

Unresolved concerns, stated plainly:

1. **Unsigned.** No Sigstore, no PGP, no in-toto attestation. Hash pinning
   gives integrity, never authorship.
2. **Anonymous metadata** — `Author: Developer`, `developer@example.com`.
3. **Single-vendor CDN** with no published transparency log; a replaced
   artefact would break the build rather than be detected as tampering.
4. **No reproducible build** — the digest cannot be independently derived.
5. **Unused surface.** It declares `stripe` payments code this product never
   calls, plus `openai`, `google-genai`, `google-generativeai` and `pillow`.
   `--no-deps` prevents it from pulling anything unreviewed, since every
   transitive dependency is already pinned in `requirements.txt`.
6. **Direct-URL transitive dependency** — it declares `litellm` from a
   `customer-assets.emergentagent.com` URL. Already pinned by hash in
   `requirements.txt`, so it is constrained, not floating.

Mitigation: `NIVXRAY_INTEGRATIONS=excluded` builds an image without it at all;
LLM routes then fail closed with 503 and the 25-check acceptance trace is
unaffected, since it exercises no LLM route.

## Still blocked

Phases 3–13 of host acceptance, `docker build`, image digests and the
kernel-enforced egress denial test are **BLOCKED and unverified**. Neither the
Docker build nor any security acceptance may be recorded as passed until it is
independently executed on the isolated Hetzner host.
