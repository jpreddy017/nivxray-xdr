# Stage 2B Part 2 — bundle transfer record

Date: 2026-06
Bundle: `/app/rocket-evidence/e3/nivxray-e3-stage2b-part2.bundle`
Disposition: existing bundle served unchanged. Nothing regenerated, pushed, deployed or published.
Pinned source tree untouched — `/app/rocket-p0/src` HEAD `1efa6dc8`, 0 dirty entries.

## Verification

| Check | Result |
|---|---|
| Bundle present | yes, 23,523,587 bytes |
| SHA-256 at rest | `704d0561052ac9e2e8d770e326c417bab0269c28b6094f7f143297ff8cf799f0` — **MATCH** |
| SHA-256 after HTTPS round-trip | **identical** |
| `git bundle verify` on downloaded copy | okay, records a complete history |
| Clone of downloaded copy | HEAD `1efa6dc8…`, tree `b0fe6fa3…`, 10 commits, no alternates, `fsck` clean, tree clean |
| Acceptance scripts in clone | both mode `100755` |

## Delivery method

Static serving via `frontend/public/` was attempted first and **rejected**: this
app's dev server returns the SPA `index.html` fallback for every path, including
pre-existing files under `/downloads/`, so the bundle would have arrived
corrupt. The staging directory was removed.

Delivered instead through a token-gated backend route:

- `backend/transfer_bundle.py` — single `GET /api/transfer/stage2b-part2`
- Token compared with `secrets.compare_digest`; read from `STAGE2B_TRANSFER_TOKEN`
  in `backend/.env`, never hardcoded
- Wrong token and unset token both return `404`; missing token returns `422`
- Streams `application/octet-stream`; no directory listing, no other path exposed

Scope: this is the **preview** app's backend (`/app/backend`), not the pinned
XDR source and not production.

## Revocation

Remove the `STAGE2B_TRANSFER_TOKEN` line from `backend/.env` and restart the
backend; the route then returns `404` to everyone. Optionally delete
`backend/transfer_bundle.py` and its two `server.py` lines.

## Host-side notes

`git clone <bundle>` alone leaves no checkout — the bundle carries only
`refs/heads/engineering/e3-stage2b-package`, no `HEAD`. Clone with
`-b engineering/e3-stage2b-package`. Verified: exec bits survive, so
`host_acceptance.sh` and `egress_denied.sh` stay runnable.
