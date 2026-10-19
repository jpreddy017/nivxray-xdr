# Smallest controlled backend promotion before Windows re-enrolment

**Nothing in this plan has been executed.** It requires owner authorization
at step 0 and an owner-initiated deployment at step 4.

## What is actually serving today

Established from deployment metadata (deployer, read-only), **not** from
OpenAPI parity — and it corrects an earlier inference of mine: I had read the
workspace's own deploy markers as "last deployed 2026-10-03/04". That build
is **superseded**.

| Fact | Value | How it is known |
|---|---|---|
| Deployment run | `4067c54d-e252-4243-a214-27a9f17715bc` | deployer run record |
| Image digest | `sha256:9ee9b9a21f79d0f2e1cde5dcc5d2bf4de6063a2f05a5cb3195d59f0b7db1a5f2` (arm64, AWS ECR us-west-2) | the authoritative handle; no "Publish NN" integer is surfaced |
| Published | **2026-10-15T01:39:25Z** (build 01:33:22Z → 01:37:43Z), trigger `code_version_deploy` | 11 days later than assumed, across an amd64/GCP → arm64/ECR migration |
| Git commit | **UNVERIFIABLE** | `.git` is stripped from the source archive, no embedded build-metadata file carries a commit, and build-log lookup hit a retention limit. Reported as unverifiable, not inferred |
| Source binding | the serving archive reproduces, byte-for-byte, the three git blobs captured externally: `REAL_WORLD_LOG.md` `cd694f09…`, `EVIDENCE_INVENTORY_2026-02-28.md` `f4f5aa5c…`, `DIAGNOSTIC_RC4…` `506a73e6…` | ties the externally probed content to this image |
| **Enrolment code** | **byte-identical to the copy the proof ran against** | serving `store.py` 633 lines `sha256 73698aba979d9f99c23933345cddb48914193ab7419bb5adb01fd1c64fbc4e24`, `edr_onboarding.py` 623 lines `sha256 ad23d07b09929fd1dd06d1c0a13bf7be944ea25d2fe8d28ec7014c32a68d9811` — both match the local pre-fix files exactly |
| Placement fix | **CONFIRMED ABSENT** | `group_id` does not appear anywhere in the serving `store.py`; the `$setOnInsert` at line 307 carries only the 8 delivery fields |
| Pods | 2/2 Running and ready, `restart_count=0`, `/health` steady 200, no startup errors | intermittent 503 readiness/liveness probe warnings on one pod 2026-10-18/19, no restarts crossed, currently healthy — observation only |
| Mongo binding | **`greeting-app-5782-test_database`** — 103 collections incl. `edr_endpoints`, `edr_enrollment_tokens`, `edr_agent_credentials` | identity only, no documents read. The `-test_database` suffix on a production binding needs an owner answer before a customer sensor is enrolled (see step 0b) |

## Step 0 · Decide (owner)

Promotion is **not required** to recover the endpoint. Identity, credential
and history are safe on the build that is serving now. Promotion is required
only to stop the recovery from moving the computer into the default group
and policy. Either:

* **(A) Promote first** — follow steps 1-5, then re-enrol. The computer keeps
  its group, policy and assignment provenance.
* **(B) Recover first** — re-enrol on the current build and re-assign the
  group and policy in the console afterwards (procedure §4.4). Every future
  re-enrolment repeats that chore until the fix lands.

Both are defensible. (A) is cleaner; (B) is faster and reversible by hand.

## Step 0b · Answer the database binding question (owner, BLOCKING)

The serving pods are bound to **`greeting-app-5782-test_database`**. The
endpoint records, enrolment tokens and agent credentials for the customer
tenant live in a database whose name ends in `-test_database`. Before a real
customer sensor is re-enrolled against it, confirm that this is genuinely the
intended production database and not a staging/test binding that production
traffic has been landing in. If it is not intended, re-enrolment would write
the recovered identity and its credential into the wrong store, and the
157,226-event history already in there is itself in that database.

This is a question only the owner can answer; it was not visible from the
code or the preview, and I have read no documents from it.

## Step 1 · Quarantine what must NOT ride along

An Emergent deployment publishes **the workspace**, not a git branch. Three
things are in the workspace today that are not in production and must not
reach it:

1. `backend/transfer_bundle.py` and its two `server.py` lines — a
   token-gated file download exposing `/app/SECURE_EXPORT`. **Must be
   removed or the route must be disabled before any deploy.** This is the
   single largest promotion risk and it is entirely self-inflicted (it exists
   to hand you these packages).
2. `/app/SECURE_EXPORT/**` — the handoff archives themselves.
3. Any other uncommitted workspace edit. `git status --short` must be read
   and understood immediately before the deploy, not assumed.

## Step 2 · Apply the fix to the workspace, and nothing else

Cherry-pick the single functional commit (`faa8046b` / `e81f77dd`) into the
workspace tree. The expected diff is exactly:

```
backend/edr_plane/enrollment/store.py                        +13
backend/routers/edr_onboarding.py                            +20 -2
backend/tests/edr/test_p0_reenrol_placement_preserved.py    +228
```

The CI workflow (`f1aacf1d`) is for GitHub review and does not need to be in
the deployed image.

## Step 3 · Pre-deploy gate (no deployment yet)

```
cd backend
python -m pytest -p no:randomly -n 0 \
  tests/edr/test_p0_reenrol_placement_preserved.py \
  tests/edr/test_p0_win_reenrol_recovery.py \
  tests/edr/test_p0_windows_reenrol_staging_race.py \
  tests/edr/test_b5_gap1_windows_gate0_ci_contract.py
```
Expect **48 passed**. Then the security gate, and `git status --short` to
re-confirm step 1. Confirm `/api/transfer` is gone from the local OpenAPI:

```
curl -s localhost:8001/api/openapi.json | python3 -c \
  "import json,sys; print('/api/transfer/{name}' in json.load(sys.stdin)['paths'])"
```
It must print `False` before you deploy.

## Step 4 · Deploy (owner-initiated, one change in flight)

Deploy only after steps 1-3. Nothing else should be in flight. Record the
new Publish number and run id — that is the attestation the next assessment
will rely on.

## Step 5 · Post-deploy verification (read-only)

```
curl -s https://nivxray.nivxforge.com/api/health
curl -s https://nivxray.nivxforge.com/api/openapi.json \
  | python3 -c "import json,sys; d=json.load(sys.stdin); \
    print(len(d['paths']), len(d['components']['schemas']), \
          '/api/transfer/{name}' in d['paths'])"
```
Expect `873 315 False`. The fix changes no contract, so OpenAPI parity is
the correct expectation — the placement behaviour itself is first observed
during the recovery, at procedure §4.2/§4.4.

Then, and only then, run the Windows recovery procedure.

## Step 6 · Close B2 permanently (recommended, not required)

Production has no build-metadata route: `/api/version`, `/api/build-info`
and `/api/status` all 404, and no response header carries a build id. Worse,
the deployer could not recover a git commit for the serving image either —
`.git` is stripped from the source archive and nothing in the image embeds
one — so the strongest available handles are a run id and an image digest,
and the code identity had to be established by hashing files in the serving
archive.

A `GET /api/deployment/revision` returning the build commit, run id and build
time — read from environment variables set by the pipeline, no secrets, no
database access — plus writing the commit into the image at build time, would
make every future assessment a single unauthenticated request. It **cannot**
retro-attest the image serving today, so it is deliberately NOT part of this
promotion. Propose it as the next change after the recovery is closed.
