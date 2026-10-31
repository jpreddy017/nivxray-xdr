"""Create reconciliation/edr-local-backend-2026-10-31 from the frozen release head.

Two narrowly scoped commits. Source-only. Never touches release/main/preview refs.
"""
import base64, json, subprocess, sys, urllib.error, urllib.request

REPO = "jpreddy017/nivxray-xdr"
BASE = "73e2bfea8d09b269792db92360b902a6b75f7b76"
BRANCH = "reconciliation/edr-local-backend-2026-10-31"
TOK = subprocess.run(
    ["bash", "-lc", "grep '^GITHUB_TOKEN=' /app/backend/.env | cut -d= -f2- | tr -d '\"'"],
    capture_output=True, text=True).stdout.strip()
API = f"https://api.github.com/repos/{REPO}"

SOURCE = [
    "backend/edr_trajectory/contracts.py",
    "backend/edr_trajectory/identity.py",
    "backend/edr_trajectory/production_adapter.py",
    "backend/edr_trajectory/production_service.py",
    "backend/edr_trajectory/providers.py",
    "backend/edr_trajectory/v3_presentation.py",
    "backend/tests/edr_trajectory/test_sd_raw_reference.py",
    "backend/tests/edr_trajectory/test_activity_identity.py",
    "backend/tests/edr_trajectory/test_v3_authentication_contract.py",
]
REVIEW = [
    "backend/server.py",
    "backend/transfer_bundle.py",
    "backend/routers/edr_maintenance.py",
]

MSG_SOURCE = """preserve(edr_trajectory): local DT-v3 authentication + activity-identity work

Source-only preservation of backend work that exists ONLY in the Emergent
workspace and was never pushed. Based on the frozen release head 73e2bfea.
PRESERVATION ONLY - this branch is not a release and is not approval to deploy.

Local provenance:
  0fb1ea41 2026-10-29 fix(dt-v3): classify authentication evidence from the
                      source's own class token
  f9fd38e5 2026-10-29 fix(dt-v3): one activity is one row - match the stores
                      on their stated identity

Semantics:
  - contracts.py        adds AUTH_KINDS to KINDS; adds identity_keys and
                        authentication to the event contract. CONTRACT
                        EXTENSION: additive, but EVENT_SCHEMA stays
                        e3.dt.event.v1 with no version bump.
  - identity.py         dedupe() reworked from a single (tenant,event_id) key
                        to ranked multi-key identity grouping, tenant-scoped,
                        so one activity seen in two stores collapses to one row.
  - providers.py        classifies the source's own class token instead of
                        collapsing authentication records into OTHER.
  - production_service  carries the authentication block through, mapping
                        Windows '-' to NOT_COLLECTED rather than a value.
  - production_adapter  observed_us = min() across merged representations.
  - v3_presentation     renders authentication families and their detail.

Tests: 441 passed / 9 skipped / 0 failed against the candidate.
Isolated release-baseline: 396 passed / 9 skipped. No candidate regression.
Secret-scanned: 0 findings across all files in this commit.

Excluded deliberately: .git history, .env, archives, telemetry, credentials,
and unrelated dirty paths.
"""

MSG_REVIEW = """review(backend): server.py wiring - privileged and temporary routes, DO NOT DEPLOY

Separate review commit. These differences exist in the Emergent workspace and
are NOT part of the release candidate. Recorded for review only.
THIS COMMIT IS NOT APPROVAL TO DEPLOY ANY ROUTE BELOW.

1. transfer_bundle (transfer_router)
   Local-only module, absent from the release head. Unreviewed in this release.

2. routers/edr_maintenance.py (edr_maintenance_router)  ** PRIVILEGED **
   Tenant-wide development RESET. A0-03 recorded it as touching 13 non-EDR
   collections. Gated behind EDR_MAINTENANCE_TOKEN and 404s when unset, but it
   would enter the production image if the workspace were published as-is.
   Recommendation: EXCLUDE from any production payload.

3. Temporary _arch and _pv static mounts  ** TEMPORARY **
   Added by the Emergent agent for owner-requested documentation and
   preservation downloads. Inert unless ARCH_DOCS_SHARE=1.
   Recommendation: REMOVE before any publish. Not for production.

Secret-scanned: 0 findings. No credential, token or telemetry content included.
"""


def req(path, data=None, method=None):
    r = urllib.request.Request(
        API + path,
        data=json.dumps(data).encode() if data is not None else None,
        headers={"Authorization": f"Bearer {TOK}",
                 "Accept": "application/vnd.github+json",
                 "Content-Type": "application/json"},
        method=method)
    try:
        return json.load(urllib.request.urlopen(r, timeout=60))
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:400]
        print(f"  HTTP {e.code} on {method or 'GET'} {path}: {body}")
        raise


def blob(local_path):
    data = open("/app/" + local_path, "rb").read()
    return req("/git/blobs", {"content": base64.b64encode(data).decode(),
                              "encoding": "base64"})["sha"]


def commit(parent, paths, message):
    tree = req("/git/trees", {
        "base_tree": parent,
        "tree": [{"path": p, "mode": "100644", "type": "blob", "sha": blob(p)}
                 for p in paths]})["sha"]
    return req("/git/commits", {"message": message, "tree": tree, "parents": [parent]})["sha"]


# refuse to run if the branch already exists, so nothing is ever force-moved
try:
    existing = req(f"/git/ref/heads/{BRANCH}")
    print(f"branch already exists at {existing['object']['sha']} - refusing to move it")
    sys.exit(2)
except urllib.error.HTTPError:
    pass

c1 = commit(BASE, SOURCE, MSG_SOURCE)
print(f"commit 1 (source) : {c1}")
c2 = commit(c1, REVIEW, MSG_REVIEW)
print(f"commit 2 (review) : {c2}")
ref = req("/git/refs", {"ref": f"refs/heads/{BRANCH}", "sha": c2})
print(f"branch created    : {ref['ref']} -> {ref['object']['sha']}")
print(f"\nhttps://github.com/{REPO}/tree/{BRANCH}")
print(f"compare: https://github.com/{REPO}/compare/{BASE[:12]}...{BRANCH}")
