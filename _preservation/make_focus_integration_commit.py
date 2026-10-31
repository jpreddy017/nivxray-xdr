"""Second follow-up on reconciliation/edr-identity-repair-2026-10-31.

Addresses the three integration defects found by independent review of 8927306, plus the
test-harness and ID-contract items. Prints a per-file audit against the parent BEFORE
committing so nothing unrelated rides along, and refuses if the branch head has moved.
"""
import base64
import difflib
import json
import subprocess
import sys
import urllib.error
import urllib.request

REPO = "jpreddy017/nivxray-xdr"
BRANCH = "reconciliation/edr-identity-repair-2026-10-31"
PARENT = "8927306cc9fb3fe5d9ac16444fa1949ea3ce7bb3"
TOK = subprocess.run(
    ["bash", "-lc", "grep '^GITHUB_TOKEN=' /app/backend/.env | cut -d= -f2- | tr -d '\"'"],
    capture_output=True, text=True).stdout.strip()
API = f"https://api.github.com/repos/{REPO}"

PATHS = [
    "backend/edr_trajectory/production_adapter.py",
    "backend/routers/edr.py",
    "backend/tests/edr/conftest.py",
    "backend/tests/edr/test_focus_route_lookup_states.py",
    "backend/tests/edr/test_p0_f13_5_detection_handoff.py",
    "backend/tests/edr/test_g41_temporal_authority.py",
    "backend/tests/edr/test_g41_transitional_read.py",
    "backend/tests/edr_trajectory/test_focus_lookup_completeness.py",
    "apps/nivxray-xdr/src/nivxforge/trajectory_v3/amp/deeplink.js",
    "apps/nivxray-xdr/src/nivxforge/trajectory_v3/amp/DeepLinkBanner.jsx",
    "apps/nivxray-xdr/src/nivxforge/trajectory_v3/amp/TrajectoryPage.jsx",
    "apps/nivxray-xdr/src/nivxforge/trajectory_v3/amp/__tests__/deeplink.incomplete.test.js",
    "apps/nivxray-xdr/src/nivxforge/trajectory_v3/amp/__tests__/deeplink.banner.mounted.test.jsx",
    "apps/nivxray-xdr/vite.config.js",
    "apps/nivxray-xdr/package.json",
    "apps/nivxray-xdr/yarn.lock",
]

SUBSTITUTED = {}

MSG = """fix(edr_trajectory): only an explicit completed absence may say "not found"

Independent review of 8927306 found the resolver correct and three INTEGRATION defects that
undid it at the boundaries. All three are fixed here; none required a wider budget, a longer
timeout or a new architecture.

1 · NOT_FOUND was the fallback, so an unavailable lookup became an absence.
   deeplink.js returned NOT_FOUND for anything it did not recognise - and the focus route emits
   FOCUS_AUTHORITY_UNAVAILABLE on any resolver exception, so a store that could not be read
   reached the analyst as "not found in retained evidence for this device". The superseded name
   OBSERVATION_NOT_RESOLVED_SEARCH_INCOMPLETE, an empty body and an unknown future state did
   the same. The absence claim is now DEFAULT-DENY: NOT_FOUND is reachable ONLY from
   OBSERVATION_NOT_RESOLVED that also declares itself complete, is unscoped, reports no
   unreadable store and carries no capped search marker (state or the V1 cursor_state).
   Everything else - authority failure, unknown state, empty or missing body - is INCOMPLETE.

2 · Ambiguity offered buttons that could not resolve.
   trajectory_focus forwarded candidates with the §d `event_id` only. decode_iid deliberately
   rejects anything outside the V3 namespace, so decode_iid("e3i1:0:YQ") is None while the
   navigable form is encode_iid(...) = "e3_ZTNpMTowOllR"; the UI's `c.event_iid || c.event_id`
   fallback therefore produced a dead link. The route now returns BOTH identities for every
   candidate and every partial match (_focus_candidates), the UI navigates ONLY by event_iid,
   and a candidate returned without one renders disabled rather than as a dead link. A route
   test asserts the round trip decode_iid(event_iid) == event_id and that decode_iid(event_id)
   is None, which is the exact defect.

3 · "Narrow the search" narrowed nothing.
   It cleared the deep link and printed advice; neither the route nor resolve_evidence accepted
   any bound. GENUINE SCOPED LOOKUP is implemented instead, with explicit semantics:
     - time_start/time_end only ever NARROW. Tenant and endpoint refs are unchanged and are
       asserted unchanged by test.
     - An unreadable or inverted bound runs NO search at all (SEARCH_SCOPE_NOT_UNDERSTOOD /
       SEARCH_SCOPE_IS_EMPTY). Silently dropping a bound would tell the caller a narrowed
       search ran when it did not.
     - An EXACT versioned identity found inside a scope still resolves: the encoding names one
       identity group.
     - A scoped search may NEVER report an absence
       (SCOPED_SEARCH_FOUND_NOTHING_IN_THE_REQUESTED_WINDOW) and may NEVER resolve a legacy id
       off one match (SCOPED_SEARCH_CANNOT_PROVE_A_LEGACY_IDENTITY_UNIQUE) - a window is not
       retained history.
     - Ambiguity inside the window is still PROVEN and still reported.
     - `scope` is reported on EVERY outcome, scoped or not.
   The UI offers "Search this time range" (runs the scoped lookup over the range on screen),
   "Search all retained evidence" while a scope is in force, and states the window it actually
   searched. No budget or timeout changed.

Frontend reconciliation. The /app workspace copy of TrajectoryPage.jsx was older than the
branch; the branch copy is now the working copy, with this repair applied on top, so the local
tree and the branch no longer diverge for this path. The workspace original is preserved at
_preservation/upstream/TrajectoryPage.local-original.jsx. The banner is extracted to
DeepLinkBanner.jsx so it can be MOUNTED in a test; behaviour is unchanged by the extraction.

Test harness. HARNESS · UNBOUND_DATABASE + EVENT_LOOP_REUSE: in-process route tests never run
FastAPI startup, so deps.db was unbound and trajectory_focus raised before reaching anything it
asserts. deps.init_database() alone is not enough - it is idempotent and only rebinds a client
it can detect as closed, while a client bound by an earlier module in the same xdist worker is
"open" with a dead loop. tests/edr/conftest.py now offers a `bound_db` fixture that binds a
Motor client on the current test's loop and RESTORES the previous binding afterwards rather
than unbinding, because the proxies are process globals shared with every other module.

G41 ID contract, reviewed not weakened. The 17 failures in test_g41_temporal_authority.py and
test_g41_transitional_read.py were introduced by the versioned encoding in 6a4f3f5 and are NOT
excused by a clean immediate-parent comparison. They assert ORDERING, LOSS and ISOLATION on the
identifiers the writer stamped, so `ids_of()` decodes the exported identity back to the writer's
value AND asserts every exported id is well-formed in the versioned space - a check the old bare
string comparison never made. No invariant was relaxed and no production code changed for them.

Tests
  new  tests/edr/test_focus_route_lookup_states.py (8) - authenticated, in-process calls through
       the real route with real authorisation: incomplete is not reported as not resolved;
       ambiguity is offered never narrowed; every candidate and partial match carries a
       navigable presentation identity and round-trips; a completed zero-match search is the
       only OBSERVATION_NOT_RESOLVED; an authority failure declares itself incomplete; the
       requested scope reaches the resolver and the tenant/endpoint bounds are not widened; an
       unscoped lookup sends no bounds; a resolved lookup is navigable.
  new  amp/__tests__/deeplink.banner.mounted.test.jsx (11) - MOUNTED in jsdom, real clicks:
       the banner never says "not found" for an incomplete lookup; an authority failure renders
       incomplete with a working Retry; an unknown state is incomplete; the scoped banner states
       the window it searched; Search this time range and Search all retained evidence fire;
       both candidates render and a click hands back event_iid; a candidate without a navigable
       identity is disabled and cannot be clicked through; only a completed zero-match search
       renders NOT_FOUND.
  +13  amp/__tests__/deeplink.incomplete.test.js - every non-absence shape, including an empty
       body, no body, a capped cursor_state, an unreadable store and a scoped-only absence.
  +8   tests/edr_trajectory/test_focus_lookup_completeness.py - the scoped-lookup semantics
       above, including unreadable and inverted bounds.
  jsdom/@testing-library added as devDependencies; vitest runs Node per file and the mounted
  suite opts in with `// @vitest-environment jsdom`, so the pure-logic suites stay in Node.

Results
  backend  tests/edr + tests/edr_trajectory + tests/edr_behavior: 14 failed / 2995 passed /
           12 skipped, against the ORIGINAL baseline of 36 failed / 2925 passed over identical
           inputs. Zero regressions and 22 pre-existing failures fixed.
  frontend 315 passed / 17 files. vite build clean.
  live     preview, 360k-observation endpoint, unchanged from 8927306: exact id RESOLVED 1.87s;
           legacy id SEARCH_INCOMPLETE with continuation, 8.14s; absent versioned id
           SEARCH_INCOMPLETE after 4,000 compared; foreign tenant NOT_RESOLVED.

Remaining 14, classified against BOTH the parent and the original release head 73e2bfea - all
pre-existing, none introduced by this release, none fixed here:
  12  tests/edr/test_34h_a_migration_control.py - HARNESS · CROSS-MODULE DATABASE BINDING.
      PROVEN by isolation: the file passes 19/19 run alone and fails 12 in the combined run.
      401 "User not found" from get_current_user. Imports deps, server, migration_control and
      edr_migration_control - none of them changed by this release.
  2   tests/edr/test_gate16_edr_independence.py - WORKSPACE DRIFT, not a code defect. The file
      reads frontend SOURCE under /app and asserts test ids in NivXForgeConsole.jsx and
      EdrTrajectoryResolver.jsx. Those /app copies are OLDER than the release head, exactly as
      TrajectoryPage.jsx was; neither file is touched by this release. Fixing it means
      reconciling those two files with the release head, which is outside this repair.

Secret-scanned: 0 findings across all files in this commit.
NOT a release. No production publish, no release merge, no ref moved, no archive deleted.
Preview backend validation only; production untouched and rollout remains HOLD.
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
        return json.load(urllib.request.urlopen(r, timeout=120))
    except urllib.error.HTTPError as e:
        print(f"  HTTP {e.code} on {method or 'GET'} {path}: {e.read().decode()[:300]}")
        raise


def local_path(p):
    return SUBSTITUTED.get(p, "/app/" + p)


def parent_text(path):
    try:
        got = req(f"/contents/{path}?ref={PARENT}")
    except urllib.error.HTTPError:
        return None
    return base64.b64decode(got["content"]).decode("utf-8")


def audit():
    for p in PATHS + list(SUBSTITUTED):
        local = open(local_path(p), encoding="utf-8").read()
        remote = parent_text(p)
        if remote is None:
            print(f"  NEW      {p}  ({len(local.splitlines())} lines)")
            continue
        if remote == local:
            print(f"  SAME     {p}  -- no-op")
            continue
        d = list(difflib.unified_diff(remote.splitlines(), local.splitlines(), n=0, lineterm=""))
        add = sum(1 for x in d if x.startswith("+") and not x.startswith("+++"))
        rem = sum(1 for x in d if x.startswith("-") and not x.startswith("---"))
        print(f"  CHANGED  {p}  +{add} -{rem}")


def blob(path):
    data = open(local_path(path), "rb").read()
    return req("/git/blobs", {"content": base64.b64encode(data).decode(),
                              "encoding": "base64"})["sha"]


if __name__ == "__main__":
    head = req(f"/git/ref/heads/{BRANCH}")["object"]["sha"]
    print(f"branch head : {head}")
    if head != PARENT:
        print(f"REFUSING: head is not the expected parent {PARENT}")
        sys.exit(2)
    print("\nper-file audit against the parent:")
    audit()
    if "--commit" not in sys.argv:
        print("\ndry run. pass --commit to publish.")
        sys.exit(0)
    tree = req("/git/trees", {"base_tree": PARENT,
                              "tree": [{"path": p, "mode": "100644", "type": "blob",
                                        "sha": blob(p)}
                                       for p in PATHS + list(SUBSTITUTED)]})["sha"]
    sha = req("/git/commits", {"message": MSG, "tree": tree, "parents": [PARENT]})["sha"]
    req(f"/git/refs/heads/{BRANCH}", {"sha": sha, "force": False}, method="PATCH")
    print(f"\nfollow-up commit : {sha}")
    print(f"compare: https://github.com/{REPO}/compare/{PARENT[:12]}...{sha[:12]}")
