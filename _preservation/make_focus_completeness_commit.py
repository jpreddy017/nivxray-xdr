"""Follow-up commit on reconciliation/edr-identity-repair-2026-10-31.

Bounded legacy-lookup completeness repair. Preserves 6a4f3f5 as the parent and never moves
release/main/preview refs. Prints the exact per-file difference against the parent BEFORE
committing, so nothing unrelated to this repair can ride along.
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
PARENT = "6a4f3f5f17ce494fd5d79b7aac8707753eff2300"
TOK = subprocess.run(
    ["bash", "-lc", "grep '^GITHUB_TOKEN=' /app/backend/.env | cut -d= -f2- | tr -d '\"'"],
    capture_output=True, text=True).stdout.strip()
API = f"https://api.github.com/repos/{REPO}"

PATHS = [
    "backend/edr_trajectory/identity.py",
    "backend/edr_trajectory/production_adapter.py",
    "backend/edr_trajectory/production_service.py",
    "backend/edr_trajectory/v3_presentation.py",
    "backend/routers/edr.py",
    "backend/tests/edr_trajectory/test_focus_lookup_completeness.py",
    "backend/tests/edr_trajectory/test_identity_paging_integration.py",
    "backend/tests/edr_trajectory/test_v3_presentation.py",
    "apps/nivxray-xdr/src/nivxforge/trajectory_v3/amp/deeplink.js",
    "apps/nivxray-xdr/src/nivxforge/trajectory_v3/amp/__tests__/deeplink.incomplete.test.js",
]

#: The /app copy of TrajectoryPage.jsx is OLDER than the branch head, which already carries
#: later frontend work. Committing the workspace copy would silently revert it, so this blob is
#: built from the BRANCH copy plus exactly this repair (see patch_trajectory_page.py).
SUBSTITUTED = {
    "apps/nivxray-xdr/src/nivxforge/trajectory_v3/amp/TrajectoryPage.jsx":
        "/app/_preservation/upstream/TrajectoryPage.commit.jsx",
}

MSG = """fix(edr_trajectory): an unfinished identifier lookup is neither a find nor an absence

A single LEGACY match was resolved even when the search that found it had not completed.
The versioned encoding made EXPORTED ids unambiguous, but a legacy bare id stays non-unique:
the same text can name rows in more than one identity namespace. Resolving the one match that
happened to fall inside the page budget was therefore a silent choice between candidates, and
the response was indistinguishable from an ordinary success. A capped zero-match walk had the
same defect in reverse: it was returned as FOCUS_NOT_RESOLVED, which reads as "this endpoint
never held it" - a claim the bounded walk never established.

Contract. resolve_evidence now returns FOUR distinct outcomes and never rounds one to another:

  FOCUS_RESOLVED          exact versioned identity or one of its aliases (unique by
                          construction), or exactly ONE legacy match after a COMPLETED
                          exhaustive search over EVERY requested store.
  FOCUS_AMBIGUOUS         two or more verified matches. Returned as soon as the second is
                          seen - ambiguity is proven by what was read, so the walk stops.
  FOCUS_SEARCH_INCOMPLETE the search did not finish: page budget reached, continuation
                          remaining, or an evidence store that could not be read. `event` is
                          always None, any match already seen is disclosed as a PARTIAL match,
                          and a resume cursor plus narrowing guidance is returned.
  FOCUS_NOT_RESOLVED      reserved for a COMPLETED zero-match search.

Scope and bounds are unchanged: same tenant, same endpoint refs, same FOCUS_PAGE_BUDGET, same
PAGE_MAX, no timeout change and no unbounded history scan. The repair narrows what may be
CLAIMED, not how much is read.

Store-read honesty. page_device_evidence no longer lets one failing branch abort the page or
silently shrink it: the failure is recorded as `provenance.stores_unavailable` with
`read_complete=false` and page state PARTIAL_STORE_READ. Rows that were read stay real
evidence; the rows that were not read prove nothing, so a lookup over a partially read store
set can neither find nor deny. An EXACT versioned hit still resolves through a partial read,
because the encoding names one identity group regardless of what else was readable.

Namespaces are never guessed. An identifier that PARSES as the versioned encoding is matched
only in the versioned space and is never retried as a legacy bare value - a stored raw identity
may literally read "e3i1:0:..." and matching it as the namespace its text spells out would be a
guess. Malformed and unknown-version identifiers match nothing and are not repaired.

Carried through every consumer:
  production_service  in-page resolution is restricted to the EXACT identity; a legacy hit
                      inside the loaded page no longer short-circuits the only search that can
                      count the matches. An empty page no longer converts an unfinished lookup
                      into an absence. `details` is None in every non-resolved outcome.
  v3_presentation     new `focus` block carries the state, reason, search scope, retry and
                      candidates in V3 identity vocabulary, plus
                      `evidence_read_complete`. Nothing is flattened.
  routers/edr         /trajectory/focus returns OBSERVATION_LOOKUP_INCOMPLETE,
                      OBSERVATION_IDENTIFIER_AMBIGUOUS or OBSERVATION_NOT_RESOLVED with
                      `lookup_complete`, instead of one state with an explanatory reason.
  served frontend     amp/deeplink.js is the single mapping the Device Trajectory page renders
                      from. "Lookup incomplete" and "Identifier is ambiguous" are their own
                      states with Retry lookup and Narrow the search actions; candidates are
                      OFFERED, never applied; no row is auto-selected and the loaded evidence
                      is preserved. Selection remains an exact event_iid match or nothing.

Documentation corrected: the encoding is UNAMBIGUOUS, not unforgeable. It carries no signature
and makes no integrity claim; its guarantee is that nothing has to be guessed when reading an
identifier.

Tests
  test_focus_lookup_completeness.py (new, 31):
    one match inside the budget with a second beyond it -> INCOMPLETE, never resolved
    the same fixture with a sufficient budget -> AMBIGUOUS
    zero matches before budget exhaustion -> INCOMPLETE, not an absence
    last allowed page exhausts the data with one match -> RESOLVED (exhaustive)
    two known matches -> AMBIGUOUS immediately, walk stopped, retryable=false
    duplicate representations of one activity -> one row, resolved
    partial store failure -> INCOMPLETE for zero matches AND for one match
    exact versioned identity still resolves through a partial read
    tenant isolation both directions; another tenant's id is absent, not ambiguous
    raw values shaped like the encoding; malformed and unknown-version identifiers
    production_service and v3_presentation carry all four states without flattening
  deeplink.incomplete.test.js (new, 9): incomplete and ambiguous never become NOT_FOUND and
    never select a row; exact-match selection has no first-row fallback.
    SCOPE: this package has no jsdom, so these exercise the mapping the component renders
    from, NOT a mounted DOM.
  test_identity_paging_integration.py: legacy deep link may now report INCOMPLETE, and a
    capped search on real retained history is asserted to report INCOMPLETE with a resume
    cursor rather than an absence.
  test_v3_presentation.py: the capped-search test now asserts the state itself, so a consumer
    reading only `state` cannot mistake it for an absence.

Results: edr_trajectory 506 passed / 19 skipped / 0 failed. Frontend 290 passed / 16 files,
vite build clean - verified against the exact TrajectoryPage.jsx blob in this commit.
Like-for-like comparison over tests/edr + tests/edr_trajectory + tests/edr_behavior, identical
inputs: baseline 36 failed / 2925 passed, candidate 35 failed / 2958 passed, with the candidate
failure set a SUBSET of the baseline - zero regressions. Those pre-existing failures are NOT
fixed here and are reported as outstanding: 17 in tests/edr/test_g41_transitional_read.py and
test_g41_temporal_authority.py assert the OLD bare event_id and were broken by the versioned
encoding in 6a4f3f5; 12 in test_34h_a_migration_control.py fail on a 401 auth harness; 4 in
test_p0_f13_5_detection_handoff.py fail on "deps.db accessed before init_database()"; 2 in
test_gate16_edr_independence.py are unrelated.

Live preview, real retained history (360k-observation endpoint, tenant default):
  exact versioned id    -> FOCUS_RESOLVED, MATCH_FOUND_SEARCH_STOPPED, 1.87s
  legacy bare id        -> FOCUS_SEARCH_INCOMPLETE, budget reached, continuation available,
                           1 partial match disclosed, 8.14s  (previously a silent resolve)
  absent versioned id   -> FOCUS_SEARCH_INCOMPLETE after 4,000 observations compared, 5.90s
  foreign tenant        -> FOCUS_NOT_RESOLVED, event None
Known consequence, stated rather than hidden: on a large endpoint a LEGACY deep link now
commonly reports "Lookup incomplete" instead of resolving, because uniqueness cannot be proven
within the bound. The versioned event_id resolves immediately and is the narrowing action the
UI offers.

Note on TrajectoryPage.jsx: the /app workspace copy of this file is OLDER than the branch head,
which already carries later frontend work (older-page abort handling, cursor-advance guard,
OUTSIDE_PAGE state). The committed blob is the BRANCH copy plus exactly this repair, so none of
that work is reverted. The workspace original is preserved unmodified.

Secret-scanned: 0 findings across all files in this commit.
NOT a release. No production publish, no release merge, no ref moved, no archive deleted.
Preview backend validation only; production remains untouched and rollout remains HOLD.
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
        return json.load(urllib.request.urlopen(r, timeout=90))
    except urllib.error.HTTPError as e:
        print(f"  HTTP {e.code} on {method or 'GET'} {path}: {e.read().decode()[:400]}")
        raise


def parent_text(path):
    try:
        got = req(f"/contents/{path}?ref={PARENT}")
    except urllib.error.HTTPError:
        return None
    return base64.b64decode(got["content"]).decode("utf-8")


def local_path(p):
    return SUBSTITUTED.get(p, "/app/" + p)


def audit():
    """Print the exact change per file against the parent. Nothing unrelated may ride along."""
    clean = True
    for p in PATHS + list(SUBSTITUTED):
        local = open(local_path(p), encoding="utf-8").read()
        remote = parent_text(p)
        if remote is None:
            print(f"  NEW      {p}  ({len(local.splitlines())} lines)")
            continue
        if remote == local:
            print(f"  SAME     {p}  -- would be a no-op")
            continue
        d = list(difflib.unified_diff(remote.splitlines(), local.splitlines(), n=0, lineterm=""))
        add = sum(1 for x in d if x.startswith("+") and not x.startswith("+++"))
        rem = sum(1 for x in d if x.startswith("-") and not x.startswith("---"))
        print(f"  CHANGED  {p}  +{add} -{rem}")
        for x in d:
            if x.startswith("@@"):
                print(f"             {x}")
    return clean


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
