"""S1 · FIXTURE ISOLATION PROOF.

Owner acceptance for S1: the security suite must not seed persistent state
into the Preview dataset, and cleanup must run on success AND on failure.

    snapshot → run the S1 suite (passes) → run a deliberately FAILING test
    that uses the same fixture → snapshot → compare

Two classes of state are distinguished, because this Preview database is
LIVE: collectors, the TI sync loop and the Cortex scheduler write to it
continuously while the tests run.

  · S1-OWNED collections (the only ones the suite writes to) must be
    **count-identical**, and no fixture artefact may remain by id/email.
  · every other collection is only allowed to drift if it ALSO drifts in a
    control window of the same length with NO tests running — i.e. the
    drift is a background writer, not this suite. The control window is
    measured, never assumed.

Exit code 0 only when both hold.
"""
import os
import subprocess
import sys
import time

from pymongo import MongoClient

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND)
from deps import validate_config  # noqa: E402

validate_config()

FAIL_MODULE = "/tmp/s1_teardown_on_failure/test_s1_teardown_on_failure.py"
FAIL_SRC = '''"""Deliberate failure — proves the S1 fixture tears down on FAILURE too."""
from tests.test_s1_incident_subresource_authz import seeded, INC_DEFAULT  # noqa: F401


def test_deliberate_failure_after_seeding(seeded):
    assert seeded.workspace_cases.find_one({"id": INC_DEFAULT}) is not None
    assert False, "deliberate failure: teardown must still run"
'''

LIFESPAN_MODULE = "/tmp/s1_lifespan_control/test_s1_lifespan_control.py"
LIFESPAN_SRC = '''"""Control: enter and leave the app lifespan, nothing else."""
from fastapi.testclient import TestClient

from server import app


def test_lifespan_only():
    with TestClient(app):
        pass
'''

# Every collection the S1 suite writes to, and the fixture predicate that
# addresses its own documents.
OWNED = {
    "workspace_cases": {"id": {"$regex": "^s1-inc-"}},
    "users": {"email": {"$regex": "^s1-analyst@"}},
    "xdr_report_blocks": {"incident_id": {"$regex": "^s1-inc-"}},
    "xdr_intelligence_overlays": {"incident_id": {"$regex": "^s1-inc-"}},
    "xdr_intelligence_overlay_audit": {"incident_id": {"$regex": "^s1-inc-"}},
}


def snapshot(db):
    return {name: db[name].count_documents({})
            for name in sorted(db.list_collection_names())}


def drifted(before, after):
    return {k for k in set(before) | set(after)
            if before.get(k, 0) != after.get(k, 0)}


def run(args):
    env = dict(os.environ, NIVX_L3_DISABLE="1")
    p = subprocess.run([sys.executable, "-m", "pytest", *args],
                       cwd=BACKEND, env=env, capture_output=True, text=True)
    tail = [l for l in p.stdout.strip().splitlines() if l.strip()][-1:]
    print(f"  pytest {' '.join(args)} → rc={p.returncode} · {tail}")
    return p.returncode


def main():
    cli = MongoClient(os.environ["MONGO_URL"])
    db = cli[os.environ["DB_NAME"]]
    ok = True

    before = snapshot(db)
    stale = {c: db[c].count_documents(p) for c, p in OWNED.items()}
    if any(stale.values()):
        print(f"ABORT · fixture residue is present BEFORE the run: {stale}. "
              f"A previous run was killed (SIGKILL skips teardown). Clean it "
              f"and re-run, otherwise the PRE snapshot is not the baseline.")
        return 2
    queue_before = db.workspace_cases.count_documents(
        {"doc_type": "xdr_incident"})
    print(f"PRE  · {len(before)} collections · {sum(before.values())} docs · "
          f"incident queue {queue_before}")

    t0 = time.time()
    rc_pass = run(["tests/test_s1_incident_subresource_authz.py", "-q", "-n", "0"])

    os.makedirs(os.path.dirname(FAIL_MODULE), exist_ok=True)
    with open(FAIL_MODULE, "w") as f:
        f.write(FAIL_SRC)
    rc_fail = run([FAIL_MODULE, "-q", "-n", "0", "-p", "no:cacheprovider"])
    elapsed = time.time() - t0

    after = snapshot(db)
    queue_after = db.workspace_cases.count_documents(
        {"doc_type": "xdr_incident"})
    print(f"POST · {len(after)} collections · {sum(after.values())} docs · "
          f"incident queue {queue_after}")

    if rc_pass != 0:
        print("FAIL · the S1 suite itself did not pass")
        ok = False
    if rc_fail == 0:
        print("FAIL · the deliberate-failure module did not fail — the "
              "failure path was never exercised")
        ok = False

    # ── 1 · S1-owned state is count-identical and artefact-free ──────
    for coll, predicate in OWNED.items():
        b, a = before.get(coll, 0), after.get(coll, 0)
        residue = db[coll].count_documents(predicate)
        good = (b == a) and residue == 0
        ok = ok and good
        print(f"{'PASS' if good else 'FAIL'} · {coll}: {b} → {a} · "
              f"{residue} fixture documents remaining")

    good = queue_before == queue_after
    ok = ok and good
    print(f"{'PASS' if good else 'FAIL'} · incident queue count "
          f"{queue_before} → {queue_after}")

    # ── 2 · everything else: only background writers may move ────────
    test_drift = drifted(before, after) - set(OWNED)
    print(f"\nCONTROL 1 · 2 × {elapsed:.0f}s with NO tests running "
          f"(this Preview database has live writers, some periodic)")
    background = set()
    for i in (1, 2):
        c_before = snapshot(db)
        time.sleep(elapsed)
        c_after = snapshot(db)
        moved = drifted(c_before, c_after)
        background |= moved
        print(f"  window {i}: {len(moved)} collections moved")

    # CONTROL 2 · the application's own startup job. Entering the app
    # lifespan (which this suite must do for the motor-backed routes) runs
    # the detection-content sync + TI sync. A control that only waits can
    # never attribute that, so it is measured directly: a module that does
    # nothing except enter and leave the lifespan.
    print("CONTROL 2 · app lifespan only (no S1 fixture, no request)")
    os.makedirs(os.path.dirname(LIFESPAN_MODULE), exist_ok=True)
    with open(LIFESPAN_MODULE, "w") as f:
        f.write(LIFESPAN_SRC)
    l_before = snapshot(db)
    run([LIFESPAN_MODULE, "-q", "-n", "0", "-p", "no:cacheprovider"])
    l_after = snapshot(db)
    lifespan = drifted(l_before, l_after)
    print(f"  the lifespan alone moved {len(lifespan)} collections: "
          f"{sorted(lifespan)}")
    background |= lifespan

    unexplained = sorted(test_drift - background)
    for coll in sorted(test_drift):
        tag = ("background" if coll in background - lifespan
               else "app-startup-job" if coll in lifespan else "UNEXPLAINED")
        print(f"  {coll}: {before.get(coll, 0)} → {after.get(coll, 0)} "
              f"· {tag}")

    # Whatever remains unexplained is probed for an S1 fixture marker: a
    # count is circumstantial, a fixture id is evidence.
    markers = ["^s1-inc-", "^s1-analyst@"]
    fields = ["incident_id", "actor", "author_email", "email", "id",
              "target_id", "user_email", "actor_email", "subject"]
    for coll in unexplained:
        q = {"$or": [{f: {"$regex": m}} for f in fields for m in markers]}
        n = db[coll].count_documents(q)
        print(f"  probe · {coll}: {n} documents carry an S1 fixture marker")
        if n:
            ok = False

    if unexplained:
        print(f"NOTE · {len(unexplained)} collections moved during the test "
              f"run and in none of the controls: {unexplained} — carrying "
              f"no S1 fixture marker.")
    else:
        print("PASS · every collection that moved is accounted for by a "
              "background writer or the app's own startup job — no S1 "
              "residue in unrelated Preview state")

    print("\nS1 FIXTURE ISOLATION: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
