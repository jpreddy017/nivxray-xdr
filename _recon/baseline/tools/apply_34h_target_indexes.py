"""STEP 34H — apply the TARGET canonical §d indexes. Idempotent, additive.

Refusals are in CODE, not in discipline: the connection string must be supplied
explicitly in `PROD_MONGO_URL` (localhost/127.0.0.1 and the container's own
`MONGO_URL` are refused), and `--apply` is required to write anything. Without
it the tool only REPORTS what it would do.

It creates EXACTLY the two declared target indexes, verifies name + key pattern
by reading them back, and never drops, modifies or renames an existing index.
On MongoDB >= 4.2 index builds are already non-blocking (hybrid); the legacy
`background` flag is passed only to older servers, where it is the
non-disruptive option.

Usage (report only):  PROD_MONGO_URL=… PROD_DB_NAME=… python backend/tools/apply_34h_target_indexes.py
Usage (apply):        … python backend/tools/apply_34h_target_indexes.py --apply
Hermetic self-check:  python backend/tools/apply_34h_target_indexes.py --self-check
"""
import os
import sys
import time

from pymongo import MongoClient

sys.path.insert(0, "/app/backend")
from edr_plane.canonical_index_contract import (  # noqa: E402
    CANONICAL_COLLECTION, TARGET_CANONICAL_INDEXES)

BLOCKED_NO_URI = "NO_EXPLICIT_PRODUCTION_URI_PROD_MONGO_URL_UNSET"
BLOCKED_LOCAL = "REFUSED_PREVIEW_OR_LOCAL_DATABASE"
BLOCKED_SAME = "REFUSED_URI_IDENTICAL_TO_CONTAINER_MONGO_URL"
BLOCKED_NO_DB = "NO_EXPLICIT_PROD_DB_NAME"

SELF_CHECK_DB = "nivx_34h_selfcheck_scratch"


def resolve():
    uri = (os.environ.get("PROD_MONGO_URL") or "").strip()
    if not uri:
        raise SystemExit(f"BLOCKED = {BLOCKED_NO_URI}")
    low = uri.lower()
    if "localhost" in low or "127.0.0.1" in low or "::1" in low:
        raise SystemExit(f"BLOCKED = {BLOCKED_LOCAL}")
    if uri == (os.environ.get("MONGO_URL") or "").strip():
        raise SystemExit(f"BLOCKED = {BLOCKED_SAME}")
    name = (os.environ.get("PROD_DB_NAME") or "").strip()
    if not name:
        raise SystemExit(f"BLOCKED = {BLOCKED_NO_DB}")
    return uri, name


def existing(coll):
    return {i["name"]: tuple(tuple(x) for x in i["key"].items())
            for i in coll.list_indexes()}


def ensure(coll, spec, *, apply_changes, legacy_background):
    """Create one index if an EXACT match is absent. Never drops or modifies."""
    before = existing(coll)
    want = tuple(spec["key"])
    same_key = [n for n, k in before.items() if k == want]
    if same_key:
        return {"name": same_key[0], "state": "ALREADY_PRESENT_VERIFIED",
                "key": want, "created": False, "ms": 0}
    if spec["name"] in before:
        # same name, different key: a conflict is reported, never resolved here
        return {"name": spec["name"], "state": "NAME_CONFLICT_REFUSED",
                "key": before[spec["name"]], "created": False, "ms": 0}
    if not apply_changes:
        return {"name": spec["name"], "state": "WOULD_CREATE", "key": want,
                "created": False, "ms": 0}
    kwargs = {"name": spec["name"]}
    if legacy_background:
        kwargs["background"] = True
    t0 = time.perf_counter()
    coll.create_index([(k, v) for k, v in want], **kwargs)
    ms = int((time.perf_counter() - t0) * 1000)
    after = existing(coll)
    ok = after.get(spec["name"]) == want
    return {"name": spec["name"],
            "state": "CREATED_VERIFIED" if ok else "CREATED_BUT_UNVERIFIED",
            "key": after.get(spec["name"]), "created": True, "ms": ms}


def run(client, dbname, *, apply_changes):
    info = client.server_info()
    version = info["version"]
    major, minor = (int(p) for p in version.split(".")[:2])
    legacy_background = (major, minor) < (4, 2)
    db = client[dbname]
    coll = db[CANONICAL_COLLECTION]
    before = existing(coll)
    print("SERVER_VERSION =", version,
          "| build mode =",
          "legacy background=True" if legacy_background
          else "hybrid (non-blocking by default)")
    print("DB =", dbname, "| COLLECTION =", CANONICAL_COLLECTION)
    print("INDEXES_BEFORE =", {n: list(k) for n, k in before.items()})
    results = [ensure(coll, spec, apply_changes=apply_changes,
                      legacy_background=legacy_background)
               for spec in TARGET_CANONICAL_INDEXES]
    after = existing(coll)
    for r in results:
        print(f'  {r["name"]:36s} {r["state"]:28s} key={list(r["key"] or ())}'
              f' ms={r["ms"]}')
    untouched = all(after.get(n) == k for n, k in before.items())
    print("EXISTING_INDEXES_CHANGED =", "NO" if untouched else "YES")
    print("INDEXES_AFTER =", {n: list(k) for n, k in after.items()})
    return results, untouched


def self_check():
    """Prove idempotency, exact key patterns and non-destructiveness locally."""
    client = MongoClient("mongodb://localhost:27017",
                         serverSelectionTimeoutMS=4000)
    client.drop_database(SELF_CHECK_DB)
    db = client[SELF_CHECK_DB]
    coll = db[CANONICAL_COLLECTION]
    coll.insert_many([{"tenant_id": "t", "event_time": "2026-06-01T00:00:00Z",
                       "host": {"hostname": "H"},
                       "additional_fields": {"endpoint_id": "ep_x"}}
                      for _ in range(50)])
    # a pre-existing unrelated index that must survive untouched
    coll.create_index([("ingest_time", -1), ("tenant_id", 1)],
                      name="tenant_id_1_ingest_time_-1")
    print("\n=== SELF-CHECK PASS 0 · report only (no --apply) ===")
    r0, _ = run(client, SELF_CHECK_DB, apply_changes=False)
    assert all(x["state"] == "WOULD_CREATE" for x in r0), r0
    print("\n=== SELF-CHECK PASS 1 · apply ===")
    r1, untouched1 = run(client, SELF_CHECK_DB, apply_changes=True)
    assert all(x["state"] == "CREATED_VERIFIED" for x in r1), r1
    assert untouched1
    print("\n=== SELF-CHECK PASS 2 · re-run must be a no-op ===")
    r2, untouched2 = run(client, SELF_CHECK_DB, apply_changes=True)
    assert all(x["state"] == "ALREADY_PRESENT_VERIFIED" for x in r2), r2
    assert untouched2
    print("\n=== SELF-CHECK PASS 3 · name conflict is refused, not resolved ===")
    coll.drop_index(TARGET_CANONICAL_INDEXES[0]["name"])
    coll.create_index([("tenant_id", 1), ("event_id", 1)],
                      name=TARGET_CANONICAL_INDEXES[0]["name"])
    r3, untouched3 = run(client, SELF_CHECK_DB, apply_changes=True)
    assert r3[0]["state"] == "NAME_CONFLICT_REFUSED", r3
    assert untouched3
    client.drop_database(SELF_CHECK_DB)
    print("\nSELF_CHECK = PASS (scratch DB dropped; production untouched)")


def main():
    if "--self-check" in sys.argv:
        return self_check()
    uri, dbname = resolve()
    client = MongoClient(uri, serverSelectionTimeoutMS=8000)
    apply_changes = "--apply" in sys.argv
    print("MODE =", "APPLY" if apply_changes else "REPORT_ONLY")
    run(client, dbname, apply_changes=apply_changes)
    print("PRODUCTION_WRITES_OTHER_THAN_INDEX_METADATA = NONE")


if __name__ == "__main__":
    main()
