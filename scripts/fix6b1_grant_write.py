"""P0 TENANT AUTHORITY · FIX 6B-1 — write ONLY owner-approved tenant grants.

Owner-approved 2026-06. Data preparation only: no authority code, no
enforcement change, no fixture change. Idempotent — re-running it writes
nothing once the approved values are in place.

Writes exactly ONE field (`tenant_ids`) on exactly THREE principals, each
verified to exist, with every approved tenant verified present + ACTIVE under
an ACTIVE organization first. `a05-admin-37051a53@nivxray.test` is never
touched.
"""
from __future__ import annotations

import json
import os
import sys

from dotenv import load_dotenv

load_dotenv("/app/backend/.env")
sys.path.insert(0, "/app/backend")

from pymongo import MongoClient  # noqa: E402

APPROVED = {
    "admin@nivxray.com": ["default", "nivx-live"],
    "p0a-approver@nivxray.com": ["default"],
    "approver@nivxray.com": ["default"],
}
UNTOUCHED = "a05-admin-37051a53@nivxray.test"

PROJ = {"_id": 0, "email": 1, "role": 1, "tenant_id": 1, "tenant_ids": 1}

db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
users, tenants, orgs = db.users, db.tenants, db.organizations


def snapshot(email):
    return users.find_one({"email": email}, PROJ)


def registry_ok(tenant_id):
    t = tenants.find_one({"id": tenant_id}, {"_id": 0, "id": 1, "state": 1,
                                             "organization_id": 1, "kind": 1})
    if t is None:
        return {"tenant": tenant_id, "ok": False, "why": "NOT_REGISTERED"}
    o = orgs.find_one({"id": t.get("organization_id")},
                      {"_id": 0, "id": 1, "state": 1, "kind": 1, "slug": 1})
    ok = t.get("state") == "ACTIVE" and (o or {}).get("state") == "ACTIVE"
    return {"tenant": tenant_id, "ok": ok, "tenant_state": t.get("state"),
            "tenant_kind": t.get("kind"), "organization": (o or {}).get("id"),
            "organization_slug": (o or {}).get("slug"),
            "organization_kind": (o or {}).get("kind"),
            "organization_state": (o or {}).get("state")}


report = {"pre_write_state": {}, "registry_validation": [], "writes": [],
          "post_write_state": {}, "refusals": []}

# ── pre-write state (all four principals + a full fingerprint) ────
for email in list(APPROVED) + [UNTOUCHED]:
    report["pre_write_state"][email] = snapshot(email)

fingerprint_before = {d["email"]: d.get("tenant_ids")
                      for d in users.find({}, {"_id": 0, "email": 1,
                                               "tenant_ids": 1})}

# ── registry validation BEFORE any write ──────────────────────────
for tenant_id in sorted({t for v in APPROVED.values() for t in v}):
    report["registry_validation"].append(registry_ok(tenant_id))
if not all(r["ok"] for r in report["registry_validation"]):
    print(json.dumps({"verdict": "REFUSED", **report}, indent=2, default=str))
    raise SystemExit(1)

# ── the write · one field, one principal at a time, idempotent ────
for email, grants in APPROVED.items():
    current = snapshot(email)
    if current is None:
        report["refusals"].append({"principal": email,
                                   "why": "PRINCIPAL_NOT_FOUND"})
        continue
    if current.get("tenant_ids") == grants:
        report["writes"].append({"principal": email, "action": "NO_OP",
                                 "tenant_ids": grants})
        continue
    res = users.update_one({"email": email}, {"$set": {"tenant_ids": grants}})
    report["writes"].append({"principal": email, "action": "SET",
                             "tenant_ids": grants,
                             "matched": res.matched_count,
                             "modified": res.modified_count})

# ── post-write proof ──────────────────────────────────────────────
for email in list(APPROVED) + [UNTOUCHED]:
    report["post_write_state"][email] = snapshot(email)

fingerprint_after = {d["email"]: d.get("tenant_ids")
                     for d in users.find({}, {"_id": 0, "email": 1,
                                              "tenant_ids": 1})}
unexpected = {e: (fingerprint_before.get(e), v)
              for e, v in fingerprint_after.items()
              if fingerprint_before.get(e) != v and e not in APPROVED}
report["other_principals_changed"] = unexpected
report["users_total_before"] = len(fingerprint_before)
report["users_total_after"] = len(fingerprint_after)
report["a05_untouched"] = (report["pre_write_state"][UNTOUCHED]
                           == report["post_write_state"][UNTOUCHED])
report["verdict"] = ("PASS" if not unexpected and report["a05_untouched"]
                     and not report["refusals"] else "REVIEW")
print(json.dumps(report, indent=2, default=str))
