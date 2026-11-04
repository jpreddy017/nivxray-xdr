"""P0 TENANT AUTHORITY · FIX 6B-1b — designate the initial PLATFORM Super Admin.

Owner-approved 2026-06. Exactly ONE field on exactly ONE principal:

    users.authority_scope = "PLATFORM"   for admin@nivxray.com

PLATFORM authority is exceptional and must be explicit; every other principal
stays CUSTOMER by absence (missing / null / malformed ⇒ CUSTOMER). Nothing
else is written — role, tenant_id, tenant_ids, password, status and every
other document remain untouched. Enforcement is NOT changed by this step.

Idempotent: re-running writes nothing once the designation is in place.
"""
from __future__ import annotations

import json
import os

from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv("/app/backend/.env")

PRINCIPAL = "admin@nivxray.com"
SCOPE = "PLATFORM"
EXPECTED_GRANTS = ["default", "nivx-live"]

PROJ = {"_id": 0, "email": 1, "role": 1, "tenant_id": 1, "tenant_ids": 1,
        "authority_scope": 1, "must_change_password": 1}

db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
users = db.users

report = {}

before = users.find_one({"email": PRINCIPAL}, PROJ)
report["pre_write_state"] = before
if before is None:
    report["verdict"] = "REFUSED · PRINCIPAL_NOT_FOUND"
    print(json.dumps(report, indent=2, default=str))
    raise SystemExit(1)
if before.get("tenant_ids") != EXPECTED_GRANTS:
    report["verdict"] = ("REFUSED · UNEXPECTED_GRANTS — Fix 6B-1 grants must "
                         "be present and unchanged before designation")
    print(json.dumps(report, indent=2, default=str))
    raise SystemExit(1)

fingerprint_before = {d["email"]: d.get("authority_scope")
                      for d in users.find({}, {"_id": 0, "email": 1,
                                               "authority_scope": 1})}
report["authority_scope_holders_before"] = {
    e: v for e, v in fingerprint_before.items() if v is not None}

if before.get("authority_scope") == SCOPE:
    report["write_method"] = "NO_OP · already designated"
else:
    res = users.update_one({"email": PRINCIPAL},
                           {"$set": {"authority_scope": SCOPE}})
    report["write_method"] = {
        "op": 'update_one({"email": PRINCIPAL}, {"$set": {"authority_scope": "PLATFORM"}})',
        "matched": res.matched_count, "modified": res.modified_count}

after = users.find_one({"email": PRINCIPAL}, PROJ)
report["post_write_state"] = after

fingerprint_after = {d["email"]: d.get("authority_scope")
                     for d in users.find({}, {"_id": 0, "email": 1,
                                              "authority_scope": 1})}
report["authority_scope_holders_after"] = {
    e: v for e, v in fingerprint_after.items() if v is not None}
report["other_users_changed"] = {
    e: (fingerprint_before.get(e), v) for e, v in fingerprint_after.items()
    if fingerprint_before.get(e) != v and e != PRINCIPAL}

report["authority_scope"] = after.get("authority_scope")
report["tenant_ids_preserved"] = after.get("tenant_ids") == EXPECTED_GRANTS
report["role_preserved"] = after.get("role") == before.get("role")
report["other_fields_changed"] = {
    k: (before.get(k), after.get(k)) for k in set(before) | set(after)
    if k != "authority_scope" and before.get(k) != after.get(k)}
report["users_total"] = users.count_documents({})
report["verdict"] = ("PASS" if report["authority_scope"] == SCOPE
                     and report["tenant_ids_preserved"]
                     and report["role_preserved"]
                     and not report["other_fields_changed"]
                     and not report["other_users_changed"] else "REVIEW")
print(json.dumps(report, indent=2, default=str))
