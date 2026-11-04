#!/usr/bin/env python3
"""Create a REAL customer-scoped analyst account (idempotent).

The console's customer/organisation name is an authorisation fact
resolved by `resolve_tenant_scope`, which reads `role` + `tenant_id`
off the persisted user. Until now every account in this deployment was
the cross-tenant `admin`, so the pill could only ever say ALL
CUSTOMERS — the single-customer path was unproven, not broken.

This seeds one analyst bound to an EXISTING tenant from the real case
corpus. It uses the same `hash_password` the admin seed uses; it does
not introduce an auth mechanism and it never re-sets an existing
password.
"""
import asyncio
import os
import sys

sys.path.insert(0, "/app/backend")


async def main() -> None:
    import dotenv
    dotenv.load_dotenv("/app/backend/.env")
    from motor.motor_asyncio import AsyncIOMotorClient

    from deps import hash_password

    email = sys.argv[1] if len(sys.argv) > 1 else "analyst@nivx-live.com"
    tenant = sys.argv[2] if len(sys.argv) > 2 else "nivx-live"
    password = sys.argv[3] if len(sys.argv) > 3 else "NivxLive!Analyst2026"

    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]

    # The tenant must already exist in the case corpus — we do not
    # invent customers to populate a dropdown.
    known = await db.workspace_cases.count_documents({"tenant_id": tenant})
    if not known:
        raise SystemExit(f"tenant {tenant!r} has no cases — refusing to "
                         f"create an account for a customer that does not "
                         f"exist")

    existing = await db.users.find_one({"email": email})
    if existing:
        await db.users.update_one({"email": email},
                                  {"$set": {"role": "analyst",
                                            "tenant_id": tenant,
                                            "enabled": True}})
        print(f"updated scope of existing user {email} -> tenant {tenant}")
        return

    from datetime import datetime, timezone
    await db.users.insert_one({
        "email": email,
        "password": hash_password(password),
        "role": "analyst",
        "tenant_id": tenant,
        "enabled": True,
        "must_change_password": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    print(f"created {email} · role=analyst · tenant_id={tenant} "
          f"· cases={known}")


asyncio.run(main())
