"""W1-E · read-only-equivalent probe of the DEPLOYED delivery-identity contract.

Runs against the PREVIEW database only (DB_NAME from backend/.env). Production
is never contacted. It exercises the exact module that production runs
(`services.ingest_idempotency`, byte-identical at the deployed commit) with a
Sysmon-shaped envelope carrying `DESKTOP-A9HGFJJ|<record_id>` identities.
"""
from __future__ import annotations

import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/backend")

from dotenv import load_dotenv  # noqa: E402

load_dotenv("/app/backend/.env")

from services import ingest_idempotency as idem  # noqa: E402

TEN = f"probe-ten-{uuid.uuid4().hex[:8]}"
COL = f"probe-col-{uuid.uuid4().hex[:8]}"
HOST = "DESKTOP-A9HGFJJ"
RECORDS = [1696988, 1696989, 1696990, 1696991, 1696992]


def raw_for(rid: int) -> dict:
    return {"event_id": 1, "provider": "Microsoft-Windows-Sysmon",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": HOST, "record_id": rid,
            "Image": r"C:\Windows\System32\notepad.exe"}


def ident(rid: int) -> dict:
    return idem.event_identity(TEN, COL, "microsoft-sysmon",
                               f"{HOST}|{rid}", raw_for(rid))


ok = True


def check(label: str, got, want):
    global ok
    good = got == want
    ok = ok and good
    print(f"{'PASS' if good else 'FAIL'}  {label}: got={got!r} want={want!r}")


keys = {}
for rid in RECORDS:
    i = ident(rid)
    keys[rid] = i["key"]
    d, rec = idem.claim(i)
    check(f"first delivery of {HOST}|{rid}", d, "FRESH")
    check(f"identity carries source_event_id {rid}", i["source_event_id"], f"{HOST}|{rid}")

check("five distinct delivery keys", len(set(keys.values())), 5)

for rid in RECORDS:
    idem.complete(keys[rid], trace_id=f"probe_{rid}")

for rid in RECORDS:
    d, rec = idem.claim(ident(rid))
    check(f"replay of {HOST}|{rid}", d, "DUPLICATE")
    check(f"  duplicate_count after one replay ({rid})", rec.get("duplicate_count"), 1)
    check(f"  delivery_count after one replay ({rid})", rec.get("delivery_count"), 2)
    check(f"  original trace reported back ({rid})", rec.get("trace_id"), f"probe_{rid}")

d, _ = idem.claim(ident(1697001))
check("a NEW record id is NOT suppressed", d, "FRESH")

mutated = idem.event_identity(TEN, COL, "microsoft-sysmon", f"{HOST}|{RECORDS[0]}",
                              {**raw_for(RECORDS[0]), "Image": r"C:\Windows\System32\cmd.exe"})
d, _ = idem.claim(mutated)
check("same id + different payload is NOT suppressed", d, "FRESH")

other_tenant = idem.event_identity(f"{TEN}-b", COL, "microsoft-sysmon",
                                   f"{HOST}|{RECORDS[0]}", raw_for(RECORDS[0]))
d, _ = idem.claim(other_tenant)
check("same delivery in another tenant is NOT suppressed", d, "FRESH")

idx = idem._coll().index_information()
uniq = [n for n, s in idx.items() if s.get("unique") and s.get("key") == [("key", 1)]]
check("unique index on delivery key exists", bool(uniq), True)

print("\nRESULT:", "CONTRACT PROVEN (preview, deployed code)" if ok else "CONTRACT VIOLATED")
sys.exit(0 if ok else 1)
