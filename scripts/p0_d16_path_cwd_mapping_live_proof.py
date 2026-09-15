#!/usr/bin/env python3
"""D16 · auditd PATH / CWD -> canonical file & directory evidence, over real
HTTP (PREVIEW ONLY).

One real auditd execution is delivered as the six records auditd actually
emits — SYSCALL, EXECVE, CWD and three PATH records — through the
authenticated, DECLARED (D15) ingest path. Then the canonical evidence is
read back from Mongo and checked for:

    file.path                      the observed binary, verbatim
    path_mapping.path_items        all three PATH records, unmerged
    absolute_path basis            VERBATIM_ABSOLUTE / DERIVED_FROM_CWD /
                                   NOT_RESOLVABLE — never invented
    working_directory              the CWD record, or NOT_OBSERVED
    directory_paths                only nametype=PARENT
    record_ref per item            back to the verbatim auditd record

Plus a relative path delivered WITHOUT a CWD record, which must stay
unresolved, and a standalone PATH record, which must be accepted as the
auditd fragment it is instead of refused.

TEST/SYNTHETIC payloads. NOT LIVE — no real host is connected. Nothing
touches production.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

from dotenv import load_dotenv

load_dotenv("/app/backend/.env")
load_dotenv("/app/frontend/.env")
BASE = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0"
STAMP = int(time.time())
TENANT = "t-d16-paths"
AUD = f"1757452888.161:{6100 + STAMP % 300}"
AUD_REL = f"1757452888.162:{6500 + STAMP % 300}"
AUD_LONE = f"1757452888.163:{6900 + STAMP % 300}"

ok = True


def check(label, cond, detail=""):
    global ok
    ok = ok and bool(cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}"
          + (f" — {detail}" if detail else ""))


def call(path, method="GET", token=None, key=None, tenant=None, body=None):
    h = {"User-Agent": UA, "Content-Type": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    if key:
        h["X-XDR-API-Key"] = key
    if tenant:
        h["X-Tenant-Id"] = tenant
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, headers=h,
                               method=method)
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]


RECORDS = [
    (f'node=web-prod-16 type=SYSCALL msg=audit({AUD}): arch=c000003e '
     f'syscall=59 success=yes exit=0 uid=0 euid=0 auid=1000 pid={STAMP % 9000}'
     f' ppid=4200 comm="bash" exe="/usr/bin/bash" key="exec"'),
    f'type=EXECVE msg=audit({AUD}): argc=3 a0="/bin/bash" a1="-c" '
    f'a2="cat /etc/shadow"',
    f'type=CWD msg=audit({AUD}): cwd="/home/deploy"',
    f'type=PATH msg=audit({AUD}): item=0 name="/usr/bin/bash" inode=1234 '
    f'dev=fd:01 mode=0100755 ouid=0 ogid=0 nametype=NORMAL',
    f'type=PATH msg=audit({AUD}): item=1 name="scripts/payload-{STAMP}.sh" '
    f'inode=999 mode=0100644 ouid=1000 ogid=1000 nametype=CREATE',
    f'type=PATH msg=audit({AUD}): item=2 name="scripts" nametype=PARENT',
]
#: the same shape with NO CWD record — the relative path must stay unresolved
RECORDS_NO_CWD = [
    (f'node=web-prod-16 type=SYSCALL msg=audit({AUD_REL}): arch=c000003e '
     f'syscall=59 success=yes uid=0 euid=0 pid={STAMP % 9000} ppid=4200 '
     f'comm="bash" exe="/usr/bin/bash" key="exec"'),
    f'type=EXECVE msg=audit({AUD_REL}): argc=1 a0="/bin/bash"',
    f'type=PATH msg=audit({AUD_REL}): item=0 name="relative-{STAMP}.sh" '
    f'nametype=NORMAL',
]
LONE_PATH = (f'type=PATH msg=audit({AUD_LONE}): item=0 '
             f'name="/etc/shadow-{STAMP}" inode=77 mode=0100000 ouid=0 '
             f'nametype=NORMAL')


def envelope(col, line, i, tag):
    return {"tenant_id": TENANT, "collector_id": col,
            "source_event_id": f"d16:{STAMP}:{tag}:{i}",
            "collection_method": "syslog", "source": "d16-proof-host",
            "declared_source": "linux-auditd",
            "raw": {"line": line, "payload_format": "auditd"}}


def main() -> int:
    code, body = call("/api/auth/login", "POST", body={
        "email": "admin@nivxray.com",
        "password": "uulVDp5cCSB3Hva99s7UUAwK"})
    if code != 200:
        print(f"login failed: {code} {body}")
        return 1
    token = body["access_token"]
    print("login: 200\n1 · provision TEST collector + ingest key")
    code, body = call("/api/xdr/collectors", "POST", token=token,
                      tenant=TENANT, body={
                          "name": "d16-proof-collector",
                          "protocol": "syslog",
                          "authorized_sources": ["linux-auditd"],
                          "tenant_id": TENANT, "confirm_tenant_id": TENANT,
                          "allow_new_tenant": True})
    if code == 409:
        _, lst = call("/api/xdr/collectors", token=token, tenant=TENANT)
        col = next((c["id"] for c in
                    ((lst.get("data") or {}).get("collectors") or [])
                    if c.get("name") == "d16-proof-collector"), None)
    elif code in (200, 201):
        d = body.get("data") or body
        col = d.get("id") or (d.get("collector") or {}).get("id")
    else:
        print(f"  collector create -> {code} {body}")
        return 1
    if col:
        call(f"/api/xdr/collectors/{col}", "PUT", token=token, tenant=TENANT,
             body={"authorized_sources": ["linux-auditd"]})
    check("collector ready", bool(col), col)
    code, body = call("/api/xdr/api-keys", "POST", token=token,
                      tenant=TENANT, body={
                          "name": f"d16-proof-key-{STAMP}",
                          "confirm_tenant_id": TENANT,
                          "allow_new_tenant": True,
                          "scopes": ["collectors.enroll", "collectors.read"]})
    _d = body.get("data") or {}
    key = (_d.get("api_key") or _d.get("key") or _d.get("secret")
           or _d.get("plaintext") or _d.get("token") or _d.get("value"))
    check("ingest key minted (value not printed)", bool(key))
    if not key:
        return 1

    from pymongo import MongoClient
    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    ev = db.xdr_canonical_evidence

    print("\n2 · deliver ONE execution as the six records auditd emits")
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key,
                      tenant=TENANT, body={"envelopes": [
                          envelope(col, ln, i, "full")
                          for i, ln in enumerate(RECORDS)]})
    check("ingest accepted", code == 200, f"HTTP {code} {str(body)[:200]}")
    if code != 200:
        return 1
    data = body.get("data") or body
    st = [o.get("status") for o in (data.get("reasoning") or [])]
    print(f"  outcomes: {st}")
    check("one canonical event, five records stitched into it",
          st.count("REASONED") == 1 and st.count("STITCHED_INTO") == 5,
          str(st))
    time.sleep(2)

    row = ev.find_one({"tenant_id": TENANT,
                       "additional_fields.stitch_audit_identity": AUD},
                      sort=[("_id", -1)])
    check("canonical evidence exists", bool(row))
    if not row:
        return 1
    m = (row.get("additional_fields") or {}).get("path_mapping") or {}
    f = row.get("file") or {}
    print(f"  file.path = {f.get('path')!r}  items = "
          f"{[e.get('absolute_path') for e in (m.get('path_items') or [])]}")

    print("\n3 · the canonical file entity cites an OBSERVED path")
    check("file.path is the path auditd named", f.get("path")
          == "/usr/bin/bash", str(f.get("path")))
    check("file.name is its basename", f.get("name") == "bash")
    check("the selection basis is declared",
          m.get("primary_file_basis") == "LOWEST_PATH_ITEM_EXCLUDING_PARENT",
          str(m.get("primary_file_basis")))
    check("the primary item references its verbatim auditd record",
          (m.get("file_path_record_ref") or {}).get("line") == RECORDS[3])

    print("\n4 · every PATH record survives, unmerged")
    items = m.get("path_items") or []
    check("three PATH records, in item order",
          [e.get("item") for e in items] == [0, 1, 2], str(
              [e.get("item") for e in items]))
    check("no two items share a path",
          len({e.get("absolute_path") for e in items}) == 3)
    check("item 0 is verbatim absolute",
          items and items[0].get("absolute_path_basis")
          == "VERBATIM_ABSOLUTE")
    check("item 1 is DERIVED from the observed CWD and says so",
          len(items) > 1
          and items[1].get("absolute_path")
          == f"/home/deploy/scripts/payload-{STAMP}.sh"
          and items[1].get("absolute_path_basis")
          == "DERIVED_FROM_OBSERVED_CWD"
          and items[1].get("absolute_path_state") == "DERIVED",
          str(items[1] if len(items) > 1 else None)[:200])
    check("item 1's action comes from nametype=CREATE",
          len(items) > 1 and items[1].get("action") == "create")
    check("item 2 is a DIRECTORY only because auditd said PARENT",
          len(items) > 2 and items[2].get("kind") == "DIRECTORY"
          and items[2].get("kind_state") == "OBSERVED")
    check("a NORMAL path does not claim to be a file or a directory",
          items and items[0].get("kind_state")
          == "OBJECT_KIND_NOT_OBSERVED")
    check("every item cites the record it came from",
          all((e.get("record_ref") or {}).get("line") for e in items))

    print("\n5 · the working directory")
    wd = m.get("working_directory") or {}
    check("the CWD record is the working directory",
          wd.get("path") == "/home/deploy" and wd.get("state") == "OBSERVED",
          str(wd))
    check("the directory list holds only the PARENT path",
          m.get("directory_paths") == ["/home/deploy/scripts"],
          str(m.get("directory_paths")))

    print("\n6 · a relative path with NO CWD record stays unresolved")
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key,
                      tenant=TENANT, body={"envelopes": [
                          envelope(col, ln, i, "nocwd")
                          for i, ln in enumerate(RECORDS_NO_CWD)]})
    check("ingest accepted", code == 200, f"HTTP {code}")
    time.sleep(2)
    row2 = ev.find_one({"tenant_id": TENANT,
                        "additional_fields.stitch_audit_identity": AUD_REL},
                       sort=[("_id", -1)])
    check("canonical evidence exists", bool(row2))
    if row2:
        m2 = (row2.get("additional_fields") or {}).get("path_mapping") or {}
        it = (m2.get("path_items") or [{}])[0]
        print(f"  path={it.get('path')!r} absolute={it.get('absolute_path')!r}"
              f" state={it.get('absolute_path_state')}")
        check("the relative name is kept verbatim",
              it.get("path") == f"relative-{STAMP}.sh")
        check("no absolute path was invented",
              it.get("absolute_path") is None
              and it.get("absolute_path_state") == "NOT_RESOLVABLE")
        check("the reason names the missing CWD record",
              "no CWD record was delivered"
              in str(it.get("absolute_path_not_resolvable_reason")))
        check("the working directory is NOT_OBSERVED, never '/'",
              (m2.get("working_directory") or {}).get("state")
              == "NOT_OBSERVED"
              and (m2.get("working_directory") or {}).get("path") is None)

    print("\n7 · a standalone PATH record is auditd, not garbage")
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key,
                      tenant=TENANT, body={"envelopes": [
                          envelope(col, LONE_PATH, 0, "lone")]})
    check("ingest accepted", code == 200, f"HTTP {code}")
    data = body.get("data") or body if code == 200 else {}
    st = [o.get("status") for o in (data.get("reasoning") or [])]
    check("it was reasoned, not refused as an unsupported format",
          st == ["REASONED"], str(st))
    time.sleep(2)
    row3 = ev.find_one({"tenant_id": TENANT,
                        "file.path": f"/etc/shadow-{STAMP}"},
                       sort=[("_id", -1)])
    check("its file evidence landed", bool(row3))
    if row3:
        extra = row3.get("additional_fields") or {}
        check("it is labelled a standalone fragment",
              extra.get("fragment_state")
              == "STANDALONE_RECORD_NO_PROCESS_CONTEXT",
              str(extra.get("fragment_state")))
        check("identity is NOT_OBSERVED, not unprivileged",
              extra.get("identity_state") == "NOT_OBSERVED")
        check("the event type names what it is",
              row3.get("event_type") == "auditd_path_record",
              str(row3.get("event_type")))

    print("\n8 · paths are evidence, never identity material")
    n = ev.count_documents(
        {"tenant_id": TENANT,
         "additional_fields.stitch_audit_identity": AUD})
    check("the stitched execution is exactly ONE canonical event", n == 1,
          str(n))

    print("\n" + ("D16 PATH/CWD MAPPING: PASS" if ok
                  else "D16 PATH/CWD MAPPING: FAIL"))
    print("TEST/SYNTHETIC auditd records. NOT LIVE. Preview only, nothing "
          "deployed.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
