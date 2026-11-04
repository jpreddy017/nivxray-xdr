#!/usr/bin/env python3
"""Production read-only reconnaissance — API keys and collectors per tenant.

Credential is read from the NIVXPW environment variable and is NEVER written
to disk, logged, or echoed. Key plaintext is never requested (it cannot be
re-read after issuance by design); only metadata is listed.

READ-ONLY. GET requests only.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

API = "https://nivxray.nivxforge.com"
TENANTS = ["default", "nivx-prod-1"]


def call(path: str, token: str, tenant: str | None = None):
    h = {"Authorization": f"Bearer {token}"}
    if tenant:
        h["X-Tenant-Id"] = tenant
    req = urllib.request.Request(API + path, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]
    except Exception as e:                                        # noqa: BLE001
        return 0, f"{type(e).__name__}: {e}"


def login() -> str:
    body = json.dumps({"email": "admin@nivxray.com",
                       "password": os.environ["NIVXPW"]}).encode()
    req = urllib.request.Request(
        API + "/api/auth/login", data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        d = json.loads(r.read())
    return d.get("access_token") or d.get("token")


def rows(payload):
    """The API nests lists under `data` as `api_keys` / `collectors` / etc.
    An earlier version of this helper only looked at the TOP level and
    silently reported zero — the bug is called out here so it cannot
    quietly return [] again."""
    if isinstance(payload, dict):
        inner = payload.get("data")
        for src in (inner, payload):
            if isinstance(src, list):
                return src
            if isinstance(src, dict):
                for k in ("api_keys", "collectors", "items", "keys",
                          "results", "events", "incidents"):
                    v = src.get(k)
                    if isinstance(v, list):
                        return v
        return []
    return payload if isinstance(payload, list) else []


def main() -> int:
    token = login()
    print("login: 200 (token held in memory only)\n")

    for ten in TENANTS:
        print("=" * 78)
        print(f"TENANT {ten}")
        print("=" * 78)

        code, body = call("/api/xdr/api-keys", token, ten)
        print(f"GET /api/xdr/api-keys -> {code}")
        if code == 200:
            ks = rows(body)
            print(f"  api keys: {len(ks)}")
            for k in ks:
                print(f"   - id={k.get('id')} name={k.get('name')!r} "
                      f"tenant={k.get('tenant_id')} "
                      f"scopes={k.get('scopes')} "
                      f"ENABLED={k.get('enabled')} "
                      f"revoked_at={k.get('revoked_at')} "
                      f"created={k.get('created_at')} "
                      f"last_used={k.get('last_used_at')}")
        else:
            print(f"  {body}")

        code, body = call("/api/xdr/collectors", token, ten)
        print(f"GET /api/xdr/collectors -> {code}")
        if code == 200:
            cs = rows(body)
            print(f"  collectors: {len(cs)}")
            for c in cs:
                print(f"   - id={c.get('id')} name={c.get('name')!r} "
                      f"tenant={c.get('tenant_id')} proto={c.get('protocol')} "
                      f"state={c.get('state')} "
                      f"rx={c.get('events_received')} "
                      f"parsed={c.get('events_parsed')} "
                      f"norm={c.get('events_normalized')} "
                      f"last_event={c.get('last_event_at')}")
        else:
            print(f"  {body}")
        print()

    # Is there any real telemetry in production at all?
    for ten in TENANTS:
        for path in ("/api/incidents?limit=5", "/api/xdr/incidents?limit=5"):
            code, body = call(path, token, ten)
            if code == 200:
                print(f"{path} [{ten}] -> 200 count={len(rows(body))}")
                break
        else:
            print(f"incidents [{ten}] -> not resolvable on either path")
    return 0


if __name__ == "__main__":
    sys.exit(main())
