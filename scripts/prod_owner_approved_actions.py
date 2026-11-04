#!/usr/bin/env python3
"""Owner-approved production actions — revoke one credential, delete one
stray collector. Preconditions are verified and PRINTED before each action;
if any precondition fails the action is refused, not forced.

Credential comes from NIVXPW. No secret is printed or written anywhere.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

API = "https://nivxray.nivxforge.com"
KEY_ID = "key_dd92dd232f434bbba88b"          # unused live ingest credential
KEY_TENANT = "nivx-prod-1"
COL_ID = "col_c7147fd01df2438cbe08"          # stray, default tenant
COL_TENANT = "default"


def req(path: str, token: str, tenant: str, method: str = "GET"):
    r = urllib.request.Request(
        API + path, method=method,
        headers={"Authorization": f"Bearer {token}", "X-Tenant-Id": tenant,
                 "Content-Type": "application/json"},
        data=b"{}" if method == "POST" else None)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]
    except Exception as e:                                        # noqa: BLE001
        return 0, f"{type(e).__name__}: {e}"


def main() -> int:
    body = json.dumps({"email": "admin@nivxray.com",
                       "password": os.environ["NIVXPW"]}).encode()
    lr = urllib.request.Request(
        API + "/api/auth/login", data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    token = json.loads(urllib.request.urlopen(lr, timeout=30).read()
                       ).get("access_token")
    print("login: 200\n")

    # ── ACTION 1 · revoke the unused live credential ─────────────────
    print("=" * 74)
    print(f"ACTION 1 · revoke {KEY_ID} (tenant {KEY_TENANT})")
    print("=" * 74)
    code, before = req(f"/api/xdr/api-keys/{KEY_ID}", token, KEY_TENANT)
    d = (before or {}).get("data") if isinstance(before, dict) else {}
    if code != 200 or not d:
        print(f"REFUSED — could not read the key: HTTP {code} {before}")
        return 1
    print(f"  before: name={d.get('name')!r} enabled={d.get('enabled')} "
          f"revoked_at={d.get('revoked_at')} "
          f"last_used_at={d.get('last_used_at')} scopes={d.get('scopes')}")
    checks = {
        "tenant is nivx-prod-1": d.get("tenant_id") == KEY_TENANT,
        "currently enabled": d.get("enabled") is True,
        "never used": d.get("last_used_at") in (None, ""),
    }
    for k, v in checks.items():
        print(f"  precondition · {k}: {'OK' if v else 'FAILED'}")
    if not all(checks.values()):
        print("REFUSED — a precondition failed. Nothing was changed.")
        return 1
    code, res = req(f"/api/xdr/api-keys/{KEY_ID}/revoke", token, KEY_TENANT,
                    "POST")
    print(f"  POST revoke -> HTTP {code} {json.dumps(res)[:200]}")
    code, after = req(f"/api/xdr/api-keys/{KEY_ID}", token, KEY_TENANT)
    a = (after or {}).get("data") if isinstance(after, dict) else {}
    print(f"  after : enabled={a.get('enabled')} "
          f"revoked_at={a.get('revoked_at')}")
    print(f"  VERIFIED: {'YES' if a.get('enabled') is False else 'NO'}\n")

    # ── ACTION 2 · delete ONLY the stray default-tenant collector ────
    print("=" * 74)
    print(f"ACTION 2 · delete {COL_ID} (tenant {COL_TENANT})")
    print("=" * 74)
    code, cb = req(f"/api/xdr/collectors/{COL_ID}", token, COL_TENANT)
    c = (cb or {}).get("data") if isinstance(cb, dict) else {}
    if code != 200 or not c:
        print(f"REFUSED — could not read the collector: HTTP {code} {cb}")
        return 1
    print(f"  before: name={c.get('name')!r} tenant={c.get('tenant_id')} "
          f"state={c.get('state')} reason={c.get('state_reason')!r} "
          f"rx={c.get('events_received')} parsed={c.get('events_parsed')} "
          f"norm={c.get('events_normalized')} "
          f"last_event={c.get('last_event_at')} "
          f"created={c.get('created_at')}")

    # No credential in this tenant can be feeding it: prove it rather than
    # assume it.
    kc, kb = req("/api/xdr/api-keys", token, COL_TENANT)
    keys = ((kb or {}).get("data") or {}).get("api_keys") or []
    live = [k for k in keys if k.get("enabled")]
    print(f"  api keys in tenant {COL_TENANT}: {len(keys)} "
          f"(enabled: {len(live)})")

    checks = {
        "tenant is default": c.get("tenant_id") == COL_TENANT,
        "zero events received": int(c.get("events_received") or 0) == 0,
        "zero parsed": int(c.get("events_parsed") or 0) == 0,
        "zero normalized": int(c.get("events_normalized") or 0) == 0,
        "never saw telemetry": c.get("last_event_at") in (None, ""),
        "no enabled credential in this tenant": len(live) == 0,
        "pre-patch artefact (state STARTING / 'start requested')":
            c.get("state") == "STARTING",
    }
    for k, v in checks.items():
        print(f"  precondition · {k}: {'OK' if v else 'FAILED'}")
    if not all(checks.values()):
        print("REFUSED — a precondition failed. Nothing was deleted.")
        return 1

    code, res = req(f"/api/xdr/collectors/{COL_ID}", token, COL_TENANT,
                    "DELETE")
    print(f"  DELETE -> HTTP {code} {json.dumps(res)[:200]}")
    code, gone = req(f"/api/xdr/collectors/{COL_ID}", token, COL_TENANT)
    print(f"  re-read -> HTTP {code} (404 expected)")
    print(f"  VERIFIED: {'YES' if code == 404 else 'NO'}")

    # The nivx-prod-1 collector is deliberately LEFT ALONE.
    code, keep = req(f"/api/xdr/collectors/col_a3e09eddb0544a31882e", token,
                     "nivx-prod-1")
    k = (keep or {}).get("data") if isinstance(keep, dict) else {}
    print(f"\n  UNTOUCHED (per owner instruction): "
          f"col_a3e09eddb0544a31882e state={k.get('state')} "
          f"tenant={k.get('tenant_id')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
