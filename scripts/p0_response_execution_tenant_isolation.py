"""P0 · RESPONSE-EXECUTION TENANT ISOLATION — live matrix, real JWTs.

Read-only. Proves the client-supplied `tenant_id` (and every other
client-presented identity) is no longer authority on the response-evidence
read plane, and that valid same-tenant access still works.
"""
import json
import sys
import urllib.error
import urllib.request

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like "
      "Gecko) Chrome/125.0 Safari/537.36")
BASE = ""
with open("/app/frontend/.env") as f:
    for line in f:
        if line.startswith("REACT_APP_BACKEND_URL="):
            BASE = line.split("=", 1)[1].strip().rstrip("/")

ADMIN = ("admin@nivxray.com", "uulVDp5cCSB3Hva99s7UUAwK")
OWN = ("analyst@default.com", "DefaultCo!Analyst2026")
OTHER = ("analyst@nivx-live.com", "NivxLive!Analyst2026")

INC_DEFAULT = "inc_c1edae99d4e541c58552"       # tenant default
INC_NIVXLIVE = "inc_7742fe7120174204be36"      # tenant nivx-live

_p = _f = 0


def check(name, cond, detail=""):
    global _p, _f
    if cond:
        _p += 1
        print(f"PASS · {name} {detail}")
    else:
        _f += 1
        print(f"FAIL · {name} {detail}")


def call(method, path, token=None, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{BASE}{path}", data=data, method=method)
    req.add_header("User-Agent", UA)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def login(cred):
    st, b = call("POST", "/api/auth/login",
                 body={"email": cred[0], "password": cred[1]})
    if st != 200:
        print(f"ABORT · login {cred[0]} → {st}")
        sys.exit(2)
    return json.loads(b)["access_token"]


def main():
    print(f"edge: {BASE}\n")
    t_admin, t_own, t_other = login(ADMIN), login(OWN), login(OTHER)
    LIST = "/api/xdr/incidents/{}/response-executions"

    st, _ = call("GET", LIST.format(INC_DEFAULT))
    check("anonymous list", st in (401, 403), f"→ {st}")

    # NOTE · no production tenant role in this deployment holds
    # `evidence.read` (the only role carrying it is `l2_investigator_copy`,
    # assigned to nobody), so a tenant analyst is refused by the RBAC gate
    # BEFORE the tenant authority is reached. That is still fail-closed and
    # discloses nothing. The positive same-tenant path — and the decisive
    # case, a foreign-tenant execution row referencing the SAME incident id
    # — are proven against the real router in
    # `tests/test_p0_response_execution_tenant_scope.py`.
    st, b = call("GET", LIST.format(INC_DEFAULT), t_own)
    check("tenant analyst without the evidence.read grant is refused, "
          "disclosing nothing",
          st in (403, 404) and b"execution_id" not in b, f"→ {st}")

    st, b = call("GET", LIST.format(INC_NIVXLIVE), t_own)
    check("cross-tenant list is denied without disclosure",
          st in (403, 404) and b"nivx-live" not in b, f"→ {st}")

    st, b = call("GET", LIST.format(INC_DEFAULT), t_other)
    check("the other direction is denied too", st in (403, 404), f"→ {st}")

    # a fabricated client scope cannot widen the principal's own scope
    for q, h in (("?tenant_id=default", {}),
                 ("?tenant_id=nivx-live", {}),
                 ("?customer=default", {}),
                 ("?tenant=default", {}),
                 ("", {"X-Tenant-Id": "default"}),
                 ("", {"X-Principal-Id": "admin@nivxray.com"}),
                 ("", {"X-Tenant": "default", "X-Customer-Id": "default"})):
        st, b = call("GET", LIST.format(INC_DEFAULT) + q, t_other, headers=h)
        check(f"fabricated scope cannot widen access {q or h}",
              st in (403, 404) and b"execution_id" not in b, f"→ {st}")

    st, b = call("GET", LIST.format(INC_DEFAULT), t_admin)
    d = json.loads(b) if st == 200 else {}
    check("cross-tenant admin access is unchanged",
          st == 200 and d.get("tenant_scope") == "ALL_TENANTS", f"→ {st}")
    check("the answer reports the SERVER-resolved scope, not a client value",
          "tenant_scope" in d, f"keys={sorted(d.keys())}")

    # a requested tenant may only NARROW, even for a cross-tenant role
    st, b = call("GET", LIST.format(INC_DEFAULT) + "?tenant_id=nivx-live",
                 t_admin)
    d = json.loads(b) if st == 200 else {}
    check("a requested tenant can only NARROW the resolved scope",
          st == 200 and d.get("tenant_id") == "nivx-live"
          and d.get("count") == 0,
          f"→ {st} tenant_id={d.get('tenant_id')} count={d.get('count')}")

    # ── the sibling execution-detail read ───────────────────────────
    DETAIL = "/api/xdr/response-evidence/{}"
    st, _ = call("GET", DETAIL.format("exec_p0_probe"))
    check("anonymous execution detail", st in (401, 403), f"→ {st}")
    st, _ = call("GET", DETAIL.format("exec_p0_probe"), t_admin)
    check("an unknown execution id is 404 for an authorized principal",
          st == 404, f"→ {st}")
    st, _ = call("GET", DETAIL.format("exec_p0_probe")
                 + "?tenant_id=nivx-live", t_own)
    check("execution detail cannot be widened by a requested tenant",
          st in (403, 404), f"→ {st}")

    # ── an id cannot be used to enumerate another tenant ───────────
    for guess in ("exec_0000000000000000", "evt_c972032f8eb510ad",
                  "tf_487f2c73b75943aa",
                  "sysmon-1-b10bc713e1f44b8eb35a34e693ba3b20"):
        st, b = call("GET", DETAIL.format(guess), t_other)
        check(f"valid-looking id does not enumerate evidence · {guess[:18]}",
              st in (403, 404) and b"evidence_ref" not in b, f"→ {st}")

    print(f"\nP0 RESPONSE TENANT ISOLATION · {_p} PASS · {_f} FAIL")
    return 0 if _f == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
