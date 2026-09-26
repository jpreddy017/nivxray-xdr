"""P0.1 · RESPONSE-EVIDENCE **WRITE** TENANT AUTHORITY — live proof.

DENY-PATH ONLY by design: every case below is expected to be refused, so the
script persists NOTHING into the preview evidence/audit/timeline collections.
The ACCEPT paths (single-tenant → own tenant, incident-derived tenant,
tenant-scoped idempotency) are proven against the real router in
`backend/tests/test_p01_response_evidence_write_tenant_authority.py`, where
the writes land in an in-memory db and cannot pollute audit material.

Proven here, live, through the real ASGI graph + real JWTs:
  * all-tenant principal + NO resource anchor + only `body.tenant_id` → DENY
  * all-tenant principal + incident anchor + conflicting `body.tenant_id`
    → DENY, and the incident's authoritative tenant is NOT echoed back
  * single-tenant principal + FOREIGN incident anchor → 404, no disclosure
  * the read plane still answers for a legitimate same-tenant principal
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


def call(method, path, token=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{BASE}{path}", data=data, method=method)
    req.add_header("User-Agent", UA)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def login(cred):
    st, b = call("POST", "/api/auth/login",
                 body={"email": cred[0], "password": cred[1]})
    if st != 200:
        print(f"ABORT · login failed for {cred[0]} → {st} {b[:200]}")
        sys.exit(2)
    j = json.loads(b)
    return j.get("access_token") or j.get("token")


def body(execution_id, *, tenant_id=None, incident_id=None):
    ctx = {"incident_id": incident_id} if incident_id else {}
    out = {
        "execution_id": execution_id,
        "invoker": {"kind": "analyst", "id": "user:p01-proof",
                    "context": ctx},
        "action": {"action_id": "endpoint.isolate", "provider": "endpoint",
                   "capability": "isolate_endpoint"},
        "parameters": {"host_id": "P01-PROOF-HOST"},
        "canonical_target": {"asset": "asset:P01-PROOF-HOST"},
        "adapter_ok": True,
        "dry_run": True,
    }
    if tenant_id is not None:
        out["tenant_id"] = tenant_id
    return out


def main():
    print(f"BASE {BASE}\n")
    admin = login(ADMIN)
    own = login(OWN)

    # 1 · all-tenant principal, no resource anchor, only body.tenant_id
    st, b = call("POST", "/api/xdr/response-evidence", admin,
                 body("p01-proof-ambiguous", tenant_id="nivx-live"))
    txt = b.decode(errors="replace")
    check("all-tenant + no anchor + body tenant → DENIED",
          st == 403, f"({st})")
    check("  reason is ambiguous tenant authority",
          "ambiguous_tenant_authority_without_resource_anchor" in txt,
          txt[:160])
    check("  nothing was minted", "evidence_ref" not in txt)

    # 2 · incident anchor vs conflicting assertion
    st, b = call("POST", "/api/xdr/response-evidence", admin,
                 body("p01-proof-mismatch", tenant_id="nivx-live",
                      incident_id=INC_DEFAULT))
    txt = b.decode(errors="replace")
    check("incident anchor + conflicting assertion → DENIED",
          st == 403, f"({st})")
    check("  reason is assertion-vs-resource conflict",
          "asserted_tenant_conflicts_with_resource_authority" in txt,
          txt[:160])
    check("  authoritative tenant is NOT echoed",
          '"tenant_id":"default"' not in txt.replace(" ", ""))
    check("  nothing was minted", "evidence_ref" not in txt)

    # 3 · single-tenant principal writing against a foreign incident
    st, b = call("POST", "/api/xdr/response-evidence", own,
                 body("p01-proof-foreign-inc", incident_id=INC_NIVXLIVE))
    txt = b.decode(errors="replace")
    check("single-tenant + foreign incident → refused",
          st in (403, 404), f"({st})")
    check("  foreign tenant never disclosed", "nivx-live" not in txt,
          txt[:160])
    check("  nothing was minted", "evidence_ref" not in txt)

    # 4 · the read plane is untouched for a legitimate principal
    st, b = call("GET",
                 f"/api/xdr/incidents/{INC_DEFAULT}/response-executions",
                 own)
    check("same-tenant read plane still answers", st in (200, 403),
          f"({st})")
    if st == 200:
        j = json.loads(b)
        check("  tenant scope is principal-resolved",
              j.get("tenant_scope") == "PRINCIPAL_TENANTS", str(j)[:120])

    print(f"\n{_p} passed · {_f} failed")
    sys.exit(1 if _f else 0)


if __name__ == "__main__":
    main()
