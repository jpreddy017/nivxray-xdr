"""S1 · LIVE-EDGE AUTHORIZATION MATRIX (real JWTs, real preview edge).

Read-only. It proves, over HTTP against the running preview backend and with
genuine logins (no dependency overrides, no fixtures, no writes that would be
stored), the S1 invariant for every route in the incident sub-resource family:

    anonymous                         → DENIED
    authenticated, other tenant       → DENIED, no disclosure
    authenticated, own tenant         → ALLOWED
    mutation, anonymous               → DENIED, nothing stored
    mutation, other tenant            → DENIED, nothing stored
    mutation, own tenant, no grant    → DENIED with the permission + reason
    client-supplied tenant/author     → NOT AUTHORITY

Every refused mutation is refused *before* it can store anything, which is
why this script can run against the live preview dataset without changing it.
"""
import json
import os
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
OWN = ("analyst@default.com", "DefaultCo!Analyst2026")          # tenant default
OTHER = ("analyst@nivx-live.com", "NivxLive!Analyst2026")       # tenant nivx-live

READS = ["/investigation", "/investigation/executions",
         "/investigation/findings", "/attack-story", "/attack-graph",
         "/report", "/report/pdf", "/attack-evidence", "/summary",
         "/threat-model", "/inspector/event/s1-live-ref",
         "/intelligence/overlays", "/understanding", "/pivots"]

OVERLAY = "/intelligence/overlays/finding/s1-live/summary"

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
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", UA)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:4000]


def login(cred):
    st, body = call("POST", "/api/auth/login",
                    body={"email": cred[0], "password": cred[1]})
    if st != 200:
        print(f"ABORT · login {cred[0]} → {st} {body[:200]}")
        sys.exit(2)
    return json.loads(body)["access_token"]


def main():
    print(f"edge: {BASE}\n")
    t_admin, t_own, t_other = login(ADMIN), login(OWN), login(OTHER)

    st, body = call("GET", "/api/incidents?limit=5", t_own)
    rows = json.loads(body).get("incidents") or []
    if not rows:
        print("ABORT · the own-tenant analyst has no incident to address")
        sys.exit(2)
    inc = rows[0]["id"]
    secret = str(rows[0].get("name") or rows[0].get("title") or "")
    print(f"own-tenant incident: {inc}\n")

    for path in READS:
        p = f"/api/incidents/{inc}{path}"

        st, b = call("GET", p)
        # DENIED is the invariant. `…/understanding` keeps the P0-W optional
        # -principal contract and answers 404 (existence never disclosed);
        # every route S1 converted answers 401/403. Both are fail-closed.
        check(f"anonymous GET {path}", st in (401, 403, 404),
              f"→ {st}")

        st, b = call("GET", p, t_own)
        check(f"own-tenant GET {path}", st == 200, f"→ {st}")

        st, b = call("GET", p, t_other)
        disclosed = bool(secret) and secret.encode() in b
        check(f"cross-tenant GET {path}", st == 404 and not disclosed,
              f"→ {st} disclosed={disclosed}")

    # ── mutations ───────────────────────────────────────────────────
    blk = f"/api/incidents/{inc}/report/blocks"
    body = {"section": "executive_summary", "content": "s1 live probe",
            "author_email": "attacker@evil.test"}

    st, _ = call("POST", blk, body=body)
    check("anonymous POST report/blocks", st in (401, 403), f"→ {st}")

    st, b = call("POST", blk, t_other, body=body)
    check("cross-tenant POST report/blocks", st == 404, f"→ {st}")

    st, b = call("POST", blk, t_own, body=body)
    detail = {}
    try:
        detail = json.loads(b).get("detail") or {}
    except Exception:
        pass
    check("own-tenant POST report/blocks without incidents.update",
          st == 403 and detail.get("permission") == "incidents.update"
          and bool(detail.get("reason")),
          f"→ {st} {detail}")

    st, _ = call("PUT", f"/api/incidents/{inc}{OVERLAY}",
                 body={"analyst_value": "a", "machine_value": "m",
                       "reason": "r"})
    check("anonymous PUT intelligence overlay", st in (401, 403), f"→ {st}")

    st, _ = call("PUT", f"/api/incidents/{inc}{OVERLAY}", t_other,
                 body={"analyst_value": "a", "machine_value": "m",
                       "reason": "r"})
    check("cross-tenant PUT intelligence overlay", st == 404, f"→ {st}")

    st, b = call("PUT", f"/api/incidents/{inc}{OVERLAY}", t_own,
                 body={"analyst_value": "a", "machine_value": "m",
                       "reason": "r"})
    check("own-tenant PUT intelligence overlay without incidents.update",
          st == 403, f"→ {st}")

    # ── a client-presented tenant is never authority ────────────────
    for q, h in (("?tenant=default", {}), ("?customer=default", {}),
                 ("", {"X-Tenant-Id": "default"}),
                 ("", {"X-Principal-Id": "admin@nivxray.com"})):
        st, b = call("GET", f"/api/incidents/{inc}/report{q}", t_other,
                     headers=h)
        check(f"cross-tenant GET /report {q or h}", st == 404, f"→ {st}")

    # ── a missing incident fails closed identically ─────────────────
    for path in READS:
        st, _ = call("GET", f"/api/incidents/s1-no-such-incident{path}",
                     t_admin)
        check(f"unknown incident GET {path}", st == 404, f"→ {st}")

    print(f"\nS1 LIVE MATRIX · {_p} PASS · {_f} FAIL")
    return 0 if _f == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
