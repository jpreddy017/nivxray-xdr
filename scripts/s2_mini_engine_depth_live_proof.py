"""S2-mini · ENGINE-DEPTH READ AUTHORIZATION — live proof, real JWTs.

Deterministic. No sleeps, no polling. Read-only except three mutation probes
that MUST be refused (and therefore store nothing).

Fixtures are REAL preview records, chosen by what the stores actually record:
  · `inc_c1edae99d4e541c58552` — tenant `default`, engine observations exist
  · `inc_7742fe7120174204be36` — tenant `nivx-live`, engine observations exist
  · `inc_r381_promote`         — tenant `default`, NO engine observation
  · `case_dfir_bumblebee_akira_2026` — an engine-NATIVE case with no incident
    and no tenant. No analyst may read it; it must never be attached to an
    incident because the ids "look like" cases.
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
A_DEFAULT = ("analyst@default.com", "DefaultCo!Analyst2026")
A_NIVX = ("analyst@nivx-live.com", "NivxLive!Analyst2026")

INC_DEFAULT = "inc_c1edae99d4e541c58552"     # default  · associated
INC_NIVX = "inc_7742fe7120174204be36"        # nivx-live · associated
INC_UNASSOC = "inc_r381_promote"             # default  · not associated
ENGINE_NATIVE = "case_dfir_bumblebee_akira_2026"

READS = ["/investigation?limit=50", "/trajectory/device?limit=50",
         "/artifacts?limit=50"]

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
        print(f"ABORT · login {cred[0]} → {st} {b[:200]}")
        sys.exit(2)
    return json.loads(b)["access_token"]


def main():
    print(f"edge: {BASE}\n")
    t_admin, t_def, t_nivx = login(ADMIN), login(A_DEFAULT), login(A_NIVX)

    for path in READS:
        p = f"/api/v2/cases/{INC_NIVX}{path}"

        st, _ = call("GET", p)
        check(f"anonymous {path}", st in (401, 403), f"→ {st}")

        # ── the whole point of S2-mini ────────────────────────────────
        st, b = call("GET", p, t_nivx)
        assoc = {}
        if st == 200:
            assoc = (json.loads(b) or {}).get("engine_association") or {}
        check(f"own-tenant analyst reads engine depth {path}",
              st == 200 and assoc.get("state") == "ASSOCIATED"
              and assoc.get("authority") == "INCIDENT_TENANT_AUTHORITY",
              f"→ {st} {assoc.get('state')}/{assoc.get('authority')}")

        st, b = call("GET", p, t_def)
        check(f"cross-tenant analyst {path}", st == 404, f"→ {st}")

        st, b = call("GET", p, t_admin)
        check(f"admin still reads {path}", st == 200, f"→ {st}")

        # an engine-NATIVE case: admin keeps it, an analyst never gets it
        st, _ = call("GET", f"/api/v2/cases/{ENGINE_NATIVE}{path}", t_admin)
        check(f"admin reads the engine-native case {path}", st == 200,
              f"→ {st}")
        st, _ = call("GET", f"/api/v2/cases/{ENGINE_NATIVE}{path}", t_nivx)
        check(f"analyst CANNOT read the engine-native case {path}",
              st == 404, f"→ {st}")

        # a client-presented identity is never authority
        for q, h in ((f"&tenant_id=nivx-live", {}),
                     (f"&customer=nivx-live", {}),
                     ("", {"X-Tenant-Id": "nivx-live"}),
                     ("", {"X-Principal-Id": "admin@nivxray.com"})):
            st, _ = call("GET", f"/api/v2/cases/{INC_NIVX}{path}{q}", t_def,
                         headers=h)
            check(f"fabricated identity cannot elevate {path} {q or h}",
                  st == 404, f"→ {st}")

    # ── an authorized incident with NO engine evidence says so ───────
    st, b = call("GET", f"/api/v2/cases/{INC_UNASSOC}/investigation?limit=50",
                 t_def)
    assoc = (json.loads(b) or {}).get("engine_association") or {} if st == 200 else {}
    check("authorized but unassociated incident states NOT_ASSOCIATED",
          st == 200 and assoc.get("state") == "NOT_ASSOCIATED"
          and bool(assoc.get("reason")) and bool(assoc.get("read_from")),
          f"→ {st} {assoc.get('state')}")

    # ── the analyst gains NO engine mutation / administration ────────
    st, _ = call("POST", "/api/v2/cases", t_nivx,
                 body={"name": "s2mini must be refused"})
    check("analyst cannot create an engine case", st in (401, 403), f"→ {st}")

    st, _ = call("DELETE", f"/api/v2/cases/{ENGINE_NATIVE}", t_nivx)
    check("analyst cannot delete an engine case", st in (401, 403), f"→ {st}")

    st, _ = call("GET", "/api/v2/cases", t_nivx)
    check("analyst cannot list the engine case registry", st in (401, 403),
          f"→ {st}")

    st, _ = call("POST", f"/api/v2/cases/{INC_NIVX}/observations", t_nivx,
                 body={"kind": "process", "event": {}})
    check("analyst cannot ingest an engine observation", st in (401, 403),
          f"→ {st}")

    st, _ = call("GET",
                 f"/api/v2/cases/{INC_NIVX}/investigation/explain/lateral_movement",
                 t_nivx)
    check("engine-only negative explainability stays admin-only",
          st in (401, 403), f"→ {st}")

    # admin administration is unchanged
    st, _ = call("GET", "/api/v2/cases", t_admin)
    check("admin still lists the engine case registry", st == 200, f"→ {st}")

    print(f"\nS2-MINI LIVE PROOF · {_p} PASS · {_f} FAIL")
    return 0 if _f == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
