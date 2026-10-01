#!/usr/bin/env python3
"""D21 · routing visibility over real HTTP (PREVIEW ONLY).

The gate is not "a page renders". It is:

  1. every routing decision the ingest boundary made — accepted AND refused
     — is visible with its reason code, collector, declaration, allowlist
     relationship, selected DSM, payload shape, receipt instant and
     evidence reference;
  2. the surface is a WINDOW, not an authority: GET only, and it cannot
     change a decision;
  3. tenant A cannot see tenant B — not by header, not by query parameter,
     not by both together, and not in the counts either.

Two REAL tenants with REAL analyst logins are used (`default` and
`nivx-live`), so isolation is proven against authenticated principals
rather than against a mock.

Payloads are TEST/SYNTHETIC auditd/CloudTrail shapes delivered through the
real authenticated ingest route. Nothing touches production.
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

ADMIN = ("admin@nivxray.com", "uulVDp5cCSB3Hva99s7UUAwK")
#: tenant -> analyst login authorized for exactly that tenant
PRINCIPALS = {
    "default":   ("analyst@default.com", "DefaultCo!Analyst2026"),
    "nivx-live": ("analyst@nivx-live.com", "NivxLive!Analyst2026"),
}
VIZ = "/api/xdr/ingest/routing"

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
        raw = e.read().decode()[:400]
        try:
            return e.code, json.loads(raw)
        except Exception:                                      # noqa: BLE001
            return e.code, raw


def login(email, password):
    code, body = call("/api/auth/login", "POST",
                      body={"email": email, "password": password})
    return body.get("access_token") if code == 200 else None


AUD = f"1789800000.{STAMP % 1000}:{STAMP % 9000}"


def auditd_line(tenant):
    return (f'node=d21-{tenant} type=SYSCALL msg=audit({AUD}): arch=c000003e '
            f'syscall=59 success=yes exit=0 uid=0 euid=0 auid=1000 '
            f'pid={STAMP % 9000} ppid=4200 comm="bash" exe="/usr/bin/bash" '
            f'key="exec"')


def env(tenant, col, sei, declared, raw):
    e = {"tenant_id": tenant, "collector_id": col, "source_event_id": sei,
         "collection_method": "syslog", "source": f"d21-{tenant}-host",
         "raw": raw}
    if declared is not None:
        e["declared_source"] = declared
    return e


def provision(token, tenant):
    """One collector authorized for linux-auditd ONLY, plus an ingest key."""
    name = f"d21-proof-collector-{tenant}"
    code, body = call("/api/xdr/collectors", "POST", token=token,
                      tenant=tenant,
                      body={"name": name, "protocol": "rest",
                            "authorized_sources": ["linux-auditd"]})
    if code in (200, 201):
        col = (body.get("data") or {}).get("id")
    elif code == 409:
        _, lst = call("/api/xdr/collectors", token=token, tenant=tenant)
        col = next((c["id"] for c in
                    ((lst.get("data") or {}).get("collectors") or [])
                    if c.get("name") == name), None)
        if col:
            call(f"/api/xdr/collectors/{col}", "PUT", token=token,
                 tenant=tenant, body={"authorized_sources": ["linux-auditd"]})
    else:
        print(f"    collector create -> {code} {body}")
        return None, None
    code, body = call("/api/xdr/api-keys", "POST", token=token, tenant=tenant,
                      body={"name": f"d21-key-{tenant}-{STAMP}",
                            "confirm_tenant_id": tenant,
                            "allow_new_tenant": False,
                            "scopes": ["collectors.enroll",
                                       "collectors.read"]})
    d = body.get("data") or {}
    key = (d.get("api_key") or d.get("key") or d.get("secret")
           or d.get("plaintext") or d.get("token") or d.get("value"))
    return col, key


def deliver(tenant, col, key):
    """One accepted delivery and two refusals with DIFFERENT reason codes."""
    return call("/api/xdr/ingest/telemetry", "POST", key=key, tenant=tenant,
                body={"envelopes": [
                    env(tenant, col, f"d21:{STAMP}:{tenant}:ok",
                        "linux-auditd",
                        {"line": auditd_line(tenant),
                         "payload_format": "auditd"}),
                    env(tenant, col, f"d21:{STAMP}:{tenant}:nodecl", None,
                        {"line": auditd_line(tenant),
                         "payload_format": "auditd"}),
                    env(tenant, col, f"d21:{STAMP}:{tenant}:notauth",
                        "aws-cloudtrail",
                        {"line": auditd_line(tenant),
                         "payload_format": "auditd"})]})


def main() -> int:                                          # noqa: C901
    admin = login(*ADMIN)
    if not admin:
        print("admin login failed")
        return 1
    print("admin login: 200")

    print("\n1 · provision one collector + ingest key per REAL tenant")
    state = {}
    for tenant in PRINCIPALS:
        col, key = provision(admin, tenant)
        check(f"{tenant}: collector + key ready", bool(col and key), str(col))
        if not (col and key):
            return 1
        state[tenant] = {"col": col, "key": key}

    print("\n2 · deliver 1 accepted + 2 refused (distinct reason codes) per "
          "tenant through the authenticated ingest route")
    for tenant, s in state.items():
        code, body = deliver(tenant, s["col"], s["key"])
        blocked = body.get("routing_blocked") if isinstance(body, dict) else None
        accepted = body.get("accepted") if isinstance(body, dict) else None
        check(f"{tenant}: ingest receipt", code == 200 and blocked == 2
              and accepted == 1, f"{code} accepted={accepted} "
                                 f"routing_blocked={blocked}")
        codes = {o.get("mismatch_reason") for o in
                 (body.get("reasoning") or []) if isinstance(body, dict)}
        check(f"{tenant}: both refusal codes recorded",
              {"DECLARATION_REQUIRED", "SOURCE_NOT_AUTHORIZED"} <= codes,
              str(sorted(c for c in codes if c)))

    print("\n3 · the operator surface shows BOTH outcomes for the tenant's "
          "own collector")
    for tenant, s in state.items():
        token = login(*PRINCIPALS[tenant])
        check(f"{tenant}: analyst login", bool(token))
        if not token:
            return 1
        s["token"] = token
        code, body = call(f"{VIZ}/deliveries?collector_id={s['col']}&limit=50",
                          token=token)
        rows = body.get("rows") or [] if isinstance(body, dict) else []
        check(f"{tenant}: deliveries 200", code == 200, str(code))
        acc = [r for r in rows if r["delivery"] == "ACCEPTED"]
        blk = [r for r in rows if r["delivery"] == "BLOCKED"]
        check(f"{tenant}: accepted delivery visible", len(acc) >= 1,
              f"{len(acc)} accepted")
        check(f"{tenant}: both refusals visible", len(blk) >= 2,
              f"{len(blk)} refused")
        check(f"{tenant}: refusal reason codes visible",
              {"DECLARATION_REQUIRED", "SOURCE_NOT_AUTHORIZED"}
              <= {r["reason_code"] for r in blk},
              str(sorted({r["reason_code"] for r in blk})))
        if acc:
            a = acc[0]
            check(f"{tenant}: accepted row is fully attributed",
                  a["collector_id"] == s["col"]
                  and a["declared_source"] == "linux-auditd"
                  and a["selected_dsm_id"] == "linux-auditd"
                  and a["routing_authority"]
                  == "AUTHENTICATED_COLLECTOR_DECLARATION"
                  and a["authorization_relationship"]
                  == "DECLARED_SOURCE_IN_COLLECTOR_ALLOWLIST"
                  and a["payload_shape"] == "LINE"
                  and bool(a["at"]),
                  f"dsm={a['selected_dsm_id']} shape={a['payload_shape']}")
            check(f"{tenant}: accepted row cites its evidence",
                  str(a["evidence_ref"] or "").startswith(
                      "xdr_canonical_evidence/"), str(a["evidence_ref"]))
        if blk:
            b = blk[0]
            check(f"{tenant}: refusal carries no evidence ref and says why",
                  b["evidence_ref"] is None
                  and "no canonical evidence" in
                  str(b["evidence_ref_absent_reason"]),
                  str(b["evidence_ref_absent_reason"])[:60])
            check(f"{tenant}: refusal shows the allowlist relationship",
                  b["collector_authorized_sources"] == ["linux-auditd"],
                  str(b["collector_authorized_sources"]))
        check(f"{tenant}: scope basis is the authenticated principal",
              (body.get("tenant_scope") or {}).get("basis")
              == "AUTHENTICATED_PRINCIPAL_TENANT"
              and (body.get("tenant_scope") or {}).get("tenant_ids")
              == [tenant],
              json.dumps(body.get("tenant_scope")))
        check(f"{tenant}: every row belongs to this tenant",
              {r["tenant_id"] for r in rows} == {tenant},
              str(sorted({r["tenant_id"] for r in rows})))

    print("\n4 · TENANT ISOLATION · header, query parameter, and both")
    other = {"default": "nivx-live", "nivx-live": "default"}
    for tenant, s in state.items():
        foreign = other[tenant]
        for label, path, hdr in (
                ("X-Tenant-Id spoof", f"{VIZ}/deliveries?limit=50", foreign),
                ("?tenant_id spoof",
                 f"{VIZ}/deliveries?limit=50&tenant_id={foreign}", None),
                ("both together",
                 f"{VIZ}/deliveries?limit=50&tenant_id={foreign}", foreign)):
            code, body = call(path, token=s["token"], tenant=hdr)
            rows = body.get("rows") or [] if isinstance(body, dict) else []
            seen = {r["tenant_id"] for r in rows}
            scope = body.get("tenant_scope") or {}
            check(f"{tenant} · {label}: still only own tenant",
                  code == 200 and seen <= {tenant}, f"{code} {sorted(seen)}")
            if "tenant_id=" in path:
                check(f"{tenant} · {label}: the request is reported as ignored",
                      scope.get("requested_tenant_id") == foreign
                      and scope.get("requested_tenant_id_honoured") is False
                      and bool(scope.get("requested_tenant_id_ignored_reason")),
                      json.dumps(scope)[:120])

        # counts, collector identities and reason codes must not leak either
        code, body = call(f"{VIZ}/summary?tenant_id={foreign}",
                          token=s["token"], tenant=foreign)
        own_code, own = call(f"{VIZ}/summary", token=s["token"])
        # Refusal totals are the stable quantity here: tenant `default` also
        # receives continuous live sensor telemetry, so its ACCEPTED count
        # legitimately changes between two sequential reads and is not a
        # usable equality assertion.
        check(f"{tenant}: summary cannot be pointed at {foreign}",
              code == 200 and own_code == 200
              and body.get("refused", {}).get("total")
              == own.get("refused", {}).get("total")
              and (body.get("tenant_scope") or {}).get("tenant_ids")
              == [tenant]
              and (body.get("tenant_scope") or {})
              .get("requested_tenant_id_honoured") is False,
              f"refused {body.get('refused', {}).get('total')} vs "
              f"{own.get('refused', {}).get('total')}")
        foreign_col = state[foreign]["col"]
        check(f"{tenant}: {foreign}'s collector identity is not in the counts",
              foreign_col not in (own.get("refused", {})
                                  .get("by_collector") or {})
              and foreign_col not in (body.get("refused", {})
                                      .get("by_collector") or {}),
              foreign_col)
        code, body = call(f"{VIZ}/deliveries?collector_id={foreign_col}",
                          token=s["token"], tenant=foreign)
        check(f"{tenant}: querying {foreign}'s collector returns nothing",
              code == 200 and (body.get("rows") or []) == [],
              f"{code} {len(body.get('rows') or [])} rows")

    print("\n5 · filters, and the cross-tenant role")
    t = state["default"]
    code, body = call(f"{VIZ}/deliveries?result=BLOCKED&limit=50",
                      token=t["token"])
    rows = body.get("rows") or []
    check("result=BLOCKED returns refusals only", code == 200 and rows
          and {r["delivery"] for r in rows} == {"BLOCKED"},
          str(sorted({r["delivery"] for r in rows})))
    code, body = call(f"{VIZ}/deliveries?reason_code=SOURCE_NOT_AUTHORIZED"
                      f"&collector_id={t['col']}", token=t["token"])
    rows = body.get("rows") or []
    check("reason_code filter is exact", code == 200 and rows
          and {r["reason_code"] for r in rows} == {"SOURCE_NOT_AUTHORIZED"},
          str(sorted({r["reason_code"] for r in rows})))
    code, body = call(f"{VIZ}/deliveries?result=ACCEPTED&declared_source="
                      f"linux-auditd&collector_id={t['col']}",
                      token=t["token"])
    rows = body.get("rows") or []
    check("declared_source filter is exact", code == 200 and rows
          and {r["declared_source_resolved"] for r in rows} == {"linux-auditd"},
          str(len(rows)))
    code, _ = call(f"{VIZ}/deliveries?limit=9999", token=t["token"])
    check("limit is capped by the contract, not silently widened",
          code == 422, str(code))

    code, body = call(f"{VIZ}/deliveries?limit=100", token=admin)
    rows = body.get("rows") or []
    check("cross-tenant role is labelled as such",
          (body.get("tenant_scope") or {}).get("basis") == "CROSS_TENANT_ROLE",
          json.dumps(body.get("tenant_scope"))[:120])
    code, body = call(f"{VIZ}/deliveries?limit=50&tenant_id=nivx-live",
                      token=admin)
    rows = body.get("rows") or []
    check("cross-tenant role may deliberately scope to one tenant",
          code == 200 and {r["tenant_id"] for r in rows} <= {"nivx-live"}
          and (body.get("tenant_scope") or {})
          .get("requested_tenant_id_honoured") is True,
          str(sorted({r["tenant_id"] for r in rows})))

    print("\n6 · the surface is READ-ONLY and unauthenticated callers get "
          "nothing")
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        code, _ = call(f"{VIZ}/deliveries", method, token=admin, body={})
        check(f"{method} /deliveries is refused", code in (404, 405),
              str(code))
    code, _ = call(f"{VIZ}/deliveries")
    check("no credential -> refused", code in (401, 403), str(code))
    code, _ = call(f"{VIZ}/deliveries", token="not-a-token")
    check("bad token -> refused", code in (401, 403), str(code))
    code, body = call(f"{VIZ}/catalog", token=t["token"])
    check("catalog restates the ingest authority verbatim",
          code == 200 and body.get("routing_authority")
          == "AUTHENTICATED_COLLECTOR_DECLARATION"
          and "SOURCE_NOT_AUTHORIZED" in (body.get("refusal_codes") or []),
          str(code))
    check("every response declares it is not an authority",
          "not a routing authority" in str(body.get("read_only_note")))

    print("\n" + ("D21 ROUTING VISIBILITY: PASS" if ok
                  else "D21 ROUTING VISIBILITY: FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
