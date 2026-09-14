#!/usr/bin/env python3
"""D8 citation endpoint · end-to-end proof against the PREVIEW deployment.

Chain proven:
  real sensor activity → canonical evidence → rule evaluation
  → persisted D8 citations → read-only API → SAME stored values

Nothing is written. The D8 evidence is not adjusted to make the output
prettier — the endpoint is asserted against what the pipeline stored.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv("/app/backend/.env")
load_dotenv("/app/frontend/.env")
BASE = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
DB = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]

ADMIN = ("admin@nivxray.com", "uulVDp5cCSB3Hva99s7UUAwK")
ANALYST = ("analyst@nivx-live.com", "NivxLive!Analyst2026")   # tenant nivx-live

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like "
      "Gecko) Chrome/126.0 Safari/537.36")

ok = True


def check(label: str, cond: bool, detail: str = "") -> None:
    global ok
    ok = ok and cond
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}"
          + (f" — {detail}" if detail else ""))


def login(email: str, password: str) -> str | None:
    body = json.dumps({"email": email, "password": password}).encode()
    r = urllib.request.Request(f"{BASE}/api/auth/login", data=body,
                               headers={"Content-Type": "application/json",
                                        "User-Agent": UA},
                               method="POST")
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return json.loads(resp.read()).get("access_token")
    except urllib.error.HTTPError as e:
        print(f"    login {email} -> {e.code} {e.read().decode()[:120]}")
        return None


def get(path: str, token: str | None = None, extra: dict | None = None):
    h = {"User-Agent": UA, **(extra or {})}
    if token:
        h["Authorization"] = f"Bearer {token}"
    try:
        with urllib.request.urlopen(
                urllib.request.Request(f"{BASE}{path}", headers=h),
                timeout=30) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:220]


def main() -> int:
    # ── 0 · what the pipeline actually stored ────────────────────────
    print("0 · persisted D8 citation, straight from storage")
    stored = DB.xdr_detection_matches.find_one(
        {"declaration_state": "DECLARED",
         "citation_completeness": "CITED"}, sort=[("_id", -1)])
    if not stored:
        print("  no persisted citation — generate real activity first")
        return 1
    event_id = stored["canonical_event_id"]
    print(f"  canonical_event_id : {event_id}")
    print(f"  rule               : {stored['rule_id']} "
          f"v{stored['rule_version']}")
    print(f"  trust_state        : {stored['trust_state']}")
    for c in stored["evaluated_conditions"]:
        print(f"    [{c['result']:10s}] {c['canonical_field']:24s}"
              f" {c['operator']:24s} observed={str(c['observed_value'])[:40]!r}")

    # the evidence the citation points at must really exist
    src = DB.xdr_canonical_evidence.find_one({"event_id": event_id})
    check("evidence_ref resolves to real canonical evidence", src is not None)
    check("evidence is REAL sensor telemetry",
          (src or {}).get("source_product") == "LinuxSensor"
          and ((src or {}).get("provenance") or {}).get("trust_state")
          == "AUTHENTICATED")

    # ── 1 · authenticated read ───────────────────────────────────────
    print("\n1 · authenticated read (admin JWT)")
    token = login(*ADMIN)
    if not token:
        print("  cannot authenticate admin on preview — aborting")
        return 1
    code, body = get(f"/api/xdr/detections/{event_id}/citations", token)
    check("HTTP 200", code == 200, str(body)[:120] if code != 200 else "")
    if code != 200:
        return 1
    cits = body["data"]["citations"]
    api = next(c for c in cits if c["rule_id"] == stored["rule_id"])

    # ── 2 · the API returns the SAME stored values ───────────────────
    print("\n2 · API output == persisted values (not recomputed)")
    check("rule_id matches", api["rule_id"] == stored["rule_id"])
    check("rule_version matches",
          api["rule_version"] == stored["rule_version"],
          f"api={api['rule_version']} stored={stored['rule_version']}")
    check("evidence_ref matches", api["evidence_ref"] == stored["evidence_ref"],
          api["evidence_ref"])
    check("trust_state matches", api["trust_state"] == stored["trust_state"])
    check("rule_result is MATCH", api["rule_result"] == "MATCH")
    check("condition count identical",
          len(api["evaluated_conditions"])
          == len(stored["evaluated_conditions"]))
    same = all(a == s for a, s in zip(api["evaluated_conditions"],
                                      stored["evaluated_conditions"]))
    check("every condition byte-identical to storage", same)

    # ── 3 · at least one MATCH and one NO_MATCH ──────────────────────
    print("\n3 · positive AND negative condition both visible")
    matched = [c for c in api["evaluated_conditions"]
               if c["result"] == "MATCH"]
    nomatch = [c for c in api["evaluated_conditions"]
               if c["result"] == "NO_MATCH"]
    check("at least one MATCH condition", bool(matched),
          f"{len(matched)} matched")
    check("at least one NO_MATCH condition", bool(nomatch),
          f"{len(nomatch)} did not match")
    if matched:
        m = matched[-1]
        check("MATCH carries a real observed_value",
              m["observed_value"] not in (None, ""),
              f"{m['canonical_field']}={m['observed_value']!r}")
        # the cited value must still equal the evidence it was read from
        cur = src
        for part in m["canonical_field"].split("."):
            cur = (cur or {}).get(part) if isinstance(cur, dict) else None
        check("observed_value still equals the evidence", cur == m["observed_value"],
              f"evidence={cur!r}")
    if nomatch:
        n = nomatch[0]
        check("NO_MATCH is explained, not hidden",
              n["observed_value"] is not None,
              f"{n['canonical_field']} {n['operator']} "
              f"observed={n['observed_value']!r}")

    # ── 4 · unauthenticated rejected ─────────────────────────────────
    print("\n4 · unauthorized access rejected")
    code, body = get(f"/api/xdr/detections/{event_id}/citations")
    check("no credential -> 401/403", code in (401, 403), f"HTTP {code}")
    code, body = get(f"/api/xdr/detections/{event_id}/citations",
                     "not-a-real-token")
    check("bad token -> 401/403", code in (401, 403), f"HTTP {code}")

    # caller-supplied tenant header must not establish authorization
    code, body = get(f"/api/xdr/detections/{event_id}/citations", None,
                     {"X-Tenant-Id": stored["tenant_id"]})
    check("X-Tenant-Id header alone grants nothing",
          code in (401, 403), f"HTTP {code}")

    # ── 5 · cross-tenant rejected ────────────────────────────────────
    print("\n5 · cross-tenant access rejected")
    at = login(*ANALYST)
    if not at:
        print("  [SKIP] tenant-scoped analyst not available on this "
              "deployment — cross-tenant case not testable here")
    else:
        code, body = get(f"/api/xdr/detections/{event_id}/citations", at)
        check("analyst of another tenant cannot read it",
              code in (403, 404), f"HTTP {code} {str(body)[:100]}")
        code, body = get(
            f"/api/xdr/detections/{event_id}/citations?tenant="
            f"{stored['tenant_id']}", at)
        check("explicit ?tenant= cannot widen scope",
              code in (403, 404), f"HTTP {code} {str(body)[:100]}")

    print(f"\n{'ALL CHECKS PASSED' if ok else 'FAILURES PRESENT'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
