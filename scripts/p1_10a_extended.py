"""P1.10a extended validation: verdict_card, API surface, adversarial."""
import asyncio, os, json, requests
from motor.motor_asyncio import AsyncIOMotorClient

BASE = os.environ.get("REACT_APP_BACKEND_URL", "http://localhost:8001").rstrip("/")
H = {"X-Tenant-Id": "nivx-live", "X-Principal-Id": "admin@nivxray.com"}


async def main():
    client = AsyncIOMotorClient(os.environ.get("MONGO_URL", "mongodb://localhost:27017"))
    db = client[os.environ.get("DB_NAME", "test_database")]

    print("=== verdict_card reason for TRACK A2 incident ===")
    case = await db.workspace_cases.find_one({"tenant_id": "nivx-live"}, {"_id": 0})
    vc = (case or {}).get("verdict_card") or {}
    reason = vc.get("reason")
    print("reason:", reason)
    print("score:", vc.get("score"), "label:", vc.get("label"))
    expected_reason = "detection(+45) + iue.severity_hint(+5) + ice.matches(+60)"
    print("MATCH_EXPECTED_LITERAL:", reason == expected_reason)

    print("\n=== xdr_correlation_matches - verify claims/honesty ===")
    async for r in db.xdr_correlation_matches.find({"rule_id": "SPREAD-WATCH-001"}, {"_id": 0}):
        c = r.get("claim", "")
        forbidden = [w for w in ["spread to", "lateral movement", "compromised", "patient zero"] if w in c.lower()]
        print(f"  claim OK (no forbidden phrases): {not forbidden}; forbidden hits: {forbidden}")
        print(f"  honesty_note has 'lateral movement': {'lateral movement' in r.get('honesty_note','')}")

    print("\n=== xdr_spread_watchlist src_ip/username never as indicator ===")
    for bad in ["src_ip", "username"]:
        found = await db.xdr_spread_watchlist.count_documents({"indicator_type": bad})
        print(f"  indicator_type={bad}: {found} rows (must be 0)")
    # Verify no watchlist doc has verdict/score at top level
    async for w in db.xdr_spread_watchlist.find({}, {"_id": 0}):
        assert "score" not in w and "verdict" not in w, f"leak: {w.keys()}"
    print("  no top-level 'score' or 'verdict' fields on watchlist docs: PASS")

    # === API surface ===
    print("\n=== GET /api/xdr/spread ===")
    r = requests.get(f"{BASE}/api/xdr/spread", headers=H, timeout=15)
    print("status:", r.status_code)
    j = r.json()
    print("count:", j.get("count"), "totals:", j.get("totals"))
    assert "observed_on_multiple_endpoints" in j.get("totals", {}), "totals key wrong"

    print("\n=== GET /api/xdr/spread (missing X-Tenant-Id) ===")
    r = requests.get(f"{BASE}/api/xdr/spread", timeout=15)
    print("status:", r.status_code, r.text[:200])

    print("\n=== GET /api/xdr/spread/policy ===")
    r = requests.get(f"{BASE}/api/xdr/spread/policy", headers=H, timeout=15)
    p = r.json()
    print("is_engine:", p.get("is_engine"))
    print("correlation_engine:", p.get("correlation_engine"))
    print("scoring_engine:", p.get("scoring_engine"))
    print("promotion_authority:", p.get("promotion_authority"))

    print("\n=== GET /api/xdr/spread/signals ===")
    r = requests.get(f"{BASE}/api/xdr/spread/signals", headers=H, timeout=15)
    print("status:", r.status_code, "count:", r.json().get("count"))

    # Fetch a watch_id
    print("\n=== GET /api/xdr/spread/{watch_id} ===")
    row = await db.xdr_spread_watchlist.find_one({"indicator_type": "dest_ip", "indicator_value": "203.0.113.77"}, {"_id": 0})
    wid = row["watch_id"]
    r = requests.get(f"{BASE}/api/xdr/spread/{wid}", headers=H, timeout=15)
    d = r.json()
    print("status:", r.status_code)
    print("has watch, sightings, unknown_endpoint_sightings, correlation_evidence, claim:", 
          all(k in d for k in ["watch", "sightings", "unknown_endpoint_sightings", "correlation_evidence", "claim"]))
    print("claim:", d.get("claim"))
    print("unknown_endpoint_sightings count:", len(d.get("unknown_endpoint_sightings", [])))

    print("\n=== GET /{watch_id} cross-tenant (must 404) ===")
    r = requests.get(f"{BASE}/api/xdr/spread/{wid}", headers={"X-Tenant-Id": "other-tenant", "X-Principal-Id": "admin@nivxray.com"}, timeout=15)
    print("cross-tenant status:", r.status_code)

    print("\n=== POST /api/xdr/spread with unsupported types ===")
    for bad in ["username", "src_ip"]:
        r = requests.post(f"{BASE}/api/xdr/spread", headers={**H, "Content-Type": "application/json"},
                          json={"indicator_type": bad, "indicator_value": "foo"}, timeout=15)
        print(f"  {bad}: status={r.status_code} body={r.text[:200]}")

    print("\n=== POST /api/xdr/spread analyst enrollment (dest_ip 192.0.2.55) ===")
    r = requests.post(f"{BASE}/api/xdr/spread", headers={**H, "Content-Type": "application/json"},
                      json={"indicator_type": "dest_ip", "indicator_value": "192.0.2.55", "note": "test"}, timeout=15)
    print("status:", r.status_code)
    body = r.json()
    print("created:", body.get("created"))
    w = body.get("watch", {})
    print("endpoint_count:", w.get("endpoint_count"), "cardinality:", w.get("epistemic_state", {}).get("endpoint_cardinality"))
    print("source:", w.get("source"), "sighting_count:", w.get("sighting_count"))

    analyst_wid = w.get("watch_id")

    print("\n=== POST /{watch_id}/retire ===")
    r = requests.post(f"{BASE}/api/xdr/spread/{analyst_wid}/retire",
                      headers={**H, "Content-Type": "application/json"},
                      json={"reason": "not interesting"}, timeout=15)
    print("status:", r.status_code, "retired status:", r.json().get("watch", {}).get("status"))

    # Verify sightings/evidence not deleted for a previous auto watch
    print("\n=== POST retire on real auto watch, verify sightings preserved ===")
    r = requests.post(f"{BASE}/api/xdr/spread/{wid}/retire",
                      headers={**H, "Content-Type": "application/json"},
                      json={"reason": "e2e test"}, timeout=15)
    remaining_sightings = await db.xdr_spread_sightings.count_documents({"watch_id": wid})
    remaining_ev = await db.xdr_correlation_matches.count_documents({"spread.watch_id": wid})
    print(f"  after retire: sightings={remaining_sightings}, correlation_evidence={remaining_ev}")

    print("\n=== Fingerprint tests: DIE normalizer + volatile ===")
    from detection_content.xdr_spread_watchlist import cmdline_fingerprint
    a = cmdline_fingerprint("C:\\Users\\alice\\Downloads\\tool.exe -c 10.0.0.1")
    b = cmdline_fingerprint("D:\\ProgramData\\Temp\\tool.exe -c 192.168.5.9")
    print(f"  fp1={a}\n  fp2={b}\n  SAME? {a[0]==b[0]}")

    import base64
    enc = base64.b64encode("Get-Process | Where-Object CPU -gt 100".encode("utf-16-le")).decode()
    p1 = cmdline_fingerprint(f"powershell.exe -enc {enc}")
    p2 = cmdline_fingerprint("powershell.exe Get-Process | Where-Object CPU -gt 100")
    print(f"  ps-enc fp={p1}\n  ps-plain fp={p2}\n  SAME? {p1[0]==p2[0] if p1 and p2 else False}")

    short = cmdline_fingerprint("ls")
    print(f"  short cmd 'ls' fingerprint (must be None): {short}")

    print("\n=== xdr_ice signal_from_canonical: flat vs nested ===")
    import sys; sys.path.insert(0, "/app/backend")
    from detection_content.xdr_ice import _signal_from_canonical
    flat = {"host": {"hostname": "HOSTA"}, "network": {"dest_ip": "1.2.3.4", "src_ip": "5.6.7.8"}, "event_id": "e1", "event_time": "2026-01-01T00:00:00Z"}
    nested = {"host": {"hostname": ""}, "network": {"src": {"ip": "9.9.9.9"}, "dst": {"ip": "8.8.8.8"}}, "event_id": "e2", "event_time": "2026-01-01T00:00:00Z"}
    sf = _signal_from_canonical(flat)
    sn = _signal_from_canonical(nested)
    print(f"  flat: host_id={sf.get('host_id')} dst_ip={sf.get('dst_ip')}")
    print(f"  nested: host_id={sn.get('host_id')} dst_ip={sn.get('dst_ip')}")

    print("\n=== Adversarial: dvc IP becomes host_id but must NOT count ===")
    # Simulate: canonical with host.host_id = IP literal only, no hostname
    from detection_content.xdr_spread_watchlist import endpoint_identity
    for candidate in [{"host": {"host_id": "10.0.0.5"}}, {"host": {"host_id": "UNKNOWN"}}, {"host": {}}]:
        ident, state = endpoint_identity(candidate)
        print(f"  {candidate} -> identity={ident} state={state}")

    print("\n=== VEEE cap: 50 matches vs 3 matches identical score ===")
    from detection_content.xdr_veee import veee_compute
    ev = {"tenant_id": "nivx-live", "event_id": "x"}
    iue = {"severity_hint": "LOW"}
    det = {"matched": True, "detections": [{"rule_id": "r1", "severity": "MEDIUM"}]}
    m3 = [{"rule_id": "SPREAD-WATCH-001", "evidence_level": "CORRELATION_OBSERVED"}] * 3
    m50 = [{"rule_id": "SPREAD-WATCH-001", "evidence_level": "CORRELATION_OBSERVED"}] * 50
    v3 = veee_compute(ev, iue, det, {"matches": m3})
    v50 = veee_compute(ev, iue, det, {"matches": m50})
    print(f"  score with 3 matches: {v3.get('score')} label={v3.get('label')}")
    print(f"  score with 50 matches: {v50.get('score')} label={v50.get('label')}")
    print(f"  IDENTICAL? {v3.get('score') == v50.get('score')}")

asyncio.run(main())
