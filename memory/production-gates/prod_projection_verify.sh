# PRODUCTION PROJECTION ACCEPTANCE — owner-run, STRICTLY READ-ONLY
#
# Run this AFTER the backend republish. Every call is a GET. No write, no
# patch, no deploy, no DB change, no endpoint action, nothing printed that
# contains a payload, XML, credential or token.
#
#   1. Sign in to the EDR console as admin, DevTools → Application/Storage,
#      copy the bearer token the console is using.
#   2. export NIVXJWT='<paste the token>'
#      bash prod_projection_verify.sh
#
# It prints PASS/FAIL per acceptance criterion. Paste the whole output back.

set -u
API="https://nivxray.nivxforge.com"
EP="ep_1989031c8c1d0085812f"
TENANT="ten_e759b7288598bd882e3dcac49d"
AUTH=(-H "Authorization: Bearer $NIVXJWT" -H "X-Tenant-Id: $TENANT")

echo "=== 0 · build identity (compare with the pre-publish baseline) ==="
curl -s "$API/api/health"; echo
curl -s "$API/api/openapi.json" | python3 -c '
import sys,hashlib,json
raw=sys.stdin.buffer.read()
print("openapi paths:", len(json.loads(raw).get("paths",{})),
      "| sha256:", hashlib.sha256(raw).hexdigest()[:16],
      "| BEFORE was 862 / 8c04168feebf43f0")'

echo
echo "=== 1 · activity facets (criterion: AUTH and PROCESS > 0) ==="
curl -s "${AUTH[@]}" "$API/api/edr/events/facets?hours=24" | python3 -c '
import sys, json
d = json.load(sys.stdin)
if "activity" not in d:
    print("RESPONSE:", json.dumps(d)[:400]); raise SystemExit(1)
act = d["activity"]
print("tenant_id          :", d.get("tenant_id"))
print("total_events (24h) :", d.get("total_events"))
print("activity facet     :", json.dumps(act))
print("not observed       :", d.get("activity_not_observed"))
for cls in ("PROCESS", "AUTH"):
    n = act.get(cls, 0)
    print(f"  {cls:8} = {n:6}  ->", "PASS" if n > 0 else "FAIL (expected > 0)")
print("  AUTHENTICATION must NOT appear unprojected ->",
      "PASS" if "AUTHENTICATION" not in act else "FAIL")'

echo
for CLS in PROCESS AUTH; do
echo "=== 2 · filter activity=$CLS returns genuine canonical records ==="
curl -s "${AUTH[@]}" "$API/api/edr/events?endpoint_id=$EP&hours=24&activity=$CLS&limit=25" \
 | CLS=$CLS python3 -c '
import sys, json, os, collections
cls = os.environ["CLS"]
d = json.load(sys.stdin)
if "events" not in d:
    print("RESPONSE:", json.dumps(d)[:400]); raise SystemExit(1)
rows = d["events"]
print("filters_applied    :", json.dumps(d.get("filters_applied")))
print("rows               :", len(rows))
wrong = [r["raw_id"] for r in rows if r.get("activity") != cls]
nocanon = [r["raw_id"] for r in rows if not r.get("canonical_event_id")]
print("  every row stamped", cls, "->", "PASS" if rows and not wrong else
      ("FAIL " + str(wrong[:3]) if rows else "FAIL (no rows)"))
print("  every row has canonical_event_id ->",
      "PASS" if rows and not nocanon else
      ("FAIL " + str(nocanon[:3]) if rows else "n/a"))
print("  activity_basis    :",
      json.dumps(dict(collections.Counter(r.get("activity_basis") for r in rows))))
print("  parser_state      :",
      json.dumps(dict(collections.Counter(r.get("parser_state") for r in rows))))
print("  hostname          :",
      json.dumps(dict(collections.Counter(r.get("hostname") for r in rows))))
if rows:
    print("  RAW_ID_FOR_TRAJECTORY_%s = %s" % (cls, rows[0]["raw_id"]))'
echo
done

echo "=== 3 · Sysmon 1 -> PROCESS and Security 4624 -> AUTH, per record ==="
curl -s "${AUTH[@]}" "$API/api/edr/events?endpoint_id=$EP&hours=24&limit=200" | python3 -c '
import sys, json, re, collections
d = json.load(sys.stdin)
rows = d.get("events") or []
def eid(r):
    p = (r.get("payload_preview") or "").replace("\x27", "\"")
    m = re.search(r"\"event_id\"\s*:\s*\"?(\d+)", p)
    prov = "sysmon" if "Sysmon/Operational" in p else (
        "winsec" if "\"channel\": \"Security\"" in p or "Security-Auditing" in p
        else "?")
    return prov, (int(m.group(1)) if m else None)
seen = collections.defaultdict(collections.Counter)
for r in rows:
    prov, e = eid(r)
    if e is not None:
        seen[(prov, e)][str(r.get("activity"))] += 1
print("rows sampled:", len(rows))
expect = {("sysmon",1):"PROCESS", ("sysmon",3):"NETWORK", ("sysmon",11):"FILE",
          ("sysmon",12):"REGISTRY", ("sysmon",13):"REGISTRY",
          ("sysmon",22):"DNS", ("winsec",4688):"PROCESS",
          ("winsec",4624):"AUTH"}
for key in sorted(seen, key=str):
    got = dict(seen[key])
    want = expect.get(key)
    if want:
        ok = list(got) == [want]
        print(f"  {key} -> {got}   expected {want} -> " +
              ("PASS" if ok else "FAIL"))
    else:
        ok = list(got) in ([ "None" ], [])
        print(f"  {key} -> {got}   UNSUPPORTED, must stay None -> " +
              ("PASS" if ok else "FAIL — a gap was falsely classified"))'

echo
echo "=== 4 · unsupported families stay an EXPLICIT coverage gap ==="
curl -s "${AUTH[@]}" "$API/api/edr/events?endpoint_id=$EP&hours=24&limit=200" | python3 -c '
import sys, json, re
d = json.load(sys.stdin)
gaps = [r for r in (d.get("events") or []) if r.get("activity") is None]
print("rows with no activity class:", len(gaps))
for r in gaps[:8]:
    p = (r.get("payload_preview") or "").replace("\x27", "\"")
    m = re.search(r"\"event_id\"\s*:\s*\"?(\d+)", p)
    print("  event_id", (m.group(1) if m else "?"),
          "| canonical:", bool(r.get("canonical_event_id")),
          "| basis:", (r.get("activity_basis") or "")[:96])
print("criterion: each line above must carry a truthful NOT_SUPPORTED-style",
      "basis and no invented class")'

echo
echo "=== 5 · tenant isolation unchanged (expect 403, never data) ==="
curl -s -o /tmp/iso.json -w "http=%{http_code}\n" \
  -H "Authorization: Bearer $NIVXJWT" -H "X-Tenant-Id: ten_does_not_exist_0000" \
  "$API/api/edr/events?endpoint_id=$EP&hours=1&limit=1"
python3 -c '
import json
d = json.load(open("/tmp/iso.json"))
code = (d.get("detail") or {}).get("code") if isinstance(d.get("detail"), dict) else d.get("detail")
print("  body code:", code, "| events key present:", "events" in d)
print("  ->", "PASS" if "events" not in d else "FAIL — foreign tenant got rows")'

echo
echo "=== 6 · Device Trajectory consumes real canonical PROCESS evidence ==="
read -r -p "paste RAW_ID_FOR_TRAJECTORY_PROCESS from section 2: " RID
curl -s "${AUTH[@]}" "$API/api/edr/endpoints/$EP/trajectory/focus?raw_event_id=$RID" \
 | python3 -c '
import sys, json
d = json.load(sys.stdin)
print("state      :", d.get("state"))
f = d.get("focus") or {}
for k in ("event_iid", "event_type", "process_iid", "lane_id", "timestamp"):
    print(f"  {k:12} =", f.get(k))
prov = (f.get("provenance") or {})
print("  provenance  =", json.dumps({k: prov.get(k) for k in
      ("raw_event_id", "canonical_event_id")}))
s = d.get("search") or {}
print("  search      =", json.dumps({k: s.get(k) for k in
      ("pages_searched", "observations_examined", "cursor_state")}))
print("  ->", "PASS" if d.get("state") == "FOCUS_RESOLVED"
      and prov.get("raw_event_id") else "REVIEW — see state above")'

echo
curl -s "${AUTH[@]}" "$API/api/edr/endpoints/$EP/trajectory?limit=50" | python3 -c '
import sys, json, collections
d = json.load(sys.stdin)
ev = d.get("events") or d.get("observations") or []
print("trajectory rows:", len(ev))
print("  event_type mix:", json.dumps(dict(collections.Counter(
      e.get("event_type") for e in ev))))
print("  distinct process_iids:", len({e.get("process_iid") for e in ev}))
print("  ->", "PASS" if ev else "REVIEW — window returned nothing")'
