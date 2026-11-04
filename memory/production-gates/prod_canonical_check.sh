# PRODUCTION CANONICAL CONFIRMATION — owner-run, READ-ONLY
#
# Two GETs only. No write, no patch, no deploy, no DB change.
# The script prints an AGGREGATE summary plus one sanitised sample event.
# It never prints payloads, credentials, tokens or XML content.
#
# 1. Get a short-lived JWT: sign in to the console as admin, open DevTools →
#    Application/Storage → copy the bearer token used by the console.
# 2. Run:
#       export NIVXJWT='<paste the token>'
#       bash prod_canonical_check.sh
#    (the token stays in your shell only)

set -u
API="https://nivxray.nivxforge.com"
EP="ep_1989031c8c1d0085812f"
TENANT="ten_e759b7288598bd882e3dcac49d"
AUTH=(-H "Authorization: Bearer $NIVXJWT" -H "X-Tenant-Id: $TENANT")

echo "=== 1/2  GET /api/edr/events?endpoint_id=$EP&hours=24&limit=200"
curl -s "${AUTH[@]}" "$API/api/edr/events?endpoint_id=$EP&hours=24&limit=200" | python3 -c '
import sys, json, collections
d = json.load(sys.stdin)
if "events" not in d:
    print("RESPONSE (no events key):", json.dumps(d)[:400]); raise SystemExit
rows = d["events"]
print("tenant_id        :", d.get("tenant_id"))
print("rows returned    :", d.get("count"), "| has_more:", d.get("has_more"))
c = collections.Counter
print("parser_state     :", dict(c(r.get("parser_state") for r in rows)))
print("canonical_event_id present:",
      sum(1 for r in rows if r.get("canonical_event_id")), "/", len(rows))
print("detection.outcome:",
      dict(c((r.get("detection") or {}).get("outcome") for r in rows)))
print("activity stamped :", dict(c(r.get("activity") for r in rows)))
print("operation        :", dict(c(r.get("operation") for r in rows)))
print("trust_state      :", dict(c(r.get("trust_state") for r in rows)))
print("sensor_version   :", dict(c(r.get("sensor_version") for r in rows)))
print("derivation_count :", dict(c(r.get("derivation_count") for r in rows)))
sysmon1 = [r for r in rows
           if "Microsoft-Windows-Sysmon/Operational" in (r.get("payload_preview") or "")
           and "\"event_id\": \"1\"" in (r.get("payload_preview") or "").replace("\x27", "\"")]
print("\n-- rows whose preview shows Sysmon/Operational event_id 1:", len(sysmon1))
sample = (sysmon1 or rows)
if sample:
    s = sample[0]
    print("SAMPLE (sanitised, no payload):")
    for k in ("raw_id", "ingest_time", "event_time", "endpoint_ref",
              "hostname", "activity", "operation", "parser_state",
              "canonical_event_id", "derivation_count", "trust_state",
              "telemetry_quality", "payload_sha256"):
        print(f"   {k:20} = {s.get(k)}")
    print("   detection            =", json.dumps(s.get("detection"))[:300])
    print("\nRAW_ID FOR STEP 2    =", s.get("raw_id"))
'

echo
echo "=== 2/2  GET /api/edr/events/{raw_id}   (paste the RAW_ID printed above)"
read -r -p "raw_id: " RAWID
curl -s "${AUTH[@]}" "$API/api/edr/events/$RAWID" | python3 -c '
import sys, json
d = json.load(sys.stdin)
ev = d.get("event") or {}
print("tenant_id     :", d.get("tenant_id"))
for k in ("raw_id", "activity", "operation", "parser_state",
          "canonical_event_id", "trust_state", "telemetry_quality",
          "payload_sha256", "derivation_count"):
    print(f"  {k:20} = {ev.get(k)}")
print("  authentication.keys =", sorted((ev.get("authentication") or {}).keys()))
print("  DERIVATIONS (no payload):")
for i, der in enumerate(ev.get("derivations") or []):
    keep = {k: der.get(k) for k in
            ("replay_generation", "derived_at", "parser_name",
             "parser_version", "parser_state", "normalizer_version",
             "detection_content_version", "event_id", "evidence_ids",
             "outcome") if der.get(k) is not None}
    print(f"   [{i}] {json.dumps(keep)[:400]}")
    notes = der.get("parser_notes") or []
    if notes:
        print("        parser_notes:", json.dumps(notes)[:300])
    reason = der.get("reason")
    if reason:
        print("        reason      :", str(reason)[:300])
print("\n  winlog fields from the stored payload (channel/event_id/record_id only):")
try:
    env = json.loads(ev.get("payload") or "{}")
    w = env.get("winlog") or {}
    print("   kind       =", env.get("kind"))
    print("   channel    =", w.get("channel"))
    print("   event_id   =", w.get("event_id"))
    print("   record_id  =", w.get("record_id"))
    print("   provider   =", w.get("provider"))
    print("   computer   =", w.get("computer"))
    print("   xml_present=", bool(w.get("xml")), "| xml_len =", len(w.get("xml") or ""))
except Exception as ex:
    print("   (payload not JSON:", type(ex).__name__, ")")
'
