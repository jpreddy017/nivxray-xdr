"""DT2-8 PERFORMANCE BASELINE HARNESS — READ-ONLY.

Measures V1 trajectory hot paths separately (never one blended number).
Nothing is written; every call is a GET except the login that mints a session.

Preview/local:
    python3 memory/production-gates/dt2_perf_baseline.py --api http://127.0.0.1:8001 \
        --device dev_42e8c6dc74b9 --tenant default
Production (owner-run, token only, no password):
    export NIVXJWT='<console bearer token>'
    python3 memory/production-gates/dt2_perf_baseline.py \
        --api https://nivxray.nivxforge.com --device ep_1989031c8c1d0085812f \
        --tenant ten_e759b7288598bd882e3dcac49d
"""
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.request

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", required=True)
    ap.add_argument("--device", required=True)
    ap.add_argument("--tenant", required=True)
    ap.add_argument("--limit", default="500")
    ap.add_argument("--email", default="admin@nivxray.com")
    a = ap.parse_args()

    token = os.environ.get("NIVXJWT", "").strip()
    if not token:
        import getpass
        pw = getpass.getpass(f"password for {a.email} (not echoed): ")
        req = urllib.request.Request(
            a.api + "/api/auth/login",
            data=json.dumps({"email": a.email, "password": pw}).encode(),
            headers={"Content-Type": "application/json"})
        del pw
        token = json.loads(urllib.request.urlopen(req, timeout=60)
                           .read())["access_token"]

    def get(path: str, label: str) -> dict:
        req = urllib.request.Request(a.api + path)
        req.add_header("Authorization", "Bearer " + token)
        req.add_header("X-Tenant-Id", a.tenant)
        t = time.perf_counter()
        try:
            raw = urllib.request.urlopen(req, timeout=300).read()
        except Exception as ex:                       # noqa: BLE001
            print(f"{'ERR':>10}  {type(ex).__name__}: {ex}   <- {label}")
            return {}
        dt = (time.perf_counter() - t) * 1000
        d = json.loads(raw)
        print(f"{dt:9.0f} ms {len(raw)/1024:9.1f} KiB "
              f"rows={d.get('returned')} lanes="
              f"{(d.get('lane_axis') or {}).get('total_lanes')} "
              f"state={(d.get('projection') or {}).get('state')}   <- {label}")
        return d

    base = f"/api/edr/endpoints/{a.device}/trajectory?limit={a.limit}"
    cold = get(base, "initial window · COLD projection")
    warm = get(base, "initial window · warm cache")
    get(base + "&lane_start=40&lane_end=80", "lane scroll +40")
    get(base + "&time_start=2026-09-01T00:00:00Z"
               "&time_end=2026-09-27T00:00:00Z", "time window change")
    get(base + "&q=powershell", "search q=powershell")
    get(base + "&kinds=process_create", "filter kinds=process_create")
    get(base + "&dispositions=MALICIOUS", "filter disposition")
    src = warm or cold
    prov = ((src.get("events") or [{}])[0].get("provenance") or {})
    if prov.get("raw_event_id"):
        get(f"/api/edr/endpoints/{a.device}/trajectory/focus"
            f"?raw_event_id={prov['raw_event_id']}", "focus · raw_event_id")
    if prov.get("canonical_event_id"):
        get(f"/api/edr/endpoints/{a.device}/trajectory/focus"
            f"?canonical_event_id={prov['canonical_event_id']}",
            "focus · canonical_event_id")
    print("observations_all_time:", src.get("observations_all_time"),
          "| matched_in_window:", src.get("matched_in_window"),
          "| has_more:", src.get("has_more"))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
