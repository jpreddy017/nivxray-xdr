#!/usr/bin/env python3
"""
Legacy Watchdog — READ-ONLY availability + replacement detector.

Purpose (owner-approved, deliberately small): notice immediately if the
frozen legacy production host stops answering, or if its frontend is
silently REPLACED by a different app — the exact consequence of a stray
Deploy on the frozen Emergent project.

It performs GET requests only. It cannot restart, redeploy, alter
configuration or write to any remote system. Its only local side effect is
a status file.

    python3 scripts/legacy_watchdog.py            # one shot, exit 1 on alert
    python3 scripts/legacy_watchdog.py --quiet    # for cron

Exit codes: 0 healthy · 1 ALERT.
"""
import argparse
import json
import re
import sys
import urllib.request
from datetime import datetime, timezone

LEGACY = "https://nivxray.nivxforge.com"
HEALTH = "/api/health"          # unauthenticated GET, verified 200
UA = "Mozilla/5.0 (NivXRay legacy watchdog; read-only)"
STATE = "/app/memory/legacy_watchdog_state.json"

# The legacy Workspace ships these nav testids. If BOTH vanish, the
# frontend on this host is no longer the legacy Workspace.
LEGACY_NAV_MARKERS = ["nav-xdr", "nav-investigations"]


HOST = LEGACY  # overridable via --host, used only to PROVE the alert paths


def get(path, timeout=25):
    req = urllib.request.Request(HOST + path, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return 0, f"__ERROR__ {type(e).__name__}: {e}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--host", default=LEGACY,
                    help="only for proving the alert paths fire; "
                         "production monitoring uses the default")
    ap.add_argument("--state", default=STATE)
    args = ap.parse_args()
    global HOST
    HOST = args.host.rstrip("/")

    alerts, facts = [], {}

    # 1 · the site answers
    st, body = get("/")
    facts["root_status"] = st
    if st != 200:
        alerts.append(f"LEGACY FRONTEND DOWN · GET / returned {st}")

    # 2 · the API answers (the Workspace's temporary dependency)
    hst, hbody = get(HEALTH)
    facts["api_health_status"] = hst
    facts["api_health_body"] = hbody[:120]
    if hst != 200:
        alerts.append(f"LEGACY API DOWN · GET {HEALTH} returned {hst}")
    elif '"status":"ok"' not in hbody.replace(" ", ""):
        alerts.append(f"LEGACY API UNHEALTHY · {HEALTH} → {hbody[:120]}")

    # 3 · the frontend is still the legacy Workspace, not a replacement
    if st == 200:
        mst, man = get("/asset-manifest.json")
        facts["manifest_status"] = mst
        if mst != 200:
            alerts.append(
                f"CANNOT VERIFY LEGACY BUNDLE · asset-manifest.json → {mst}")
        else:
            try:
                chunks = [v for v in json.loads(man)["files"].values()
                          if v.endswith(".js") and not v.endswith(".map")]
                facts["chunk_count"] = len(chunks)
                blob = ""
                for u in chunks:
                    _, b = get(u)
                    blob += b
                found = [m for m in LEGACY_NAV_MARKERS if m in blob]
                facts["nav_markers_found"] = found
                routes = sorted(set(re.findall(r'path:"(/[^"]*)"', blob)))
                facts["route_count"] = len(routes)
                facts["has_workspace_route"] = "/auto-investigate" in routes
                if not found:
                    alerts.append(
                        "LEGACY FRONTEND REPLACED · neither "
                        f"{LEGACY_NAV_MARKERS} found across {len(chunks)} "
                        "chunks — the host is no longer serving the legacy "
                        "Workspace. A Deploy may have fired on the FROZEN "
                        "Emergent project."
                    )
                if not facts["has_workspace_route"]:
                    alerts.append(
                        "LEGACY WORKSPACE ROUTES MISSING · /auto-investigate "
                        "is absent from the served bundle."
                    )
            except Exception as e:
                # A non-JSON asset-manifest means the host is not serving a
                # CRA build at all — on an SPA host the rewrite hands back
                # index.html. That IS the replacement signal, so it must not
                # be reported as a vague check failure.
                alerts.append(
                    "LEGACY FRONTEND REPLACED · asset-manifest.json is not a "
                    "CRA manifest, so this host is no longer serving the "
                    "legacy Workspace build. A Deploy may have fired on the "
                    f"FROZEN Emergent project. ({type(e).__name__})"
                )

    now = datetime.now(timezone.utc).isoformat()
    state = {"checked_at": now, "host": HOST,
             "healthy": not alerts, "alerts": alerts, "facts": facts}
    with open(args.state, "w") as fh:
        json.dump(state, fh, indent=2)

    if alerts:
        print(f"ALERT · legacy watchdog · {now}")
        for a in alerts:
            print(f"  · {a}")
        print("\nThis watchdog is read-only. It has changed nothing. "
              "Investigate before taking any action on the frozen project.")
        return 1

    if not args.quiet:
        print(f"healthy · {now}")
        print(f"  / → {facts['root_status']} · {HEALTH} → "
              f"{facts['api_health_status']}")
        print(f"  legacy bundle intact · {facts.get('chunk_count')} chunks · "
              f"markers {facts.get('nav_markers_found')} · "
              f"{facts.get('route_count')} routes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
