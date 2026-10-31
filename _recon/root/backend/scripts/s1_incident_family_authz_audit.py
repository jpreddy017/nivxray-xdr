"""S1 · static inventory of the incident resource family and its authority.

Lists every `/api/incidents*` route with the authentication dependency it
declares and whether its handler resolves the incident through the ONE
authority (`routers.incidents.authorized_incident`).
"""
import inspect
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deps import validate_config, init_database  # noqa: E402

validate_config()
init_database()

from server import app  # noqa: E402

AUTH_NAMES = ("get_current_user", "get_current_user_optional", "require_admin",
              "require_permission", "authorized_incident",
              "require_incident_action")


def _deps(route):
    names = []
    for d in getattr(route, "dependencies", []) or []:
        c = getattr(d, "dependency", None)
        names.append(getattr(c, "__name__", str(c)))
    fn = route.endpoint
    sig = inspect.signature(fn)
    for p in sig.parameters.values():
        dflt = p.default
        c = getattr(dflt, "dependency", None)
        if c is not None:
            names.append(getattr(c, "__name__", str(c)))
    return names


rows = []
# Routes that are not single-incident addressing: they resolve the caller's
# tenant scope themselves (the queue projection / the provenance rollup) and
# therefore never call the single-incident authority.
AGGREGATE = {"/api/incidents", "/api/incidents/provenance/summary"}

for r in app.routes:
    path = getattr(r, "path", "")
    if not path.startswith("/api/incidents"):
        continue
    fn = r.endpoint
    try:
        src = inspect.getsource(fn)
    except OSError:
        src = ""
    rows.append((sorted(getattr(r, "methods", []) or []), path,
                 _deps(r),
                 "authorized_incident" in src or "_authorized_incident" in src,
                 "require_incident_action" in src))

rows.sort(key=lambda x: x[1])
print(f"{len(rows)} routes in the incident family\n")
leaks = []
for methods, path, deps, resolved, action in rows:
    authed = any(n in ("get_current_user", "require_admin",
                       "require_permission") for n in deps)
    if path in AGGREGATE:
        # tenant scope is resolved inside the handler, by the same
        # `resolve_tenant_scope` authority — there is no single incident.
        flag = "AGG"
        good = True
    else:
        good = authed and resolved
        flag = "OK " if good else "!! "
    if not good:
        leaks.append((methods, path, deps, authed, resolved))
    print(f"{flag}{','.join(methods):7} {path:70} deps={deps} "
          f"resolved={resolved} action_gate={action}")

print(f"\nNOT (authenticated AND incident-resolved): {len(leaks)}")
for methods, path, deps, authed, resolved in leaks:
    print(f"  {','.join(methods):7} {path:70} authed={authed} resolved={resolved} {deps}")
sys.exit(1 if leaks else 0)
