from fastapi import APIRouter, Request

router = APIRouter(tags=["telemetry-health"])


@router.get("/telemetry-health")
def telemetry_health(request: Request):
    """Health projection per configured source.

    Phase A: emits an honest per-source-type NEVER CONNECTED row for
    every source-type the framework KNOWS ABOUT.  Once vendor adapters
    are registered (Phase C+) and a tenant configures an instance,
    the row flips to the real health reported by the connector.
    """
    reg = request.app.state.registry
    rows_by_source = {}
    for c in reg.all():
        rows_by_source.setdefault(c.source_type, []).append(c.describe())

    known_source_types = [
        "edr", "siem", "firewall", "network", "dns", "email",
        "identity", "cloud", "saas", "app", "api", "custom",
    ]
    out = []
    for st in known_source_types:
        instances = rows_by_source.get(st, [])
        if not instances:
            out.append({"source_type": st, "health": "never_connected",
                          "instances": 0,
                          "note": "no connector instance configured for this tenant"})
        else:
            for inst in instances:
                out.append({"source_type": st,
                              "identity":    inst["identity"],
                              "health":      inst["health"],
                              "metrics":     inst["metrics"]})
    return {"rows": out, "phase": "A"}
