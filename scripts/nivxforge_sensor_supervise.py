#!/usr/bin/env python3
"""P0-3 · supervised launcher for the NivXForge Linux sensor.

WHY THIS FILE EXISTS — the root cause of the outage it fixes:

The sensor had delivered 8k real events and then went silent on
2026-09-06. It was not a bug in the sensor, the transport, the auth or the
ingest path. It was two structural mistakes:

  1. **The sensor was never a supervised program.** It had been started by
     hand, so the next time the container was recreated nothing started it
     again — and nothing on the platform said so, because the platform had
     no way to notice its own blindness (that half is fixed by
     `services/edr/endpoint_health.resolve_delivery_freshness`).

  2. **Its durable state lived on an ephemeral path.**
     `/var/lib/nivxforge-sensor` is the correct default for a real
     endpoint, but in this container it does not survive recreation — so
     the enrolment credential, the outbox and the "already reported" set
     were destroyed along with the process. A sensor that cannot find its
     credential exits; a supervisor would simply have restarted it into
     the same exit.

So this launcher does exactly two things: it keeps the sensor's state on a
persistent path, and it makes enrolment idempotent so a restart resumes
the SAME endpoint identity instead of needing a human with a token.

Endpoint identity is unchanged by design: `endpoint_id` is minted by the
platform from `/etc/machine-id`, so re-enrolling this box resolves to the
same `ep_…` and the historical trajectory stays attached to it.

Nothing here fabricates telemetry. If enrolment cannot be completed the
launcher exits with a stated reason and the console keeps reporting
`BLIND_NO_DELIVERY` — which is the truth.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

SENSOR = Path("/app/agents/nivxforge-linux/nivxforge_sensor.py")
BACKEND_ENV = Path("/app/backend/.env")


def _env_file() -> dict[str, str]:
    out: dict[str, str] = {}
    if not BACKEND_ENV.exists():
        return out
    for line in BACKEND_ENV.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _post(url: str, body: dict, bearer: str | None = None) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 **({"Authorization": f"Bearer {bearer}"} if bearer else {})},
        method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def _enrol(api: str, tenant: str, state: Path, env: dict[str, str]) -> None:
    email = os.environ.get("NIVXFORGE_ENROL_EMAIL") or env.get("ADMIN_EMAIL")
    password = (os.environ.get("NIVXFORGE_ENROL_PASSWORD")
                or env.get("ADMIN_PASSWORD"))
    if not email or not password:
        sys.exit("cannot bootstrap enrolment: no operator credential is "
                 "configured (NIVXFORGE_ENROL_EMAIL/PASSWORD or "
                 "ADMIN_EMAIL/ADMIN_PASSWORD). Refusing to start; the "
                 "console will correctly report this endpoint as blind.")
    token = _post(f"{api}/api/auth/login",
                  {"email": email, "password": password}).get("access_token")
    if not token:
        sys.exit("operator login returned no access token; not enrolling")
    minted = _post(f"{api}/api/edr/enrollment/tokens",
                   {"label": "nivxforge-linux sensor · supervised",
                    "ttl_seconds": 600}, bearer=token)
    enrolment_token = (minted.get("enrollment_token")
                       or minted.get("token") or minted.get("plaintext"))
    if not enrolment_token:
        sys.exit(f"token mint returned no plaintext: {sorted(minted)}")
    os.execv(sys.executable,
             [sys.executable, str(SENSOR), "enrol", "--api", api,
              "--tenant", tenant, "--token", enrolment_token])


def main() -> None:
    env = _env_file()
    api = os.environ.get("NIVXFORGE_SENSOR_API", "http://localhost:8001")
    tenant = os.environ.get("NIVXFORGE_SENSOR_TENANT", "default")
    interval = os.environ.get("NIVXFORGE_SENSOR_INTERVAL", "15")
    watch = os.environ.get("NIVXFORGE_SENSOR_WATCH") or None
    state = Path(os.environ["NIVXFORGE_SENSOR_STATE"])
    state.mkdir(parents=True, exist_ok=True)
    if watch:
        Path(watch).mkdir(parents=True, exist_ok=True)

    if not (state / "identity.json").exists():
        print(f"[supervise] no credential at {state}/identity.json — "
              f"bootstrapping enrolment", flush=True)
        _enrol(api, tenant, state, env)   # exec's; does not return
        return

    ident = json.loads((state / "identity.json").read_text())
    print(f"[supervise] resuming endpoint_id={ident['endpoint_id']} "
          f"state={state} interval={interval}s", flush=True)
    argv = [sys.executable, str(SENSOR), "run", "--api", api,
            "--interval", str(interval)]
    if watch:
        argv += ["--watch", watch]
    os.execv(sys.executable, argv)


if __name__ == "__main__":
    try:
        main()
    except urllib.error.HTTPError as e:
        sys.exit(f"bootstrap HTTP {e.code}: {e.read().decode()[:300]}")
