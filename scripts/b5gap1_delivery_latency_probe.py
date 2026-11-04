#!/usr/bin/env python3
"""GATE B · transport latency decomposition for sensor telemetry delivery.

MEASURES, does not assume. Runs against the PREVIEW ingress and against the
backend loopback, so ingress/TLS/network cost can be separated from backend
processing and database persistence.

It is deliberately read-mostly: it enrols ONE synthetic test endpoint in the
preview database and posts synthetic payloads. No production endpoint, no
production database, no real sensor is touched.
"""
from __future__ import annotations

import http.client
import json
import os
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = os.environ["PROBE_API"].rstrip("/")
LOOPBACK = os.environ.get("PROBE_LOOPBACK", "http://localhost:8001")
EMAIL = os.environ["PROBE_EMAIL"]
PASSWORD = os.environ["PROBE_PASSWORD"]
TENANT = os.environ["PROBE_TENANT"]
N = int(os.environ.get("PROBE_N", "30"))


def post(url: str, path: str, body: dict, bearer: str | None = None,
         extra: dict | None = None) -> dict:
    req = urllib.request.Request(
        f"{url}{path}", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 "User-Agent": "NivXForge-EDR-Probe/1.0",
                 **(extra or {}),
                 **({"Authorization": f"Bearer {bearer}"} if bearer else {})},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{path} -> {e.code} {e.read().decode()[:300]}")


def payload(record_id: int) -> str:
    xml = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/"
           "event'><System><Provider Name='Microsoft-Windows-Sysmon' "
           "Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>1"
           "</EventID><TimeCreated SystemTime='2026-06-01T10:04:00.0Z'/>"
           f"<EventRecordID>{record_id}</EventRecordID><Channel>"
           "Microsoft-Windows-Sysmon/Operational</Channel><Computer>"
           "NIVX-PROBE</Computer></System><EventData>"
           "<Data Name='ProcessGuid'>{aaaaaaaa-0000-0000-0000-"
           f"{record_id:012d}}}</Data>"
           f"<Data Name='ProcessId'>{record_id}</Data>"
           "<Data Name='Image'>C:\\Windows\\System32\\probe.exe</Data>"
           "<Data Name='UtcTime'>2026-06-01 10:04:00.000</Data>"
           "</EventData></Event>")
    return json.dumps({"observed_at": "2026-06-01T10:05:00+00:00",
                       "kind": "WINDOWS_EVENT_LOG",
                       "winlog": {"channel": "Microsoft-Windows-Sysmon/"
                                             "Operational",
                                  "record_id": record_id, "event_id": "1",
                                  "provider": "Microsoft-Windows-Sysmon",
                                  "computer": "NIVX-PROBE",
                                  "time_created": "2026-06-01T10:04:00Z",
                                  "xml": xml}},
                      separators=(",", ":"))


def timed_new_connection(base: str, token: str, start: int, count: int):
    """One fresh connection per POST — exactly what the sensor does today
    (`urllib.request.urlopen` per event, no pooling)."""
    samples = []
    for i in range(count):
        t0 = time.perf_counter()
        post(base, "/api/edr/agent/telemetry",
             {"payload": payload(start + i), "source_kind": "sensor",
              "sensor_version": "probe"}, bearer=token)
        samples.append(time.perf_counter() - t0)
    return samples


def timed_keepalive(base: str, token: str, start: int, count: int):
    """One persistent connection, reused. Isolates the per-request cost of
    DNS + TCP + TLS from the cost of the request itself."""
    parsed = urllib.parse.urlparse(base)
    conn_cls = (http.client.HTTPSConnection if parsed.scheme == "https"
                else http.client.HTTPConnection)
    conn = conn_cls(parsed.netloc, timeout=60)
    handshake_t0 = time.perf_counter()
    conn.connect()
    handshake = time.perf_counter() - handshake_t0
    samples = []
    for i in range(count):
        t0 = time.perf_counter()
        conn.request("POST", "/api/edr/agent/telemetry",
                     body=json.dumps({"payload": payload(start + i),
                                      "source_kind": "sensor",
                                      "sensor_version": "probe"}),
                     headers={"Content-Type": "application/json",
                              "Authorization": f"Bearer {token}",
                              "User-Agent": "NivXForge-EDR-Probe/1.0"})
        resp = conn.getresponse()
        resp.read()
        samples.append(time.perf_counter() - t0)
        if resp.status >= 300:
            raise RuntimeError(f"{resp.status}")
    conn.close()
    return handshake, samples


def stats(name: str, samples: list[float]) -> dict:
    return {"probe": name, "n": len(samples),
            "mean_s": round(statistics.mean(samples), 4),
            "median_s": round(statistics.median(samples), 4),
            "p95_s": round(sorted(samples)[int(len(samples) * 0.95) - 1], 4),
            "min_s": round(min(samples), 4), "max_s": round(max(samples), 4),
            "events_per_sec": round(1.0 / statistics.mean(samples), 2)}


def main() -> int:
    out: dict = {"api": API, "loopback": LOOPBACK, "n_per_probe": N}
    token = post(API, "/api/auth/login",
                 {"email": EMAIL, "password": PASSWORD})
    jwt = token.get("access_token") or token.get("token")
    minted = post(API, "/api/edr/enrollment/tokens",
                  {"label": "b5gap1-delivery-probe", "ttl_seconds": 3600},
                  bearer=jwt, extra={"X-Tenant-Id": TENANT})
    enrol = post(API, "/api/edr/agent/enroll",
                 {"tenant_id": TENANT,
                  "enrollment_token": minted["enrollment_token"],
                  "sensor_version": "probe",
                  "machine_guid": "b5gap1-delivery-probe",
                  "hostname": "NIVX-PROBE", "platform": "WINDOWS"})
    out["endpoint_id"] = enrol["endpoint_id"]

    session = post(API, "/api/edr/agent/session",
                   {"tenant_id": TENANT,
                    "agent_credential": enrol["agent_credential"]})
    ingress_token = session["session_token"]

    base_record = int(time.time()) % 1_000_000 * 100
    out["A_ingress_new_connection_per_post"] = stats(
        "ingress · fresh connection per POST (today's sensor)",
        timed_new_connection(API, ingress_token, base_record, N))
    handshake, samples = timed_keepalive(API, ingress_token,
                                         base_record + 1000, N)
    out["B_ingress_keepalive"] = stats(
        "ingress · one persistent connection", samples)
    out["B_ingress_handshake_s"] = round(handshake, 4)

    def timed_batch(base, token, start, batch, rounds):
        parsed = urllib.parse.urlparse(base)
        cls = (http.client.HTTPSConnection if parsed.scheme == "https"
               else http.client.HTTPConnection)
        conn = cls(parsed.netloc, timeout=120)
        conn.connect()
        samples, accepted = [], 0
        rec = start
        for _ in range(rounds):
            events = [{"payload": payload(rec + i)} for i in range(batch)]
            rec += batch
            body = json.dumps({"events": events, "source_kind": "sensor",
                               "sensor_version": "probe"})
            t0 = time.perf_counter()
            conn.request("POST", "/api/edr/agent/telemetry/batch", body=body,
                         headers={"Content-Type": "application/json",
                                  "Authorization": f"Bearer {token}",
                                  "User-Agent": "NivXForge-EDR-Probe/1.0"})
            resp = conn.getresponse()
            data = json.loads(resp.read())
            samples.append(time.perf_counter() - t0)
            if resp.status >= 300:
                raise RuntimeError(f"{resp.status} {data}")
            accepted += data["accepted"]
        conn.close()
        total = sum(samples)
        return {"probe": f"ingress · batch of {batch}", "rounds": rounds,
                "batch": batch, "events": batch * rounds,
                "accepted": accepted,
                "mean_request_s": round(statistics.mean(samples), 4),
                "total_s": round(total, 4),
                "events_per_sec": round(batch * rounds / total, 1)}

    for size in (10, 50, 100):
        out[f"D_ingress_batch_{size}"] = timed_batch(
            API, ingress_token, base_record + 10000 * size, size, 5)

    try:
        loop_session = post(LOOPBACK, "/api/edr/agent/session",
                            {"tenant_id": TENANT,
                             "agent_credential": enrol["agent_credential"]})
        loop_token = loop_session["session_token"]
        lh, lsamples = timed_keepalive(LOOPBACK, loop_token,
                                       base_record + 2000, N)
        out["C_loopback_keepalive"] = stats(
            "loopback · one persistent connection (backend + DB only)",
            lsamples)
        out["C_loopback_handshake_s"] = round(lh, 4)
    except (urllib.error.URLError, RuntimeError, OSError) as ex:
        out["C_loopback_keepalive"] = {"error": str(ex)[:200]}

    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
