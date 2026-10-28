#!/usr/bin/env python3
"""Read-only HTTPS G4 backend acceptance. Never enrolls a sensor."""
from __future__ import annotations

import argparse
import json
import ssl
import sys
import urllib.request

from entrypoint import ConfigurationRefused, _hostname

REQUIRED = {
    ("post", "/api/edr/agent/enroll"),
    ("post", "/api/edr/agent/session"),
    ("post", "/api/edr/agent/telemetry"),
    ("post", "/api/edr/agent/telemetry/batch"),
    ("post", "/api/edr/agent/heartbeat"),
    ("get", "/api/edr/agent/policy"),
    ("post", "/api/edr/agent/acquisition-integrity"),
}


def get_json(url: str, timeout: float) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "NivXForge-G4-ReadOnly-Preflight/1"})
    with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as res:
        if res.status != 200:
            raise RuntimeError("NON_200_READ_ONLY_RESPONSE")
        body = res.read(1024 * 1024 + 1)
        if len(body) > 1024 * 1024:
            raise RuntimeError("RESPONSE_OVERSIZE")
        result = json.loads(body)
        if not isinstance(result, dict):
            raise RuntimeError("RESPONSE_NOT_OBJECT")
        return result


def check(origin: str, timeout: float) -> list[str]:
    _hostname(origin, must_be_public=True)
    base = origin.rstrip("/")
    problems = []
    try:
        live = get_json(base + "/api/health", timeout)
        if live.get("status") != "ok":
            problems.append("LIVENESS_NOT_OK")
    except Exception:
        problems.append("LIVENESS_FAILED")
    try:
        deep = get_json(base + "/api/health/deep", timeout)
        if deep.get("status") != "ok" or deep.get("checks", {}).get("mongo") != "ok":
            problems.append("DEEP_READINESS_NOT_OK")
    except Exception:
        problems.append("DEEP_READINESS_FAILED")
    try:
        spec = get_json(base + "/openapi.json", timeout)
        declared = {(method.lower(), path) for path, operations in spec.get("paths", {}).items()
                    if isinstance(operations, dict) for method in operations}
        if REQUIRED - declared:
            problems.append("AGENT_ENDPOINT_CONTRACT_INCOMPLETE")
    except Exception:
        problems.append("AGENT_ENDPOINT_CONTRACT_UNVERIFIABLE")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only live G4 backend check; no enrollment")
    parser.add_argument("--origin", required=True)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()
    try:
        issues = check(args.origin, args.timeout)
    except ConfigurationRefused:
        print("G4_PREFLIGHT_BLOCKED: invalid or forbidden origin")
        return 2
    if issues:
        print("G4_PREFLIGHT_BLOCKED: " + ", ".join(sorted(issues)))
        return 1
    print("G4_PREFLIGHT_PASS: HTTPS liveness, Mongo readiness, and 7 agent routes")
    print("No enrollment token consumed and no endpoint or database mutation requested")
    return 0


if __name__ == "__main__":
    sys.exit(main())
