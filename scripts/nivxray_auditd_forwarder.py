#!/usr/bin/env python3
"""NivXRay XDR · Linux auditd → XDR ingest forwarder.

Host-side SHIPPER only. It is NOT a second ingestion implementation: it does
no parsing, no normalization, no detection and no verdict. It reads verbatim
auditd lines and posts them to the ONE authoritative endpoint,
``POST /api/xdr/ingest/telemetry``, using the documented envelope contract
(``apps/nivxray-xdr-collector/INGEST_CONTRACT.md`` §2.1). Every downstream
decision stays in the core (DSM → parser → normalizer → canonical evidence →
detection → IUE → ICE → VEEE → gated incident).

Standard library only — no pip install on the monitored host.

Configuration (environment, no defaults for the required ones):
    NIVX_INGEST_URL     e.g. https://nivxray.nivxforge.com/api/xdr/ingest/telemetry
    NIVX_XDR_API_KEY    nvx_<48 hex>   (scope: collectors.enroll)
    NIVX_TENANT_ID      e.g. nivx-prod-1
    NIVX_COLLECTOR_ID   col_<...>      (created by the platform operator)
    NIVX_AUDIT_LOG      default /var/log/audit/audit.log
    NIVX_STATE_FILE     default /var/lib/nivxray/auditd_forwarder.offset
    NIVX_BATCH_MAX      default 50
    NIVX_SOURCE         default the host's FQDN

Modes:
    --preflight   auth + reachability only. Sends NO telemetry.
    --dry-run     read real lines, build real envelopes, print them, send nothing.
    --once        send one batch, then exit. Use this for the first proof.
    --follow      keep tailing (long-running).
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import urllib.error
import urllib.request

AUDIT_MARKERS = ("type=EXECVE", "type=SYSCALL", "type=PROCTITLE")


def env(name: str, default: str | None = None, *, required: bool = False) -> str:
    v = os.environ.get(name, default)
    if required and not v:
        sys.exit(f"FATAL: {name} is required and not set")
    return v or ""


class Config:
    def __init__(self) -> None:
        self.url = env("NIVX_INGEST_URL", required=True)
        self.key = env("NIVX_XDR_API_KEY", required=True)
        self.tenant = env("NIVX_TENANT_ID", required=True)
        self.collector = env("NIVX_COLLECTOR_ID", required=True)
        self.audit_log = env("NIVX_AUDIT_LOG", "/var/log/audit/audit.log")
        self.state = env("NIVX_STATE_FILE",
                         "/var/lib/nivxray/auditd_forwarder.offset")
        self.batch_max = int(env("NIVX_BATCH_MAX", "50"))
        self.source = env("NIVX_SOURCE", socket.getfqdn())

    def headers(self) -> dict[str, str]:
        return {"X-XDR-API-Key": self.key, "X-Tenant-Id": self.tenant,
                "Content-Type": "application/json",
                "User-Agent": "nivxray-auditd-forwarder/1.0"}


def post(cfg: Config, payload: dict) -> tuple[int, str]:
    req = urllib.request.Request(cfg.url, method="POST",
                                 data=json.dumps(payload).encode(),
                                 headers=cfg.headers())
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:                                        # noqa: BLE001
        return 0, f"{type(e).__name__}: {e}"


def audit_id(line: str) -> str | None:
    """The auditd event identity `audit(<epoch>:<serial>)` — used verbatim as
    `source_event_id` so the platform's exactly-once claim recognises a retry."""
    if "audit(" not in line:
        return None
    inner = line.split("audit(", 1)[1].split(")", 1)[0]
    return inner or None


def envelope(cfg: Config, line: str) -> dict:
    aid = audit_id(line)
    return {
        "tenant_id": cfg.tenant,
        "collector_id": cfg.collector,
        "collection_method": "syslog",
        "source": cfg.source,
        "connector_id": f"auditd@{cfg.source}",
        "event_type": "process_creation",
        "source_event_id": f"auditd:{aid}" if aid else None,
        "parser_version": "auditd-raw",
        # The verbatim line is the ONLY authority. `message` is what the core's
        # linux-auditd parser reads; nothing is pre-parsed or invented here.
        "raw": {"message": line.rstrip("\n"), "payload_format": "auditd"},
    }


def read_offset(path: str) -> int:
    try:
        with open(path) as f:
            return int(f.read().strip() or 0)
    except Exception:                                             # noqa: BLE001
        return 0


def write_offset(path: str, offset: int) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(offset))
    os.replace(tmp, path)


def collect(cfg: Config, offset: int) -> tuple[list[str], int]:
    if not os.path.exists(cfg.audit_log):
        sys.exit(f"FATAL: {cfg.audit_log} not found — is auditd installed "
                 f"and running? (systemctl status auditd)")
    lines: list[str] = []
    with open(cfg.audit_log, errors="replace") as f:
        size = os.fstat(f.fileno()).st_size
        if offset > size:
            offset = 0                     # log rotated
        f.seek(offset)
        # readline() rather than `for line in f`: iteration enables read-ahead
        # buffering, which makes f.tell() raise
        # "OSError: telling position disabled by next() call" — and the offset
        # is what guarantees we never re-send a line.
        while len(lines) < cfg.batch_max:
            line = f.readline()
            if not line:
                break
            if not line.endswith("\n"):
                break                      # partial write; re-read next run
            offset = f.tell()
            if any(m in line for m in AUDIT_MARKERS):
                lines.append(line)
    return lines, offset


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--preflight", action="store_true")
    g.add_argument("--dry-run", action="store_true")
    g.add_argument("--once", action="store_true")
    g.add_argument("--follow", action="store_true")
    args = ap.parse_args()
    cfg = Config()

    print(f"ingest    : {cfg.url}")
    print(f"tenant    : {cfg.tenant}")
    print(f"collector : {cfg.collector}")
    print(f"source    : {cfg.source}")
    print(f"audit log : {cfg.audit_log}")
    print(f"key       : {cfg.key[:12]}… (never printed in full)")

    if args.preflight:
        # Stage 1 — an EMPTY batch is refused by the handler with 400
        # "empty batch", which only happens AFTER auth, the rate limiter and
        # the tenant guard have all passed. So 400 is the success signal and
        # no telemetry is written. 401/403/429/503 each name the exact failure.
        status, body = post(cfg, {"envelopes": []})
        print(f"\n[1/2] credential HTTP {status}: {body[:400]}")
        if not (status == 400 and "empty batch" in body):
            print("PREFLIGHT FAIL — fix the reported reason before sending "
                  "telemetry. 401=key unknown/malformed · 403=scope, tenant "
                  "or revocation · 429=rate limited · 503=store unavailable.")
            return 1

        # Stage 2 — read-only confirmation that the collector exists in THIS
        # tenant. Needs the key's `collectors.read` scope. Still no write.
        base = cfg.url.split("/api/xdr/ingest/")[0]
        req = urllib.request.Request(
            f"{base}/api/xdr/collectors/{cfg.collector}", headers=cfg.headers())
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                doc = json.loads(r.read()).get("data") or {}
            print(f"[2/2] collector HTTP 200: name={doc.get('name')!r} "
                  f"protocol={doc.get('protocol')} state={doc.get('state')} "
                  f"tenant={doc.get('tenant_id')} "
                  f"events_received={doc.get('events_received')}")
            if doc.get("tenant_id") != cfg.tenant:
                print("PREFLIGHT FAIL — collector belongs to another tenant.")
                return 1
        except urllib.error.HTTPError as e:
            print(f"[2/2] collector HTTP {e.code}: {e.read().decode()[:300]}")
            print("PREFLIGHT FAIL — collector not visible to this credential "
                  "(404=wrong id/tenant, 403=missing collectors.read scope).")
            return 1

        print("PREFLIGHT PASS — credential, tenant, scope, rate limiter and "
              "collector identity all confirmed. No telemetry sent.")
        return 0

    offset = read_offset(cfg.state)
    lines, new_offset = collect(cfg, offset)
    print(f"\nauditd lines collected: {len(lines)} (offset {offset} → {new_offset})")
    if not lines:
        print("Nothing new to send. Generate real activity on this host, or "
              "confirm the execve audit rule is loaded: auditctl -l")
        return 0

    envelopes = [envelope(cfg, ln) for ln in lines]
    if args.dry_run:
        print(json.dumps({"envelopes": envelopes[:3]}, indent=2))
        print(f"\nDRY RUN — {len(envelopes)} envelope(s) built, none sent. "
              f"Offset NOT advanced.")
        return 0

    status, body = post(cfg, {"envelopes": envelopes})
    print(f"ingest HTTP {status}: {body[:1200]}")
    if status != 200:
        print("Offset NOT advanced — the same lines will be retried, and the "
              "platform's exactly-once claim prevents duplicates.")
        return 1
    write_offset(cfg.state, new_offset)
    if args.follow:
        print("NOTE: --follow sends one batch per invocation in this version; "
              "schedule it (systemd timer / cron) or use the collector runtime "
              "in apps/nivxray-xdr-collector for a long-lived process.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
