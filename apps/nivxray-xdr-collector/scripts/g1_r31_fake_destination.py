#!/usr/bin/env python3
"""G1-R3.1 · Scratch acceptance destination — a controllable fake ingest.

A real HTTP server, so the scratch acceptance exercises the real
`IngestClient`, real sockets, the real wall clock and real OS process
boundaries. It is NOT the NivXRay ingest and must never be pointed at one.

Availability is controlled by a FLAG FILE, so the operator can take the
destination down and bring it back without killing the process:

    UP      : flag file absent        -> HTTP 200 + X-Request-ID
    DOWN    : flag file present       -> HTTP 503 + X-Request-ID
    EDGE404 : flag file contains 404  -> HTTP 404 WITHOUT attribution
              (the exact G1 failure: an unattributed edge 404)

Usage:
    python scripts/g1_r31_fake_destination.py --port 8099 \
        --flag /tmp/r31-scratch/destination.flag
"""
from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FLAG = "/tmp/r31-scratch/destination.flag"
ACCEPTED: list[str] = []


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):                      # noqa: A003
        print(f"[destination] {fmt % args}", flush=True)

    def _mode(self) -> str:
        if not os.path.exists(FLAG):
            return "UP"
        try:
            with open(FLAG, "r", encoding="utf-8") as fh:
                body = fh.read().strip()
        except OSError:
            return "DOWN"
        return "EDGE404" if "404" in body else "DOWN"

    def do_POST(self) -> None:                              # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        mode = self._mode()

        if mode == "UP":
            try:
                envs = (json.loads(raw.decode() or "{}").get("envelopes")
                        or [])
            except json.JSONDecodeError:
                envs = []
            for e in envs:
                ACCEPTED.append(str(e.get("source_event_id")))
            payload = json.dumps({"accepted": len(envs),
                                  "total_accepted": len(ACCEPTED)}).encode()
            self.send_response(200)
            self.send_header("X-Request-ID", "r31-scratch-up")
        elif mode == "EDGE404":
            payload = b"<html>404 not found</html>"
            self.send_response(404)                 # NO attribution header
            self.send_header("Content-Type", "text/html")
        else:
            payload = b"destination unavailable"
            self.send_response(503)
            self.send_header("X-Request-ID", "r31-scratch-down")

        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:                               # noqa: N802
        payload = json.dumps({"mode": self._mode(),
                              "accepted": len(ACCEPTED),
                              "unique_accepted": len(set(ACCEPTED))}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main() -> None:
    global FLAG
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--flag", default=FLAG)
    args = ap.parse_args()
    FLAG = args.flag
    print(f"[destination] listening on 127.0.0.1:{args.port} · flag={FLAG}",
          flush=True)
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
