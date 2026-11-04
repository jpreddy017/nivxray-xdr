#!/usr/bin/env python3
"""B5-GAP-1 CANARY · delivery-path impairment, ON THE CANARY HOST ONLY.

Scenarios BACKEND_SLOW, BACKEND_DOWN and NETWORK_INTERRUPTION need the
delivery path to be degraded WITHOUT changing the sensor, without changing
the backend, and without pointing the sensor at a non-production origin
(the installer's production-origin guard would refuse that, correctly).

So this is a transparent TCP relay. It forwards raw bytes to the real
production ingress, so TLS stays end-to-end between the sensor and the
platform: this process cannot read or alter any payload, and it holds no
credential. Only the TIMING and the REACHABILITY change.

Wiring, on the canary host only, reversible in one line:

    1. hosts file:   127.0.0.1   nivxray.nivxforge.com
    2. python b5gap1_canary_impair.py --upstream-ip <real A record> \
           --listen-port 443 --mode slow --delay-ms 750
    3. undo:         remove the hosts entry, stop this process

Modes:
    normal   forward immediately (control run through the same relay)
    slow     add --delay-ms latency to every forwarded chunk
    down     accept and immediately close  (BACKEND_DOWN)
    cut      accept, forward, then sever after --cut-after-bytes
             (NETWORK_INTERRUPTION mid-batch)

NEVER run this on DESKTOP-A9HGFJJ and never on a production host.
"""
from __future__ import annotations

import argparse
import socket
import threading
import time

BUFFER = 65536


def _pump(src: socket.socket, dst: socket.socket, delay_ms: float,
          cut_after: int | None) -> None:
    forwarded = 0
    try:
        while True:
            chunk = src.recv(BUFFER)
            if not chunk:
                break
            if delay_ms:
                time.sleep(delay_ms / 1000.0)
            dst.sendall(chunk)
            forwarded += len(chunk)
            if cut_after and forwarded >= cut_after:
                print(f"[impair] severing after {forwarded} bytes")
                break
    except OSError:
        pass
    finally:
        for sock in (src, dst):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()


def _serve(listen_host: str, listen_port: int, upstream: tuple[str, int],
           mode: str, delay_ms: float, cut_after: int | None) -> None:
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((listen_host, listen_port))
    server.listen(64)
    print(f"[impair] mode={mode} listening {listen_host}:{listen_port} -> "
          f"{upstream[0]}:{upstream[1]}")
    while True:
        client, peer = server.accept()
        if mode == "down":
            print(f"[impair] refusing {peer} (BACKEND_DOWN)")
            client.close()
            continue
        try:
            upstream_sock = socket.create_connection(upstream, timeout=30)
        except OSError as ex:
            print(f"[impair] upstream unreachable: {ex}")
            client.close()
            continue
        latency = delay_ms if mode == "slow" else 0.0
        limit = cut_after if mode == "cut" else None
        for a, b in ((client, upstream_sock), (upstream_sock, client)):
            threading.Thread(target=_pump, args=(a, b, latency, limit),
                             daemon=True).start()


def main() -> None:
    ap = argparse.ArgumentParser(prog="b5gap1_canary_impair")
    ap.add_argument("--upstream-ip", required=True,
                    help="real A record of the production ingress")
    ap.add_argument("--upstream-port", type=int, default=443)
    ap.add_argument("--listen-host", default="127.0.0.1")
    ap.add_argument("--listen-port", type=int, default=443)
    ap.add_argument("--mode", default="normal",
                    choices=("normal", "slow", "down", "cut"))
    ap.add_argument("--delay-ms", type=float, default=750.0)
    ap.add_argument("--cut-after-bytes", type=int, default=4096)
    args = ap.parse_args()
    _serve(args.listen_host, args.listen_port,
           (args.upstream_ip, args.upstream_port), args.mode,
           args.delay_ms, args.cut_after_bytes)


if __name__ == "__main__":
    main()
