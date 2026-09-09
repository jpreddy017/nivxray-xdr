#!/usr/bin/env python3
"""Serve /app/frontend/build with the same SPA fallback Vercel applies.

Used to validate scripts/workspace_live_acceptance.py before
workspace.nivxmachines.com exists. Not part of the deployment.
"""
import functools
import http.server
import os
import socketserver
import sys

BUILD = "/app/frontend/build"


class SPAHandler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        p = super().translate_path(path)
        if os.path.isdir(p) or os.path.exists(p):
            return p
        return os.path.join(BUILD, "index.html")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9096
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(
            ("127.0.0.1", port),
            functools.partial(SPAHandler, directory=BUILD)) as httpd:
        print(f"serving {BUILD} with SPA fallback on http://127.0.0.1:{port}")
        httpd.serve_forever()
