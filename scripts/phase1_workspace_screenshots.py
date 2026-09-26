"""
Phase 1 · evidence screenshots of the CLEANED Workspace on real surfaces.

Deliberately captures the product pages, not the flag-gated /v2/* shadow
route (a previous capture landed there and read as a blank page).
Served from the preview-backed build of the same cleaned source, signed in
with real credentials.
"""
import functools
import http.server
import os
import socketserver
import threading

BUILD = "/tmp/ws_preview_build"
PORT = 9097
BASE = f"http://127.0.0.1:{PORT}"
EMAIL = "admin@nivxray.com"
PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"

SHOTS = [
    ("/", "workspace_home"),
    ("/history", "history"),
    ("/heatmap", "heatmap"),
    ("/investigations", "retained_investigations_deeplink"),
]


class SPAHandler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        p = super().translate_path(path)
        if os.path.isdir(p) or os.path.exists(p):
            return p
        return os.path.join(BUILD, "index.html")

    def log_message(self, *a):
        pass


def main():
    from playwright.sync_api import sync_playwright

    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(
        ("127.0.0.1", PORT), functools.partial(SPAHandler, directory=BUILD))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    with sync_playwright() as p:
        b = p.chromium.launch()
        page = b.new_page(viewport={"width": 1600, "height": 900})
        page.goto(f"{BASE}/login", wait_until="networkidle")
        page.fill('[data-testid="login-email-input"]', EMAIL)
        page.fill('[data-testid="login-password-input"]', PASSWORD)
        page.click('[data-testid="login-submit-btn"]')
        page.wait_for_url(f"{BASE}/", timeout=30000)
        page.wait_for_timeout(3000)

        for path, name in SHOTS:
            page.goto(f"{BASE}{path}", wait_until="networkidle")
            page.wait_for_timeout(2600)
            out = f"/app/memory/phase1_ws_{name}.png"
            page.screenshot(path=out, full_page=False)
            print(f"captured {path} -> {out}")
        b.close()

    httpd.shutdown()


if __name__ == "__main__":
    main()
