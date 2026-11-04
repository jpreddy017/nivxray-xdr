"""Isolated Chromium acceptance against real app code and synthetic Sysmon data.

No production credentials/data, no running app edits, no public listener.
Requires the opt-in local Mongo tests and an already guarded frontend build.
"""
import argparse
import importlib.util
import json
import pathlib
import sys
import threading
import time
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-backend", required=True)
    parser.add_argument("--candidate-backend", required=True)
    parser.add_argument("--dist", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    base, candidate = pathlib.Path(args.base_backend), pathlib.Path(args.candidate_backend)
    output = pathlib.Path(args.output); output.mkdir(exist_ok=True, parents=True)
    sys.path.insert(0, str(base))
    import os
    os.environ["NIVX_FILES_MONGO_INTEGRATION"] = "1"
    import services.edr, routers
    services.edr.__path__.insert(0, str(candidate / "services/edr"))
    routers.__path__.insert(0, str(candidate / "routers"))
    spec = importlib.util.spec_from_file_location("file_browser_auth_fixture", candidate / "tests/edr/test_endpoint_file_authorization.py")
    fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
    owner = fixture.FileAuthorizationTests
    owner.setUpClass()
    api_server = static_server = None
    try:
        fixture_case = owner("test_no_authentication_is_refused")
        fixture_case.setUp()
        from routers import auth, xdr_rbac, edr_onboarding
        from fastapi.middleware.cors import CORSMiddleware
        owner.app.include_router(auth.router, prefix="/api")
        owner.app.include_router(xdr_rbac.router)
        owner.app.include_router(edr_onboarding.router, prefix="/api")
        owner.app.add_middleware(CORSMiddleware, allow_origins=["http://127.0.0.1:8311"],
                                 allow_methods=["GET", "POST", "OPTIONS"], allow_headers=["Authorization", "Content-Type", "X-Tenant-Id"])
        password = "Synthetic-browser-test-only-8311"
        owner.database.users.update_one({"email": "files-a@example.invalid"},
            {"$set": {"email": "files-a@example.com", "password": owner.deps.hash_password(password)}})

        # Simulated source XML traverses the actual bridge and observation
        # adapter. This is NOT proof of a live Windows sensor acquisition.
        from tests.edr import fixtures_windows_eventlog as fx
        from edr_plane import canonical_bridge
        from v2.ingestion.telemetry_bridge import observation_doc
        owner.database.v2_shadow_observations.delete_many({"tenant_id": "ten_files_a"})
        observations = []
        for i in range(120):
            event = fx.sysmon(11, 9000 + i, {
                "UtcTime": "2026-09-02 10:00:00.000",
                "ProcessGuid": "{aaaaaaaa-1111-2222-3333-444444444444}",
                "ProcessId": "2000", "Image": "C:\\Windows\\System32\\cmd.exe",
                "TargetFilename": f"C:\\test-fixture\\file-{i:03d}.dll",
                "CreationUtcTime": "2026-09-02 10:00:00.000"})
            canonical = canonical_bridge.parse(event)
            canonical["host"] = {"host_id": "ep_files_a", "hostname": "FILES-A"}
            canonical["additional_fields"]["endpoint_id"] = "ep_files_a"
            canonical["event_id"] = canonical_bridge.canonical_event_id(f"TEST_FIXTURE_{i}", 0)
            canonical_bridge.bind_process_identity(canonical, "ep_files_a")
            record = observation_doc(canonical, envelope={
                "connector_id": "ep_files_a", "collector_id": "ep_files_a",
                "source": "TEST_FIXTURE_NOT_LIVE", "collection_method": "WINDOWS_EVENT_LOG",
                "parser_version": "1.0.0", "source_event_id": f"TEST_FIXTURE_{i}",
                "collection_timestamp": "2026-09-02T10:00:00Z"}, tenant_id="ten_files_a")
            observations.append(record)
        owner.database.v2_shadow_observations.insert_many(observations)
        owner.database.edr_endpoints.update_one({"endpoint_id": "ep_files_a"},
            {"$set": {"device_iid": observations[0]["event"]["device_iid"], "hostname": "FILES-A"}})

        import uvicorn
        api_server = uvicorn.Server(uvicorn.Config(owner.app, host="127.0.0.1", port=8312,
                                                  log_level="warning", access_log=False))
        api_thread = threading.Thread(target=api_server.run, daemon=True); api_thread.start()

        class SPA(SimpleHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                if not pathlib.Path(self.translate_path(self.path)).is_file():
                    self.path = "/index.html"
                return super().do_GET()

        static_server = ThreadingHTTPServer(("127.0.0.1", 8311), partial(SPA, directory=args.dist))
        threading.Thread(target=static_server.serve_forever, daemon=True).start()
        deadline = time.monotonic() + 15
        while not api_server.started and time.monotonic() < deadline:
            time.sleep(.1)
        assert api_server.started, "isolated API did not start"

        from playwright.sync_api import sync_playwright, expect
        checks, errors = [], []
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path="/usr/bin/chromium", headless=True,
                                                   args=["--no-sandbox"])
            context = browser.new_context(viewport={"width": 1440, "height": 1050})

            def proxy(route):
                parsed = urlsplit(route.request.url)
                if parsed.hostname == "greeting-app-5782.preview.emergentagent.com" and parsed.path.startswith("/api/"):
                    response = route.fetch(url="http://127.0.0.1:8312" + parsed.path + ("?" + parsed.query if parsed.query else ""))
                    route.fulfill(response=response)
                elif parsed.hostname == "127.0.0.1":
                    route.continue_()
                else:
                    route.abort()

            context.route("**/*", proxy)
            page = context.new_page()
            page.on("pageerror", lambda e: errors.append(str(e)))
            network = []
            page.on("response", lambda r: network.append({"path": urlsplit(r.url).path, "status": r.status}) if "/api/" in r.url else None)
            page.goto("http://127.0.0.1:8311/edr/login")
            page.locator('input[type="email"]').fill("files-a@example.com")
            page.locator('input[type="password"]').fill(password)
            page.get_by_role("button", name="Sign in", exact=True).click()
            try:
                page.wait_for_url("**/edr", timeout=15000)
            except Exception:
                page.screenshot(path=str(output / "login-failure.png"))
                print(json.dumps({"login_url": page.url, "visible_text": page.locator("body").inner_text()[:1400], "network": network}))
                raise
            page.goto("http://127.0.0.1:8311/edr/files?device=ep_files_a&t0=1788220800000&t1=1790812800000")
            try:
                page.get_by_test_id("edr-file-evidence").wait_for(state="visible", timeout=5000)
            except Exception:
                page.screenshot(path=str(output / "files-entry-failure.png"))
                print(json.dumps({"files_url": page.url, "visible_text": page.locator("body").inner_text()[:2000], "network": network, "errors": errors}))
                raise
            page.get_by_role("button", name="Search observations", exact=True).click()
            expect(page.get_by_text("100 observations loaded", exact=False)).to_be_visible(timeout=15000)
            checks.append("real login and source XML→bridge→Mongo→API→UI, first100")
            page.get_by_role("button", name="Inspect file-119.dll", exact=True).click()
            expect(page.get_by_role("complementary", name="Selected file observation")).to_be_visible()
            page.get_by_role("button", name="Continue scanning", exact=True).click()
            expect(page.get_by_text("120 observations loaded", exact=False)).to_be_visible()
            expect(page.get_by_role("complementary", name="Selected file observation")).to_be_visible()
            checks.append("pagination120 and selected observation preserved")
            page.get_by_role("heading", name="File Trajectory", exact=True).scroll_into_view_if_needed()
            page.screenshot(path=str(output / "files-light.png"), full_page=False)
            page.get_by_test_id("nvf-theme-toggle").click()
            page.screenshot(path=str(output / "files-dark.png"), full_page=False)
            checks.append("light and dark rendered")
            page.set_viewport_size({"width": 390, "height": 844})
            page.get_by_role("heading", name="File Trajectory", exact=True).scroll_into_view_if_needed()
            page.screenshot(path=str(output / "files-mobile.png"), full_page=False)
            checks.append("390px viewport rendered")
            page.set_viewport_size({"width": 1440, "height": 1050})
            page.get_by_role("link", name="Open Device Trajectory in this window").click()
            expect(page).to_have_url("http://127.0.0.1:8311/edr/computers/ep_files_a/trajectory?t0=1788220800000&t1=1790812800000")
            page.get_by_test_id("edr-device-tab-files").click()
            expect(page.get_by_test_id("edr-file-evidence")).to_be_visible()
            checks.append("device and standalone paths and preserved window")
            # Drain pending proxy callbacks before their API context is disposed.
            page.goto("about:blank")
            context.unroute_all(behavior="wait")
            context.close()
            browser.close()
        result = {"evidence_type": "SYNTHETIC_NOT_LIVE_SENSOR", "checks": checks,
                  "page_errors": errors, "source_xml_observations": 120,
                  "production_modified": False}
        (output / "browser-result.json").write_text(json.dumps(result, indent=2))
        print(json.dumps(result, indent=2))
        assert not errors, "browser page errors occurred"
    finally:
        if api_server:
            api_server.should_exit = True
            api_thread.join(timeout=10)
        if static_server:
            static_server.shutdown()
            static_server.server_close()
        owner.tearDownClass()


if __name__ == "__main__":
    main()

