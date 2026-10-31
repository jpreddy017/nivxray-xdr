"""Deep-link resolver regression through the REAL HTTP layer (running preview backend), URL-encoded '#'."""
import os
from urllib.parse import quote

import httpx
import pytest

BASE = os.environ.get("E3_PREVIEW_HTTP", "http://localhost:8001")
DEV = "dev_f22d20b97b6d"


def _get(path, **params):
    try:
        return httpx.get(f"{BASE}{path}", params=params, timeout=60)
    except httpx.HTTPError as e:  # pragma: no cover
        pytest.skip(f"preview backend not reachable: {e}")


@pytest.fixture(scope="module")
def cases():
    r = _get("/api/e3/preview/deeplink-cases")
    if r.status_code == 404:
        pytest.skip("preview adapter not mounted")
    return r.json()


@pytest.mark.parametrize("name", ["newest", "deep_historical", "late_arrived"])
@pytest.mark.parametrize("param", ["event", "event_iid"])
def test_focus_resolves_url_encoded(cases, name, param):
    eid = cases[name]
    assert eid and "#" in eid
    url = f"{BASE}/api/edr/endpoints/{DEV}/trajectory/focus?{param}={quote(eid, safe='')}"
    assert "%23" in url
    body = httpx.get(url, timeout=60).json()
    assert body["state"] == "FOCUS_RESOLVED", body
    assert body["focus"]["event_iid"] == eid
    w = body["focus"]["window"]
    page = _get(f"/api/edr/endpoints/{DEV}/trajectory", time_start=w["time_start"], time_end=w["time_end"],
                lane_start=0, lane_end=100000, limit=500).json()
    assert eid in {e["event_iid"] for e in page["events"]}, "focus window must contain the event"


def test_focus_by_bare_observation_id(cases):
    obs = cases["newest"].split("#")[0]
    body = _get(f"/api/edr/endpoints/{DEV}/trajectory/focus", event=obs).json()
    assert body["state"] == "FOCUS_RESOLVED" and body["focus"]["event_iid"] == cases["newest"]


def test_double_encoded_hash_still_resolves(cases):
    eid = cases["deep_historical"]
    url = f"{BASE}/api/edr/endpoints/{DEV}/trajectory/focus?event={quote(quote(eid, safe=''), safe='')}"
    assert httpx.get(url, timeout=60).json()["state"] == "FOCUS_RESOLVED"


def test_nonexistent_is_truthful(cases):
    url = f"{BASE}/api/edr/endpoints/{DEV}/trajectory/focus?event={quote(cases['nonexistent'], safe='')}"
    assert httpx.get(url, timeout=60).json()["state"] == "OBSERVATION_NOT_RESOLVED"
