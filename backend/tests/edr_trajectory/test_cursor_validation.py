"""Client-supplied cursor boundaries fail closed before evidence comparison."""
import base64
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from edr_trajectory.api import build_router
from edr_trajectory.paging import BadCursor, page_newest_first


def encode(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode()


@pytest.mark.parametrize("value", [
    [], None, {"t": 1}, {"t": True, "id": "e"},
    {"t": "1", "id": "e"}, {"t": 1.5, "id": "e"},
    {"t": 1, "id": None}, {"t": 1, "id": ""},
    {"t": 1, "id": "e", "as_of": "2"},
    {"t": 1, "id": "e", "as_of": True},
    {"t": 1, "id": "e", "as_of": []},
])
def test_invalid_cursor_is_bad_cursor_even_with_no_evidence(value):
    with pytest.raises(BadCursor):
        page_newest_first([], cursor=encode(value))


def test_generated_cursor_preserves_snapshot_and_equal_time_boundary():
    events = [{"event_id": name, "observed_ms": 10, "ingested_ms": 20}
              for name in ("a", "b", "c")]
    first = page_newest_first(events, 1, as_of_ms=20)
    late = {"event_id": "bb", "observed_ms": 10, "ingested_ms": 21}
    rest = page_newest_first(events + [late], 10, first["next_cursor"])
    assert [e["event_id"] for e in first["items"] + rest["items"]] == ["c", "b", "a"]
    assert rest["as_of"] == 20


def test_invalid_ingestion_boundary_returns_http_400():
    app = FastAPI()
    app.include_router(build_router(), prefix="/api")
    with TestClient(app) as client:
        response = client.get("/api/e3/trajectory/devices/SYN-WS-01/events", params={
            "scenario": "office_chain", "tenant": "ten_syn_a",
            "cursor": encode({"t": 1, "id": "e", "as_of": "invalid"}),
        })
    assert response.status_code == 400
    assert response.json()["detail"] == "cursor is not a valid e3 trajectory cursor"
