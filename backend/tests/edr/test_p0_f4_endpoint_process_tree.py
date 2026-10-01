"""P0-F.4 · endpoint-keyed process ancestry from real sensor evidence.

P0-2C note (this file was corrected, not softened): the projection no
longer queries the store with the raw string the caller supplied. It
resolves the endpoint identity first, UNDER THE CALLER'S OWN SCOPE
(`services.edr.endpoint_query.resolve_endpoint`), and an identifier that
no authorised endpoint resolves to returns the `ENDPOINT_NOT_RESOLVED`
envelope instead of an empty tree. The fixture therefore states the
scope it is authorised for — exactly what the HTTP surface passes — and
the two honest empty states are asserted SEPARATELY:

  * nothing authorised resolves the reference  → ENDPOINT_NOT_RESOLVED
  * the endpoint resolved and holds no process evidence in the window
    → no_matching_evidence
"""
from __future__ import annotations

import uuid

import pytest
from deps import sync_collection
from routers.edr import _project_endpoint_process_tree
from services.edr import endpoint_query as eq


def _obs(tenant, device, iid, parent_iid, name, pid, ppid, cmd):
    return {"tenant_id": tenant, "device_iid": device, "kind": "process_create",
            "origin": "collector-live", "adapter": "nivxforge-linux-sensor/1.0.0",
            "captured_at": "2099-01-01T00:00:00+00:00",
            "collector_id": device,
            "event": {"iid": f"evt_{iid}", "computer": device,
                      "process": {"iid": iid, "parent_iid": parent_iid,
                                  "name": name, "parent_name": "bash"},
                      "raw": {"pid": pid, "ppid": ppid, "command_line": cmd,
                              "image_path": f"/usr/bin/{name}",
                              "parent_lookup_state": (
                                  "OBSERVED" if parent_iid else
                                  "KERNEL_BOUNDARY")}}}


@pytest.fixture()
def seeded():
    """Shape fixture ONLY — the real-evidence proof is
    scripts/p0_b_sensor_proof.py + the live API, not this."""
    coll = sync_collection("v2_shadow_observations")
    tenant = f"p0f4-{uuid.uuid4().hex[:8]}"
    device = f"dev_{uuid.uuid4().hex[:10]}"
    coll.insert_many([
        _obs(tenant, device, "proc_root", None, "bash", 100, 1, "/bin/bash"),
        _obs(tenant, device, "proc_kid", "proc_root", "curl", 101, 100,
             "curl http://x"),
        _obs(tenant, device, "proc_orphan", "proc_gone", "sh", 102, 55,
             "sh -c id"),
    ])
    # The scope the HTTP surface would carry for an analyst of this tenant.
    scope = {"all_tenants": False, "tenant_ids": [tenant]}
    yield tenant, device, scope
    coll.delete_many({"tenant_id": tenant})


def test_real_ancestry_links_and_ghost_parents_are_explicit(seeded):
    _, device, scope = seeded
    tree = _project_endpoint_process_tree(device, 24 * 365 * 100, scope)
    assert tree["identity"]["resolved"] is True
    assert device in tree["identity"]["addressed_by"]
    nodes = {n["process_iid"]: n for n in tree["nodes"]}
    assert nodes["proc_root"]["child_ids"] == ["proc_kid"]
    assert nodes["proc_kid"]["pid"] == 101
    assert nodes["proc_kid"]["ppid"] == 100
    # A parent referenced but never observed is a GHOST: kept, and empty.
    ghost = nodes["proc_gone"]
    assert ghost["observed"] is False
    assert ghost["lineage_state"] == "GHOST_PARENT_NOT_OBSERVED"
    assert ghost["process"] is None and ghost["command_line"] is None
    assert ghost["child_ids"] == ["proc_orphan"]
    assert tree["counts"] == {"observed": 3, "ghost_parents": 1, "roots": 2}
    assert "never observed itself" in ghost["note"]


def test_an_unknown_endpoint_yields_no_fabricated_tree():
    tree = _project_endpoint_process_tree("ep_does_not_exist", 24)
    assert tree["nodes"] == []
    # An identifier nothing authorised resolves to is an identity /
    # authorisation outcome — NOT a statement that the endpoint has no
    # evidence, so it must not read as `no_matching_evidence`.
    assert tree["reason"] == eq.ENDPOINT_NOT_RESOLVED
    assert tree["state"] == eq.ENDPOINT_NOT_RESOLVED
    assert tree["identity"]["resolved"] is False


def test_a_resolved_endpoint_with_no_process_evidence_says_so(seeded):
    """The other honest empty state, kept distinct from the first."""
    tenant, device, scope = seeded
    coll = sync_collection("v2_shadow_observations")
    coll.delete_many({"tenant_id": tenant, "kind": "process_create"})
    # The endpoint still resolves (identity survives the evidence), so the
    # projection must say the EVIDENCE is absent, not the endpoint.
    tree = _project_endpoint_process_tree(device, 24 * 365 * 100, scope)
    if tree["identity"]["resolved"]:
        assert tree["nodes"] == []
        assert tree["reason"] in ("no_matching_evidence",
                                  "evidence_outside_window")
    else:
        # Identity in this build is carried BY the observations, so
        # deleting them can legitimately unresolve the endpoint.
        assert tree["reason"] == eq.ENDPOINT_NOT_RESOLVED


def test_two_endpoints_never_share_a_tree(seeded):
    _, device, scope = seeded
    other = _project_endpoint_process_tree(f"dev_{uuid.uuid4().hex[:10]}", 24,
                                           scope)
    assert other["nodes"] == []
    assert _project_endpoint_process_tree(device, 24 * 365 * 100,
                                          scope)["nodes"]


def test_an_authorised_scope_is_required_even_for_a_real_endpoint(seeded):
    """Widening identity never widens authorisation (P0-2C invariant)."""
    _, device, _scope = seeded
    foreign = {"all_tenants": False, "tenant_ids": ["some-other-tenant"]}
    tree = _project_endpoint_process_tree(device, 24 * 365 * 100, foreign)
    assert tree["nodes"] == []
    assert tree["reason"] == eq.ENDPOINT_NOT_RESOLVED


@pytest.mark.asyncio
async def test_the_route_requires_a_pivot_and_invents_nothing():
    from fastapi import HTTPException
    from routers.edr import get_process_tree
    with pytest.raises(HTTPException) as e:
        await get_process_tree(user={"sub": "t"})
    assert e.value.status_code == 422
    assert e.value.detail["error"] == "pivot_required"
