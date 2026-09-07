"""P0-2C · structural guard for the endpoint-identity query invariant.

WHY THIS IS NOT A GREP TEST
---------------------------
The F-1 defect class recurred three times because each fix was local. A
text search for variable names cannot stop the fourth occurrence: a
developer only has to name the variable something else. This guard works
on the **AST**, and it is anchored on the two things a bypass cannot
avoid:

  1. the STORE it queries — one of `ENDPOINT_KEYED_STORES`; and
  2. the IDENTITY FIELD it puts in the filter — one of that store's
     declared fields.

Any query that names both must either be built by
`services.edr.endpoint_query.endpoint_predicate` (directly or through
`EndpointResolution.predicate`) or be listed in `ALLOWED_RAW_SITES` with
a written reason. A new query site that satisfies neither fails this
test with its own file:line.

HONEST ENFORCEMENT BOUNDARY
---------------------------
This guard is static, so it cannot see:
  · a store name or field name assembled at runtime from variables;
  · a query filter passed in from another module as an opaque dict;
  · an aggregation pipeline built dynamically.
Those cases are covered by the runtime equivalence proof
(`scripts/p0_2c_alias_site_sweep_proof.py`) and by the per-route
contract tests below, not by static analysis. The three layers together
are the enforcement; no single one of them is sufficient, and this
docstring exists so nobody believes otherwise.
"""
from __future__ import annotations

import ast
import pathlib
from typing import Dict, List, Set, Tuple

import pytest

from services.edr.endpoint_query import (ENDPOINT_KEYED_STORES,
                                         ENDPOINT_NOT_RESOLVED,
                                         endpoint_predicate,
                                         unresolved_envelope)

BACKEND = pathlib.Path(__file__).resolve().parents[2]
SCAN_DIRS = ("routers", "services", "edr_plane", "detection_content",
             "v2", "security_state", "workspace", "nivxforge")
QUERY_METHODS = {"find", "find_one", "count_documents", "aggregate",
                 "update_one", "update_many", "delete_one", "delete_many",
                 "distinct", "find_one_and_update"}
CONFORMING_CALLS = {"endpoint_predicate", "predicate", "identity_refs",
                    "resolve_endpoint"}

#: A raw identity predicate is legitimate ONLY for a reason that is
#: written down here. The reason is part of the contract: a future
#: reader must be able to see why this site is not an F-1 bypass.
ALLOWED_RAW_SITES: Dict[str, str] = {
    "services/edr/device_identity.py": (
        "THE RESOLVER ITSELF. `_endpoint_id_aliases`, `identity_refs` and "
        "`_endpoint_owners` read the enrolment registry to BUILD the alias "
        "set; they cannot consume it."),
    "services/edr/endpoint_query.py": (
        "The invariant module — it is the thing being enforced."),
    "edr_plane/enrollment/store.py": (
        "Sensor-side identity. The endpoint_id comes from the "
        "AUTHENTICATED enrolment session, never from a caller, so alias "
        "resolution would weaken it."),
    "edr_plane/enrollment/transport.py": (
        "Sensor-side identity: the endpoint_id is taken from the "
        "authenticated transport session, so there is no caller-supplied "
        "alias to resolve."),
    "edr_plane/enrollment/rejection.py": (
        "Sensor-side identity: a rejected-telemetry record is keyed by the "
        "identity the sensor presented, which is exactly what must be "
        "recorded — resolving it would rewrite the evidence."),
    "edr_plane/enrollment/identity.py": (
        "Sensor-side identity: this module mints and verifies the "
        "authenticated endpoint identity that everything else resolves TO."),
    "edr_plane/campaign_story.py": (
        "Identity is read from the incident record the server already "
        "authorised (`endpoint_campaign.endpoint_id`), not supplied by the "
        "caller, so there is no external alias to resolve."),
    "edr_plane/response.py": (
        "The enrolment registry is keyed by the canonical endpoint_id and "
        "IS the authority on enrolment; aliases are resolved at the HTTP "
        "boundary (`routers/edr_response.py::_canonical_endpoint_id`) "
        "before this module is reached."),
    "routers/edr_response.py": (
        "`_canonical_endpoint_id` deliberately asks whether the literal "
        "string is already an enrolment key BEFORE resolving, so that an "
        "enrolled endpoint is never re-resolved."),
    "routers/edr.py": (
        "One deliberate literal lookup in `get_device_trajectory` asks "
        "'is this exact string an enrolment key?' in order to tell "
        "not-enrolled from revoked from never-reported. Every EVIDENCE "
        "query in this module goes through the invariant."),
    "edr_plane/isolation_policy.py": (
        "Tenant-keyed policy, not endpoint-keyed evidence."),
}


def _store_of(node: ast.Call) -> str | None:
    """The declared endpoint-keyed store this query call addresses."""
    if not isinstance(node.func, ast.Attribute):
        return None
    if node.func.attr not in QUERY_METHODS:
        return None
    recv = node.func.value
    names: List[str] = []
    if isinstance(recv, ast.Subscript) and isinstance(recv.slice, ast.Constant):
        names.append(str(recv.slice.value))
    if (isinstance(recv, ast.Call) and isinstance(recv.func, ast.Name)
            and recv.func.id in ("sync_collection", "collection")
            and recv.args and isinstance(recv.args[0], ast.Constant)):
        names.append(str(recv.args[0].value))
    for n in names:
        if n in ENDPOINT_KEYED_STORES:
            return n
    return None


def _literal_identity_fields(node: ast.Call, store: str) -> Set[str]:
    """Declared identity fields used as LITERAL keys in this filter."""
    declared = set(ENDPOINT_KEYED_STORES[store])
    found: Set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Dict):
            for k in sub.keys:
                if isinstance(k, ast.Constant) and str(k.value) in declared:
                    found.add(str(k.value))
    return found


def _conforming(fn: ast.AST) -> bool:
    """Does the enclosing function build its predicate through the
    invariant?"""
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Call):
            name = (sub.func.attr if isinstance(sub.func, ast.Attribute)
                    else getattr(sub.func, "id", None))
            if name in CONFORMING_CALLS:
                return True
    return False


def _scan() -> List[Tuple[str, int, str, Set[str], bool]]:
    """(rel_path, lineno, store, fields, conforming) for every live
    endpoint-keyed query site that names an identity field."""
    sites = []
    for d in SCAN_DIRS:
        root = BACKEND / d
        if not root.exists():
            continue
        for path in root.rglob("*.py"):
            rel = str(path.relative_to(BACKEND))
            if "/tests/" in rel or rel.startswith("tests/"):
                continue
            try:
                tree = ast.parse(path.read_text())
            except SyntaxError:
                continue
            fns = [n for n in ast.walk(tree)
                   if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            for fn in fns:
                for node in ast.walk(fn):
                    if not isinstance(node, ast.Call):
                        continue
                    store = _store_of(node)
                    if not store:
                        continue
                    fields = _literal_identity_fields(node, store)
                    if not fields:
                        continue
                    sites.append((rel, node.lineno, store, fields,
                                  _conforming(fn)))
    return sites


#: THE RECONCILED LIVE-SITE INVENTORY.
#: Every HTTP handler (or the projection it delegates to) that accepts a
#: CALLER-SUPPLIED endpoint identifier and then queries endpoint-keyed
#: evidence. The proof script must cover this list, and this list must
#: cover the product: adding a new endpoint-addressed surface without
#: adding it here fails `test_every_live_route_resolves_identity`.
LIVE_ENDPOINT_ROUTES: List[Tuple[str, str]] = [
    ("routers/edr.py", "_project_endpoint_process_tree"),
    ("routers/edr.py", "list_endpoint_detections"),
    ("routers/edr.py", "endpoint_trajectory_window"),
    ("routers/edr.py", "get_device_trajectory"),
    ("routers/edr.py", "observation_narrative"),
    ("routers/edr.py", "linked_incidents"),
    ("routers/edr.py", "trajectory_focus"),
    ("routers/edr.py", "edr_entry_context"),
    ("routers/edr_response.py", "list_actions"),
    ("routers/edr_response.py", "_canonical_endpoint_id"),
]


def _func(rel: str, name: str):
    tree = ast.parse((BACKEND / rel).read_text())
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and n.name == name:
            return n
    return None


def test_every_live_route_resolves_identity():
    """Route-contract half of the guard: each enumerated live surface
    must call the authoritative resolver itself."""
    missing = []
    for rel, name in LIVE_ENDPOINT_ROUTES:
        fn = _func(rel, name)
        if fn is None:
            missing.append(f"{rel}::{name} NOT FOUND")
            continue
        calls = {(n.func.attr if isinstance(n.func, ast.Attribute)
                  else getattr(n.func, "id", None))
                 for n in ast.walk(fn) if isinstance(n, ast.Call)}
        if "resolve_endpoint" not in calls:
            missing.append(f"{rel}::{name} does not call resolve_endpoint")
    assert not missing, ("P0-2C ROUTE CONTRACT VIOLATION:\n  " +
                         "\n  ".join(missing))


def _invariant_sites() -> List[Tuple[str, int, str]]:
    """Every call that builds a predicate THROUGH the invariant, with the
    store it names. This is the positive half of the enumeration: it is
    what proves the invariant is actually load-bearing rather than merely
    unviolated."""
    out: List[Tuple[str, int, str]] = []
    for d in SCAN_DIRS:
        root = BACKEND / d
        if not root.exists():
            continue
        for path in root.rglob("*.py"):
            rel = str(path.relative_to(BACKEND))
            if rel.startswith("tests/") or "/tests/" in rel:
                continue
            try:
                tree = ast.parse(path.read_text())
            except SyntaxError:
                continue
            consts = {t.id: n.value.value
                      for n in tree.body if isinstance(n, ast.Assign)
                      and isinstance(n.value, ast.Constant)
                      for t in n.targets if isinstance(t, ast.Name)}
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = (node.func.attr if isinstance(node.func, ast.Attribute)
                        else getattr(node.func, "id", None))
                if name not in ("endpoint_predicate", "predicate"):
                    continue
                store = None
                for a in node.args:
                    if isinstance(a, ast.Constant) and \
                            str(a.value) in ENDPOINT_KEYED_STORES:
                        store = str(a.value)
                    elif isinstance(a, ast.Name) and \
                            str(consts.get(a.id)) in ENDPOINT_KEYED_STORES:
                        store = str(consts[a.id])
                out.append((rel, node.lineno,
                            store or "<not statically resolvable>"))
    return out


def test_no_live_endpoint_keyed_query_bypasses_the_invariant():
    """THE GUARD. A new query site on a declared endpoint-keyed store
    that filters on a declared identity field must either build its
    predicate through the invariant or be an allowed raw site with a
    written reason."""
    offenders = [s for s in _scan()
                 if not s[4] and s[0] not in ALLOWED_RAW_SITES]
    assert not offenders, (
        "P0-2C INVARIANT BYPASS — these query sites address an "
        "endpoint-keyed store by a raw identity field without "
        "authoritative alias resolution:\n" +
        "\n".join(f"  {p}:{ln}  {store}  fields={sorted(f)}"
                  for p, ln, store, f, _ in offenders) +
        "\n\nFix by resolving through services.edr.endpoint_query."
        "resolve_endpoint() and building the filter with "
        "EndpointResolution.predicate(store) — or, if the identifier is "
        "genuinely not caller-supplied, add the file to ALLOWED_RAW_SITES "
        "WITH A REASON.")


def test_the_guard_actually_finds_the_known_query_sites():
    """A guard that silently matches nothing is worse than no guard.
    Pin BOTH halves of the enumeration: the raw-predicate sites it can
    see, and the sites that go through the invariant."""
    raw = _scan()
    via = _invariant_sites()
    assert len(raw) >= 8, f"scanner found only {len(raw)} raw sites"
    assert len(via) >= 8, f"only {len(via)} sites use the invariant"
    raw_stores = {s[2] for s in raw}
    via_stores = {s[2] for s in via}
    for expected in ("edr_endpoints", "edr_raw_events"):
        assert expected in raw_stores, f"{expected} raw sites not seen"
    for expected in ("v2_shadow_observations", "edr_raw_events",
                     "edr_response_commands", "workspace_cases",
                     "edr_endpoints"):
        assert expected in via_stores, (
            f"no query on {expected} is built through the invariant — "
            f"either the store lost its resolution or the scanner broke")


def test_every_allowed_raw_site_carries_a_reason():
    for path, reason in ALLOWED_RAW_SITES.items():
        assert len(reason) > 40, f"{path} has no real reason recorded"
        assert (BACKEND / path).exists(), f"{path} no longer exists — " \
                                          "remove it from the allow-list"


# ── contract of the invariant helper itself ─────────────────────────
def test_an_undeclared_store_cannot_be_queried_through_the_helper():
    with pytest.raises(KeyError):
        endpoint_predicate(["dev_1"], "some_new_evidence_store")


def test_an_undeclared_field_cannot_be_smuggled_in():
    with pytest.raises(KeyError):
        endpoint_predicate(["dev_1"], "edr_raw_events",
                           fields=["totally_made_up"])


def test_an_empty_alias_set_never_degrades_to_an_unfiltered_read():
    pred = endpoint_predicate([], "v2_shadow_observations")
    assert pred and pred != {}
    assert "_nivx_unresolved_endpoint" in pred


def test_a_single_field_store_yields_an_in_predicate():
    assert endpoint_predicate(["a", "b"], "edr_response_commands") == {
        "endpoint_id": {"$in": ["a", "b"]}}


def test_a_multi_field_store_addresses_every_declared_field():
    pred = endpoint_predicate(["a"], "v2_shadow_observations")
    got = {list(c.keys())[0] for c in pred["$or"]}
    assert got == set(ENDPOINT_KEYED_STORES["v2_shadow_observations"])


def test_unresolved_envelope_is_a_state_not_an_empty_collection():
    env = unresolved_envelope("dev_forged")
    assert env["state"] == ENDPOINT_NOT_RESOLVED
    assert env["reason"] == ENDPOINT_NOT_RESOLVED
    assert env["identity"] == {"resolved": False, "resolved_via": None,
                               "addressed_by": []}
    assert "authorisation or identity outcome" in env["note"]
