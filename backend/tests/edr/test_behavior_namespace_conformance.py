"""Regression lock on the Behavior evidence field namespace.

The flat namespace this guard exists to prevent failed almost SILENTLY: no
predicate could address `image`, so rules evaluated nothing and only a row
carrying a `user` ever raised. Without Step 30's engine execution it would have
reached production as suppressed detections with no error anywhere (G-14).

So the guard reads BOTH namespaces from their own source rather than from a
hand-written list, and fails if the adapter can ever emit a path the existing
Behavior field contract cannot address:

* authoritative  — every canonical path `edr_behavior.normalize` LABELS for
  itself (`b.s(value, "process.executable_path")`, ...), plus
  `predicates.FIELD_PREFIXES` as the resolver's own admission rule;
* emitted        — every path the adapter's `_put(tree, "...", value)` calls can
  produce.

This is a regression guard, not a schema framework: no registry, no validator,
no runtime change. Hermetic: no engine execution, no real evidence, no
production, no sensor.
"""
from __future__ import annotations

import ast
import inspect
from typing import Dict, Iterable, Set

from edr_behavior import normalize as N
from edr_behavior import predicates as P
from edr_behavior.rules import parse_rule
from edr_plane import behavior_evidence_adapter as A

#: G-11, owner decision: genuine §d evidence with no canonical consumer yet.
#: Kept because real evidence must not be discarded merely because no current
#: rule reads it. NON-AUTHORITATIVE for rule semantics until a canonical
#: consumer is designed.
G11_ALLOWLIST = frozenset({"file.previous_path", "network.initiated"})

#: The adapter copies the §d detection object verbatim under its domain root;
#: its children (`detection.rule_id`, ...) are what rules address.
DOMAIN_ROOTS = frozenset({"detection"})

#: The §d row fixture already used by the Step-22/31 adapter tests. Reused
#: rather than re-declared, so this guard reads the same evidence shape.
from .test_behavior_evidence_adapter import EP, RAW, TEN, ok, row

MAXIMAL = dict(
    file={"path": r"C:\\tmp\\b.exe", "prev_path": r"C:\\tmp\\a.exe",
          "sha256": "cd" * 32, "operation": "rename"},
    network={"dest_ip": "10.1.1.1", "dest_port": 443, "src_ip": "10.0.0.5",
             "protocol": "tcp", "initiated": True, "query": "a.example.test"})


def authoritative_paths() -> Set[str]:
    """Canonical paths the normalizer names for itself."""
    out = set()
    for node in ast.walk(ast.parse(inspect.getsource(N))):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                and addressable(node.value):
            out.add(node.value)
    return out


def emitted_paths() -> Set[str]:
    """Paths the adapter can emit. Also pins them to literals: a computed path
    would make this guard unenforceable."""
    out = set()
    for node in ast.walk(ast.parse(inspect.getsource(A))):
        if isinstance(node, ast.Call) and \
                getattr(node.func, "id", "") == "_put":
            arg = node.args[1]
            assert isinstance(arg, ast.Constant) and \
                isinstance(arg.value, str), "_put path must be a literal"
            out.add(arg.value)
    return out


def addressable(path: str) -> bool:
    """The resolver's own rule: a leading domain prefix, then a nested walk."""
    return "." in path and path.split(".")[0] + "." in P.FIELD_PREFIXES


def offenders(paths: Iterable[str]) -> Set[str]:
    """Paths no predicate could ever reach, nor the allow-list permits."""
    return {p for p in paths
            if p not in DOMAIN_ROOTS and p not in G11_ALLOWLIST
            and not addressable(p)}


def leaves(fields: Dict, prefix: str = "") -> Set[str]:
    out = set()
    for key, value in fields.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict) and path not in DOMAIN_ROOTS:
            out |= leaves(value, f"{path}.")
        else:
            out.add(path)
    return out


def test_every_emitted_path_is_addressable_by_the_existing_resolver():
    assert offenders(emitted_paths()) == set()
    for path in sorted(emitted_paths() - DOMAIN_ROOTS):
        assert addressable(path), path


def test_every_emitted_path_is_accepted_by_the_rule_compiler():
    """Addressability proven through the real gate rules must pass."""
    for path in sorted(emitted_paths() - DOMAIN_ROOTS):
        rule = parse_rule({
            "rule_id": "guard", "version": 1, "name": "guard",
            "description": "namespace guard", "lifecycle": "ACTIVE",
            "severity": "LOW", "confidence": 10, "time_window_seconds": 60,
            "entity_scope": "device",
            "stages": [{"id": "s1", "type": "PROCESS",
                        "predicate": {"field": path, "op": "exists"}}]})
        assert rule.stages[0].predicate["field"] == path


def test_emitted_paths_stay_inside_the_authoritative_namespace():
    extra = emitted_paths() - DOMAIN_ROOTS - authoritative_paths() - \
        G11_ALLOWLIST
    assert extra == set(), (
        "the adapter emits a path the normalizer does not name and the G-11 "
        f"allow-list does not permit: {sorted(extra)}")


def test_a_flat_key_would_fail_the_guard():
    """The exact defect this lock exists for: `image` instead of
    `process.executable_path`."""
    assert offenders({"image"}) == {"image"}
    assert offenders({"command_line", "user", "dest_ip", "file_path",
                      "activity_family", "severity"}) == {
        "command_line", "user", "dest_ip", "file_path", "activity_family",
        "severity"}
    assert offenders({"process.executable_path"}) == set()
    assert not addressable("image")


def test_a_path_in_an_unknown_domain_would_fail_the_guard():
    assert offenders({"telemetry.image", "sd.kind"}) == {"telemetry.image",
                                                          "sd.kind"}


def test_runtime_output_never_exceeds_the_declared_paths():
    """The AST view and the real conversion must agree, so the guard cannot be
    satisfied by source that does not describe runtime behaviour."""
    actual = leaves(ok(**MAXIMAL).fields)
    allowed = emitted_paths() | DOMAIN_ROOTS
    assert actual - allowed == set()
    assert offenders(actual) == set()
    # a maximal row exercises every mapped domain
    assert {"process.name", "process.executable_path", "process.command_line",
            "process.sha256", "parent.name", "parent.executable_path",
            "user.name", "file.path", "file.name", "file.operation",
            "file.sha256", "network.dest_ip", "network.dest_port",
            "network.src_ip", "network.protocol", "dns.query_name"} <= actual


def test_nested_paths_resolve_through_the_existing_resolver():
    rec = ok(**MAXIMAL)
    assert P.get_field(rec, "process.name") == "chrome.exe"
    assert P.get_field(rec, "process.executable_path").endswith("chrome.exe")
    assert P.get_field(rec, "process.command_line") == \
        "chrome.exe --type=renderer"
    assert P.get_field(rec, "parent.name") == "explorer.exe"
    assert P.get_field(rec, "user.name") == "KUSHU\\jp"
    assert P.get_field(rec, "file.path").endswith("b.exe")
    assert P.get_field(rec, "file.operation") == "rename"
    assert P.get_field(rec, "network.dest_ip") == "10.1.1.1"
    assert P.get_field(rec, "dns.query_name") == "a.example.test"
    det = ok(kind="DETECTION", detection={"rule_id": "R-1"})
    assert P.get_field(det, "detection.rule_id") == "R-1"


# ── G-11 ─────────────────────────────────────────────────────────────────

def test_g11_fields_are_the_only_additive_exceptions():
    assert G11_ALLOWLIST == {"file.previous_path", "network.initiated"}
    auth = authoritative_paths()
    for path in G11_ALLOWLIST:
        assert path not in auth, f"{path} is no longer additive"
        assert addressable(path)
        assert path in emitted_paths()


def test_g11_fields_carry_real_evidence_and_keep_their_types():
    rec = ok(**MAXIMAL)
    assert P.get_field(rec, "file.previous_path").endswith("a.exe")
    assert P.get_field(rec, "network.initiated") is True
    assert P.get_field(ok(network={"initiated": False}),
                       "network.initiated") is False


def test_no_shipped_rule_depends_on_a_g11_field():
    """They stay non-authoritative for rule semantics."""
    import json
    from pathlib import Path
    corpus = json.loads(
        (Path(inspect.getfile(N)).parent / "content" /
         "starter_rules.json").read_text())
    used = {p["predicate"]["field"]
            for rule in (corpus if isinstance(corpus, list)
                         else corpus.get("rules", []))
            for p in rule.get("stages", [])
            if isinstance(p.get("predicate"), dict)
            and "field" in p["predicate"]}
    assert used & G11_ALLOWLIST == set()


# ── what must stay missing ───────────────────────────────────────────────

def test_registry_and_auth_stay_missing_because_sd_does_not_carry_them():
    rec = ok(kind="REGISTRY_SET")
    for path in ("registry.key", "registry.value_data", "registry.operation",
                 "auth.logon_type", "auth.outcome", "auth.target_user"):
        assert P.get_field(rec, path) is None, path
    assert not {p for p in emitted_paths()
                if p.startswith(("registry.", "auth."))}


def test_no_network_direction_is_inferred_from_initiated():
    for initiated in (True, False):
        rec = ok(network={"dest_ip": "10.1.1.1", "initiated": initiated})
        assert P.get_field(rec, "network.direction") is None
    assert "network.direction" not in emitted_paths()
    assert "direction" not in inspect.getsource(A._fields)


def test_unavailable_canonical_paths_are_absent_not_empty():
    rec = ok(**MAXIMAL)
    for path in ("process.signer", "process.integrity_level",
                 "process.current_directory", "process.original_file_name",
                 "file.signer", "dns.answers", "network.dest_hostname"):
        assert P.get_field(rec, path) is None, path
        assert path not in emitted_paths(), path


# ── nothing else moved ───────────────────────────────────────────────────

def test_only_the_adapter_shapes_evidence_fields():
    from edr_plane import behavior_sd_provider as prov
    from edr_plane import behavior_shadow_runner as runner
    for module in (prov, runner):
        src = inspect.getsource(module)
        assert "_put(" not in src
        assert ".fields[" not in src
        assert "fields=" not in src


def test_the_resolver_and_rule_contract_are_untouched():
    assert P.FIELD_PREFIXES == ("process.", "parent.", "file.", "registry.",
                               "dns.", "network.", "auth.", "user.",
                               "detection.", "host.")
    assert N.NORMALIZER_ID == "edr_behavior.normalize.canonical_v1"


def test_raw_reference_and_stable_key_semantics_are_unchanged():
    a, b = ok(**MAXIMAL), ok(**MAXIMAL)
    assert a.ref.raw_id == RAW
    assert a.ref.tenant_id == TEN
    assert a.stable_key == b.stable_key          # deterministic
    assert a.ref.stable_key() == a.stable_key
    other = A.to_evidence_record(row(provenance={"store": "SHADOW_OBSERVATION",
                                                 "raw_ref": "raw_2"}),
                                 tenant_id=TEN, endpoint_id=EP,
                                 raw_id="raw_2")[0]
    assert other.stable_key != a.stable_key      # identity follows raw_ref
    assert a.event_time == b.event_time
    assert a.provenance["observation_time_authority"] == \
        "STORED_OBSERVATION_TIME"
