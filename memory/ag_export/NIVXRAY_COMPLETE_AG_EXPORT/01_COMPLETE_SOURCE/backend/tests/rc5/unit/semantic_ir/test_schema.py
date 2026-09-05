"""Unit tests · SIR schema (25 tests)."""
import json

import pytest
from pydantic import ValidationError

from engine.semantic_ir import SIR_SCHEMA_VERSION, SIRKind, SIRNode, SIRTree


# ---------------------------------------------------------------------------
# SIRKind enum
# ---------------------------------------------------------------------------
def test_sir_schema_version_pinned():
    assert SIR_SCHEMA_VERSION == 1


def test_sir_kind_count():
    # Number of frozen SIR kinds; changing this is a schema-version bump.
    assert len(list(SIRKind)) == 31


def test_sir_kind_values_are_stable_strings():
    for k in SIRKind:
        assert isinstance(k.value, str) and k.value


def test_sir_kind_specific_members_exist():
    for name in ("program", "call_expr", "format_op", "script_block_lit",
                 "delayed_ref", "unresolved"):
        assert hasattr(SIRKind, name)


# ---------------------------------------------------------------------------
# SIRNode construction
# ---------------------------------------------------------------------------
def test_sirnode_defaults():
    n = SIRNode(kind=SIRKind.string_literal, value="hello")
    assert n.value == "hello"
    assert n.children == ()
    assert n.attrs == {}
    assert n.schema_version == 1
    assert n.id.startswith("s_")


def test_sirnode_is_frozen():
    n = SIRNode(kind=SIRKind.string_literal, value="x")
    with pytest.raises(ValidationError):
        n.value = "y"


def test_sirnode_children_is_tuple():
    root = SIRNode(kind=SIRKind.program, children=(
        SIRNode(kind=SIRKind.string_literal, value="a"),
        SIRNode(kind=SIRKind.string_literal, value="b"),
    ))
    assert isinstance(root.children, tuple)
    assert len(root.children) == 2


def test_sirnode_extra_fields_forbidden():
    with pytest.raises(ValidationError):
        SIRNode(kind=SIRKind.string_literal, bogus_field="oops")  # type: ignore[call-arg]


def test_sirnode_attrs_arbitrary_json():
    n = SIRNode(kind=SIRKind.call_expr, attrs={"target": "powershell", "args": ["-nop", "-w", "hidden"]})
    assert n.attrs["target"] == "powershell"


def test_sirnode_source_span_two_ints():
    n = SIRNode(kind=SIRKind.string_literal, value="x", source_span=(0, 5))
    assert n.source_span == (0, 5)


# ---------------------------------------------------------------------------
# SIRTree
# ---------------------------------------------------------------------------
def _mini_tree(parser="cmd"):
    root = SIRNode(kind=SIRKind.program, children=(
        SIRNode(kind=SIRKind.assignment, attrs={"name": "X"}, children=(
            SIRNode(kind=SIRKind.string_literal, value="1"),
        )),
    ))
    return SIRTree(root=root, parser=parser, original_length=10)


def test_sirtree_construction():
    t = _mini_tree()
    assert t.parser == "cmd"
    assert t.root.kind == SIRKind.program


def test_sirtree_is_frozen():
    t = _mini_tree()
    with pytest.raises(ValidationError):
        t.parser = "powershell"


def test_sirtree_warnings_tuple():
    root = SIRNode(kind=SIRKind.program)
    t = SIRTree(root=root, parser="cmd", original_length=0, warnings=("unresolved: %UNK%",))
    assert t.warnings == ("unresolved: %UNK%",)


def test_sirtree_requires_root():
    with pytest.raises(ValidationError):
        SIRTree(parser="cmd", original_length=0)  # type: ignore[call-arg]


def test_sirtree_requires_parser():
    root = SIRNode(kind=SIRKind.program)
    with pytest.raises(ValidationError):
        SIRTree(root=root, original_length=0)  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# JSON roundtrip
# ---------------------------------------------------------------------------
def test_sirtree_json_roundtrip():
    t = _mini_tree()
    j = t.model_dump_json()
    back = SIRTree.model_validate_json(j)
    assert back == t


def test_sirtree_dict_roundtrip():
    t = _mini_tree()
    d = t.model_dump()
    back = SIRTree(**d)
    assert back == t


def test_sirtree_serialisation_contains_schema_version():
    t = _mini_tree()
    d = json.loads(t.model_dump_json())
    assert d["schema_version"] == 1
    assert d["root"]["schema_version"] == 1


def test_sirnode_recursive_serialisation():
    root = SIRNode(kind=SIRKind.program, children=(
        SIRNode(kind=SIRKind.call_expr, children=(
            SIRNode(kind=SIRKind.string_literal, value="powershell"),
            SIRNode(kind=SIRKind.string_literal, value="-nop"),
        )),
    ))
    j = root.model_dump_json()
    back = SIRNode.model_validate_json(j)
    assert back == root


# ---------------------------------------------------------------------------
# Kind coverage — assert every "critical" kind can be constructed
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("kind", [
    SIRKind.program, SIRKind.assignment, SIRKind.call_expr,
    SIRKind.format_op, SIRKind.join_op, SIRKind.split_op,
    SIRKind.replace_op, SIRKind.substring_op,
    SIRKind.script_block_lit, SIRKind.invocation_expr,
    SIRKind.var_ref, SIRKind.env_ref, SIRKind.delayed_ref,
    SIRKind.unresolved,
])
def test_every_critical_kind_constructs(kind):
    n = SIRNode(kind=kind, value="x")
    assert n.kind == kind


def test_unresolved_records_reason_via_attrs():
    n = SIRNode(kind=SIRKind.unresolved, attrs={"reason": "delayed_expansion inside FOR /F"})
    assert n.attrs["reason"].startswith("delayed_expansion")


def test_parser_tag_optional_but_recommended():
    n = SIRNode(kind=SIRKind.string_literal, value="x", parser="powershell")
    assert n.parser == "powershell"


def test_ids_are_stable_and_unique():
    ids = {SIRNode(kind=SIRKind.string_literal, value="x").id for _ in range(20)}
    assert len(ids) == 20
