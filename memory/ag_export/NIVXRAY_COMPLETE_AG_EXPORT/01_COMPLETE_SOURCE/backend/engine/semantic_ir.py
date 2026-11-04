"""RC5 · Semantic Intermediate Representation (SIR).

Language-agnostic AST-like tree emitted by every parser (CMD, PowerShell,
Bash, Python, VBScript, JScript, MSBuild, HTA, WMI, future). The Execution
Graph builder consumes SIR — never raw text.

See § 3 of `/app/memory/RC5_SEMANTIC_ENGINE_SPEC.md`.

Frozen node types (adding a kind is a schema-version bump):

    Program · Statement · Expression
    Assignment · CallExpr · MemberExpr · IndexExpr
    StringLiteral · NumberLiteral · ArrayLiteral · MapLiteral
    VarRef · EnvRef · DelayedRef
    BinaryOp · UnaryOp · FormatOp · JoinOp · SplitOp · ReplaceOp · SubstringOp
    Pipeline · Block · If · Loop · Try · Return
    ScriptBlockLiteral · InvocationExpr
    Comment · Unresolved
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


SIR_SCHEMA_VERSION: int = 1


class SIRKind(str, Enum):
    program            = "Program"
    statement          = "Statement"
    expression         = "Expression"
    assignment         = "Assignment"
    call_expr          = "CallExpr"
    member_expr        = "MemberExpr"
    index_expr         = "IndexExpr"
    string_literal     = "StringLiteral"
    number_literal     = "NumberLiteral"
    array_literal      = "ArrayLiteral"
    map_literal        = "MapLiteral"
    var_ref            = "VarRef"
    env_ref            = "EnvRef"
    delayed_ref        = "DelayedRef"
    binary_op          = "BinaryOp"
    unary_op           = "UnaryOp"
    format_op          = "FormatOp"
    join_op            = "JoinOp"
    split_op           = "SplitOp"
    replace_op         = "ReplaceOp"
    substring_op       = "SubstringOp"
    pipeline           = "Pipeline"
    block              = "Block"
    if_stmt            = "If"
    loop_stmt          = "Loop"
    try_stmt           = "Try"
    return_stmt        = "Return"
    script_block_lit   = "ScriptBlockLiteral"
    invocation_expr    = "InvocationExpr"
    comment            = "Comment"
    unresolved         = "Unresolved"


class SIRNode(BaseModel):
    """A single SIR tree node.

    Immutable. Roundtrip-safe (JSON-serialisable). Every node carries a
    `source_span` (byte offsets in normalized text) and `parser` tag so
    downstream evidence trails always reach back to the original source.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: "s_" + uuid4().hex[:10])
    kind: SIRKind
    # Language-neutral value slot — literals put their value here,
    # ops put their canonical name (e.g. "-f", "-join", "+").
    value: Optional[Any] = None
    # Ordered children.
    children: Tuple["SIRNode", ...] = ()
    # Kind-specific attributes (name of variable, argument spread, etc.).
    attrs: Dict[str, Any] = Field(default_factory=dict)
    # Provenance — always populated by conformant parsers.
    source_span: Optional[Tuple[int, int]] = None
    parser: Optional[str] = None
    schema_version: int = SIR_SCHEMA_VERSION


# Allow SIRNode.children forward-reference to resolve.
SIRNode.model_rebuild()


class SIRTree(BaseModel):
    """The top-level SIR container returned by every parser."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    root: SIRNode
    parser: str                                 # "cmd" | "powershell" | ...
    original_length: int                        # length of the normalized input
    schema_version: int = SIR_SCHEMA_VERSION
    warnings: Tuple[str, ...] = ()              # non-fatal parser diagnostics


__all__ = [
    "SIR_SCHEMA_VERSION",
    "SIRKind",
    "SIRNode",
    "SIRTree",
]
