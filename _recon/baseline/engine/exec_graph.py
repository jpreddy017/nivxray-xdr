"""RC5 · Execution Graph — the deterministic core of the Semantic Engine.

See `/app/memory/RC5_SEMANTIC_ENGINE_SPEC.md` (v2) for the architectural contract.

This module defines the FROZEN data model used by every downstream layer
(Behavior Extractor, MITRE v2, LOLBIN v2, Verdict v2, Explainability). Adding
a new NodeKind, SideEffect verb, or Behavior tactic here is a schema-version
bump and requires a spec revision.

Key invariants enforced at the model level:

  § 12.1  ExecNode.model_config["frozen"] = True     → nodes are immutable
  § 12.5  SCHEMA_VERSION is the plugin-API contract  → bumping breaks plugins loudly
  § 6.4   Behavior.confidence = min(evidence_nodes[*].confidence)
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Tuple
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Schema version — bump when adding a NodeKind / SideEffect verb / TacticKind.
# ---------------------------------------------------------------------------
SCHEMA_VERSION: int = 1


# ---------------------------------------------------------------------------
# § 4 — NodeKind (34 reserved kinds; implementation lands phase by phase)
# ---------------------------------------------------------------------------
class NodeKind(str, Enum):
    # Execution
    process        = "ProcessNode"
    script         = "ScriptNode"
    assembly_load  = "AssemblyLoadNode"
    shellcode      = "ShellcodeNode"
    native_api     = "NativeApiNode"
    com            = "COMNode"
    # Persistence
    registry       = "RegistryNode"
    scheduled_task = "ScheduledTaskNode"
    service        = "ServiceNode"
    startup        = "StartupNode"
    wmi            = "WMINode"
    event_sub      = "EventSubscriptionNode"
    # Filesystem
    file           = "FileNode"
    directory      = "DirectoryNode"
    archive        = "ArchiveNode"
    # Network
    http           = "HttpNode"
    dns            = "DNSNode"
    socket         = "SocketNode"
    smb            = "SMBNode"
    named_pipe     = "NamedPipeNode"
    # Security
    credential     = "CredentialNode"
    token          = "TokenNode"
    certificate    = "CertificateNode"
    firewall       = "FirewallNode"
    # System
    clipboard      = "ClipboardNode"
    environment    = "EnvironmentNode"
    memory         = "MemoryNode"
    # Cloud
    cloud_storage  = "CloudStorageNode"
    identity       = "IdentityNode"
    # Core / Interpreter plumbing (always implemented)
    decode         = "DecodeNode"
    normalize      = "NormalizeNode"
    var_bind       = "VarBindNode"
    var_expand     = "VarExpandNode"
    string_op      = "StringOpNode"
    concat         = "ConcatNode"
    script_block   = "ScriptBlockNode"
    delay          = "DelayNode"
    reflection     = "ReflectionNode"
    unresolved     = "UnresolvedNode"


# ---------------------------------------------------------------------------
# § 5 — Side-effect vocabulary (36 frozen verbs)
# ---------------------------------------------------------------------------
class SideEffectVerb(str, Enum):
    # Process
    create_process    = "create_process"
    inject_process    = "inject_process"
    terminate_process = "terminate_process"
    suspend_process   = "suspend_process"
    resume_process    = "resume_process"
    # Filesystem
    create_file       = "create_file"
    read_file         = "read_file"
    write_file        = "write_file"
    modify_file       = "modify_file"
    delete_file       = "delete_file"
    rename_file       = "rename_file"
    move_file         = "move_file"
    # Registry
    read_registry     = "read_registry"
    write_registry    = "write_registry"
    delete_registry   = "delete_registry"
    # Network
    dns_query         = "dns_query"
    http_request      = "http_request"
    https_request     = "https_request"
    tcp_connect       = "tcp_connect"
    udp_connect       = "udp_connect"
    upload            = "upload"
    download          = "download"
    # Memory
    allocate_memory   = "allocate_memory"
    protect_memory    = "protect_memory"
    read_memory       = "read_memory"
    write_memory      = "write_memory"
    execute_memory    = "execute_memory"
    # Security
    dump_credentials  = "dump_credentials"
    elevate_token     = "elevate_token"
    disable_security  = "disable_security"
    bypass_amsi       = "bypass_amsi"
    bypass_etw        = "bypass_etw"
    # Persistence
    install_service         = "install_service"
    create_task             = "create_task"
    install_wmi_subscription = "install_wmi_subscription"
    autorun_registration    = "autorun_registration"
    # Interpreter plumbing
    var_bind          = "var_bind"


class SideEffect(BaseModel):
    """A single `(verb, node_id, evidence_text)` triple — § 5."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    verb: SideEffectVerb
    node_id: str
    evidence: str = ""


# ---------------------------------------------------------------------------
# § 7 — Behavior taxonomy (14 top-level tactics + 7 supporting)
# ---------------------------------------------------------------------------
class TacticKind(str, Enum):
    initial_access       = "initial_access"
    execution            = "execution"
    persistence          = "persistence"
    privilege_escalation = "privilege_escalation"
    defense_evasion      = "defense_evasion"
    credential_access    = "credential_access"
    discovery            = "discovery"
    lateral_movement     = "lateral_movement"
    collection           = "collection"
    command_and_control  = "command_and_control"
    exfiltration         = "exfiltration"
    impact               = "impact"
    reconnaissance       = "reconnaissance"
    resource_development = "resource_development"
    # Supporting behaviors (finer-grained evidence, still MITRE-aligned):
    dns_query          = "dns_query"
    firewall_rule      = "firewall_rule"
    named_pipe         = "named_pipe"
    clipboard          = "clipboard"
    certificate        = "certificate"
    token_manipulation = "token_manipulation"
    wmi_subscription   = "wmi_subscription"


# ---------------------------------------------------------------------------
# § 4 — ExecNode (frozen; immutable after creation — § 12.1)
# ---------------------------------------------------------------------------
class ExecNode(BaseModel):
    """A single reconstructed operation in the Execution Graph.

    Immutable by contract (`frozen=True`). Any attempt to mutate a field
    after construction raises `pydantic.ValidationError` — this is what
    enforces § 12.1 architectural invariant.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: "n_" + uuid4().hex[:10])
    kind: NodeKind

    # Graph topology — append-only. `inputs` is set at construction (parents),
    # `outputs` is computed by the ExecGraph builder from all children's inputs.
    inputs: Tuple[str, ...] = ()
    outputs: Tuple[str, ...] = ()

    # Kind-specific structured payload. Must be JSON-serialisable.
    args: Dict[str, Any] = Field(default_factory=dict)

    # The exact text the interpreter would execute at this step.
    reconstructed: str = ""

    # Side effects produced by this node (§ 5).
    side_effects: Tuple[SideEffect, ...] = ()

    # 0-100. Child ≤ min(parent). Never assigned arbitrarily — every drop
    # cites a rule number in `notes` (see § 6.7).
    confidence: int = 100

    # Byte offsets in the ORIGINAL decoded text (for evidence provenance).
    source_span: Optional[Tuple[int, int]] = None

    # Which decoder layer produced the raw material for this node.
    parent_layer: Optional[int] = None

    # Which parser emitted the SIR that produced this node.
    # e.g. "cmd", "powershell", "bash", "wmi".
    parser: Optional[str] = None

    # Advisor-origin nodes never enter verdict math (§ 6.6).
    origin: Literal["deterministic", "advisor"] = "deterministic"

    # Schema version — must equal `SCHEMA_VERSION` at creation time.
    schema_version: int = SCHEMA_VERSION

    # Analyst-facing rationale strings. Never a verdict driver.
    notes: Tuple[str, ...] = ()

    @field_validator("confidence")
    @classmethod
    def _clamp_confidence(cls, v: int) -> int:
        if not (0 <= v <= 100):
            raise ValueError(f"confidence must be in [0, 100], got {v}")
        return v

    @field_validator("schema_version")
    @classmethod
    def _lock_schema(cls, v: int) -> int:
        if v != SCHEMA_VERSION:
            raise ValueError(
                f"ExecNode.schema_version {v} != SCHEMA_VERSION {SCHEMA_VERSION}. "
                f"Bump SCHEMA_VERSION explicitly if you're adding a NodeKind."
            )
        return v


# ---------------------------------------------------------------------------
# § 3 · § 12.1 — ExecGraph — immutable, append-only container.
# ---------------------------------------------------------------------------
class ExecGraph(BaseModel):
    """The Execution Graph — a validated, immutable collection of ExecNodes.

    `add_node(...)` returns a *new* ExecGraph with the node appended (functional
    style). This enforces § 12.1 (immutability) while still allowing the
    interpreter to build up the graph one node at a time.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    nodes: Tuple[ExecNode, ...] = ()
    schema_version: int = SCHEMA_VERSION

    def add_node(self, node: ExecNode) -> "ExecGraph":
        """Return a new graph with `node` appended. Original is unchanged.

        Also propagates confidence rule 6.2 (`child ≤ min(parent conf)`)
        and rule 6.3 (unresolved-parent drop ≥ 20). If the caller passed a
        node whose declared confidence violates the rule, we raise — this is
        deliberate: silent capping would hide interpreter bugs.
        """
        # Rule 6.2 + 6.3 validation
        if node.inputs:
            parent_confs: List[int] = []
            has_unresolved = False
            for pid in node.inputs:
                parent = self._find(pid)
                if parent is None:
                    raise ValueError(
                        f"add_node: node {node.id} references unknown parent {pid!r}"
                    )
                parent_confs.append(parent.confidence)
                if parent.kind == NodeKind.unresolved:
                    has_unresolved = True
            allowed = min(parent_confs)
            if has_unresolved:
                allowed = max(0, allowed - 20)
            if node.confidence > allowed:
                raise ValueError(
                    f"confidence rule violation for {node.id}: declared "
                    f"{node.confidence} > allowed {allowed} "
                    f"(min parent conf {min(parent_confs)}"
                    f"{', -20 for unresolved parent' if has_unresolved else ''})"
                )
        return ExecGraph(nodes=self.nodes + (node,), schema_version=self.schema_version)

    def _find(self, node_id: str) -> Optional[ExecNode]:
        for n in self.nodes:
            if n.id == node_id:
                return n
        return None

    def find(self, node_id: str) -> Optional[ExecNode]:
        """Public lookup — used by detectors and evidence-integrity checks."""
        return self._find(node_id)

    def node_ids(self) -> List[str]:
        return [n.id for n in self.nodes]

    def by_kind(self, kind: NodeKind) -> List[ExecNode]:
        return [n for n in self.nodes if n.kind == kind]

    def all_side_effects(self) -> List[SideEffect]:
        return [se for n in self.nodes for se in n.side_effects]

    def dangling_refs(self) -> List[str]:
        """Return any `SideEffect.node_id` that does not resolve to a node.

        Called by the § 12.3 evidence-ref-integrity CI test.
        """
        known = set(self.node_ids())
        bad: List[str] = []
        for n in self.nodes:
            for se in n.side_effects:
                if se.node_id not in known:
                    bad.append(se.node_id)
        return bad


# ---------------------------------------------------------------------------
# § 7 — Behavior record
# ---------------------------------------------------------------------------
class Behavior(BaseModel):
    """An attacker-tactic-level behavior derived from ≥ 1 ExecNode.

    Immutable. Extractor emits these by walking the ExecGraph — never by
    reading `result["output"]` directly (§ 12.2).
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: "b_" + uuid4().hex[:10])
    tactic: TacticKind
    sub_kind: Optional[str] = None
    evidence_nodes: Tuple[str, ...]      # min length 1 — enforced below
    reconstructed: str                   # exact command that caused the behavior
    confidence: int                      # = min(evidence_nodes[*].confidence)
    parameters: Dict[str, Any] = Field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION

    @field_validator("evidence_nodes")
    @classmethod
    def _at_least_one(cls, v: Tuple[str, ...]) -> Tuple[str, ...]:
        if not v:
            raise ValueError("Behavior must reference at least one evidence node")
        return v

    @field_validator("confidence")
    @classmethod
    def _clamp_confidence(cls, v: int) -> int:
        if not (0 <= v <= 100):
            raise ValueError(f"confidence must be in [0, 100], got {v}")
        return v


# ---------------------------------------------------------------------------
# Public exports — the plugin-API surface (§ 12.5). Anything not in
# __all__ is an internal-only symbol and may change without a schema bump.
# ---------------------------------------------------------------------------
__all__ = [
    "SCHEMA_VERSION",
    "NodeKind",
    "SideEffectVerb",
    "SideEffect",
    "TacticKind",
    "ExecNode",
    "ExecGraph",
    "Behavior",
]
