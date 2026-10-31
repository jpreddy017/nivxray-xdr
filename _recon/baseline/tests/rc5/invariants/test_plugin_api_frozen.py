"""§ 12.5 — Plugin API surface is frozen. Schema version stability.

Bumping SCHEMA_VERSION requires an explicit spec revision. This test locks
the current version + surface so a stray addition can't slip in.
"""
from engine import exec_graph as eg
from engine import semantic_ir as sir
from engine import plugin_api as papi


LOCKED_NODE_KINDS = {
    "ProcessNode", "ScriptNode", "AssemblyLoadNode", "ShellcodeNode",
    "NativeApiNode", "COMNode",
    "RegistryNode", "ScheduledTaskNode", "ServiceNode", "StartupNode",
    "WMINode", "EventSubscriptionNode",
    "FileNode", "DirectoryNode", "ArchiveNode",
    "HttpNode", "DNSNode", "SocketNode", "SMBNode", "NamedPipeNode",
    "CredentialNode", "TokenNode", "CertificateNode", "FirewallNode",
    "ClipboardNode", "EnvironmentNode", "MemoryNode",
    "CloudStorageNode", "IdentityNode",
    "DecodeNode", "NormalizeNode", "VarBindNode", "VarExpandNode",
    "StringOpNode", "ConcatNode", "ScriptBlockNode", "DelayNode",
    "ReflectionNode", "UnresolvedNode",
}

LOCKED_SIDE_EFFECT_VERBS = {
    "create_process", "inject_process", "terminate_process",
    "suspend_process", "resume_process",
    "create_file", "read_file", "write_file", "modify_file",
    "delete_file", "rename_file", "move_file",
    "read_registry", "write_registry", "delete_registry",
    "dns_query", "http_request", "https_request",
    "tcp_connect", "udp_connect", "upload", "download",
    "allocate_memory", "protect_memory", "read_memory",
    "write_memory", "execute_memory",
    "dump_credentials", "elevate_token", "disable_security",
    "bypass_amsi", "bypass_etw",
    "install_service", "create_task", "install_wmi_subscription",
    "autorun_registration",
    "var_bind",
}

LOCKED_TACTICS = {
    "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "command_and_control", "exfiltration", "impact",
    "reconnaissance", "resource_development",
    "dns_query", "firewall_rule", "named_pipe", "clipboard",
    "certificate", "token_manipulation", "wmi_subscription",
}


def test_schema_version_pinned():
    assert eg.SCHEMA_VERSION == 1, (
        "SCHEMA_VERSION bump detected. If intentional, update this test AND "
        "the plugin-API doc at /app/memory/RC5_PLUGIN_API.md."
    )
    assert sir.SIR_SCHEMA_VERSION == 1


def test_all_node_kinds_locked():
    got = {k.value for k in eg.NodeKind}
    assert got == LOCKED_NODE_KINDS, (
        f"NodeKind enum changed. Added: {got - LOCKED_NODE_KINDS} "
        f"Removed: {LOCKED_NODE_KINDS - got}. This is a schema-version bump."
    )


def test_all_side_effect_verbs_locked():
    got = {v.value for v in eg.SideEffectVerb}
    assert got == LOCKED_SIDE_EFFECT_VERBS, (
        f"SideEffectVerb enum changed. Added: {got - LOCKED_SIDE_EFFECT_VERBS} "
        f"Removed: {LOCKED_SIDE_EFFECT_VERBS - got}."
    )


def test_all_tactics_locked():
    got = {t.value for t in eg.TacticKind}
    assert got == LOCKED_TACTICS, (
        f"TacticKind enum changed. Added: {got - LOCKED_TACTICS} "
        f"Removed: {LOCKED_TACTICS - got}."
    )


def test_plugin_api_public_surface():
    """Nothing beyond the documented ABC / registry helpers is exported."""
    expected = {
        "SemanticParser", "SemanticInterpreter", "Detector",
        "register_parser", "register_interpreter", "register_detector",
        "get_parser", "get_interpreter", "list_detectors",
    }
    assert set(papi.__all__) == expected


def test_execgraph_public_surface():
    expected = {
        "SCHEMA_VERSION", "NodeKind", "SideEffectVerb", "SideEffect",
        "TacticKind", "ExecNode", "ExecGraph", "Behavior",
    }
    assert set(eg.__all__) == expected
