r"""RC5 Phase 4 · Behavior Extractor.

Walks an immutable `ExecGraph` (produced by the CMD / PowerShell / future
parsers+interpreters) and emits an ordered list of `Behavior` records.
Every Behavior carries ≥ 1 `evidence_nodes` reference (§ 12.3 enforced by
the model) and its `reconstructed` command is the exact text the
interpreter attributes to the attacker action.

Contract (§ 12.2 architectural invariant):
  * Reads ONLY the ExecGraph — never `result["output"]`.
  * Never mutates a node.
  * Same graph in ⇒ same behaviors out (deterministic).

Behavior derivation rules — each rule maps
`(NodeKind, args match, side-effect verb) → TacticKind + sub_kind`.
Nothing here is keyword-driven on raw text; every match consults the
structured `ExecNode.args` shape.

Rule table (frozen at Phase 4 — expansion is a compliance-note item):

    Node                                        → Behavior tactic (sub_kind)
    ─────────────────────────────────────────────────────────────────
    ProcessNode                                  → execution (process_spawn)
    ProcessNode image∈{iwr,curl,wget,Invoke-WebRequest,
        Invoke-RestMethod,irm,bitsadmin,certutil} → command_and_control (download)
    ProcessNode image∈{ftp,scp,sftp} + upload    → exfiltration (upload)
    ProcessNode image∈{schtasks,at}              → persistence (create_task)
    ProcessNode image∈{sc,new-service,
        install-service}                         → persistence (install_service)
    ProcessNode image∈{reg,Set-ItemProperty}
        + args match HKCU\...\Run                → persistence (autorun_registration)
    ProcessNode image∈{mimikatz,procdump,
        Get-Credential,ntdsutil}                 → credential_access (dump_credentials)
    ProcessNode with semantic_tag="amsi_bypass"  → defense_evasion (bypass_amsi)
    ProcessNode with semantic_tag="etw_bypass"   → defense_evasion (bypass_etw)
    ProcessNode with args.encoded_command=True   → defense_evasion (obfuscation)
    RegistryNode / write_registry side-effect    → persistence (write_registry)
    ScheduledTaskNode                            → persistence (create_task)
    ServiceNode                                  → persistence (install_service)
    MemoryNode / allocate_memory                 → defense_evasion (memory_alloc)
    ShellcodeNode / execute_memory               → execution (shellcode_exec)
    DllLoadNode                                  → execution (dll_load)
    ReflectionNode / kind=static AmsiUtils       → defense_evasion (reflection)
    HttpNode                                     → command_and_control (http)
    DNSNode                                      → dns_query (support behavior)
    FileNode + create_file                       → collection (file_create)
    FileNode + delete_file                       → impact (file_delete)
    ClipboardNode                                → clipboard (support behavior)
    NamedPipeNode                                → named_pipe (support behavior)
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..exec_graph import (
    Behavior,
    ExecGraph,
    ExecNode,
    NodeKind,
    SideEffectVerb,
    TacticKind,
)
from ..plugin_api import Detector, register_detector


# ---------------------------------------------------------------------------
# Case-insensitive image-name sets (canonical, alias-normalised by parsers)
# ---------------------------------------------------------------------------
DOWNLOAD_IMAGES = {
    "invoke-webrequest", "iwr", "wget", "curl",
    "invoke-restmethod", "irm",
    "bitsadmin", "bitsadmin.exe",
    "certutil", "certutil.exe",
    "start-bitstransfer",
}
UPLOAD_IMAGES = {"ftp", "ftp.exe", "scp", "sftp", "tftp", "tftp.exe"}
SCHED_TASK_IMAGES = {"schtasks", "schtasks.exe", "at", "at.exe",
                     "new-scheduledtask", "register-scheduledtask"}
SERVICE_IMAGES = {"sc", "sc.exe", "new-service", "install-service"}
REG_WRITE_IMAGES = {"reg", "reg.exe", "set-itemproperty", "new-itemproperty",
                    "new-item"}
CRED_ACCESS_IMAGES = {"mimikatz", "mimikatz.exe", "procdump", "procdump.exe",
                      "get-credential", "ntdsutil", "ntdsutil.exe",
                      "vaultcmd", "vaultcmd.exe"}

RUN_KEY_MARKERS = (
    r"hkcu\software\microsoft\windows\currentversion\run",
    r"hklm\software\microsoft\windows\currentversion\run",
    r"hkey_current_user\software\microsoft\windows\currentversion\run",
    r"hkey_local_machine\software\microsoft\windows\currentversion\run",
    # PowerShell-style hive:\ prefix (Phase 9.5 RCA fix for GC-100)
    r"hkcu:\software\microsoft\windows\currentversion\run",
    r"hklm:\software\microsoft\windows\currentversion\run",
    # Common CurrentVersion\Run variants without full drive prefix
    r"currentversion\run",
)


def _low(x: Any) -> str:
    return str(x or "").strip().lower()


class BehaviorExtractor(Detector):
    """Emits `Behavior[]` from an ExecGraph. Deterministic, evidence-first."""
    name = "behavior_extractor"

    def detect(self, graph: ExecGraph) -> Dict[str, Any]:
        behaviors: List[Behavior] = []
        for n in graph.nodes:
            # Skip advisor-origin nodes (§ 6.6 — never enter verdict math).
            if n.origin == "advisor":
                continue
            new = self._behaviors_for_node(n)
            for b in new:
                behaviors.append(b)
        return {"behaviors": behaviors}

    # ── per-node dispatch ─────────────────────────────────────────────
    def _behaviors_for_node(self, n: ExecNode) -> List[Behavior]:
        out: List[Behavior] = []
        k = n.kind

        if k == NodeKind.process:
            out.extend(self._process_behaviors(n))

        if k == NodeKind.registry:
            out.append(self._behavior(
                n, TacticKind.persistence, "write_registry",
                {"key": n.args.get("key"), "value": n.args.get("value")},
            ))

        if k == NodeKind.scheduled_task:
            out.append(self._behavior(n, TacticKind.persistence, "create_task",
                                      {"name": n.args.get("name")}))

        if k == NodeKind.service:
            out.append(self._behavior(n, TacticKind.persistence, "install_service",
                                      {"name": n.args.get("name")}))

        if k == NodeKind.memory:
            out.append(self._behavior(n, TacticKind.defense_evasion, "memory_alloc",
                                      {"size": n.args.get("size")}))

        if k == NodeKind.shellcode:
            out.append(self._behavior(n, TacticKind.execution, "shellcode_exec", {}))

        if k == NodeKind.assembly_load or k == NodeKind.reflection:
            out.append(self._behavior(n, TacticKind.defense_evasion, "reflection", {}))

        if k in (NodeKind.http,):
            out.append(self._behavior(n, TacticKind.command_and_control, "http", {}))
            # HTTP nodes emitted from WebClient.DownloadString / DownloadFile
            # / DownloadData style method invocations carry a direction hint
            # ("download" / "upload"). Emit an additional download/upload
            # behavior so T1105 (Ingress Tool Transfer) or T1041 (Exfil over
            # C2 Channel) rules fire deterministically.
            direction = str(n.args.get("direction") or "").lower()
            url = n.args.get("url") or None
            if direction == "download":
                out.append(self._behavior(
                    n, TacticKind.command_and_control, "download",
                    {"url_hint": url, "image": "powershell"},
                ))
            elif direction == "upload":
                out.append(self._behavior(
                    n, TacticKind.exfiltration, "upload",
                    {"url_hint": url, "image": "powershell"},
                ))

        if k == NodeKind.dns:
            out.append(self._behavior(n, TacticKind.dns_query, None, {}))

        if k == NodeKind.file:
            se_verbs = {se.verb for se in n.side_effects}
            if SideEffectVerb.create_file in se_verbs:
                out.append(self._behavior(n, TacticKind.collection, "file_create",
                                          {"path": n.args.get("path")}))
            if SideEffectVerb.delete_file in se_verbs:
                out.append(self._behavior(n, TacticKind.impact, "file_delete",
                                          {"path": n.args.get("path")}))

        if k == NodeKind.clipboard:
            out.append(self._behavior(n, TacticKind.clipboard, None, {}))
        if k == NodeKind.named_pipe:
            out.append(self._behavior(n, TacticKind.named_pipe, None, {}))
        if k == NodeKind.wmi or k == NodeKind.event_sub:
            out.append(self._behavior(n, TacticKind.wmi_subscription, None, {}))

        return out

    # ── process-node classifier ───────────────────────────────────────
    def _process_behaviors(self, n: ExecNode) -> List[Behavior]:
        out: List[Behavior] = []
        img = _low(n.args.get("image"))
        img_bare = img.rsplit(".", 1)[0]  # strip .exe
        args_str = " ".join(str(a) for a in (n.args.get("args") or []))
        args_lower = args_str.lower()

        # Base execution
        out.append(self._behavior(n, TacticKind.execution, "process_spawn",
                                  {"image": img}))

        # Download / C2
        if img in DOWNLOAD_IMAGES or img_bare in DOWNLOAD_IMAGES:
            out.append(self._behavior(
                n, TacticKind.command_and_control, "download",
                {"image": img, "url_hint": self._first_url(args_str)},
            ))
        # Upload
        if img in UPLOAD_IMAGES or img_bare in UPLOAD_IMAGES:
            out.append(self._behavior(n, TacticKind.exfiltration, "upload",
                                      {"image": img}))
        # Scheduled task
        if img in SCHED_TASK_IMAGES or img_bare in SCHED_TASK_IMAGES:
            out.append(self._behavior(n, TacticKind.persistence, "create_task",
                                      {"image": img}))
        # Service
        if img in SERVICE_IMAGES or img_bare in SERVICE_IMAGES:
            out.append(self._behavior(n, TacticKind.persistence, "install_service",
                                      {"image": img}))
        # Registry write
        if img in REG_WRITE_IMAGES or img_bare in REG_WRITE_IMAGES:
            out.append(self._behavior(n, TacticKind.persistence, "write_registry",
                                      {"image": img}))
            # Registry Run-key persistence detection
            for marker in RUN_KEY_MARKERS:
                if marker in args_lower:
                    out.append(self._behavior(
                        n, TacticKind.persistence, "autorun_registration",
                        {"key_hint": marker},
                    ))
                    break
        # Credential access
        if img in CRED_ACCESS_IMAGES or img_bare in CRED_ACCESS_IMAGES:
            out.append(self._behavior(n, TacticKind.credential_access,
                                      "dump_credentials", {"image": img}))

        # Semantic-tag driven (AMSI/ETW bypass, encoded-command obfuscation)
        tag = n.args.get("semantic_tag")
        if tag == "amsi_bypass":
            out.append(self._behavior(n, TacticKind.defense_evasion, "bypass_amsi", {}))
        elif tag == "etw_bypass":
            out.append(self._behavior(n, TacticKind.defense_evasion, "bypass_etw", {}))
        if n.args.get("encoded_command") is True:
            out.append(self._behavior(n, TacticKind.defense_evasion, "obfuscation",
                                      {"kind": "encoded_command"}))

        return out

    # ── helpers ───────────────────────────────────────────────────────
    def _behavior(self, n: ExecNode, tactic: TacticKind,
                  sub: Optional[str], params: Dict[str, Any]) -> Behavior:
        return Behavior(
            tactic=tactic,
            sub_kind=sub,
            evidence_nodes=(n.id,),
            reconstructed=n.reconstructed or "",
            confidence=n.confidence,
            parameters={k: v for k, v in params.items() if v is not None},
        )

    def _first_url(self, s: str) -> Optional[str]:
        import re as _re
        m = _re.search(r"https?://[^\s'\"<>]{4,300}", s)
        return m.group(0) if m else None


# ---------------------------------------------------------------------------
# Register + provide accessor for callers (e.g. /api/rc5/parse in Phase 4.5).
# ---------------------------------------------------------------------------
_INSTANCE = BehaviorExtractor()
register_detector(_INSTANCE)


def extract_behaviors(graph: ExecGraph) -> List[Behavior]:
    return _INSTANCE.detect(graph)["behaviors"]  # type: ignore[return-value]


def get_behavior_extractor() -> BehaviorExtractor:
    return _INSTANCE
