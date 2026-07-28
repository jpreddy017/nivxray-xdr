"""lateral_admin · credentialed remote administration primitives.

Fires when the artefact contains behaviour that establishes remote
administration capability — PsExec with explicit credentials,
Enable-PSRemoting / WinRM configuration, or firewall reconfiguration
that opens remote-management channels.

These primitives are *dual-use*: they are what legitimate admins run
AND what post-compromise attackers run. This module never claims the
activity is malicious on its own — it fires the appropriate
LATERAL_MOVEMENT / DEFENSE_EVASION intents so the Verdict Engine can
score the *composition* of behaviours and analysts can pivot on the
Behavior Graph. Attribution (ransomware / APT / campaign) is
explicitly out of scope.
"""
from __future__ import annotations

import re

from ...evidence import Evidence
from ..models import Intent, IntentCategory, RiskBand

# ── PsExec with explicit credentials on the command line ───────
# ``PsExec.exe \\host -u user -p password [command]`` — the smoking
# gun for credentialed remote execution. Requires BOTH `-u` AND `-p`
# (or `-accepteula` equivalents) to fire — bare `PsExec.exe` alone is
# not enough.
_PSEXEC_RE      = re.compile(r"(?i)\bpsexec(?:\.exe)?\b")
_PSEXEC_HOST_RE = re.compile(r"(?i)\bpsexec(?:\.exe)?\b[^\n]*?\\\\([A-Za-z0-9._\-]+)")
_PSEXEC_USER_RE = re.compile(r"(?i)-u[= \t]+[.\\]*([A-Za-z0-9._\-\\]{1,64})")
_PSEXEC_PASS_RE = re.compile(r"(?i)-p[= \t]+([^\s'\"]{1,64})")
_PSEXEC_ELEV_RE = re.compile(r"(?i)\bpsexec(?:\.exe)?\b[^\n]*?[ \t]-[hs]\b")

# ── Remote-management enablement (WinRM / PSRemoting) ──────────
_ENABLE_PSREMOTING_RE  = re.compile(r"(?i)\bEnable-PSRemoting\b")
_SET_WINRM_STARTUP_RE  = re.compile(
    r"(?i)\bSet-Service\b[^\n]{0,200}?\bWinRM\b[^\n]{0,200}?\b-StartupType\b[ \t]+Automatic"
)
_START_WINRM_RE        = re.compile(r"(?i)\bStart-Service\b[^\n]{0,80}?\bWinRM\b")
_WINRM_QC_RE           = re.compile(r"(?i)\bwinrm\b[ \t]+quickconfig\b")

# ── Firewall configuration that opens remote-management channels ──
_ENABLE_FW_RULE_RE = re.compile(r"(?i)\bEnable-NetFirewallRule\b")
_NETSH_FW_RE       = re.compile(r"(?i)\bnetsh\b[ \t]+advfirewall\b")
_FW_DISPLAY_GROUPS_RE = re.compile(
    r"(?i)-DisplayGroup[ \t]+['\"]([^'\"\n]{1,80})['\"]"
)


class PsExecCredentialedRule:
    """Fires LATERAL_MOVEMENT when PsExec is invoked with explicit
    ``-u`` AND ``-p`` credentials on the command line."""
    NAME = "psexec_credentialed"

    def detect(self, artefact_text: str, meta: dict) -> list[Intent]:
        text = artefact_text or ""
        if not _PSEXEC_RE.search(text):
            return []
        user_m = _PSEXEC_USER_RE.search(text)
        pass_m = _PSEXEC_PASS_RE.search(text)
        if not (user_m and pass_m):
            return []

        host_m = _PSEXEC_HOST_RE.search(text)
        target_host = host_m.group(1) if host_m else "remote host"
        elevated = bool(_PSEXEC_ELEV_RE.search(text))

        evidence: list[Evidence] = [
            Evidence(
                source="intent.psexec_credentialed",
                observation=f"PsExec targeting \\\\{target_host}",
                confidence=90,
                rationale=(
                    "PsExec invoked against a remote host — credentialed "
                    "remote-execution primitive."
                ),
                meta={"primitive": "psexec", "target": target_host, "mitre": "T1021.002"},
            ),
            Evidence(
                source="intent.psexec_credentialed",
                observation=f"-u {user_m.group(1)}",
                confidence=90,
                rationale=("Explicit user credential passed on the command line — "
                            "authenticates as a specific principal on the remote host."),
                meta={"primitive": "psexec:-u", "user": user_m.group(1), "mitre": "T1078"},
            ),
            Evidence(
                source="intent.psexec_credentialed",
                observation="-p <redacted>",
                confidence=90,
                rationale=("Explicit password on the command line — credential "
                            "material is exposed in process arguments (no MITRE "
                            "mapping cited without corroborating discovery evidence)."),
                meta={"primitive": "psexec:-p"},
            ),
        ]
        if elevated:
            evidence.append(Evidence(
                source="intent.psexec_credentialed",
                observation="-h / -s (elevated remote session)",
                confidence=90,
                rationale=("PsExec `-h` / `-s` requests an elevated / SYSTEM-integrity "
                            "session on the remote host. Legitimate admins use this too; "
                            "no elevation-abuse ATT&CK ID is emitted without a "
                            "corroborating bypass pattern."),
                meta={"primitive": "psexec:elev"},
            ))

        return [Intent(
            category=IntentCategory.LATERAL_MOVEMENT,
            purpose=(
                f"PsExec remote execution against {target_host} with explicit "
                "credentials on the command line"
                + (" and elevated-session request" if elevated else "")
                + "."
            ),
            risk=RiskBand.HIGH,
            rationale=(
                "PsExec + explicit credentials + a remote target is the "
                "canonical credentialed-remote-execution primitive. "
                "Legitimate administration or post-compromise activity "
                "cannot be distinguished from the artefact alone."
            ),
            evidence=evidence,
            confidence=90,
            mitre_ids=["T1021.002", "T1078"],
        )]


class RemoteManagementEnablementRule:
    """Fires LATERAL_MOVEMENT when the payload enables PowerShell
    Remoting / WinRM — establishing a remote-management channel."""
    NAME = "remote_management_enablement"

    def detect(self, artefact_text: str, meta: dict) -> list[Intent]:
        text = artefact_text or ""
        hits: list[tuple[str, str]] = []
        if _ENABLE_PSREMOTING_RE.search(text):
            hits.append(("Enable-PSRemoting", "T1021.006"))
        if _SET_WINRM_STARTUP_RE.search(text):
            hits.append(("Set-Service WinRM -StartupType Automatic", "T1543.003"))
        if _START_WINRM_RE.search(text):
            hits.append(("Start-Service WinRM", "T1021.006"))
        if _WINRM_QC_RE.search(text):
            hits.append(("winrm quickconfig", "T1021.006"))
        if not hits:
            return []

        evidence = [Evidence(
            source="intent.remote_management_enablement",
            observation=snip,
            confidence=88,
            rationale=("Configures the WinRM / PowerShell-Remoting service "
                        "so remote commands can execute on this host."),
            meta={"primitive": snip, "mitre": mid},
        ) for snip, mid in hits]

        # Dedup MITRE while preserving order
        seen: set[str] = set()
        mitre: list[str] = []
        for _, mid in hits:
            if mid not in seen:
                seen.add(mid)
                mitre.append(mid)

        return [Intent(
            category=IntentCategory.LATERAL_MOVEMENT,
            purpose=(
                "Enables PowerShell Remoting and configures the WinRM "
                "service for automatic startup — establishes a persistent "
                "remote-command channel on the host."
            ),
            risk=RiskBand.HIGH,
            rationale=(
                "Observation: WinRM / PSRemoting is being turned on. "
                "Interpretation is dual-use — legitimate administration or "
                "post-compromise remote-management enablement. Verdict Engine "
                "scores composition with other observed behaviours; the "
                "observation itself is not attribution."
            ),
            evidence=evidence,
            confidence=88,
            mitre_ids=mitre,
        )]


class FirewallConfigurationRule:
    """Emits ``firewall_configuration`` observation via the
    DEFENSE_EVASION intent category (schema `1.1.0` reuses that
    kind — the observation-form purpose keeps the analyst-facing
    text neutral). ATT&CK label ``T1562.004`` is attached as a
    tag on the intent, not the behaviour name."""
    NAME = "firewall_configuration"

    def detect(self, artefact_text: str, meta: dict) -> list[Intent]:
        text = artefact_text or ""
        hits: list[str] = []
        for m in _ENABLE_FW_RULE_RE.finditer(text):
            hits.append("Enable-NetFirewallRule")
        for m in _NETSH_FW_RE.finditer(text):
            hits.append("netsh advfirewall")
        if not hits:
            return []

        groups = [g for g in _FW_DISPLAY_GROUPS_RE.findall(text)]
        evidence: list[Evidence] = [Evidence(
            source="intent.firewall_configuration",
            observation=h,
            confidence=85,
            rationale=("Modifies Windows Firewall rules — observation only. "
                        "Whether this represents administration or evasion is "
                        "resolved by composition with other observed behaviours."),
            meta={"primitive": h, "mitre": "T1562.004"},
        ) for h in hits]
        for grp in groups[:4]:
            evidence.append(Evidence(
                source="intent.firewall_configuration",
                observation=f"-DisplayGroup '{grp}'",
                confidence=85,
                rationale=f"Firewall rule group `{grp}` enabled — observation only.",
                meta={"primitive": "fw:group", "group": grp, "mitre": "T1562.004"},
            ))

        return [Intent(
            category=IntentCategory.DEFENSE_EVASION,
            purpose=(
                "Modifies Windows Firewall rules — opens or reconfigures "
                "network-management or file-sharing channels on the host."
            ),
            risk=RiskBand.HIGH,
            rationale=(
                "Observation: firewall rules are being changed. "
                "Interpretation as `defense_evasion` is only warranted when "
                "composed with credentialed remote execution or remote-"
                "management enablement — the Verdict Engine handles the "
                "composition, this rule only reports what was observed."
            ),
            evidence=evidence,
            confidence=85,
            mitre_ids=["T1562.004"],
        )]


PSEXEC_RULE               = PsExecCredentialedRule()
REMOTE_MGMT_RULE          = RemoteManagementEnablementRule()
FIREWALL_RULE             = FirewallConfigurationRule()
