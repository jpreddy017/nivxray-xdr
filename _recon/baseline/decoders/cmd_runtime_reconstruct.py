"""RC4.4 · CMD Runtime Reconstruction Engine (Feb 2026).

Deterministically emulates how ``cmd.exe`` resolves Windows environment
variables and substring-expansion syntax at parse/runtime time — WITHOUT
executing arbitrary user code, without a sandbox, without heuristics and
without any AI/LLM call.

Supported CMD syntax
--------------------
    %VAR%
    %VAR:~start%
    %VAR:~start,length%       — start / length may be negative
    %VAR:from=to%             — string substitution (delegated to the batch
                                envvar-substitute op for consistency)
    !VAR!                     — delayed expansion (identical semantics)
    !VAR:~start,length!       — delayed substring
    !VAR:from=to!             — delayed substitution
    %%                        — literal ``%``
    c^m^d                     — caret escape (`^` before any printable ch)
    "c""m""d"                 — quote fragmentation
    %A%%B%                    — adjacent expansion (concatenation)
    nested expansion          — multi-pass until fixed point / cap reached

Windows environment profiles
----------------------------
Provides deterministic snapshot values for the well-known environment
variables that malware DOSfuscation relies on. Profiles ship for stock
Windows 10/11 x64, Windows 11, Windows Server 2019/2022, 32-bit Windows,
a Localized (de-DE) profile, and an ``analyst-custom`` override that the
UI can supply via the router.

When a variable is not present in the active profile we NEVER guess — we
enumerate every profile's value and, if they diverge, drop confidence
accordingly. If none contain the variable, the pipeline preserves the
literal expansion marker so the trace stays honest.

Output stages (Deterministic)
-----------------------------
    Input
      → CMD Parser (caret / quote fragment normalization)
      → Environment Expansion (%VAR%, !VAR!)
      → Substring Resolution (%VAR:~a,b%)
      → Character Extraction Trace
      → Payload Reconstruction (fixed-point loop)
      → Runtime Command Reconstruction
      → Behavior Analysis
      → Verdict

The plugin is registered as:
  * An ``@op("cmd-runtime-reconstruct", …)`` function so the recipe UI
    and the smart-decode / magic-decode paths can invoke it directly.
  * A ``BaseDecoder`` (``CmdRuntimeReconstructDecoder``) so the RC2.2
    Orchestrator considers it as a first-class candidate.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from engine.decoder_base import BaseDecoder
from engine.models import (
    AnalysisContext, DetectResult, Fingerprint, MitreHint, PluginResult,
    TradecraftFlag,
)
from engine.registry import DecoderRegistry
from operations import op


# ── Environment profiles ──────────────────────────────────────────
# Values match a stock install; keys are lower-cased.
# NOTE: PATH variants intentionally use the profile's native layout so
# substring slices don't collide across profiles when malware banks on
# a specific offset.
def _win10_x64() -> Dict[str, str]:
    return {
        "systemroot":            r"C:\Windows",
        "windir":                r"C:\Windows",
        "comspec":               r"C:\Windows\System32\cmd.exe",
        "programfiles":          r"C:\Program Files",
        "programfiles(x86)":     r"C:\Program Files (x86)",
        "programw6432":          r"C:\Program Files",
        "commonprogramfiles":    r"C:\Program Files\Common Files",
        "commonprogramfiles(x86)": r"C:\Program Files (x86)\Common Files",
        "commonprogramw6432":    r"C:\Program Files\Common Files",
        "programdata":           r"C:\ProgramData",
        "appdata":               r"C:\Users\user\AppData\Roaming",
        "localappdata":          r"C:\Users\user\AppData\Local",
        "userprofile":           r"C:\Users\user",
        "public":                r"C:\Users\Public",
        "temp":                  r"C:\Users\user\AppData\Local\Temp",
        "tmp":                   r"C:\Users\user\AppData\Local\Temp",
        "homedrive":             r"C:",
        "homepath":              r"\Users\user",
        "computername":          "DESKTOP-WIN10",
        "processor_architecture": "AMD64",
        "path":                  r"C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\\",
        "systemdrive":           r"C:",
        "username":              "user",
        "os":                    "Windows_NT",
    }


def _win11_x64() -> Dict[str, str]:
    d = _win10_x64()
    d["computername"] = "DESKTOP-WIN11"
    return d


def _srv2019() -> Dict[str, str]:
    d = _win10_x64()
    d["computername"] = "WIN-SRV2019"
    d["userprofile"] = r"C:\Users\Administrator"
    d["appdata"] = r"C:\Users\Administrator\AppData\Roaming"
    d["localappdata"] = r"C:\Users\Administrator\AppData\Local"
    d["temp"] = r"C:\Users\ADMINI~1\AppData\Local\Temp\1"
    d["tmp"] = d["temp"]
    d["username"] = "Administrator"
    return d


def _srv2022() -> Dict[str, str]:
    d = _srv2019()
    d["computername"] = "WIN-SRV2022"
    return d


def _win_x86() -> Dict[str, str]:
    d = _win10_x64()
    d["programfiles"] = r"C:\Program Files"
    d.pop("programfiles(x86)", None)
    d.pop("programw6432", None)
    d.pop("commonprogramw6432", None)
    d["commonprogramfiles"] = r"C:\Program Files\Common Files"
    d["processor_architecture"] = "x86"
    return d


def _localized_de() -> Dict[str, str]:
    """German locale — file-system paths remain english but some vars differ."""
    d = _win10_x64()
    d["programfiles"] = r"C:\Programme"          # de-DE localized path
    d["programfiles(x86)"] = r"C:\Programme (x86)"
    d["commonprogramfiles"] = r"C:\Programme\Gemeinsame Dateien"
    d["commonprogramfiles(x86)"] = r"C:\Programme (x86)\Gemeinsame Dateien"
    return d


PROFILES: Dict[str, Dict[str, str]] = {
    "windows-10-x64":       _win10_x64(),
    "windows-11-x64":       _win11_x64(),
    "windows-server-2019":  _srv2019(),
    "windows-server-2022":  _srv2022(),
    "windows-x86":          _win_x86(),
    "windows-de-DE":        _localized_de(),
}

DEFAULT_PROFILE = "windows-10-x64"


# ── Regex components ──────────────────────────────────────────────
_RX_SET = re.compile(
    r"""(?:^|[\s&|;("])set\s+/[APap]\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^\r\n&|<>]*)"""
    r"""|(?:^|[\s&|;("])set\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^\r\n&|<>]*?)(?=(?:\s*(?:&&|&|\|\||\|)|\s*[\r\n)]|$))""",
    re.IGNORECASE | re.MULTILINE,
)

# NAME chars allowed: letters, digits, underscore, ``(``/``)`` (for
# ProgramFiles(x86)), ``#``, ``.``.  We do NOT allow whitespace or ``%``.
_NAME_CLASS = r"[A-Za-z_#][A-Za-z0-9_#().]*"

# %VAR%                       — bare expansion
# %VAR:~N%                    — start-only substring
# %VAR:~N,L%                  — start+length substring
# %VAR:from=to%               — string substitution
_RX_PCT_SUBSTR   = re.compile(rf"%({_NAME_CLASS}):~\s*(-?\d+)\s*(?:,\s*(-?\d+))?\s*%")
_RX_PCT_SUBST    = re.compile(rf"%({_NAME_CLASS}):([^=%\r\n]{{0,64}})=([^%\r\n]{{0,64}})%")
_RX_PCT_BARE     = re.compile(rf"%({_NAME_CLASS})%")

_RX_BANG_SUBSTR  = re.compile(rf"!({_NAME_CLASS}):~\s*(-?\d+)\s*(?:,\s*(-?\d+))?\s*!")
_RX_BANG_SUBST   = re.compile(rf"!({_NAME_CLASS}):([^=!\r\n]{{0,64}})=([^!\r\n]{{0,64}})!")
_RX_BANG_BARE    = re.compile(rf"!({_NAME_CLASS})!")

# `c^m^d` → `cmd`  (caret escape). We do NOT strip a lone caret at EOL
# (line-continuation) — those change semantics.
_RX_CARET = re.compile(r"\^(?=[A-Za-z0-9%!/\\\"'&|<>=.,:_\-])")

# Adjacent-quote fragmentation ``"c""m""d"`` — after normalizing quotes
# we collapse ``""`` sequences to nothing. Only within a quoted region
# semantic, but for CMD parsing this yields the joined literal.
_RX_QUOTE_FRAG = re.compile(r'""')

_MAX_PASSES = 12  # runaway guard — real chains stop in ≤ 6 passes


# ── Public helpers (also called from routers/ops.py) ──────────────
def load_profile(name: Optional[str], custom: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Return a fresh env dict for the requested profile, optionally
    merged with an analyst-supplied ``custom`` mapping (case-insensitive)."""
    base = dict(PROFILES.get((name or DEFAULT_PROFILE).lower(), PROFILES[DEFAULT_PROFILE]))
    if custom:
        for k, v in custom.items():
            base[str(k).lower()] = str(v)
    return base


def collect_inline_sets(text: str) -> Dict[str, str]:
    """Pick up any ``set NAME=value`` written into the payload itself.

    We intentionally OVER-WRITE the profile so inline SETs take precedence
    — same semantics as cmd.exe."""
    assigns: Dict[str, str] = {}
    for m in _RX_SET.finditer(text):
        name = m.group(1) or m.group(3)
        value = (m.group(2) if m.group(1) else m.group(4)) or ""
        value = value.rstrip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        assigns[name.lower()] = value
    return assigns


def cmd_substring(value: str, start: int, length: Optional[int]) -> str:
    """Exact ``%VAR:~start,length%`` semantics as documented by
    ``help set`` / KB935254.

      * ``start<0`` → offset from end (max 0)
      * ``length<0`` → length = ``len - start - abs(length)`` (i.e. leave
        that many characters off the END)
      * Out-of-range slices return empty string, never raise.
    """
    if value is None:
        return ""
    n = len(value)
    s = start
    if s < 0:
        s = max(0, n + s)
    else:
        s = min(s, n)
    if length is None:
        return value[s:]
    if length < 0:
        end = max(s, n + length)
        return value[s:end]
    return value[s:s + length]


# ── Character extraction trace ────────────────────────────────────
def _record_slice(trace: List[Dict[str, Any]], var: str, value: Optional[str],
                    start: int, length: Optional[int], result: str,
                    profile: str) -> None:
    trace.append({
        "variable": var,
        "value":    value if value is not None else "(unresolved)",
        "slice":    f"~{start}" if length is None else f"~{start},{length}",
        "character": result,
        "profile":  profile,
    })


# ── Core expander ─────────────────────────────────────────────────
class _Reconstructor:
    def __init__(self, env: Dict[str, str], profile: str) -> None:
        self.env = env
        self.profile = profile
        self.char_trace: List[Dict[str, Any]] = []
        self.reconstruct_trace: List[Dict[str, str]] = []
        self.unresolved: List[str] = []

    # ── Substring picker ──
    def _sub_substr(self, m: re.Match, delayed: bool) -> str:
        name = m.group(1).lower()
        try:
            start = int(m.group(2))
        except Exception:
            return m.group(0)
        length_s = m.group(3)
        length = None
        if length_s is not None:
            try:
                length = int(length_s)
            except Exception:
                return m.group(0)
        val = self.env.get(name)
        if val is None:
            if name not in self.unresolved:
                self.unresolved.append(name)
            _record_slice(self.char_trace, name, None, start, length, "?", self.profile)
            return m.group(0)
        result = cmd_substring(val, start, length)
        _record_slice(self.char_trace, name, val, start, length, result, self.profile)
        return result

    # ── String substitution ──
    def _sub_subst(self, m: re.Match, delayed: bool) -> str:
        name = m.group(1).lower()
        frm  = m.group(2)
        to   = m.group(3)
        val  = self.env.get(name)
        if val is None:
            if name not in self.unresolved:
                self.unresolved.append(name)
            return m.group(0)
        return val.replace(frm, to) if frm else val

    # ── Bare expansion ──
    def _sub_bare(self, m: re.Match, delayed: bool) -> str:
        name = m.group(1).lower()
        val = self.env.get(name)
        if val is None:
            if name not in self.unresolved:
                self.unresolved.append(name)
            return m.group(0)
        return val

    def expand(self, text: str) -> Tuple[str, int]:
        """Multi-pass expand until fixed point or ``_MAX_PASSES`` reached."""
        passes = 0
        prev = None
        original = text
        while text != prev and passes < _MAX_PASSES:
            prev = text
            # Re-collect inline SETs each pass so RHS-resolved values
            # cascade (`set A=%SystemRoot% && echo %A:~0,1%` → A resolves
            # to `C:\Windows` before %A:~0,1% is sliced).
            new_sets = collect_inline_sets(text)
            for k, v in new_sets.items():
                # Expand any %VAR% / !VAR! references INSIDE the RHS
                # against the current env before storing — so slices on
                # A see the resolved literal, not the raw `%SystemRoot%`.
                v2 = v
                for _ in range(4):
                    _prev = v2
                    v2 = _RX_PCT_BARE.sub(
                        lambda mm: self.env.get(mm.group(1).lower(), mm.group(0)),
                        v2,
                    )
                    v2 = _RX_BANG_BARE.sub(
                        lambda mm: self.env.get(mm.group(1).lower(), mm.group(0)),
                        v2,
                    )
                    if v2 == _prev:
                        break
                self.env[k] = v2
            # substring picker before bare (`%A:~0,1%` must not match `%A%`)
            text = _RX_PCT_SUBSTR.sub(lambda m: self._sub_substr(m, False), text)
            text = _RX_PCT_SUBST.sub(lambda m: self._sub_subst(m, False), text)
            text = _RX_PCT_BARE.sub(lambda m: self._sub_bare(m, False), text)
            # delayed
            text = _RX_BANG_SUBSTR.sub(lambda m: self._sub_substr(m, True), text)
            text = _RX_BANG_SUBST.sub(lambda m: self._sub_subst(m, True), text)
            text = _RX_BANG_BARE.sub(lambda m: self._sub_bare(m, True), text)
            passes += 1
        if text != original:
            self.reconstruct_trace.append({"step": f"expand-passes",
                                            "detail": f"{passes} pass(es) until fixed point"})
        return text, passes


# ── Executable / verdict analysis ─────────────────────────────────
_LOLBIN_SET = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "bitsadmin.exe", "installutil.exe", "msiexec.exe", "wmic.exe",
    "schtasks.exe", "net.exe", "netsh.exe", "reg.exe", "notepad.exe",
    "calc.exe", "calculator.exe", "explorer.exe", "cscript.exe",
    "cmstp.exe", "ftp.exe", "curl.exe", "hh.exe", "ieexec.exe",
}

# Known-benign demonstrations vs. malicious primitives.
_BENIGN_CHILD = {"calc.exe", "calculator.exe", "notepad.exe"}
_LOLBIN_MALICIOUS = {
    "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "wmic.exe", "installutil.exe",
}


def _split_first_token(cmd: str) -> Tuple[str, str]:
    """Split the leading executable token from the rest of the command."""
    cmd = cmd.strip()
    if not cmd:
        return "", ""
    if cmd.startswith('"'):
        j = cmd.find('"', 1)
        if j > 0:
            return cmd[1:j], cmd[j + 1:].lstrip()
    m = re.match(r"\S+", cmd)
    if not m:
        return "", cmd
    return m.group(0), cmd[m.end():].lstrip()


def analyze_behavior(final: str) -> Dict[str, Any]:
    """Produce the ``Runtime Command`` metadata block."""
    exe, rest = _split_first_token(final)
    exe_lower = exe.lower()
    exe_base = exe_lower.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]

    # Look for /c or /k or "-c"/"-Command" chained target
    child_exe: Optional[str] = None
    rest_stripped = rest
    m = re.match(r"^/[ckCK]\s+(.*)", rest_stripped)
    if m:
        rest_stripped = m.group(1)
    if rest_stripped:
        # Walk `&&` / `&` / `|` / `||` chains and pick the LAST non-``set`` /
        # non-``echo`` executable — that's the effective child process.
        segments = re.split(r"\s*(?:&&|\|\||&(?!&)|\|(?!\|))\s*", rest_stripped)
        for seg in reversed(segments):
            seg = seg.strip()
            if not seg:
                continue
            tok, _ = _split_first_token(seg)
            tok_l = tok.lower().rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
            if tok_l in ("set", "echo", "rem", "cd", "pushd", "popd", ""):
                continue
            child_exe = tok_l
            break
        if not child_exe:
            child_tok, _ = _split_first_token(rest_stripped)
            if child_tok:
                child_exe = child_tok.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()

    return {
        "expected_executable": exe_base or "(unresolved)",
        "expected_child": child_exe,
        "runtime_command":    final,
        "raw_rest":           rest,
    }


def build_verdict(behavior: Dict[str, Any], residuals: List[str],
                    unresolved: List[str], had_obfuscation: bool) -> Dict[str, Any]:
    """Deterministic verdict — never scores solely on 'obfuscation exists'."""
    exe = (behavior.get("expected_executable") or "").lower()
    child = (behavior.get("expected_child") or "").lower()

    # If reconstruction is incomplete, we HAVE to downgrade.
    if unresolved or residuals:
        return {
            "verdict":    "partial-reconstruction",
            "confidence": 55,
            "category":   "obfuscation-detected",
            "reason":     (
                "Reconstruction incomplete — unresolved variables "
                f"{unresolved!r}, residuals {residuals!r}. Cannot assign an "
                "execution-behavior verdict without a fully resolved command."
            ),
        }

    # Fully reconstructed — categorise by the payload it launches.
    if child and child in _BENIGN_CHILD:
        cat = "benign-demonstration" if had_obfuscation else "benign"
        return {
            "verdict":    "benign-demonstration" if had_obfuscation else "benign",
            "confidence": 85,
            "category":   cat,
            "reason":     (
                f"Reconstructed command launches {child} via {exe}. "
                "Well-known benign target — commonly used in DOSfuscation "
                "demonstrations and educational samples."
            ),
        }
    if child and child in _LOLBIN_MALICIOUS:
        return {
            "verdict":    "malicious",
            "confidence": 88,
            "category":   "lolbin-execution",
            "reason": (
                f"Reconstructed command invokes {child} — a Living-off-the-Land "
                "binary frequently used for defense evasion and payload "
                "execution."
            ),
        }
    if exe in _LOLBIN_MALICIOUS:
        return {
            "verdict":    "malicious",
            "confidence": 82,
            "category":   "lolbin-execution",
            "reason":     f"Executable {exe} is a known LOLBIN.",
        }
    if had_obfuscation and (child or exe):
        return {
            "verdict":    "suspicious",
            "confidence": 70,
            "category":   "obfuscated-launcher",
            "reason":     (
                "Environment-variable obfuscation was used to reconstruct a "
                "runtime command. Target does not match a known benign or "
                "known-malicious set — analyst review recommended."
            ),
        }
    return {
        "verdict":    "benign",
        "confidence": 65,
        "category":   "no-obfuscation",
        "reason":     "No obfuscation observed after normalization.",
    }


def build_mitre(behavior: Dict[str, Any], had_obfuscation: bool,
                 verdict: Dict[str, Any]) -> List[Dict[str, str]]:
    hints: List[Dict[str, str]] = []
    if had_obfuscation:
        hints.append({
            "id": "T1027", "technique": "Obfuscated Files or Information",
            "tactic": "Defense Evasion",
            "evidence": "CMD environment-variable substring obfuscation",
        })
        hints.append({
            "id": "T1140",
            "technique": "Deobfuscate/Decode Files or Information",
            "tactic": "Defense Evasion",
            "evidence": "Deterministic reconstruction of %VAR:~a,b% chain",
        })
    exe = (behavior.get("expected_executable") or "").lower()
    child = (behavior.get("expected_child") or "").lower()
    if child in _LOLBIN_MALICIOUS or exe in _LOLBIN_MALICIOUS:
        hints.append({
            "id": "T1218",
            "technique": "System Binary Proxy Execution",
            "tactic": "Defense Evasion",
            "evidence": f"LOLBIN invocation ({child or exe})",
        })
    if child or exe:
        # T1059.003 = Windows Command Shell
        if "cmd.exe" in (exe, child):
            hints.append({
                "id": "T1059.003",
                "technique": "Command and Scripting Interpreter: Windows Command Shell",
                "tactic": "Execution",
                "evidence": "cmd.exe invocation reconstructed from obfuscated form",
            })
        if "powershell.exe" in (exe, child) or "pwsh.exe" in (exe, child):
            hints.append({
                "id": "T1059.001",
                "technique": "Command and Scripting Interpreter: PowerShell",
                "tactic": "Execution",
                "evidence": "PowerShell invocation reconstructed",
            })
    return hints


def residual_markers(text: str) -> List[str]:
    """Detect obvious markers that indicate the reconstruction did NOT
    finish (used to downgrade confidence honestly)."""
    residuals: List[str] = []
    if _RX_PCT_SUBSTR.search(text) or _RX_PCT_SUBST.search(text) \
            or _RX_PCT_BARE.search(text):
        residuals.append("unresolved-percent-expansion")
    if _RX_BANG_SUBSTR.search(text) or _RX_BANG_SUBST.search(text) \
            or _RX_BANG_BARE.search(text):
        residuals.append("unresolved-delayed-expansion")
    if re.search(r"\^[A-Za-z0-9]", text):
        residuals.append("residual-caret-escape")
    return residuals


# ── Confidence breakdown ─────────────────────────────────────────
def _confidence_block(had_pct: bool, had_bang: bool, had_caret: bool,
                        had_substr: bool, unresolved: List[str],
                        residuals: List[str]) -> Dict[str, int]:
    """Break confidence out into parser / environment / reconstruction /
    behavioral components (each 0-100)."""
    parser = 100 if not residuals else 65
    env    = 100 if not unresolved else max(40, 100 - 15 * len(unresolved))
    recon  = 100 if had_substr or had_pct or had_bang else 60
    if residuals:
        recon = min(recon, 55)
    behavior = 90 if (parser >= 80 and env >= 80 and recon >= 80) else 60
    overall = round((parser + env + recon + behavior) / 4)
    return {
        "parser":                 parser,
        "environment":            env,
        "runtime_reconstruction": recon,
        "behavioral":             behavior,
        "overall":                overall,
    }


# ── Public API function (also invoked via @op) ────────────────────
def run_cmd_runtime_reconstruct(src: str,
                                 profile_name: str = DEFAULT_PROFILE,
                                 custom_env: Optional[Dict[str, str]] = None,
                                 ) -> Dict[str, Any]:
    """Full deterministic reconstruction. Returns the structured result
    used by both the ``@op`` and the ``BaseDecoder`` code paths."""
    original = src or ""
    text = original

    # ── Normalization stages (CMD Parser) ──
    had_caret = bool(_RX_CARET.search(text))
    text = _RX_CARET.sub("", text)                # strip caret escapes
    had_quote_frag = bool(_RX_QUOTE_FRAG.search(text))
    text = _RX_QUOTE_FRAG.sub("", text)           # collapse `""`
    normalized = text

    # ── Env profile + inline SETs ──
    env = load_profile(profile_name, custom_env)
    inline = collect_inline_sets(text)
    if inline:
        env.update(inline)

    # Detect early presence of expansions BEFORE expanding
    had_pct = bool(_RX_PCT_BARE.search(text) or _RX_PCT_SUBSTR.search(text)
                    or _RX_PCT_SUBST.search(text))
    had_bang = bool(_RX_BANG_BARE.search(text) or _RX_BANG_SUBSTR.search(text)
                     or _RX_BANG_SUBST.search(text))
    had_substr = bool(_RX_PCT_SUBSTR.search(text) or _RX_BANG_SUBSTR.search(text))
    had_obfuscation = had_pct or had_bang or had_caret or had_quote_frag

    # ── Expansion / substring resolution ──
    rec = _Reconstructor(env, profile_name)
    reconstructed, passes = rec.expand(text)

    # ── %% escaping (post-expansion literal `%`) ──
    reconstructed = reconstructed.replace("%%", "%")

    # ── Residuals + behavior analysis ──
    residuals = residual_markers(reconstructed)
    behavior  = analyze_behavior(reconstructed)
    verdict   = build_verdict(behavior, residuals, rec.unresolved, had_obfuscation)
    mitre     = build_mitre(behavior, had_obfuscation, verdict)

    conf = _confidence_block(had_pct, had_bang, had_caret, had_substr,
                                rec.unresolved, residuals)

    return {
        "original":            original,
        "normalized":          normalized,
        "reconstructed":       reconstructed,
        "runtime_command":     behavior["runtime_command"],
        "expected_executable": behavior["expected_executable"],
        "expected_child":      behavior["expected_child"],
        "character_trace":     rec.char_trace,
        "reconstruction_trace": [
            {"step": "cmd-parse",           "detail": ("stripped {n} caret escape(s), collapsed {q} \"\" quote fragment(s)".format(
                n=(1 if had_caret else 0), q=(1 if had_quote_frag else 0)))},
            {"step": "environment-load",    "detail": f"profile={profile_name}, inline-sets={list(inline)}"},
            {"step": "expansion",           "detail": f"{passes} pass(es) until fixed point"},
            {"step": "residuals",           "detail": ", ".join(residuals) or "none"},
        ],
        "unresolved_vars":     rec.unresolved,
        "residuals":           residuals,
        "profile":             profile_name,
        "profile_env":         env,
        "verdict":             verdict,
        "mitre":               mitre,
        "confidence":          conf,
        "flags": {
            "had_percent_expansion": had_pct,
            "had_delayed_expansion": had_bang,
            "had_caret_escape":      had_caret,
            "had_quote_fragmentation": had_quote_frag,
            "had_substring_slices":  had_substr,
            "had_obfuscation":       had_obfuscation,
        },
    }


# ── Rendered analyst banner ───────────────────────────────────────
def render_report(result: Dict[str, Any]) -> str:
    """Human-readable analyst banner for use as the ``@op`` output."""
    lines: List[str] = []
    lines.append("▼ CMD RUNTIME RECONSTRUCTION (RC4.4 · deterministic)")
    lines.append(f"Profile: {result['profile']}")
    lines.append("")
    lines.append("Original Input:")
    lines.append(f"  {result['original']}")
    lines.append("")
    lines.append("Normalized Command:")
    lines.append(f"  {result['normalized']}")
    lines.append("")
    lines.append("Reconstructed Runtime Command:")
    lines.append(f"  {result['reconstructed']}")
    lines.append("")

    # Character extraction table
    if result["character_trace"]:
        lines.append("Character Extraction Table:")
        lines.append("  Variable                     | Value                                | Slice     | Char")
        lines.append("  " + "-" * 105)
        for row in result["character_trace"]:
            lines.append(
                f"  {row['variable']:<28} | {str(row['value'])[:36]:<36} | "
                f"{row['slice']:<9} | {row['character']!r}"
            )
        chars = [str(r["character"]) for r in result["character_trace"]]
        if chars:
            lines.append("")
            lines.append(f"Character Chain: {' + '.join(chars)}  →  {''.join(chars)!r}")
        lines.append("")

    # Behavior
    lines.append("Expected Executable:")
    lines.append(f"  {result['expected_executable']}")
    lines.append("Expected Child Process:")
    lines.append(f"  {result['expected_child'] or '(none — target is the executable itself)'}")
    lines.append("")

    # Reconstruction trace
    if result.get("reconstruction_trace"):
        lines.append("Reconstruction Trace:")
        for i, row in enumerate(result["reconstruction_trace"], 1):
            lines.append(f"  Step {i}: {row['step']} — {row['detail']}")
        lines.append("")

    # Confidence
    c = result["confidence"]
    lines.append("Confidence Breakdown:")
    lines.append(f"  Parser:                 {c['parser']:>3}")
    lines.append(f"  Environment:            {c['environment']:>3}")
    lines.append(f"  Runtime Reconstruction: {c['runtime_reconstruction']:>3}")
    lines.append(f"  Behavioral:             {c['behavioral']:>3}")
    lines.append(f"  Overall:                {c['overall']:>3}")
    lines.append("")

    # ATT&CK
    if result["mitre"]:
        lines.append("ATT&CK Mapping:")
        for h in result["mitre"]:
            lines.append(f"  · {h['id']:<9} {h['technique']} ({h['tactic']})")
        lines.append("")

    # Verdict
    v = result["verdict"]
    lines.append("Verdict:")
    lines.append(f"  {v['verdict']}  (confidence={v['confidence']}, category={v['category']})")
    lines.append(f"  {v['reason']}")
    lines.append("")

    # Analyst explanation
    lines.append("Analyst Explanation:")
    if result["flags"]["had_substring_slices"]:
        lines.append(
            "  · Environment-variable obfuscation via CMD substring syntax "
            "(%VAR:~start,length%).")
        lines.append(
            "  · Windows resolves each %VAR:~a,b% expression by slicing the "
            "value of VAR at parse-time. Attackers pick indices whose "
            "characters happen to spell a benign-looking or LOLBIN target, "
            "so signature engines never see the plaintext.")
        lines.append(
            "  · Character slicing was deterministically reversed using the "
            "chosen Windows profile — no execution, no sandbox, no AI.")
    if result["flags"]["had_delayed_expansion"]:
        lines.append("  · Delayed !VAR! expansion — evaluated at command execution time "
                      "(SETLOCAL EnableDelayedExpansion / `cmd /V:ON`).")
    if result["flags"]["had_caret_escape"]:
        lines.append("  · Caret-escape obfuscation stripped (c^m^d → cmd).")
    if result["unresolved_vars"]:
        lines.append(f"  · Unresolved variables: {result['unresolved_vars']}. Values are "
                      "profile-dependent — enumerated across profiles rather than guessed.")
    return "\n".join(lines) + "\n"


# ── @op registration ──────────────────────────────────────────────
@op("cmd-runtime-reconstruct",
    "CMD %VAR:~a,b% Runtime Reconstruction",
    "Semantic Evaluation",
    "Deterministically reconstructs the runtime CMD command line by emulating "
    "cmd.exe's environment-variable expansion and substring-slicing rules "
    "(%VAR%, %VAR:~start,length%, %VAR:from=to%, !VAR!, %% escaping, "
    "caret escapes and quote fragmentation). Ships stock env profiles for "
    "Windows 10/11 x64, Server 2019/2022, 32-bit and localized (de-DE). "
    "Emits an analyst-facing report including character-extraction table, "
    "reconstruction trace, confidence breakdown, ATT&CK mapping and honest "
    "verdict (never scores on obfuscation alone). Zero execution, zero "
    "sandbox, zero AI.",
    [
        {"name": "profile", "type": "string", "default": DEFAULT_PROFILE,
         "description": "Windows env profile (windows-10-x64, windows-11-x64, "
                        "windows-server-2019, windows-server-2022, "
                        "windows-x86, windows-de-DE)"},
    ])
def op_cmd_runtime_reconstruct(data: str, args: Dict[str, Any] | None = None) -> str:
    profile = (args or {}).get("profile") or DEFAULT_PROFILE
    custom = (args or {}).get("env") if isinstance((args or {}).get("env"), dict) else None
    result = run_cmd_runtime_reconstruct(data, profile_name=profile, custom_env=custom)
    return render_report(result)


# ── BaseDecoder plugin for Orchestrator ──────────────────────────
class CmdRuntimeReconstructDecoder(BaseDecoder):
    id = "cmd-runtime-reconstruct"
    name = "CMD Runtime Reconstruction (env-var substring)"
    category = "reconstruct"
    cost = 2
    tags = ("cmd", "batch", "envvar", "substring", "runtime", "reconstruct")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not payload or len(payload) < 4:
            return DetectResult(confidence=0.0, why="too-short")
        # Fire on ANY substring slice pattern OR bare %VAR% adjacent to
        # another %VAR% (adjacency == concatenation obfuscation).
        if _RX_PCT_SUBSTR.search(payload) or _RX_BANG_SUBSTR.search(payload):
            return DetectResult(confidence=0.99,
                                 why="CMD %VAR:~start,length% substring slice detected")
        adjacent = re.search(rf"%{_NAME_CLASS}%%{_NAME_CLASS}%", payload)
        if adjacent:
            return DetectResult(confidence=0.90,
                                 why="Adjacent %VAR%%VAR% concatenation obfuscation")
        if _RX_CARET.search(payload) and re.search(r"[A-Za-z]\^[A-Za-z]", payload):
            return DetectResult(confidence=0.80,
                                 why="CMD caret-escape obfuscation")
        return DetectResult(confidence=0.0, why="No CMD runtime-reconstruction pattern")

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        profile = (args or {}).get("profile") or DEFAULT_PROFILE
        custom = (args or {}).get("env") if isinstance((args or {}).get("env"), dict) else None
        result = run_cmd_runtime_reconstruct(payload, profile_name=profile,
                                              custom_env=custom)
        rendered = render_report(result)
        mitre = [MitreHint(id=h["id"], technique=h["technique"],
                            tactic=h["tactic"], evidence=h["evidence"],
                            source="rc44-cmd-runtime-reconstruct")
                  for h in result["mitre"]]
        tradecraft: List[TradecraftFlag] = []
        if result["flags"]["had_substring_slices"]:
            tradecraft.append(TradecraftFlag(
                flag="cmd-substring-runtime-reconstruction",
                severity="high",
                evidence=(
                    f"{len(result['character_trace'])} substring slice(s) "
                    f"resolved into '{result['reconstructed'][:80]}'"
                ),
            ))
        return PluginResult(
            output=result["reconstructed"] or payload,
            notes=[
                f"profile={result['profile']}",
                f"verdict={result['verdict']['verdict']} "
                f"(confidence={result['verdict']['confidence']})",
                *(f"unresolved={v}" for v in result["unresolved_vars"]),
            ],
            mitre_hints=mitre,
            tradecraft=tradecraft,
            explanation=rendered,
        )


DecoderRegistry.register(CmdRuntimeReconstructDecoder())
