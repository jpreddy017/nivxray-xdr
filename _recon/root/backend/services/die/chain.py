"""
DIE · Chain Analyzer
────────────────────
Owner-locked 2026-02-16 (pm) — direct response to the "attacker
placed a chain of commandlines in one INPUT and NivXRay collapsed
them into a single flat verdict" complaint.

The chain analyzer:

1. Splits the input into *ordered steps* using a quote-, paren-, and
   comment-aware tokenizer (respects newlines · `;` · `&` · `&&` ·
   `||`).  Payload strings passed to nested shells (``powershell -c
   "…"``, ``cmd /c "…"``, ``bash -c '…'``) are unwrapped as CHILD
   steps so the analyst sees the full recursion.

2. Runs ``analyze()`` on each step independently — every step gets
   its OWN language, AST, MITRE, IOCs, DKP matches, obfuscation
   score.

3. Classifies each step's INTENT into an ATT&CK tactic bucket
   (Discovery · Execution · Persistence · Privilege Escalation ·
   Defense Evasion · Credential Access · Lateral Movement · Impact
   · Command and Control · Collection · Exfiltration · Impair
   Defenses).  Purely deterministic — driven by DKP hits, MITRE
   technique lookups, and lexical fallbacks.

4. Emits a step-ordered ``narrative_bullets`` list that reads like a
   real IR timeline:

       Step 1 — Discovery · `whoami`
       Step 2 — Impact Prep · vssadmin delete shadows
       Step 3 — Persistence · schtasks /create ...

5. Aggregates step-level MITRE / DKP / IOC / LOLBAS into a top-level
   union so downstream (CEM · verdict · investigation) still sees a
   single record.

Purely deterministic.  Same input → same output.  Zero backend
schema changes.
"""
from __future__ import annotations
import re
from typing import Any, Dict, List, Optional, Tuple


# ── deterministic tokenizer / splitter ────────────────────────────
# Design decision (2026-02-16 pm): the pipe `|` is NOT a chain
# separator — it's data-flow within a single command (curl | bash).
# Newlines are treated as separators ONLY when a hard shell separator
# is also present elsewhere in the input; a multi-line Python script
# is not a chain.
_STEP_SEPARATORS = {";", "&&", "||", "&"}
_MAX_STEPS = 400  # zip-bomb defense at chain layer too


def _has_hard_separator(src: str) -> bool:
    """Detect the presence of a shell chain separator outside quotes.
    Deterministic — same input yields the same boolean."""
    in_s = in_d = in_b = False
    paren = 0
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if not (in_d or in_b) and c == "'": in_s = not in_s
        elif not (in_s or in_b) and c == '"': in_d = not in_d
        elif not (in_s or in_d) and c == "`": in_b = not in_b
        elif not (in_s or in_d or in_b) and c == "(": paren += 1
        elif not (in_s or in_d or in_b) and c == ")" and paren > 0: paren -= 1
        elif not (in_s or in_d or in_b) and paren == 0:
            if src[i:i+2] in ("&&", "||"): return True
            if c in ("&", ";"):            return True
        i += 1
    return False


def _split_quoted_aware(src: str) -> List[str]:
    """Split ``src`` on shell chain separators outside quotes / parens.

    Deterministic scanner.  Handles:
      · single, double, and back-tick quoted strings
      · parenthesised subshells `( ... )`
      · bracketed .NET arrays `[ ... ]`
      · CMD caret-line continuation (`^\n`)
      · CMD `rem` and Bash `#` line comments

    Newlines are treated as *soft* separators — only split when a
    hard separator (`;`, `&`, `&&`, `||`) is present elsewhere in
    the input, so multi-line coherent scripts stay together.
    """
    steps: List[str] = []
    buf: List[str] = []
    i, n = 0, len(src)
    in_s = in_d = in_b = False
    paren = 0
    soft_split = _has_hard_separator(src)

    def _flush():
        s = "".join(buf).strip()
        if s:
            steps.append(s)
        buf.clear()

    while i < n:
        c = src[i]

        # Skip whole-line comments (deterministic).
        if not (in_s or in_d or in_b):
            if c == "\n":
                # Newline is a soft separator — only splits when the
                # input already contains a hard shell separator.  A
                # multi-line Python script that never uses ``;`` or
                # ``&`` stays as ONE step so DKP has the whole script
                # to match against.
                if soft_split:
                    _flush()
                else:
                    buf.append(c)
                i += 1
                continue
            # Line-continuation caret (CMD) or backslash (Bash).
            if c in "^\\" and i + 1 < n and src[i+1] == "\n":
                i += 2
                continue
            # `rem` at start of a step
            if (c in " \t" or not buf) and src[i:i+4].lower() == "rem ":
                # skip to newline
                while i < n and src[i] != "\n":
                    i += 1
                continue
            # `#` bash comment
            if c == "#" and (not buf or (buf[-1] in " \t")):
                while i < n and src[i] != "\n":
                    i += 1
                continue

        # Quote / paren tracking (deterministic, order-sensitive).
        if not (in_d or in_b) and c == "'":
            in_s = not in_s
        elif not (in_s or in_b) and c == '"':
            in_d = not in_d
        elif not (in_s or in_d) and c == "`":
            in_b = not in_b
        elif not (in_s or in_d or in_b) and c == "(":
            paren += 1
        elif not (in_s or in_d or in_b) and c == ")" and paren > 0:
            paren -= 1

        # Separator detection ONLY outside quotes / subshells.
        if not (in_s or in_d or in_b) and paren == 0:
            # 2-char first so `&&` beats `&` and `||` beats `|`.
            if src[i:i+2] in ("&&", "||"):
                _flush()
                i += 2
                continue
            if c in (";", "&"):
                _flush()
                i += 1
                continue

        buf.append(c)
        i += 1
    _flush()
    return steps[:_MAX_STEPS]


# ── nested-shell payload unwrapping ───────────────────────────────
# Matches the FIRST nested-shell invocation anywhere inside the step.
# Payload is whatever appears inside the outer quoted arg after
# ``-c`` / ``/c`` / ``-command`` / ``-EncodedCommand``.
_NESTED_SHELL_RE = re.compile(
    r"(?i)\b(powershell|pwsh|cmd|bash|sh|python|node|wscript|cscript|mshta)"
    r"(?:\.exe)?\b[^\n]*?"
    r"(?:-c|-command|/c|-e|-EncodedCommand)\s+"
    r"(?:\"(?P<dpayload>[^\"]+)\"|'(?P<spayload>[^']+)'|(?P<bpayload>\S.*?))\s*(?:$|\"|')"
)


def _unwrap_nested(step: str) -> Optional[Tuple[str, str]]:
    """Return ``(host, inner)`` when ``step`` invokes a nested shell
    with an inline payload.  Otherwise ``None``."""
    m = _NESTED_SHELL_RE.search(step)
    if not m:
        return None
    payload = m.group("dpayload") or m.group("spayload") or m.group("bpayload") or ""
    payload = payload.strip()
    if not payload:
        return None
    return m.group(1).lower(), payload


# ── intent classifier (deterministic) ─────────────────────────────
# Maps MITRE technique-id prefix → ATT&CK tactic.  Deterministic
# order — checked in list order, first match wins.
_MITRE_TO_TACTIC = [
    ("T1003", "Credential Access"),
    ("T1027", "Defense Evasion"),
    ("T1036", "Defense Evasion"),
    ("T1047", "Execution"),
    ("T1053", "Persistence"),
    ("T1055", "Defense Evasion"),
    ("T1059", "Execution"),
    ("T1071", "Command and Control"),
    ("T1082", "Discovery"),
    ("T1087", "Discovery"),
    ("T1105", "Command and Control"),
    ("T1112", "Defense Evasion"),
    ("T1140", "Defense Evasion"),
    ("T1218", "Defense Evasion"),
    ("T1489", "Impact"),
    ("T1490", "Impact"),
    ("T1491", "Impact"),
    ("T1547", "Persistence"),
    ("T1548", "Privilege Escalation"),
    ("T1552", "Credential Access"),
    ("T1560", "Collection"),
    ("T1562", "Defense Evasion"),
    ("T1564", "Defense Evasion"),
    ("T1570", "Lateral Movement"),
    ("T1571", "Command and Control"),
    ("T1620", "Defense Evasion"),
]

# Lexical fallbacks for steps that don't fire any MITRE.
_LEX_INTENT = [
    (re.compile(r"(?i)^\s*(whoami|hostname|ipconfig|systeminfo|net\s+user|"
                r"net\s+group|net\s+localgroup|net\s+view|tasklist|"
                r"query\s+user|wmic\s+os\s+get|arp\s+-a|nltest)"),
     "Discovery"),
    (re.compile(r"(?i)^\s*(netsh\s+advfirewall|net\s+stop|sc\s+config|"
                r"add-mppreference|set-mppreference)"),
     "Impair Defenses"),
    (re.compile(r"(?i)(psexec|paexec|wmic\s+/node:|winrs|invoke-command)"),
     "Lateral Movement"),
    (re.compile(r"(?i)\breg\s+add\b|\brundll32\b|\bschtasks\b|\bcopy\s+.*startup\b"),
     "Persistence"),
]


def classify_intent(step_env: Dict[str, Any], step_text: str) -> str:
    """Return the ATT&CK tactic bucket for a single step."""
    for t in step_env.get("techniques", []) or []:
        tid = (t.get("id") or "").upper()
        for prefix, tactic in _MITRE_TO_TACTIC:
            if tid.startswith(prefix):
                return tactic
    for rx, tactic in _LEX_INTENT:
        if rx.search(step_text):
            return tactic
    return "Uncategorised"


# ── narrative bullet ──────────────────────────────────────────────
def _step_summary(step_text: str, env: Dict[str, Any]) -> str:
    text = step_text.strip()
    if len(text) > 120:
        text = text[:117] + "…"
    dkp = env.get("dkp_matches") or []
    if dkp:
        return f"{dkp[0]['name']} — `{text}`"
    tech = env.get("techniques") or []
    if tech:
        ids = " · ".join(sorted({t.get("id","?") for t in tech})[:3])
        return f"{ids} — `{text}`"
    return f"`{text}`"


# ── public API ────────────────────────────────────────────────────
def looks_like_chain(src: str) -> bool:
    """Deterministic gate for the orchestrator."""
    if not src:
        return False
    if _has_hard_separator(src):
        return True
    return False


def analyze_chain(src: str, *, analyze_fn) -> Dict[str, Any]:
    """Split, walk, and aggregate a multi-step chain input.

    ``analyze_fn`` is injected to avoid an import cycle with
    ``services.die.api``.
    """
    from copy import deepcopy

    raw_steps = _split_quoted_aware(src)
    steps: List[Dict[str, Any]] = []
    aggregate_techniques: Dict[str, Dict[str, Any]] = {}
    aggregate_lolbins:    Dict[str, Dict[str, Any]] = {}
    aggregate_iocs:       Dict[str, Dict[str, Any]] = {}
    aggregate_dkp:        Dict[str, Dict[str, Any]] = {}
    languages_seen: Dict[str, int] = {}

    def _emit(step_text: str, index: int, parent: Optional[int] = None,
              host_hint: Optional[str] = None):
        env = analyze_fn(step_text, language=host_hint)
        env = deepcopy(env)  # detach mutations
        env.pop("_raw_source", None)
        tactic = classify_intent(env, step_text)
        step_record = {
            "index":    index,
            "text":     step_text,
            "parent":   parent,
            "language": env.get("language"),
            "intent":   tactic,
            "summary":  _step_summary(step_text, env),
            "techniques":  env.get("techniques", []),
            "lolbins":     env.get("lolbins", []),
            "iocs":        env.get("iocs", []),
            "dkp_matches": env.get("dkp_matches", []),
            "obfuscation_score": env.get("obfuscation_score", 0),
            "ast":       env.get("ast"),
        }
        steps.append(step_record)

        # Aggregate for the union envelope.
        languages_seen[env.get("language") or "unknown"] = \
            languages_seen.get(env.get("language") or "unknown", 0) + 1
        for t in step_record["techniques"]:
            aggregate_techniques.setdefault(t["id"], t)
        for lb in step_record["lolbins"]:
            aggregate_lolbins.setdefault(lb["binary"], lb)
        for i in step_record["iocs"]:
            aggregate_iocs.setdefault(f"{i['kind']}:{i['value']}", i)
        for m in step_record["dkp_matches"]:
            prev = aggregate_dkp.get(m["id"])
            if prev is None or prev["confidence"] < m["confidence"]:
                aggregate_dkp[m["id"]] = m

        # Recursively unwrap nested-shell payloads.
        unwrapped = _unwrap_nested(step_text)
        if unwrapped and len(steps) < _MAX_STEPS:
            host, payload = unwrapped
            if payload and payload != step_text:
                child_index = f"{index}.1"
                _emit(payload, child_index, parent=index,
                      host_hint=_host_hint_language(host))

    for idx, step in enumerate(raw_steps, start=1):
        _emit(step, idx)

    # Determine the *primary* shell of the chain — most common
    # language across steps, ties broken by first-appearance order.
    if languages_seen:
        primary = max(languages_seen.items(), key=lambda kv: kv[1])[0]
    else:
        primary = "unknown"

    # Narrative bullets — deterministic step order.
    bullets = [f"Step {s['index']} — {s['intent']} · {s['summary']}"
               for s in steps]

    return {
        "input":           src,
        "chain":           True,
        "step_count":      len(steps),
        "primary_language": primary,
        "languages_seen":  languages_seen,
        "steps":           steps,
        "narrative_bullets": bullets,
        "aggregate": {
            "techniques":  sorted(aggregate_techniques.values(),
                                  key=lambda t: t["id"]),
            "lolbins":     sorted(aggregate_lolbins.values(),
                                  key=lambda l: l["binary"]),
            "iocs":        sorted(aggregate_iocs.values(),
                                  key=lambda i: (i["kind"], i["value"])),
            "dkp_matches": sorted(aggregate_dkp.values(),
                                  key=lambda m: (-m["confidence"], m["id"])),
        },
        "attack_intent":   _lazy_intent_wrapper(steps, aggregate_techniques,
                                                aggregate_dkp),
    }


def _lazy_intent_wrapper(steps, techniques, dkp):
    """Compute the Attack Intent for this chain right at the tail of
    ``analyze_chain``.  Kept as a lazy import to avoid module cycles."""
    from .intent import classify_intent
    return classify_intent({
        "steps": steps,
        "aggregate": {
            "techniques":  list(techniques.values()),
            "dkp_matches": list(dkp.values()),
        },
    })


def _host_hint_language(host: str) -> Optional[str]:
    return {
        "powershell": "powershell",
        "pwsh":       "powershell",
        "cmd":        "cmd",
        "bash":       "bash",
        "sh":         "bash",
        "python":     "python",
        "node":       "javascript",
        "wscript":    "javascript",   # WSH default engine
        "cscript":    "javascript",
        "mshta":      "javascript",
    }.get(host.lower())
