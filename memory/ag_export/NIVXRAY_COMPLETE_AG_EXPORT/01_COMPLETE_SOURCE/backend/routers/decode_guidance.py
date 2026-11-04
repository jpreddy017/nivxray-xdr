"""Ensemble Input Classifier — 4 engines vote in parallel.

Engines:
  1. `deterministic`  — fast fixed regex (`_fallback_classify`)
  2. `dynamic-regex`  — patterns harvested from active training notes
                        (kind `training_note`, config.tags / config.body)
  3. `persona`        — signature/pattern rules from the active persona
                        (kind `persona` in admin_models, or default Cognis rules)
  4. `llm`            — Claude Sonnet 4.5 via emergentintegrations

All 4 run concurrently via `asyncio.gather`. The `_ensemble_vote` function
merges results:
  - `kind`: majority vote weighted by engine reliability
      (llm 0.4, persona 0.25, dynamic-regex 0.2, deterministic 0.15)
  - `signals`: union, capped at 8, order preserved by engine priority
  - `recommended`: LLM's ordering if available, else majority overlap
  - `guidance_steps`: LLM's if available, else stitched from persona/regex
  - `confidence`: max engine confidence × agreement ratio
  - `votes`: per-engine breakdown so analyst can see who agreed with whom
"""
from __future__ import annotations
import asyncio
import re
from collections import Counter
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import db, get_current_user, llm_json

router = APIRouter()

# ── Shared taxonomies ──────────────────────────────────────────────
_ALLOWED_BUTTONS = {
    "btn-nivxray-decode", "btn-auto-investigate", "btn-smart-decode",
    "btn-ai-decode", "btn-chain-add-stage", "btn-chain-run",
}
_ALLOWED_KINDS = {
    "encoded", "plaintext_malicious", "multi_line_chain",
    "unclear_cipher", "clean_text", "empty",
}

_KNOWN_HEADS = (
    "powershell", "pwsh", "cmd", "cmd.exe", "certutil", "mshta", "rundll32",
    "regsvr32", "regsvcs", "regasm", "msiexec", "installutil", "bitsadmin",
    "wmic", "wscript", "cscript", "schtasks", "at.exe", "sc.exe", "netsh",
    "curl", "wget", "iwr", "iex", "invoke-expression", "invoke-webrequest",
    "start-process", "vssadmin", "wbadmin", "bcdedit", "esentutl",
    "diskshadow", "dotnet", "dnx", "dxcap",
    # PowerShell recon / detection cmdlets — plaintext malicious signal
    "get-eventlog", "get-winevent", "get-process", "get-service",
    "get-scheduledtask", "get-cim", "get-ciminstance", "get-wmi",
    "get-wmiobject", "get-net", "get-nettcp", "get-nettcpconnection",
    "get-netudp", "get-netroute", "get-netconnection", "get-localuser",
    "get-aduser", "get-localgroup", "get-credential", "get-childitem",
    "get-content", "get-item", "get-clipboard", "get-hotfix",
    "add-mppreference", "set-mppreference", "get-mpthreat",
    "invoke-mimikatz", "invoke-command", "invoke-restmethod",
    "start-bitstransfer", "test-netconnection",
    "reg add", "reg delete", "reg query", "reg import",
    "net user", "net localgroup", "net group", "net share",
    "net use", "netstat", "tasklist", "taskkill", "systeminfo",
    "whoami", "hostname", "ipconfig", "nslookup", "arp", "route",
)

# Common English "stopwords" — presence signals real text, not cipher.
_ENGLISH_STOPWORDS = {
    "the", "and", "for", "with", "this", "that", "you", "have", "was",
    "are", "will", "from", "they", "your", "which", "when", "where",
    "please", "hello", "world", "test", "week", "day", "time", "team",
    "meeting", "report", "review", "note", "notes", "message", "document",
    "process", "system", "server", "client", "user", "data", "file",
    "roadmap", "quick", "brown", "lazy", "over", "jumps",
}

_B64_RE     = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_HEX_RE     = re.compile(r"(?:[0-9a-fA-F]{2}[\s,:-]?){20,}")
_URLENC_RE  = re.compile(r"(?:%[0-9a-fA-F]{2}){4,}")
_PSENC_RE   = re.compile(
    r"powershell(?:\.exe)?[^\n]*?(?:-e|-en|-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}",
    re.IGNORECASE)
_URL_RE     = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
_DEFANG_RE  = re.compile(r"\bhxxps?://|\[\.\]|\[dot\]", re.IGNORECASE)
_CHARCODE_RE = re.compile(r"String\.fromCharCode\s*\(|Char\s*\[\s*\]")

# Non-standard URL schemes are a strong cipher signal. `uggc://` = ROT13
# of `http://`, `arg://` = ROT13 of `net://`, etc. Skip the well-known
# safe schemes; anything else with a `://` after a short scheme prefix
# is suspicious.
_SAFE_SCHEMES = {"http", "https", "ftp", "ftps", "file", "smb", "s3",
                 "gs", "ssh", "sftp", "git", "svn", "hxxp", "hxxps"}
_URL_LIKE_RE = re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.-]{1,10})://")

# ROT13 tell-tales — the most common tokens after ROT13 rotation.
_ROT13_TOKENS = (
    "uggc://", "uggcf://",       # http(s)://
    ".rkr", ".cf1", ".ong",       # .exe .ps1 .bat
    "cbjreFuryy", "cbjrefuryy",   # powerShell / powershell
    "pregvhgvy",                  # certutil
    "eha", "pzq",                 # run, cmd
    "vrk(", "vjer ",              # iex(, iwr (
    "vaibxr",                     # invoke
)

_ENGINE_WEIGHTS = {
    "llm":            0.40,
    "persona":        0.25,
    "dynamic-regex":  0.20,
    "deterministic":  0.15,
}


# ── Engine 1: deterministic ─────────────────────────────────────────
def _looks_like_cmd(line: str) -> bool:
    t = line.strip().lower()
    if not t or len(t) > 4000:
        return False
    if re.match(r"^([#;>]|::|rem\s|\/\/)", t):
        return False
    return any(t.startswith(h) for h in _KNOWN_HEADS)


def _classify_deterministic(text: str) -> Dict[str, Any]:
    t = (text or "").strip()
    if not t:
        return {"kind": "empty", "confidence": 1.0, "signals": [],
                "recommended": [], "guidance_steps": []}
    lines = [l for l in t.splitlines() if l.strip()]
    cmd_lines = [l for l in lines if _looks_like_cmd(l)]
    is_multi = len(lines) >= 2 and (
        re.search(r"\n\s*\n", t) is not None
        or (len(cmd_lines) >= 2 and len(cmd_lines) / len(lines) >= 0.5)
    )
    signals: List[str] = []
    if is_multi:
        signals.append(f"{len(cmd_lines) or len(lines)} command-line stages")
    has_b64      = bool(_B64_RE.search(t))
    has_hex      = bool(_HEX_RE.search(t)) or "\\x" in t
    has_urlenc   = bool(_URLENC_RE.search(t))
    has_psenc    = bool(_PSENC_RE.search(t))
    has_certutil = "certutil" in t.lower() and "-decode" in t.lower()
    has_charcode = bool(_CHARCODE_RE.search(t))
    if has_psenc:    signals.append("powershell -enc detected")
    if has_certutil: signals.append("certutil -decode detected")
    if has_b64:      signals.append("base64 blob detected")
    if has_hex:      signals.append("hex string detected")
    if has_urlenc:   signals.append("url-encoded content detected")
    if has_charcode: signals.append("String.fromCharCode obfuscation")
    is_encoded = any((has_psenc, has_certutil, has_b64, has_hex, has_urlenc, has_charcode))

    # ── Cipher-family detection (ROT13, non-standard URL scheme, etc.)
    # Works with OR without whitespace — spaces stay literal under ROT13,
    # so the old "no whitespace" gate under-detected these payloads.
    rot13_hits = [tok for tok in _ROT13_TOKENS if tok.lower() in t.lower()]
    url_like = _URL_LIKE_RE.findall(t)
    exotic_schemes = [s for s in url_like if s.lower() not in _SAFE_SCHEMES]
    is_cipher_like = bool(rot13_hits) or bool(exotic_schemes)
    if rot13_hits:
        signals.append(f"ROT13 tokens: {', '.join(rot13_hits[:3])}")
    if exotic_schemes:
        signals.append(f"non-standard URL scheme: {', '.join(set(exotic_schemes[:3]))}")

    has_lolbin = any(re.search(rf"\b{re.escape(h)}\b", t, re.IGNORECASE)
                     for h in _KNOWN_HEADS)
    has_url = bool(_URL_RE.search(t))
    has_defang = bool(_DEFANG_RE.search(t))
    if has_lolbin: signals.append("LOLBAS binary present")
    if has_url:    signals.append("defanged URL" if has_defang else "URL present")
    is_malicious = has_lolbin or has_defang or (has_url and len(t) < 800)

    # High-entropy short blob heuristic (rot13 / vigenère / custom xor)
    gibberish = (not is_encoded and not is_malicious and not is_multi
                 and 12 <= len(t) <= 400
                 and re.match(r"^[\S]+$", t.splitlines()[0]) is not None)
    if gibberish:
        signals.append("high-entropy short blob — possible cipher")

    # Cipher-family wins over "clean_text" when there are ROT13 or exotic
    # URL scheme signals, even if the line contains spaces (which the
    # old whitespace-based `gibberish` gate missed).
    if is_cipher_like and not is_multi and not is_malicious:
        return {"kind": "unclear_cipher", "confidence": 0.85,
                "signals": signals,
                "recommended": ["btn-ai-decode", "btn-smart-decode",
                                "btn-auto-investigate"],
                "guidance_steps": []}

    # Language-absence cipher heuristic — if the input is 12+ chars, has
    # no LOLBAS/shell keyword, contains NO common English stopword, and
    # has ≥ 2 alphabetic words, it's almost certainly a cipher or custom
    # obfuscation (Vigenere, random-shift ROT, sub-cipher, XOR).
    if not is_encoded and not is_malicious and not is_multi and 12 <= len(t) <= 800:
        words = re.findall(r"[a-zA-Z][a-zA-Z']{2,}", t)
        english_present = any(w.lower() in _ENGLISH_STOPWORDS for w in words)
        if len(words) >= 2 and not english_present and not _URL_RE.search(t):
            signals.append(
                f"no LOLBAS keyword + no common English words in "
                f"{len(words)} tokens — cipher / obfuscation likely"
            )
            return {"kind": "unclear_cipher", "confidence": 0.80,
                    "signals": signals,
                    "recommended": ["btn-ai-decode", "btn-smart-decode",
                                    "btn-auto-investigate"],
                    "guidance_steps": []}

    if is_multi:
        return {"kind": "multi_line_chain", "confidence": 0.9, "signals": signals,
                "recommended": ["btn-chain-add-stage", "btn-chain-run",
                                "btn-auto-investigate"],
                "guidance_steps": []}
    if is_encoded and is_malicious:
        return {"kind": "encoded", "confidence": 0.95, "signals": signals,
                "recommended": ["btn-auto-investigate", "btn-smart-decode"],
                "guidance_steps": []}
    if is_encoded:
        return {"kind": "encoded", "confidence": 0.85, "signals": signals,
                "recommended": ["btn-smart-decode", "btn-auto-investigate"],
                "guidance_steps": []}
    if is_malicious:
        return {"kind": "plaintext_malicious", "confidence": 0.9, "signals": signals,
                "recommended": ["btn-auto-investigate"], "guidance_steps": []}
    if gibberish:
        return {"kind": "unclear_cipher", "confidence": 0.6, "signals": signals,
                "recommended": ["btn-ai-decode", "btn-smart-decode"],
                "guidance_steps": []}
    return {"kind": "clean_text", "confidence": 0.55, "signals": signals,
            "recommended": ["btn-auto-investigate"], "guidance_steps": []}


# ── Engine 2: dynamic regex from training notes ────────────────────
async def _load_dynamic_patterns() -> List[Dict[str, Any]]:
    """Harvest keyword/tag hints from active training-note config bodies.

    Any training note with tags like `powershell`, `certutil`, `mimikatz`
    etc. contributes those tokens as case-insensitive keyword patterns
    the ensemble can boost the `plaintext_malicious` / `encoded` weight
    with when they appear in the input.
    """
    hints: List[Dict[str, Any]] = []
    async for doc in db.admin_models.find(
        {"kind": "training_note", "enabled": True},
        {"config.tags": 1, "config.body": 1, "name": 1},
    ):
        cfg = doc.get("config") or {}
        for tag in (cfg.get("tags") or []):
            tag = str(tag).strip().lower()
            if not tag or len(tag) < 3:
                continue
            hints.append({"kind_hint": "plaintext_malicious",
                          "keyword": tag,
                          "source": doc.get("name", "")[:40]})
    return hints


def _classify_dynamic_regex(text: str, hints: List[Dict[str, Any]]) -> Dict[str, Any]:
    t = (text or "").strip()
    if not t or not hints:
        return {"kind": "clean_text", "confidence": 0.0, "signals": [],
                "recommended": [], "guidance_steps": []}
    matches: List[str] = []
    kind_votes: Counter = Counter()
    for h in hints:
        kw = h["keyword"]
        if kw and re.search(rf"\b{re.escape(kw)}\b", t, re.IGNORECASE):
            matches.append(f"training-note tag: {kw}")
            kind_votes[h["kind_hint"]] += 1
    if not matches:
        return {"kind": "clean_text", "confidence": 0.0, "signals": [],
                "recommended": [], "guidance_steps": []}
    winner_kind = kind_votes.most_common(1)[0][0]
    # confidence scales with number of matches, capped
    conf = min(0.9, 0.35 + 0.15 * len(matches))
    return {
        "kind": winner_kind,
        "confidence": conf,
        "signals": matches[:5],
        "recommended": ["btn-auto-investigate"] if winner_kind == "plaintext_malicious"
                       else ["btn-smart-decode", "btn-auto-investigate"],
        "guidance_steps": [],
    }


# ── Engine 3: active persona rules ─────────────────────────────────
async def _load_active_persona() -> Optional[Dict[str, Any]]:
    """Return the currently-active persona's rule set, if any."""
    doc = await db.admin_models.find_one(
        {"kind": "persona", "enabled": True},
        sort=[("updated_at", -1)],
    )
    if not doc:
        return None
    return doc


def _classify_persona(text: str, persona: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Very lightweight persona-driven classification.

    Reads `config.classification_rules: [{regex, kind, why}]` from the
    active persona doc. If none defined, returns empty (persona abstains).
    """
    t = (text or "").strip()
    if not t or not persona:
        return {"kind": "clean_text", "confidence": 0.0, "signals": [],
                "recommended": [], "guidance_steps": []}
    cfg = persona.get("config") or {}
    rules = cfg.get("classification_rules") or []
    if not isinstance(rules, list) or not rules:
        # Default Cognis rules — favour AUTO INVESTIGATE for anything
        # with a URL or LOLBAS binary, otherwise abstain.
        if _URL_RE.search(t) or any(h in t.lower() for h in _KNOWN_HEADS):
            return {"kind": "plaintext_malicious", "confidence": 0.7,
                    "signals": [f"persona {persona.get('name', 'default')} default rule"],
                    "recommended": ["btn-auto-investigate"],
                    "guidance_steps": []}
        return {"kind": "clean_text", "confidence": 0.0, "signals": [],
                "recommended": [], "guidance_steps": []}
    matched: List[str] = []
    kind_votes: Counter = Counter()
    for r in rules:
        try:
            pattern = str(r.get("regex", "")).strip()
            kind = str(r.get("kind", "")).strip()
            if not pattern or kind not in _ALLOWED_KINDS:
                continue
            if re.search(pattern, t, re.IGNORECASE):
                matched.append(str(r.get("why", pattern))[:80])
                kind_votes[kind] += 1
        except re.error:
            continue
    if not kind_votes:
        return {"kind": "clean_text", "confidence": 0.0, "signals": [],
                "recommended": [], "guidance_steps": []}
    winner = kind_votes.most_common(1)[0][0]
    return {
        "kind": winner,
        "confidence": min(0.92, 0.5 + 0.1 * len(matched)),
        "signals": matched[:5],
        "recommended": ["btn-auto-investigate"],
        "guidance_steps": [],
    }


# ── Engine 4: LLM ──────────────────────────────────────────────────
_LLM_SYSTEM = (
    "You are the NivXRay Guided-Response Advisor. Classify a raw SOC "
    "input and recommend the next button. Return ONLY JSON with keys "
    "`kind`, `confidence` (0..1), `signals` (array), `recommended` "
    "(1-4 button ids from the allowed list), and `guidance_steps` "
    "(1-4 objects with label + why).\n\n"
    "Allowed buttons: btn-nivxray-decode, btn-auto-investigate, "
    "btn-smart-decode, btn-ai-decode, btn-chain-add-stage, btn-chain-run.\n"
    "Allowed kinds: encoded, plaintext_malicious, multi_line_chain, "
    "unclear_cipher, clean_text, empty.\n\n"
    "Rules:\n"
    "  - 2+ separate command lines → kind=multi_line_chain, "
    "recommend btn-chain-add-stage and btn-chain-run.\n"
    "  - Encoded (base64/hex/url-encoded/-enc/certutil -decode) + LOLBAS "
    "or defanged URL → kind=encoded, recommend btn-auto-investigate.\n"
    "  - Plaintext with LOLBAS or defanged URL → kind=plaintext_malicious, "
    "recommend btn-auto-investigate.\n"
    "  - Encoded but no clear malicious markers → kind=encoded, "
    "recommend btn-smart-decode first.\n"
    "  - High-entropy short blob no obvious encoding → kind=unclear_cipher, "
    "recommend btn-ai-decode.\n"
    "  - Otherwise recommend btn-auto-investigate.\n"
    "  - NEVER invent buttons outside the allowed list."
)


async def _classify_llm(text: str) -> Dict[str, Any]:
    if not text or len(text.strip()) < 8:
        return {"kind": "empty", "confidence": 0.0, "signals": [],
                "recommended": [], "guidance_steps": []}
    view = text if len(text) <= 6000 else text[:6000] + "\n[…truncated…]"
    try:
        result = await llm_json(
            session_id="guidance-ensemble",
            system=_LLM_SYSTEM,
            user=f"---INPUT-START---\n{view}\n---INPUT-END---",
            retries=1,
        )
        return _sanitize_llm(result)
    except Exception:
        return {"kind": "clean_text", "confidence": 0.0, "signals": [],
                "recommended": [], "guidance_steps": [], "_error": True}


def _sanitize_llm(payload: Dict[str, Any]) -> Dict[str, Any]:
    kind = str(payload.get("kind", "")).strip()
    if kind not in _ALLOWED_KINDS:
        kind = "clean_text"
    try:
        conf = max(0.0, min(1.0, float(payload.get("confidence", 0.7))))
    except Exception:
        conf = 0.7
    signals = [str(s).strip()[:120]
               for s in (payload.get("signals") or []) if str(s).strip()][:8]
    rec = [r for r in (str(x).strip() for x in (payload.get("recommended") or []))
           if r in _ALLOWED_BUTTONS][:4]
    steps = []
    for s in (payload.get("guidance_steps") or [])[:4]:
        if not isinstance(s, dict):
            continue
        label = str(s.get("label", "")).strip()[:80]
        why = str(s.get("why", "")).strip()[:400]
        if label:
            steps.append({"label": label, "why": why})
    return {"kind": kind, "confidence": conf, "signals": signals,
            "recommended": rec, "guidance_steps": steps}


# ── Ensemble voting ────────────────────────────────────────────────
def _ensemble_vote(votes: Dict[str, Dict[str, Any]], text: str) -> Dict[str, Any]:
    """Merge per-engine classifications into a single answer."""
    # Weighted kind vote (skip engines that abstained → confidence 0)
    kind_scores: Counter = Counter()
    for engine, v in votes.items():
        conf = float(v.get("confidence", 0.0))
        if conf <= 0.0 or v.get("kind") in (None, "clean_text", "empty"):
            # Weak / abstaining vote — still counts if positive confidence
            if v.get("kind") == "empty":
                continue
        w = _ENGINE_WEIGHTS.get(engine, 0.1) * conf
        if w > 0 and v.get("kind"):
            kind_scores[v["kind"]] += w
    if not kind_scores:
        # Nothing voted → deterministic wins
        winner_kind = votes.get("deterministic", {}).get("kind", "clean_text")
    else:
        winner_kind = kind_scores.most_common(1)[0][0]

    # Agreement ratio — how many engines voted for the winning kind
    n_agree = sum(1 for v in votes.values() if v.get("kind") == winner_kind)
    n_active = sum(1 for v in votes.values() if v.get("confidence", 0) > 0)
    agreement = round(n_agree / max(1, n_active), 2)

    # Merged signals (union, preserve engine priority ordering)
    seen: set = set()
    merged_signals: List[str] = []
    for engine in ("llm", "persona", "dynamic-regex", "deterministic"):
        for s in votes.get(engine, {}).get("signals") or []:
            if s.lower() in seen:
                continue
            seen.add(s.lower())
            merged_signals.append(s)
    merged_signals = merged_signals[:8]

    # Recommended buttons — prefer LLM ordering, fall back to
    # highest-confidence engine that recommended for the winning kind
    ordered_recs: List[str] = []
    llm_vote = votes.get("llm") or {}
    if llm_vote.get("kind") == winner_kind and llm_vote.get("recommended"):
        ordered_recs = list(llm_vote["recommended"])
    else:
        # Pick the highest-conf engine agreeing with the winner
        candidates = [(engine, v) for engine, v in votes.items()
                      if v.get("kind") == winner_kind and v.get("recommended")]
        if candidates:
            candidates.sort(key=lambda e: -e[1].get("confidence", 0))
            ordered_recs = list(candidates[0][1]["recommended"])
        else:
            # Fallback based on the winner kind
            ordered_recs = {
                "multi_line_chain":    ["btn-chain-add-stage", "btn-chain-run",
                                        "btn-auto-investigate"],
                "encoded":             ["btn-auto-investigate", "btn-smart-decode"],
                "plaintext_malicious": ["btn-auto-investigate"],
                "unclear_cipher":      ["btn-ai-decode", "btn-smart-decode"],
                "clean_text":          ["btn-auto-investigate"],
                "empty":               [],
            }.get(winner_kind, ["btn-auto-investigate"])

    # Guidance steps — LLM's if available, else stitched deterministic default
    steps = list(llm_vote.get("guidance_steps") or [])
    if not steps:
        steps = _default_steps_for(winner_kind, ordered_recs)

    # Confidence — max engine confidence for the winner × agreement ratio
    winner_confs = [v.get("confidence", 0.0) for v in votes.values()
                    if v.get("kind") == winner_kind]
    max_conf = max(winner_confs) if winner_confs else 0.5
    ensemble_conf = round(min(1.0, max_conf * (0.6 + 0.4 * agreement)), 2)

    return {
        "kind":            winner_kind,
        "confidence":      ensemble_conf,
        "signals":         merged_signals,
        "recommended":     ordered_recs,
        "guidance_steps":  steps,
        "engine":          "ensemble",
        "votes":           votes,
        "agreement":       agreement,
    }


def _default_steps_for(kind: str, rec: List[str]) -> List[Dict[str, str]]:
    if kind == "multi_line_chain":
        return [
            {"label": "+ ADD CHAIN",
             "why": "Multiple command lines detected — each should be its own stage."},
            {"label": "RUN CHAIN",
             "why": "Decodes each stage and aggregates IOCs / MITRE / LOLBAS / verdict."},
        ]
    if kind == "encoded":
        return [
            {"label": rec[0].replace("btn-", "").replace("-", " ").upper() if rec else "AUTO INVESTIGATE",
             "why": "Encoded payload detected — run recursive decode with enrichment."},
        ]
    if kind == "plaintext_malicious":
        return [
            {"label": "AUTO INVESTIGATE",
             "why": "Malicious-looking plaintext — full pipeline for OSINT + MITRE + AI verdict."},
        ]
    if kind == "unclear_cipher":
        return [
            {"label": "AI DECODE",
             "why": "Obfuscated blob with no clear encoding — let the LLM propose a recipe."},
        ]
    return [
        {"label": "AUTO INVESTIGATE",
         "why": "No obvious markers — run full pipeline to be safe."},
    ]


# ── Endpoint ───────────────────────────────────────────────────────
class GuidanceIn(BaseModel):
    input: str = Field(..., min_length=0, max_length=32_000)


@router.post("/decode/guidance")
async def decode_guidance(body: GuidanceIn, user=Depends(get_current_user)):
    """Ensemble classifier — deterministic + dynamic-regex + persona + LLM.

    All four engines run in parallel via `asyncio.gather`. Results are
    merged by `_ensemble_vote` and returned along with a `votes` breakdown
    so the UI can show why the ensemble decided what it did.
    """
    text = body.input or ""
    if not text.strip():
        return {"kind": "empty", "confidence": 1.0, "signals": [],
                "recommended": [], "guidance_steps": [
                    {"label": "Paste a command line, encoded blob, or malware sample",
                     "why": "The tool will guide you the moment you paste."}
                ], "engine": "trivial", "votes": {}, "agreement": 1.0}

    # Load side-inputs concurrently
    hints_task = asyncio.create_task(_load_dynamic_patterns())
    persona_task = asyncio.create_task(_load_active_persona())
    hints = await hints_task
    persona = await persona_task

    # Run classifiers concurrently
    llm_task = asyncio.create_task(_classify_llm(text))
    det = _classify_deterministic(text)
    dyn = _classify_dynamic_regex(text, hints)
    per = _classify_persona(text, persona)
    llm = await llm_task

    votes = {
        "deterministic":  det,
        "dynamic-regex":  dyn,
        "persona":        per,
        "llm":            llm,
    }
    return _ensemble_vote(votes, text)
