"""NivXRay — Shared analysis-pipeline helpers.

- Deterministic winner picker (smart vs magic) — the Feb-2026 Auto Investigate fix.
- Local TI cross-reference (`lookup_ti_hits`).
- Rich AI describe+verdict schema prompt (`ai_describe_and_verdict`).
- Shared `analysis_context` used by both /analyze and /report.
- IOC extraction reused by the quality gate.
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from operations import extract_iocs, mitre_map, yara_lite_scan, risk_score
from smart_decoder import smart_decode
from magic_decoder import magic_decode, score_output as magic_score
from osint import enrich_iocs
from lolbas import scan_lolbas

from deps import db, load_osint_keys, llm_json


# ============================================================================
# Deterministic winner picker (smart vs magic) — Auto Investigate parity fix
# ============================================================================
def deterministic_best_decode(payload: str) -> Dict[str, Any]:
    """Run BOTH `smart_decode` and `magic_decode` and return the winner.

    Rationale: `smart_decode` is a greedy single-path chain runner — it stops
    the first time no rule in `_apply_next` matches, even if `magic_decode`
    could continue peeling. This function is the single source of truth for
    "the deepest deterministic decode the platform can produce", so
    `AUTO INVESTIGATE` and `MAGIC` produce IDENTICAL terminal states on
    multi-layer payloads (base64 → gzip → base64 → xor → shellcode, etc.).

    Winner selection:
      1. Shellcode terminal state wins unconditionally (only one engine reaches it).
      2. Otherwise the higher `magic_score` output wins.
      3. Tie-breaker: longer chain wins (more layers peeled).

    Returns a normalized dict: {steps: [{op, args}], output, engine, reached_shellcode}.
    """
    try:
        smart = smart_decode(payload)
    except Exception as e:
        smart = {"steps": [], "output": "", "notes": [f"smart-decode error: {e}"]}

    try:
        m = magic_decode(payload, max_depth=6, max_branches=5, top_n=3)
        top = (m.get("top_results") or [{}])[0]
    except Exception as e:
        top = {"chain": [], "output": "", "is_shellcode": False, "score_breakdown": {"score": 0.0},
               "_err": str(e)}

    smart_out = smart.get("output") or ""
    magic_out = top.get("output") or ""

    # Detect nonsense chains where the same op is repeated (e.g. rot13 → rot13
    # → rot13 on already-clean text). This penalises magic when it over-decodes.
    def _has_repeated_op(chain):
        ops = [c.get("op") for c in chain or []]
        for i in range(1, len(ops)):
            if ops[i] == ops[i - 1] and ops[i] not in ("extract-payload",):
                return True
        return False

    magic_has_loop = _has_repeated_op(top.get("chain") or [])
    smart_has_loop = _has_repeated_op(smart.get("steps") or [])
    # Detect "over-decoding" — a chain whose FINAL op is a self-inverse
    # transform (rot13, reverse) applied on top of an already-clean result.
    # Common false-positive pattern: `base64 → zlib → rot13("Hello!")` where
    # the tail rot13 mangles readable output into gibberish (`Uryyb!`).
    def _tail_self_inverse(chain):
        return chain and chain[-1].get("op") in ("rot13", "reverse")
    magic_tail_bad = _tail_self_inverse(top.get("chain") or [])
    smart_tail_bad = _tail_self_inverse(smart.get("steps") or [])

    smart_reached_sc = False
    magic_reached_sc = bool(top.get("is_shellcode"))
    try:
        from shellcode_analyzer import starts_with_known_prologue
        if smart_out:
            raw_s = smart_out.encode("latin-1") if all(ord(c) < 256 for c in smart_out) \
                                                 else smart_out.encode("utf-8", errors="replace")
            smart_reached_sc = starts_with_known_prologue(raw_s)
    except Exception:
        pass

    # Score BOTH outputs with the same scoring function so english-density,
    # printable-ratio, structure-bonuses are directly comparable.
    smart_breakdown = magic_score(smart_out) if smart_out else {"score": 0.0}
    magic_breakdown = top.get("score_breakdown") or {"score": 0.0}
    smart_score = smart_breakdown.get("score", 0.0)
    # For magic use the RAW magic_score of its output — NOT the chain-completion
    # bonus'd score from top_results (which artificially inflates repeated-op
    # chains like `rot13 × 5` above a clean shorter chain).
    magic_score_val = magic_score(magic_out).get("score", 0.0) if magic_out else 0.0

    if magic_reached_sc:
        magic_score_val += 0.35
    if smart_reached_sc:
        smart_score += 0.35
    # Loop penalty — repeated ops on the SAME layer signal over-decoding
    if magic_has_loop:
        magic_score_val -= 0.20
    if smart_has_loop:
        smart_score -= 0.20
    # Tail self-inverse penalty — final rot13/reverse on already-clean text
    # is over-decoding (Feb-2026 fix for the `Hello Compression!` regression).
    if magic_tail_bad:
        magic_score_val -= 0.25
    if smart_tail_bad:
        smart_score -= 0.25

    def _pack_smart() -> Dict[str, Any]:
        return {
            "steps": [{"op": s["op"], "args": s.get("args") or {}} for s in smart.get("steps") or []],
            "output": smart_out,
            "engine": "smart",
            "reached_shellcode": smart_reached_sc,
            "score": round(smart_score, 4),
            "notes": smart.get("notes") or [],
        }

    def _pack_magic() -> Dict[str, Any]:
        return {
            "steps": [{"op": c["op"], "args": c.get("args") or {}}
                      for c in (top.get("chain") or [])],
            "output": magic_out,
            "engine": "magic",
            "reached_shellcode": magic_reached_sc,
            "score": round(magic_score_val, 4),
            "output_hex": top.get("output_hex"),
            "output_bytes_len": top.get("output_bytes_len"),
        }

    if magic_reached_sc and not smart_reached_sc:
        return _pack_magic()
    if smart_reached_sc and not magic_reached_sc:
        return _pack_smart()

    if magic_score_val > smart_score + 0.02:
        return _pack_magic()
    if smart_score > magic_score_val + 0.02:
        return _pack_smart()

    smart_chain_len = len(smart.get("steps") or [])
    magic_chain_len = len(top.get("chain") or [])
    if magic_chain_len > smart_chain_len:
        return _pack_magic()
    if smart_chain_len > magic_chain_len:
        return _pack_smart()

    return _pack_smart() if smart_chain_len else _pack_magic()


# ============================================================================
# IOC helper reused by quality gate
# ============================================================================
def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    from command_analyzer import extract_iocs as _ex
    r = _ex(text or "")
    flat = {"urls": r.get("urls") or [], "ips": r.get("ips") or [],
            "regkeys": r.get("regkeys") or [], "file_paths": r.get("file_paths") or []}
    h = r.get("hashes") or {}
    flat["hashes"] = (h.get("md5") or []) + (h.get("sha1") or []) + (h.get("sha256") or [])
    return flat


# ============================================================================
# TI cross-reference
# ============================================================================
async def lookup_ti_hits(iocs: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    """Cross-reference extracted IOCs against local Threat-Intel DB."""
    values: List[str] = []
    for k in ("urls", "ips", "domains", "md5", "sha1", "sha256"):
        values.extend(iocs.get(k) or [])
    if not values:
        return []
    hits = []
    async for doc in db.iocs.find({"value": {"$in": values}}, {"_id": 0}):
        hits.append(doc)
    return hits


# ============================================================================
# AI describe + verdict — the main narrative call
# ============================================================================
async def ai_describe_and_verdict(inp, out, iocs, mitre, yara, osint, want_verdict, want_describe,
                                   lolbas=None,
                                   persona: Optional[Dict[str, Any]] = None,
                                   provider: Optional[Dict[str, Any]] = None,
                                   playbook: str = ""):
    """Single LLM call producing rich narrative description + verdict JSON."""
    parts = []
    if want_describe:
        parts.append(
            '"description": {\n'
            '  "summary": "2-3 sentence executive summary of what the decoded script/command does",\n'
            '  "malware_family": {\n'
            '     "name": "concrete family/tooling name if identifiable (e.g. Cobalt Strike, AsyncRAT, Emotet, Nanocore, XORDDoS, Empire, custom Python loader) or null if unknown",\n'
            '     "confidence": "low|medium|high",\n'
            '     "rationale": "why this family — cite specific TTPs, string patterns, key material, structure, or matches to public reports"\n'
            '  },\n'
            '  "mitre_techniques": [\n'
            '     {"id": "Txxxx or Txxxx.xxx", "technique": "name", "tactic": "MITRE tactic (Execution|Defense Evasion|...)", "evidence": "specific line/token in the decoded output that supports this mapping"}\n'
            '  ],\n'
            '  "attack_chain": [\n'
            '     {\n'
            '        "step": 1,\n'
            '        "title": "SHORT TECHNICAL LABEL (e.g. WRAPPER DEOBFUSCATION, CONTEXT ADJUSTMENT, STEALTH STAGER LOAD, ROLLING XOR DECRYPTION, FILELESS MEMORY INJECTION, C2 BEACONING, PERSISTENCE INSTALL, SHADOW COPY DESTROY)",\n'
            '        "summary": "2-3 sentence plain-English narrative of what THIS step does. Be specific: name the API/function invoked, files touched, algorithms used.",\n'
            '        "technical_detail": "optional: paste concrete artifact from the payload (e.g. hex key, filename, URL, IP, argv) that supports this step. null if none.",\n'
            '        "kind": "ingestion|deobfuscation|context|filesystem|network|crypto|execution|persistence|discovery|c2|impact"\n'
            '     }\n'
            '  ],\n'
            '  "entity_graph": {\n'
            '     "nodes": [\n'
            '        {"id": "e1", "label": "ADVERSARY OBJECTIVE ONLY — describe WHAT the attacker is achieving on the victim, not the script mechanic. Good examples: \'Initial Foothold via Malicious Document\', \'Encrypted Stager Delivery\', \'Fileless In-Memory Execution\', \'Defense Evasion via Extension Masquerade\', \'C2 Beacon Establishment\', \'Credential Harvesting\', \'Data Exfiltration\', \'Shadow Copy Destruction (Anti-Recovery)\'. BAD examples that must NEVER appear: \'python.exe\', \'instructions.docx\', \'XOR Key 4fab...\', \'base64.b64decode()\', \'os.chdir\', \'exec()\', filenames, function calls, hex strings, variable names.", "type": "action|ip|url|user|device", "tactic": "MITRE ATT&CK tactic — REQUIRED — Reconnaissance|Resource Development|Initial Access|Execution|Persistence|Privilege Escalation|Defense Evasion|Credential Access|Discovery|Lateral Movement|Collection|Command and Control|Exfiltration|Impact", "malicious": true, "note": "optional 1-line summary of the attacker\'s intent at this step"}\n'
            '     ],\n'
            '     "edges": [\n'
            '        {"from": "e1", "to": "e2", "label": "attacker progression verb (Enables, Escalates To, Leverages For, Feeds Into, Culminates In, Establishes, Exfiltrates To). NEVER script mechanic verbs like Reads, Loads, Decrypts, Parent Of."}\n'
            '     ]\n'
            '  },\n'
            '  "flow_graph": {\n'
            '     "nodes": [\n'
            '        {"id": "n1", "label": "short verb-phrase e.g. \'chdir to python.exe folder\'", "kind": "start|filesystem|network|crypto|execution|persistence|discovery|c2|impact|end"}\n'
            '     ],\n'
            '     "edges": [\n'
            '        {"from": "n1", "to": "n2", "label": "optional: describes transition / data flow"}\n'
            '     ]\n'
            '  },\n'
            '  "behavior": ["bullet points describing each behavior observed"],\n'
            '  "ioc_narrative": "1-2 paragraph narrative discussing extracted IOCs, referencing OSINT enrichment where present (VT verdict, AbuseIPDB score, Shodan ports, TI-hits, geolocation). Be specific with values.",\n'
            '  "attribution_hints": "any hints about actor / campaign / open-source tooling / commodity vs targeted",\n'
            '  "recommended_actions": ["array of concrete containment / IR actions"]\n'
            '}'
        )
    if want_verdict:
        parts.append(
            '"verdict": {\n'
            '  "verdict": "Malicious|Suspicious|Benign",\n'
            '  "confidence": 0-100,\n'
            '  "summary": "1-2 sentence rationale — always mention malware family if identified",\n'
            '  "key_findings": ["short strings"],\n'
            '  "recommended_actions": ["short strings"]\n'
            '}'
        )
    schema = "{\n" + ",\n".join(parts) + "\n}"

    default_system = (
        "You are a senior DFIR analyst reviewing a decoded payload. "
        "Write like an incident-report analyst: precise, factual, technical, cite specific IOC values / OSINT results / TI hits.\n"
        "For malware_family: only claim a family if there is strong evidence (unique strings, C2 patterns, packer, algorithm signatures, or matches to VT/OTX threat labels).\n"
        "For mitre_techniques: derive from the DECODED BEHAVIOR, not the outer wrapper. For each technique cite the specific evidence in the decoded output.\n"
        "For attack_chain: model 3-8 sequential steps that describe the ATTACK CHAIN (what the malware does step by step). Each step should have a strong technical title (short caps phrase) + 2-3 sentence plain-English summary + optional technical_detail (hex keys, filenames, URLs cited verbatim from the payload). Order MUST be causal. Use kinds: ingestion|deobfuscation|context|filesystem|network|crypto|execution|persistence|discovery|c2|impact.\n"
        "For entity_graph: this is a TACTICAL ATTACK CHAIN describing what THE ATTACKER is achieving on the victim system — NOT a technical decoder trace of the script's operations. Extract 5-10 ATTACKER GOALS/OUTCOMES, each mapped to a MITRE ATT&CK tactic. Frame every node from the adversary's perspective (their objectives on the target).\n"
        "  STRICT RULES:\n"
        "  - Do NOT create nodes for filenames, functions, APIs, variables, hex keys, or script internals (e.g. 'python.exe', 'instructions.docx', 'XOR Key 4fab…', 'base64.b64decode', 'os.chdir'). These are HOW the attacker operates, not WHAT they achieve.\n"
        "  - DO create nodes for adversary objectives (e.g. 'Initial Foothold via Malicious Document', 'Encrypted Stager Delivery', 'In-Memory Fileless Execution', 'Defense Evasion via Extension Masquerade', 'C2 Establishment', 'Credential Harvesting Attempt', 'Data Exfiltration', 'Shadow Copy Destruction (Anti-Recovery)').\n"
        "  - Node type should usually be 'action' (attacker action/objective) except for concrete external entities such as C2 IPs/URLs (type ip/url) or targeted victim entities (type user/device).\n"
        "  - Every node MUST carry a MITRE ATT&CK tactic. Order the graph as a kill-chain timeline (Initial Access → Execution → Defense Evasion → Persistence → Credential Access → Discovery → Command and Control → Collection → Exfiltration → Impact).\n"
        "  - Edges must express attacker progression (e.g. 'Enables', 'Escalates To', 'Leverages For', 'Feeds Into', 'Culminates In') — NOT script data-flow like 'Reads', 'Loads', 'Decrypts'.\n"
        "  - Include the malicious flag on adversary-controlled nodes.\n"
        "  Example: for a Python XOR loader dropping a stager, DO NOT list 'python.exe','base64','XOR key','instructions.docx'. INSTEAD produce nodes like: {label:'Initial Foothold (Signed LOLBin Abuse)', tactic:'Initial Access'} → {label:'Encrypted Stager Retrieval', tactic:'Defense Evasion'} → {label:'Rolling-Key Deobfuscation of Second Stage', tactic:'Defense Evasion'} → {label:'Fileless In-Memory Payload Execution', tactic:'Execution'} → {label:'C2 Beacon Establishment', tactic:'Command and Control'}.\n"
        "For flow_graph: additionally produce a compact node/edge structure for visualization — 4-10 nodes.\n"
        "Return STRICT JSON only with the keys shown in the schema. No markdown, no prose outside JSON."
    )
    if persona and (persona.get("config") or {}).get("system_prompt"):
        persona_prompt = persona["config"]["system_prompt"].strip()
        system = (
            persona_prompt
            + "\n\nIMPORTANT — OUTPUT CONTRACT (in addition to your normal analysis):\n"
            + "Return your final analysis as STRICT JSON only, matching the schema below. "
            + "Fold your persona-specific findings into the `summary`, `attack_chain`, `behavior`, and `ioc_narrative` fields. "
            + "No markdown, no prose outside JSON."
        )
    else:
        system = default_system

    if playbook:
        system = system + "\n" + playbook

    llm_provider = ((provider or {}).get("config") or {}).get("provider") or "anthropic"
    llm_model = ((provider or {}).get("config") or {}).get("model") or "claude-sonnet-4-5-20250929"

    prompt = (
        f"SCHEMA:\n{schema}\n\n"
        f"RAW INPUT:\n{inp[:3500]}\n\n"
        f"DECODED OUTPUT:\n{out[:3500]}\n\n"
        f"EXTRACTED IOCs:\n{json.dumps(iocs)[:2000]}\n\n"
        f"HEURISTIC MITRE (from wrapper text):\n{json.dumps(mitre)[:1200]}\n\n"
        f"HEURISTIC YARA:\n{json.dumps(yara)[:1200]}\n\n"
        f"LOLBAS MATCHES:\n{json.dumps(lolbas or [])[:1500]}\n\n"
        f"OSINT ENRICHMENT:\n{json.dumps(osint)[:5000]}\n\n"
        "Return only JSON."
    )
    return await llm_json(
        "describe-" + str(datetime.now(timezone.utc).timestamp()),
        system, prompt,
        provider=llm_provider, model=llm_model,
    )


# ============================================================================
# /report shared context (used by both /report and /report/{fmt})
# ============================================================================
async def analysis_context(body, user) -> Dict[str, Any]:
    """Shared analysis pipeline used by both JSON /report and multi-format /report/{fmt}."""
    text = (body.output or "") + "\n" + body.input
    iocs = extract_iocs(text)
    mitre_hits = mitre_map(text)
    yara = yara_lite_scan(text)
    lolbas = scan_lolbas(text)
    risk = risk_score(mitre_hits, yara, iocs)
    ti_hits = await lookup_ti_hits(iocs)
    osint = None
    description = None
    verdict = None
    if body.enrich_osint:
        try:
            keys = await load_osint_keys()
            osint = await enrich_iocs(iocs, keys)
        except Exception as e:
            osint = {"error": str(e)}
    if body.describe or body.use_ai_verdict:
        try:
            ai_bundle = await ai_describe_and_verdict(
                body.input, body.output or "", iocs, mitre_hits, yara, osint or {},
                lolbas=lolbas,
                want_verdict=body.use_ai_verdict, want_describe=body.describe,
            )
            description = ai_bundle.get("description")
            verdict = ai_bundle.get("verdict")
        except Exception as e:
            description = {"error": str(e)}
    merged_mitre = list(mitre_hits)
    if description and not description.get("error"):
        ai_mitre = description.get("mitre_techniques") or []
        seen_ids = {m["id"] for m in merged_mitre}
        for m in ai_mitre:
            if isinstance(m, dict) and m.get("id") and m["id"] not in seen_ids:
                merged_mitre.append({**m, "source": "ai"})
                seen_ids.add(m["id"])
        for m in merged_mitre:
            m.setdefault("source", "heuristic")
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "iocs": iocs, "mitre": merged_mitre, "yara": yara, "lolbas": lolbas,
        "risk": risk, "ti_hits": ti_hits, "osint": osint,
        "description": description, "verdict": verdict,
    }
