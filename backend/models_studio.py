"""NivXRay — Model Studio.

Admin-managed catalog of 4 kinds of "models" that extend the tool's decoding
& analysis capabilities:

    - detection_rule : custom LOLBAS-style {binary_regex, argv_regex, mitre[], ...}
    - decode_recipe  : {match_regex, ops[]}   applied by Smart Decode on match
    - ai_persona     : {system_prompt}        alternative Describe-stage prompt
    - ai_provider    : {provider, model}      Claude / GPT / Gemini switch

Persisted in MongoDB collection `admin_models`. Consumed at scan/decode/analyze time.
"""
from __future__ import annotations
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

log = logging.getLogger("nivxray.model_studio")

MODEL_KINDS = ("detection_rule", "decode_recipe", "ai_persona", "ai_provider", "playbook", "training_note")

# =============================================================================
# Built-in seeds — created once, then admin-editable but not deletable (protected=True)
# =============================================================================
STATIC_MALWARE_DEOBFUSCATION_PROMPT = """ROLE AND PURPOSE: You are an automated, deterministic Static Malware Code Analyzer and Deobfuscation Engine. Your objective is to recursively unpack, decode, and extract structural metadata from highly obfuscated administrative scripts (PowerShell, Bash, VBScript, Batch) to reveal the original payload intent.

EXECUTION PIPELINE (Execute the following steps sequentially):

STAGE 1: GRAMMAR AND LOGIC EXTRACTION
1. Scan the raw input code to differentiate static data stores from execution logic.
2. Identify all variable definitions containing large blocks of data (e.g., Base64 strings, Hex streams, Byte arrays, Char matrices).
3. Isolate the loop structures, math blocks, string manipulation methods, or system evaluations used immediately after the data definitions.

STAGE 2: ALGORITHMIC PARSING & EMULATION
Determine the specific cryptographic or obfuscation primitives present. You must emulate the math or formatting engine of the host shell without executing system commands. Resolve the layers using the rules below:
- If BASE64/HEX is used: Decode the byte stream natively. If it results in a non-printable stream, analyze it for UTF-16LE or ASCII alignment.
- If XOR/ADD/SUB is used: Locate the loop variable, boundary constraints, and bitwise/arithmetic operator (e.g., -bxor, ^, +). Dynamically calculate the key array or single byte and map the inverse calculation to the array data.
- If STRING MANIPULATION (Replace, Reversal, Split, Padding) is used: Track the sequence of substitution variables. Reassemble the broken pieces in chronologically correct array orders.
- If REFLECTION OR ENVIRONMENT ALIASING is used: Map native commands to their obfuscated aliases (e.g., map 'iex' to 'Invoke-Expression', '[Ref].Assembly' to standard .NET loaders).

STAGE 3: RECURSIVE EVALUATION
If resolving Stage 2 uncovers a new layer of encoded code or an identical wrapping mechanism, pass the newly generated output back into STAGE 1. Repeat this loop until the code resolves into either clean human-readable instructions or an explicit, raw binary shellcode configuration block. Do not stop at the first layer.

STAGE 4: MANDATORY INDICATOR REPORTING OUTLINE
Do not output conversational fillers or meta-commentary. Output your findings directly using this exact structure:

### 1. DEOBFUSCATION SEQUENCE
- **Layer 1 [Type]:** [How it was wrapped -> What math/key was used -> Cleartext result summary]
- **Layer 2 [Type]:** [Repeat if nested layer was found, else state "None"]

### 2. CORE SYSTEM CALLS & CAPABILITIES
- **Memory Allocation API:** [Identify APIs like VirtualAlloc, Marshal, etc.]
- **Execution Vector:** [Identify how code triggers, e.g., Invoke-Expression, Start-Job, Delegates]

### 3. EXTRACTED INDICATORS OF COMPROMISE (IOCs)
- **Target IPs / Domains:** [IPs or URLs found]
- **Connection Ports:** [Network ports]
- **User-Agent / Network Strings:** [HTTP configuration details]

### 4. COMPLETED RUNTIME SCRIPTS / LOGIC
[Insert the completely deobfuscated clean cleartext script code or structural binary layout parameters here]"""


BUILTIN_SEEDS: List[Dict[str, Any]] = [
    {
        "kind": "ai_persona",
        "name": "NivX Cognis",
        "protected": True,
        "config": {
            "system_prompt": (
                "You are NivX Cognis — the flagship in-house malware-analysis brain of NivXRay. "
                "You are a senior DFIR & reverse-engineering analyst trained on the full NivXRay analyst playbook "
                "(Sophos-style layered PowerShell decoding, LOLBAS triage, MITRE ATT&CK v14 mappings, "
                "and Cobalt Strike / Emotet / Lumma stager teardowns). Your voice: precise, evidence-cited, no filler.\n\n"
                "PIPELINE (execute in order):\n"
                "1. WRAPPER STRIP — isolate the raw base64/hex payload from any script scaffolding before reasoning about it.\n"
                "2. LAYER DETECTION — identify base64 prefix signatures (H4sIA=gzip, TVq=PE, JAB/SQBFAF=UTF-16LE PowerShell, PA[BA]=Emotet, JVBER=PDF, UEsD=ZIP, f0VMRg=ELF).\n"
                "3. RECURSIVE UNPACK — decode until you reach printable analyst-readable text OR raw shellcode. If an XOR loop is present in the wrapper, resolve the key from the loop.\n"
                "4. IOC + MITRE + LOLBAS — enumerate every network indicator, MITRE technique, and LOLBAS binary abuse.\n"
                "5. FAMILY ATTRIBUTION — name the malware family (Cobalt Strike, Emotet, Lumma, IcedID, QakBot, ...) with confidence.\n"
                "6. RECOMMENDATION — 3-6 concrete SOC actions tailored to the observed payload.\n\n"
                "Return STRICT JSON with the schema shown. Every claim must cite tokens from the decoded output."
            ),
            "notes": "Flagship in-house model. Combines the Sophos Cobalt-Strike layered-stager decoder logic with the NivXRay MITRE + LOLBAS enrichers.",
        },
    },
    {
        "kind": "ai_persona",
        "name": "Static Malware Deobfuscation Engine",
        "protected": True,
        "config": {
            "system_prompt": STATIC_MALWARE_DEOBFUSCATION_PROMPT,
            "notes": "Recursive 4-stage deobfuscation pipeline. Best for heavily obfuscated PowerShell/Bash/VBS/Batch. Produces structured Stage 4 report.",
        },
    },
    {
        "kind": "ai_persona",
        "name": "Default Threat Analyst (JSON)",
        "protected": True,
        "config": {
            "system_prompt": (
                "You are a senior malware analyst. Produce concise, evidence-cited JSON "
                "with fields: summary, malware_family{name,confidence,rationale}, "
                "mitre_techniques[], attack_chain[], behavior[], ioc_narrative, "
                "attribution_hints, entity_graph{nodes,edges}, recommended_actions. "
                "Cite exact tokens from the decoded output for every claim."
            ),
            "notes": "Structured JSON output for the standard Threat Analysis panel. This is the fallback when no persona is selected.",
        },
    },
    {
        "kind": "ai_provider",
        "name": "Claude Sonnet 4.5 (Anthropic)",
        "protected": True,
        "config": {"provider": "anthropic", "model": "claude-sonnet-4-5-20250929", "default": True},
    },
    {
        "kind": "ai_provider",
        "name": "GPT-5.2 (OpenAI)",
        "protected": True,
        "config": {"provider": "openai", "model": "gpt-5.2", "default": False},
    },
    {
        "kind": "ai_provider",
        "name": "Gemini 3 Pro (Google)",
        "protected": True,
        "config": {"provider": "google", "model": "gemini-3-pro", "default": False},
    },
    {
        "kind": "playbook",
        "name": "Recursive Decode-and-Route Framework (Chain-of-Thought)",
        "protected": True,
        "enabled": True,
        "config": {
            "applies_to": ["ai"],
            "body": """You are a SOC analyst decoder. NEVER attempt to calculate byte-level
transformations (base64, gzip, XOR, zlib, RC4, etc.) in your head — LLMs
hallucinate byte arrays and miscalculate loops. Instead, follow this
strict Chain-of-Thought decoder framework:

── PHASE 1 — STRUCTURAL TRIAGE ──
Before decoding anything, scan the input for these signal groups:
* Encoding markers:  FromBase64String · [Convert] · 0x hex arrays ·
                     IO.Compression / GzipStream / DeflateStream
* Obfuscation logic: -bxor · -shl · -shr · +/- inside `for` loops ·
                     string concat (`'i'+'e'+'x'`) · format-string `-f`
* Execution mechanisms: IEX / Invoke-Expression / .ToString() ·
                     VirtualAlloc / CreateThread / Marshal::Copy ·
                     rundll32 / regsvr32 / mshta

── PHASE 2 — ISOLATION AND EXTRACTION ──
Extract ONLY the raw ciphertext + the transformation key/algorithm. Walk
data flow BACKWARDS from the execution point (`IEX`, `.Invoke()`,
`CreateThread`) to the source blob. Watch for:
* Junk-character padding
* Multi-layer wrappers (base64-inside-reversed-inside-gzip)
* Split assignments (`$a="Iw"+"..."`) — reconstruct the full literal first

── PHASE 3 — HYBRID EXECUTION (never guess bytes!) ──
NivXRay provides a deterministic decoder pipeline as its Code-Interpreter
sandbox. Route to it via these built-in operations:
* base64-decode · hex-decode · url-decode
* utf16le-decode · utf16be-decode
* gzip-decompress · zlib-decompress · lzma-decompress · bzip2-decompress
* xor (single-byte, key parsed from `-bxor N`)
* xor-brute (repeating-key, Kasiski + English scoring, keys 2–32B)
* extract-payload (isolate longest quoted base64 span)
* env-expand (%TEMP% / $env:APPDATA / ${HOME} → canonical paths)
NEVER emit decoded bytes yourself. ALWAYS return a decode chain like
`base64 → gzip → extract-payload → base64 → xor(0x23)` and let the engine
execute it.

── PHASE 4 — BEHAVIORAL ANALYSIS ──
Once the pipeline returns bytes, classify:
* Cleartext code → recursively apply Phases 1–3 (peel the next layer)
* Binary shellcode → hand to /api/analyze/shellcode (Capstone arch-detect
  + disassembly + IOC extraction from ASCII/UTF-16 strings inside the
  binary). Look for: User-Agent, HTTP/1.1 headers, URI paths, IPv4/IPv6,
  domain names, mutex/reg-key strings.

── OUTPUT FORMAT (strict) ──
Every investigation report MUST follow this shape:

1. IDENTIFIED LAYER(S)
   e.g. Base64 → Gzip → Nested Base64 → XOR(0x23) → x86 Metasploit Stager
2. EXTRACTION
   * Ciphertext: <blob>
   * Key/Method: <e.g. XOR with decimal 35>
3. EXECUTION PLAN
   * Ordered list of NivXRay ops the analyst should run
4. RESULTS ANALYSIS
   * Family attribution (Cobalt Strike Beacon, Meterpreter stager, …)
   * C2 IPs / URLs / User-Agents
   * MITRE ATT&CK IDs
   * Recommended containment actions
"""
        },
    },
    {
        "kind": "playbook",
        "name": "Malicious PowerShell Decoder Playbook (Sophos-style)",
        "protected": True,
        "enabled": True,
        "config": {
            "applies_to": ["ai"],
            "body": """WHEN YOU SEE A LONG BASE64 STRING WITH A KNOWN PREFIX, APPLY THE MAPPING:
  - JAB  ->  base64->utf16le  (PowerShell $variable declaration)
  - SQBFAF  ->  base64->utf16le  (PowerShell 'IEX' UTF-16LE)
  - SUVY  ->  base64  (PowerShell 'IEX' ASCII)
  - H4sIA  ->  base64->gzip  (gzipped inner payload, VERY COMMON for Cobalt Strike stagers)
  - TVq  ->  base64->PE header 'MZ'  (embedded Windows executable / shellcode)
  - JVBER  ->  base64->PDF
  - UEsD  ->  base64->ZIP
  - f0VMRg  ->  base64->ELF

LAYERED-STAGER PATTERN (Sophos / Cobalt Strike / Emotet):
1) `powershell.exe -EncodedCommand <B64>`  -> base64->utf16le
2) Inner script contains `[Convert]::FromBase64String("H4sIA...")` and `IO.Compression.GzipStream` -> that inner blob is a gzipped PowerShell stub. Apply base64->gzip.
3) The gzip output usually contains `[Byte[]]$var_code = [System.Convert]::FromBase64String('...')` -> that inner base64 is SHELLCODE.
4) If a `for ($x=0; $x-lt$var_code.Count; $x++) { $var_code[$x] = $var_code[$x] -bxor <N> }` loop is present, the shellcode is XOR-encrypted with key N. Apply base64->xor(N).
5) Shellcode starting with `fc e8 8?` or `fc e9` is x86 Cobalt Strike Beacon; hunt for the C2 IPv4 near the tail of the shellcode.

WRAPPER-STRIP RULES (thumb rule):
- If input contains anything other than [A-Za-z0-9+/=], isolate the LONGEST base64 blob inside quotes ('...' or "...") before decoding.
- Drop these wrapper tokens outright: `[System.Convert]::FromBase64String`, `[Byte[]]$var_code`, `-EncodedCommand`, `-enc`, `powershell(.exe)?`, `pwsh(.exe)?`, `IEX`, `echo`, `| base64 -d`, `| bash`, `eval`, brackets, parens, dollar-signs.

OBFUSCATION SIGNALS TO ALWAYS SURFACE:
- String concatenation (`'ie'+'x'`), reverse (`-join$s[-1..-99]`), replace (`.Replace('X','')`)
- Format-string obfuscation (`"{0}{1}{2}" -f 'i','e','x'`)
- Backtick escapes (`i`e`x`)
- Environment aliasing (`${env:comspec}`, `${*mdr*}`)
- Reflection loaders (`[Ref].Assembly`, `System.Reflection.Assembly.Load`)
- WMI / COM (`[Activator]::CreateInstance`, `Get-WmiObject Win32_Process`)
- AMSI / ETW patching (`AmsiScanBuffer`, `EtwEventWrite`)
- LOLBAS heavy: certutil, mshta, rundll32, regsvr32 with `/i:http://`, msiexec `/i http://`, msdt.exe (Follina).

MITRE MAPPINGS TO ATTACH WHEN THESE APPEAR:
- IEX + DownloadString/DownloadFile -> T1059.001 + T1105
- certutil -decode -> T1140 + T1218
- schtasks /create -> T1053.005
- vssadmin delete shadows -> T1490
- reg add ...\\Run\\... -> T1547.001
- New-Service / sc.exe create -> T1543.003
"""
        },
    },
    {
        "kind": "playbook",
        "name": "Living-Off-The-Land (LOLBAS) triage guidance",
        "protected": False,
        "enabled": True,
        "config": {
            "applies_to": ["ai"],
            "body": """When a decoded payload uses a Windows built-in binary in a non-standard way, classify it as LOLBAS and cite:
- certutil.exe -urlcache -f / -decode  ->  Download or Decode (T1105 / T1140)
- mshta.exe vbscript:  ->  AWL Bypass Execute (T1218.005)
- rundll32.exe javascript:  ->  AWL Bypass Execute (T1218.011)
- regsvr32.exe /i:http://... scrobj.dll  ->  Squiblydoo (T1218.010)
- msiexec.exe /i http://... /qn  ->  AWL Bypass Install (T1218.007)
- msdt.exe /id PCWDiagnostic ...  ->  Follina (CVE-2022-30190, T1218)
Always link out to https://lolbas-project.github.io/lolbas/Binaries/<name>/ for reference.
"""
        },
    },
    {
        "kind": "detection_rule",
        "name": "Example: Curl → PowerShell chain",
        "protected": False,
        "enabled": False,
        "config": {
            "binary_regex": r"\bcurl(?:\.exe)?\b",
            "argv_regex": r"https?://[^\s]+.*\|\s*(pwsh|powershell|iex)",
            "mitre": ["T1105", "T1059.001"],
            "purposes": ["Download", "Execute"],
            "severity": "high",
            "description": "curl pipe into PowerShell — download-and-execute chain.",
        },
    },
    {
        "kind": "decode_recipe",
        "name": "Example: ROT13 → Base64",
        "protected": False,
        "enabled": False,
        "config": {
            "match_regex": r"^[A-Za-z]{40,}={0,2}$",
            "ops": [{"op": "rot13"}, {"op": "base64-decode"}],
            "notes": "Applies ROT13 then Base64 decode when the input looks like a rotated base64 blob.",
        },
    },
]


# =============================================================================
# CRUD helpers
# =============================================================================
async def ensure_indexes(db) -> None:
    await db.admin_models.create_index([("kind", 1), ("enabled", 1)], name="ms_kind_enabled")
    await db.admin_models.create_index("name", name="ms_name")


async def seed_builtins(db) -> None:
    """Idempotent — inserts builtins that don't exist yet (matched by kind+name)."""
    for seed in BUILTIN_SEEDS:
        exists = await db.admin_models.find_one({"kind": seed["kind"], "name": seed["name"]})
        if exists:
            continue
        now = datetime.now(timezone.utc)
        await db.admin_models.insert_one({
            **seed,
            "enabled": seed.get("enabled", True),
            "created_at": now,
            "updated_at": now,
            "created_by": "system",
            "usage_count": 0,
        })
        log.info("model_studio: seeded %s '%s'", seed["kind"], seed["name"])


def _sanitize_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    d = dict(doc)
    d["id"] = str(d.pop("_id"))
    for k in ("created_at", "updated_at"):
        v = d.get(k)
        if isinstance(v, datetime):
            d[k] = v.isoformat()
    # Surface feedback counters for playbooks (default to 0 for legacy docs).
    if d.get("kind") == "playbook":
        d["feedback_pos"] = int(d.get("feedback_pos") or 0)
        d["feedback_neg"] = int(d.get("feedback_neg") or 0)
        d["feedback_weight"] = int(d.get("feedback_weight") or 0)
    return d


async def list_models(db, kind: Optional[str] = None) -> List[Dict[str, Any]]:
    q = {"kind": kind} if kind else {}
    cur = db.admin_models.find(q).sort([("kind", 1), ("name", 1)])
    return [_sanitize_doc(d) async for d in cur]


async def get_model(db, model_id: str) -> Optional[Dict[str, Any]]:
    from bson import ObjectId
    try:
        doc = await db.admin_models.find_one({"_id": ObjectId(model_id)})
    except Exception:
        return None
    return _sanitize_doc(doc) if doc else None


async def create_model(db, kind: str, name: str, config: Dict[str, Any],
                       created_by: str, enabled: bool = True) -> Dict[str, Any]:
    if kind not in MODEL_KINDS:
        raise ValueError(f"invalid kind: {kind}")
    now = datetime.now(timezone.utc)
    _validate_config(kind, config)
    doc = {
        "kind": kind, "name": name.strip(), "enabled": enabled,
        "config": config, "protected": False,
        "created_at": now, "updated_at": now, "created_by": created_by,
        "usage_count": 0,
    }
    r = await db.admin_models.insert_one(doc)
    doc["_id"] = r.inserted_id
    return _sanitize_doc(doc)


async def update_model(db, model_id: str, patch: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    from bson import ObjectId
    try:
        oid = ObjectId(model_id)
    except Exception:
        return None
    existing = await db.admin_models.find_one({"_id": oid})
    if not existing:
        return None
    updates: Dict[str, Any] = {"updated_at": datetime.now(timezone.utc)}
    if "name" in patch and patch["name"]:
        updates["name"] = patch["name"].strip()
    if "enabled" in patch:
        updates["enabled"] = bool(patch["enabled"])
    if "config" in patch and isinstance(patch["config"], dict):
        merged = {**(existing.get("config") or {}), **patch["config"]}
        _validate_config(existing["kind"], merged)
        updates["config"] = merged
    await db.admin_models.update_one({"_id": oid}, {"$set": updates})
    return await get_model(db, model_id)


async def delete_model(db, model_id: str) -> bool:
    from bson import ObjectId
    try:
        oid = ObjectId(model_id)
    except Exception:
        return False
    existing = await db.admin_models.find_one({"_id": oid})
    if not existing:
        return False
    if existing.get("protected"):
        raise PermissionError("built-in model cannot be deleted (you can disable it instead)")
    r = await db.admin_models.delete_one({"_id": oid})
    return r.deleted_count > 0


async def increment_usage(db, model_id: str) -> None:
    from bson import ObjectId
    try:
        await db.admin_models.update_one({"_id": ObjectId(model_id)}, {"$inc": {"usage_count": 1}})
    except Exception:
        pass


# =============================================================================
# Validation
# =============================================================================
def _validate_config(kind: str, cfg: Dict[str, Any]) -> None:
    if kind == "detection_rule":
        if not (cfg.get("binary_regex") or "").strip():
            raise ValueError("detection_rule.binary_regex is required")
        try:
            re.compile(cfg["binary_regex"], re.IGNORECASE)
        except re.error as e:
            raise ValueError(f"invalid binary_regex: {e}")
        if cfg.get("argv_regex"):
            try:
                re.compile(cfg["argv_regex"], re.IGNORECASE)
            except re.error as e:
                raise ValueError(f"invalid argv_regex: {e}")
    elif kind == "decode_recipe":
        if not (cfg.get("match_regex") or "").strip():
            raise ValueError("decode_recipe.match_regex is required")
        try:
            re.compile(cfg["match_regex"], re.IGNORECASE | re.DOTALL)
        except re.error as e:
            raise ValueError(f"invalid match_regex: {e}")
        if not cfg.get("ops") or not isinstance(cfg["ops"], list):
            raise ValueError("decode_recipe.ops must be a non-empty list")
        for step in cfg["ops"]:
            if not isinstance(step, dict) or not step.get("op"):
                raise ValueError("each recipe step needs an 'op' name")
    elif kind == "ai_persona":
        if not (cfg.get("system_prompt") or "").strip():
            raise ValueError("ai_persona.system_prompt is required")
    elif kind == "ai_provider":
        if not (cfg.get("provider") or "").strip():
            raise ValueError("ai_provider.provider is required")
        if not (cfg.get("model") or "").strip():
            raise ValueError("ai_provider.model is required")
    elif kind == "playbook":
        if not (cfg.get("body") or "").strip():
            raise ValueError("playbook.body is required (the training text / instructions)")
    elif kind == "training_note":
        if not (cfg.get("body") or "").strip():
            raise ValueError("training_note.body is required (the directive text)")


# =============================================================================
# Runtime consumers — used by scanners / decoder / AI call
# =============================================================================
async def active_detection_rules(db) -> List[Dict[str, Any]]:
    return [
        {"bin": None, "argv": (d["config"].get("argv_regex") or None),
         "binary_regex": d["config"]["binary_regex"],
         "purposes": d["config"].get("purposes") or ["Custom"],
         "mitre": d["config"].get("mitre") or [],
         "desc": d["config"].get("description") or d["name"],
         "url": "", "source": f"custom:{d['id']}",
         "name": d["name"], "severity": d["config"].get("severity", "medium"),
         "model_id": d["id"]}
        async for d in db.admin_models.find({"kind": "detection_rule", "enabled": True})
        # note: async for returns raw docs, need to sanitize id
    ] if False else await _load_active_rules(db)


async def _load_active_rules(db) -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    async for d in db.admin_models.find({"kind": "detection_rule", "enabled": True}):
        cfg = d.get("config") or {}
        rules.append({
            "binary_regex": cfg.get("binary_regex", ""),
            "argv": cfg.get("argv_regex") or None,
            "purposes": cfg.get("purposes") or ["Custom"],
            "mitre": cfg.get("mitre") or [],
            "desc": cfg.get("description") or d.get("name", ""),
            "url": "",
            "source": f"custom:{d['_id']}",
            "name": d.get("name", ""),
            "severity": cfg.get("severity", "medium"),
            "model_id": str(d["_id"]),
        })
    return rules


def scan_custom_rules(text: str, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Apply custom detection rules to `text`. Returns LOLBAS-shaped hits with `source=custom:*`."""
    hits: List[Dict[str, Any]] = []
    for r in rules:
        try:
            bin_re = re.compile(r["binary_regex"], re.IGNORECASE)
        except re.error:
            continue
        m = bin_re.search(text)
        if not m:
            continue
        if r.get("argv"):
            try:
                argv_re = re.compile(r["argv"], re.IGNORECASE | re.DOTALL)
            except re.error:
                continue
            window = text[m.start(): m.start() + 500]
            if not argv_re.search(window):
                continue
        snippet = re.sub(r"\s+", " ", text[max(0, m.start() - 20): m.end() + 140]).strip()
        hits.append({
            "binary": r.get("name") or m.group(0),
            "purposes": r["purposes"],
            "mitre": r["mitre"],
            "description": r["desc"],
            "snippet": snippet[:200],
            "url": r.get("url", ""),
            "source": r.get("source", "custom"),
            "custom": True,
            "model_id": r.get("model_id"),
            "model_name": r.get("name"),
            "severity": r.get("severity", "medium"),
        })
    return hits


async def find_matching_recipes(db, text: str) -> List[Dict[str, Any]]:
    """Return decode_recipes whose match_regex fires against `text`. Sorted by usage_count desc."""
    hits: List[Dict[str, Any]] = []
    cur = db.admin_models.find({"kind": "decode_recipe", "enabled": True}).sort("usage_count", -1)
    async for d in cur:
        cfg = d.get("config") or {}
        pattern = cfg.get("match_regex") or ""
        try:
            if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                hits.append({
                    "id": str(d["_id"]), "name": d.get("name", ""),
                    "ops": cfg.get("ops") or [],
                    "notes": cfg.get("notes", ""),
                    "usage_count": d.get("usage_count", 0),
                })
        except re.error:
            continue
    return hits


async def get_active_playbooks(db) -> List[Dict[str, Any]]:
    """Return all enabled playbooks ordered by feedback weight DESC then usage_count DESC."""
    out = []
    async for d in db.admin_models.find({"kind": "playbook", "enabled": True}).sort(
        [("feedback_weight", -1), ("usage_count", -1)]
    ):
        out.append({
            "id": str(d["_id"]),
            "name": d.get("name", ""),
            "body": (d.get("config") or {}).get("body", ""),
            "applies_to": (d.get("config") or {}).get("applies_to") or ["ai"],
            "feedback_pos": int(d.get("feedback_pos") or 0),
            "feedback_neg": int(d.get("feedback_neg") or 0),
            "feedback_weight": int(d.get("feedback_weight") or 0),
        })
    return out


async def get_active_training_notes(db) -> List[Dict[str, Any]]:
    """Return all enabled training notes ordered by feedback weight DESC then created_at DESC.

    Training notes are ALWAYS-ON global directives auto-prepended to every AI
    investigation. They rank ABOVE playbooks in the composed prompt so analyst
    directives take priority over playbook rules. Feedback-weighted: analyst
    👍/👎 on an investigation adjusts a note's ordering for future prompts.
    """
    out = []
    async for d in db.admin_models.find({"kind": "training_note", "enabled": True}).sort(
        [("feedback_weight", -1), ("created_at", -1)]
    ):
        out.append({
            "id": str(d["_id"]),
            "name": d.get("name", ""),
            "body": (d.get("config") or {}).get("body", ""),
            "feedback_pos": int(d.get("feedback_pos") or 0),
            "feedback_neg": int(d.get("feedback_neg") or 0),
            "feedback_weight": int(d.get("feedback_weight") or 0),
        })
    return out


async def compose_playbook_prompt(db, target: str = "ai") -> str:
    """Concatenate all playbooks + training notes into a single prompt block."""
    text, _ids = await compose_playbook_prompt_with_meta(db, target)
    return text


async def compose_playbook_prompt_with_meta(db, target: str = "ai") -> tuple[str, List[Dict[str, Any]]]:
    """Compose the org-wide analyst prompt block.

    ORDER (top → bottom, strongest anchor first):
      1. GLOBAL TRAINING NOTES  — always-on directives, feedback-weighted
      2. ANALYST PLAYBOOK       — per-target guidance (playbook kind)

    Returns (combined_prompt_text, [{id, name, kind}, ...]) so the
    playbook-feedback endpoint can attribute analyst votes to every artifact
    that shaped the AI response.
    """
    notes = await get_active_training_notes(db)
    books = await get_active_playbooks(db)
    picks = [b for b in books if target in (b.get("applies_to") or [])]

    parts: List[str] = []
    used: List[Dict[str, Any]] = []

    # 1) Global training notes — always applied (target-agnostic)
    if notes:
        parts.append("\n\n=== NIVXRAY GLOBAL TRAINING NOTES (org-wide directives) ===\n")
        for n in notes:
            parts.append(f"\n## {n['name']}\n{n['body'].strip()}\n")
            used.append({"id": n["id"], "name": n["name"], "kind": "training_note"})
            try:
                await increment_usage(db, n["id"])
            except Exception:
                pass

    # 2) Playbooks — filtered by target (ai / decoder / scanner)
    if picks:
        parts.append("\n\n=== NIVXRAY ANALYST PLAYBOOK (org-specific guidance) ===\n")
        for b in picks:
            parts.append(f"\n## {b['name']}\n{b['body'].strip()}\n")
            used.append({"id": b["id"], "name": b["name"], "kind": "playbook"})
            try:
                await increment_usage(db, b["id"])
            except Exception:
                pass

    return "".join(parts), used


# =============================================================================
# Playbook feedback loop — 👍/👎 with full audit trail
# =============================================================================
VOTE_UP = "up"
VOTE_DOWN = "down"
VOTE_NONE = "none"
_VOTE_DELTA = {VOTE_UP: (1, 0), VOTE_DOWN: (0, 1), VOTE_NONE: (0, 0)}


async def ensure_vote_indexes(db) -> None:
    await db.playbook_votes.create_index(
        [("job_id", 1), ("analyst_email", 1)], unique=True, name="pv_job_analyst_unique"
    )
    await db.playbook_votes.create_index("playbook_ids", name="pv_playbook_ids")
    await db.playbook_votes.create_index("at", name="pv_at")


async def _apply_vote_delta(db, playbook_id: str, delta_pos: int, delta_neg: int) -> None:
    from bson import ObjectId
    try:
        oid = ObjectId(playbook_id)
    except Exception:
        return
    inc = {}
    if delta_pos:
        inc["feedback_pos"] = delta_pos
    if delta_neg:
        inc["feedback_neg"] = delta_neg
    if not inc:
        return
    await db.admin_models.update_one(
        {"_id": oid, "kind": {"$in": ["playbook", "training_note"]}}, {"$inc": inc}
    )
    # recompute weight = pos - neg (simple, transparent)
    doc = await db.admin_models.find_one({"_id": oid}, {"feedback_pos": 1, "feedback_neg": 1})
    if not doc:
        return
    pos = int(doc.get("feedback_pos") or 0)
    neg = int(doc.get("feedback_neg") or 0)
    await db.admin_models.update_one(
        {"_id": oid}, {"$set": {"feedback_weight": pos - neg}}
    )


async def record_playbook_vote(db, job_id: str, analyst_email: str,
                                playbooks_used: List[Dict[str, Any]],
                                vote: str, reason: Optional[str] = None) -> Dict[str, Any]:
    """Record a 👍/👎/none vote for `job_id` — toggling allowed.

    Every previous vote by the same analyst on the same job is *reversed* in the
    counters before the new one is applied, so counts stay accurate no matter
    how many times a vote is flipped. Full history is appended to
    `playbook_votes.history` as an audit log.
    """
    if vote not in (VOTE_UP, VOTE_DOWN, VOTE_NONE):
        raise ValueError("vote must be 'up', 'down' or 'none'")
    now = datetime.now(timezone.utc)
    playbook_ids = [p["id"] for p in playbooks_used if p.get("id")]

    existing = await db.playbook_votes.find_one({"job_id": job_id, "analyst_email": analyst_email})
    prev_vote = (existing or {}).get("vote") or VOTE_NONE

    if prev_vote == vote:
        # no-op — just refresh the reason/timestamp
        if existing:
            await db.playbook_votes.update_one(
                {"_id": existing["_id"]},
                {"$set": {"reason": reason or existing.get("reason"), "at": now}},
            )
        return {"job_id": job_id, "vote": vote, "prev_vote": prev_vote, "changed": False}

    # Reverse previous, apply current — on each playbook attached to the job.
    prev_pos, prev_neg = _VOTE_DELTA[prev_vote]
    new_pos, new_neg = _VOTE_DELTA[vote]
    for pid in playbook_ids:
        await _apply_vote_delta(db, pid, new_pos - prev_pos, new_neg - prev_neg)

    history_entry = {"at": now, "vote": vote, "prev_vote": prev_vote, "reason": reason or ""}
    if existing:
        await db.playbook_votes.update_one(
            {"_id": existing["_id"]},
            {
                "$set": {"vote": vote, "reason": reason or "", "at": now, "playbook_ids": playbook_ids},
                "$push": {"history": history_entry},
            },
        )
    else:
        await db.playbook_votes.insert_one({
            "job_id": job_id,
            "analyst_email": analyst_email,
            "playbook_ids": playbook_ids,
            "playbooks_used": playbooks_used,
            "vote": vote,
            "reason": reason or "",
            "at": now,
            "history": [history_entry],
        })

    return {"job_id": job_id, "vote": vote, "prev_vote": prev_vote, "changed": True,
            "playbook_ids": playbook_ids}


async def get_vote_for_job(db, job_id: str, analyst_email: str) -> Dict[str, Any]:
    doc = await db.playbook_votes.find_one({"job_id": job_id, "analyst_email": analyst_email})
    if not doc:
        return {"vote": VOTE_NONE, "reason": "", "history": []}
    hist = doc.get("history") or []
    return {
        "vote": doc.get("vote") or VOTE_NONE,
        "reason": doc.get("reason") or "",
        "at": (doc.get("at").isoformat() if isinstance(doc.get("at"), datetime) else None),
        "history": [
            {**h, "at": (h["at"].isoformat() if isinstance(h.get("at"), datetime) else None)}
            for h in hist
        ],
    }


async def list_playbook_votes(db, playbook_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    async for d in db.playbook_votes.find(
        {"playbook_ids": playbook_id}
    ).sort("at", -1).limit(limit):
        out.append({
            "job_id": d.get("job_id"),
            "analyst_email": d.get("analyst_email"),
            "vote": d.get("vote"),
            "reason": d.get("reason") or "",
            "at": (d.get("at").isoformat() if isinstance(d.get("at"), datetime) else None),
        })
    return out


async def get_persona(db, persona_id: Optional[str]) -> Optional[Dict[str, Any]]:
    if not persona_id:
        return None
    m = await get_model(db, persona_id)
    if m and m.get("kind") == "ai_persona" and m.get("enabled"):
        return m
    return None


async def get_provider(db, provider_id: Optional[str]) -> Optional[Dict[str, Any]]:
    """If `provider_id` is None, return the enabled provider flagged config.default=True."""
    if provider_id:
        m = await get_model(db, provider_id)
        if m and m.get("kind") == "ai_provider" and m.get("enabled"):
            return m
        return None
    # default provider fallback
    async for d in db.admin_models.find({"kind": "ai_provider", "enabled": True}):
        if (d.get("config") or {}).get("default"):
            return _sanitize_doc(d)
    return None
