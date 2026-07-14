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

MODEL_KINDS = ("detection_rule", "decode_recipe", "ai_persona", "ai_provider")

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
