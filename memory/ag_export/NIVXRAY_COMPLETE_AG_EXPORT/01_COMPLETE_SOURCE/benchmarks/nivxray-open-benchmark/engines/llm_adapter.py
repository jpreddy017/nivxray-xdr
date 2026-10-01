"""LLM adapter — Claude Sonnet 4.5 / GPT-5.2 via Emergent Universal Key.

Requires `emergentintegrations` — pip install with the internal index:
    pip install emergentintegrations --extra-index-url \
        https://d33sy5i8bnduwe.cloudfront.net/simple/

Provider must be "anthropic" or "openai".
"""
import asyncio, os, re, json
from emergentintegrations.llm.chat import LlmChat, UserMessage

PROMPT = """You are a deterministic malware-command analyst. Given an obfuscated
command line, return STRICT JSON with keys: decoded_plaintext, urls, hosts,
lolbins, mitre (list of "Txxxx"), verdict ('malicious'|'suspicious'|'benign'|
'partial-recovery'), confidence (0-100), family_or_tool, notes. Do NOT invent
indicators. If a stage requires runtime execution or a key you cannot derive,
say so under `notes`."""


def decode(payload: str, api: str = "", provider: str = "anthropic",
           model: str = "claude-sonnet-4-5-20250929", **_kw) -> dict:
    key = os.environ.get("EMERGENT_LLM_KEY", "")
    async def _go():
        chat = LlmChat(api_key=key, session_id=f"bench-{payload[:16]}",
                       system_message="benchmark").with_model(provider, model)
        return await chat.send_message(UserMessage(text=PROMPT + "\n\n" + payload))
    text = asyncio.run(_go())
    text = str(text)
    m = re.search(r"\{[\s\S]*\}", text)
    parsed = None
    if m:
        try:
            parsed = json.loads(m.group(0))
        except Exception:
            pass
    return {"_raw": text[:4000], "parsed": parsed}
