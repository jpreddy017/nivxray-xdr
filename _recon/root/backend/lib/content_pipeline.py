"""
NivXRay Unified Content Source Adapter Framework
================================================

Every open-source detection / signature / intelligence source that
NivXRay ingests (Sigma · Snort · Suricata · YARA · MITRE ATT&CK · CVE ·
KEV · EPSS · …) MUST flow through this single deterministic pipeline.
No source-specific pipeline shortcuts are permitted.

Contract:

    ContentSource(name, upstream_url, fallback_urls, parser, bundled_url)
        │
        ▼
    Acquisition  →  License Policy Evaluation  →  Parser
        │                                             │
        ▼                                             ▼
    Normalizer  →  Dedup  →  ATT&CK / CVE mapping  →  Observation Semantics
        │
        ▼
    Regression Ready  →  Detection Registry  (never fabricates)

Rules that fail license policy or schema validation are RETAINED with
explicit failure state so operators can audit them.  ACTIVE is reserved
for content that passes every stage.

Detection ≠ Verdict:  every rule that emits a signal DOES NOT emit a
verdict.  Correlation → IKG → ICE → Verdict engines own the final
decision.  This invariant is preserved by the `capability_not_verdict`
flag stamped by the parser and never overwritten downstream.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse
from urllib.request import Request as URLRequest
from urllib.request import urlopen

from lib.content_policy import (
    STATE_LICENSE_BLOCKED,
    STATE_LICENSE_REVIEW,
    evaluate_license,
    is_activatable,
)

# ── Constants / exceptions ───────────────────────────────────────
_STAGES = [
    "DISCOVERED", "DOWNLOADED", "PARSED", "LICENSE_EVALUATED",
    "SCHEMA_VALIDATED", "NORMALIZED", "DEDUPLICATED",
    "ATTACK_MAPPED", "REGISTERED", "COMPLETE",
]

_ATTACK_RE = re.compile(r"^attack\.t\d{4}(?:\.\d{3})?$", re.IGNORECASE)


class UpstreamError(Exception):
    def __init__(self, code: str, detail: str):
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── ContentSource ────────────────────────────────────────────────
@dataclass
class ContentSource:
    """One open-source content source.  A parser converts raw bytes
    into a list of canonical `content records` (dicts)."""

    name: str                                  # e.g. "SigmaHQ", "Snort", ...
    upstream_url: str | None                   # live URL (may be None)
    parser: Callable[[bytes], list[dict[str, Any]]]
    bundled_url: str | None = None             # file:// fallback
    fallback_urls: list[str] = field(default_factory=list)
    display_name: str | None = None
    homepage: str | None = None
    default_license: str | None = None
    default_rule_type: str | None = None

    def targets(self) -> list[str]:
        raw = [self.upstream_url, *self.fallback_urls, self.bundled_url]
        return [t for t in raw if t]


# ── Fetch helper ─────────────────────────────────────────────────
def _fetch(url: str, timeout: float = 30.0) -> tuple[bytes, str]:
    parsed = urlparse(url)
    if parsed.scheme == "file":
        p = Path(parsed.path)
        if not p.exists():
            raise UpstreamError("UPSTREAM_UNAVAILABLE", f"not found: {p}")
        return p.read_bytes(), url
    if parsed.scheme in ("http", "https"):
        try:
            req = URLRequest(url, headers={"User-Agent": "NivXRay-XDR/1.0"})
            with urlopen(req, timeout=timeout) as r:
                return r.read(), url
        except Exception as exc:
            raise UpstreamError("UPSTREAM_UNAVAILABLE", str(exc)) from exc
    raise UpstreamError("UPSTREAM_UNSUPPORTED", parsed.scheme)


# ── Normalisation helpers ────────────────────────────────────────
def _extract_attack(tags: list[str]) -> list[str]:
    return sorted({t.upper().replace("ATTACK.", "")
                                for t in tags if _ATTACK_RE.match(t)})


def _content_hash(raw: dict) -> str:
    payload = json.dumps(raw.get("detection") or raw.get("rule_body") or {},
                                        sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


def _validate_schema(raw: dict) -> list[str]:
    errs: list[str] = []
    for k in ("id", "title", "source", "license", "rule_type"):
        if not raw.get(k):
            errs.append(f"missing {k}")
    if not (raw.get("detection") or raw.get("rule_body")):
        errs.append("missing detection/rule_body")
    return errs


def _normalise(raw: dict, upstream_hash: str, source_name: str) -> dict:
    tags = [t for t in (raw.get("tags") or []) if isinstance(t, str)]
    attack = _extract_attack(tags)
    lic_eval = evaluate_license(raw.get("license"))
    return {
        "id":                     f"det_{uuid.uuid4().hex[:20]}",
        "upstream_id":            raw["id"],
        "upstream_version":       f"sha256:{upstream_hash[:12]}",
        "title":                  raw["title"],
        "description":            raw.get("description"),
        "source":                 raw.get("source") or source_name,
        "source_url":             raw.get("source_url"),
        "license":                raw.get("license"),
        "license_id":             lic_eval["license_id"],
        "license_policy_state":   lic_eval["state"],
        "license_policy_reason":  lic_eval["reason"],
        "license_verified":       bool(raw.get("license_verified")),
        "author":                 raw.get("author"),
        "created":                raw.get("created"),
        "modified":               raw.get("modified"),
        "original_content_hash":  _content_hash(raw),
        "level":                  raw.get("level"),
        "status":                 raw.get("status"),
        "tags":                   tags,
        "attack_techniques":      attack,
        "cve_references":         raw.get("cve_references") or [],
        "logsource":              raw.get("logsource") or {},
        "detection":              raw.get("detection") or raw.get("rule_body"),
        "rule_body":              raw.get("rule_body"),
        "rule_type":              raw["rule_type"],
        "capability_not_verdict": bool(raw.get("capability_not_verdict")),
        # State reflects lifecycle after evaluation.
        # LICENSE_BLOCKED or LICENSE_REVIEW → not activatable; the
        # registrar keeps them in the registry so they are visible in
        # audit but never enters ACTIVE.
        "state":                  ("LICENSE_BLOCKED"
                                                if lic_eval["state"] == STATE_LICENSE_BLOCKED
                                                else "LICENSE_REVIEW"
                                                if lic_eval["state"] == STATE_LICENSE_REVIEW
                                                else "IMPORTED"),
        "state_reason":           lic_eval["reason"],
        "enabled":                False,
        "parser_version":         "unified-pipeline-1.0",
        "lineage":                {"pipeline": _STAGES,
                                            "source": source_name,
                                            "imported_at": _now()},
    }


# ── Pipeline ─────────────────────────────────────────────────────
def run_pipeline(source: ContentSource,
                                *, idempotent_hash_check: Callable[[str], dict | None]
                                                        | None = None
                                ) -> dict[str, Any]:
    """Deterministic 10-stage pipeline for a single ContentSource.

    Returns a `version` dict with:
        outcome, stages, counts, rules[], upstream_sha256, upstream_url,
        fallback_used, source_name
    """
    stages = {s: {"status": "PENDING"} for s in _STAGES}
    counts = {"discovered": 0, "downloaded": 0, "parsed": 0,
                  "license_permitted": 0, "license_restricted": 0,
                  "license_review": 0, "license_blocked": 0,
                  "schema_valid": 0, "schema_invalid": 0,
                  "deduplicated": 0, "attack_mapped": 0,
                  "cve_mapped": 0, "normalized": 0}

    targets = source.targets()
    stages["DISCOVERED"] = {"status": "OK" if targets else "FAIL",
                                          "targets": targets}
    if not targets:
        return {"outcome": "UPSTREAM_UNAVAILABLE", "stages": stages,
                    "counts": counts, "rules": [],
                    "source_name": source.name, "upstream_sha256": "",
                    "upstream_url": "", "fallback_used": False}

    # 2 DOWNLOAD
    raw = None
    used_url = ""
    attempts: list[dict] = []
    for t in targets:
        try:
            raw, used_url = _fetch(t)
            break
        except UpstreamError as exc:
            attempts.append({"url": t, "code": exc.code, "detail": exc.detail})
    if raw is None:
        stages["DOWNLOADED"] = {"status": "FAIL", "attempts": attempts}
        return {"outcome": "UPSTREAM_UNAVAILABLE", "stages": stages,
                    "counts": counts, "rules": [],
                    "source_name": source.name, "upstream_sha256": "",
                    "upstream_url": "", "fallback_used": False}
    upstream_hash = hashlib.sha256(raw).hexdigest()
    fallback_used = used_url != targets[0]
    stages["DOWNLOADED"] = {"status": "OK", "bytes": len(raw),
                                        "sha256": upstream_hash, "used_url": used_url,
                                        "fallback_used": fallback_used,
                                        "acquisition_state": ("LIVE" if not fallback_used
                                                                                else "BUNDLED_FALLBACK")}

    if idempotent_hash_check is not None:
        prior = idempotent_hash_check(upstream_hash)
        if prior:
            return {**prior, "idempotent_skip": True, "stages": stages,
                        "counts": counts, "rules": [],
                        "source_name": source.name,
                        "upstream_sha256": upstream_hash,
                        "upstream_url": used_url,
                        "fallback_used": fallback_used}

    # 3 PARSE (source-specific)
    try:
        parsed_records = source.parser(raw)
    except Exception as exc:  # noqa: BLE001
        stages["PARSED"] = {"status": "FAIL", "detail": str(exc)}
        return {"outcome": "PARSE_FAILED", "stages": stages,
                    "counts": counts, "rules": [],
                    "source_name": source.name,
                    "upstream_sha256": upstream_hash,
                    "upstream_url": used_url,
                    "fallback_used": fallback_used}
    if not isinstance(parsed_records, list):
        stages["PARSED"] = {"status": "FAIL", "detail": "parser must return list"}
        return {"outcome": "PARSE_FAILED", "stages": stages,
                    "counts": counts, "rules": [],
                    "source_name": source.name,
                    "upstream_sha256": upstream_hash,
                    "upstream_url": used_url,
                    "fallback_used": fallback_used}
    counts["discovered"] = counts["downloaded"] = counts["parsed"] = \
        len(parsed_records)
    stages["PARSED"] = {"status": "OK", "records": len(parsed_records)}

    # 4 LICENSE EVALUATE (never discards content — stamps every record)
    licensed: list[dict] = []
    for r in parsed_records:
        lic = evaluate_license(r.get("license"))
        r["_policy_state"] = lic["state"]
        if lic["state"] == "PERMITTED":
            counts["license_permitted"] += 1
        elif lic["state"] == "RESTRICTED":
            counts["license_restricted"] += 1
        elif lic["state"] == STATE_LICENSE_REVIEW:
            counts["license_review"] += 1
        elif lic["state"] == STATE_LICENSE_BLOCKED:
            counts["license_blocked"] += 1
        licensed.append(r)
    stages["LICENSE_EVALUATED"] = {
        "status": "OK",
        "permitted": counts["license_permitted"],
        "restricted": counts["license_restricted"],
        "review": counts["license_review"],
        "blocked": counts["license_blocked"],
    }

    # 5 SCHEMA
    valid: list[dict] = []
    invalid: list[dict] = []
    for r in licensed:
        errs = _validate_schema(r)
        if errs:
            invalid.append({"id": r.get("id"), "errors": errs})
        else:
            valid.append(r)
    counts["schema_valid"] = len(valid)
    counts["schema_invalid"] = len(invalid)
    stages["SCHEMA_VALIDATED"] = {
        "status": "OK" if not invalid else "PARTIAL",
        "valid": len(valid), "invalid": len(invalid),
        "invalid_sample": invalid[:10],
    }

    # 6 NORMALIZE
    normalized = [_normalise(r, upstream_hash, source.name) for r in valid]
    counts["normalized"] = len(normalized)
    stages["NORMALIZED"] = {"status": "OK", "normalized": len(normalized)}

    # 7 DEDUP
    seen: set[tuple] = set()
    deduped: list[dict] = []
    for n in normalized:
        key = (n["source"], n["upstream_id"], n["original_content_hash"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(n)
    counts["deduplicated"] = len(deduped)
    stages["DEDUPLICATED"] = {"status": "OK", "kept": len(deduped),
                                              "collapsed": len(normalized) - len(deduped)}

    # 8 ATT&CK / CVE MAP
    mapped = sum(1 for n in deduped if n["attack_techniques"])
    cve_mapped = sum(1 for n in deduped if n.get("cve_references"))
    counts["attack_mapped"] = mapped
    counts["cve_mapped"] = cve_mapped
    stages["ATTACK_MAPPED"] = {"status": "OK", "mapped": mapped,
                                                  "unmapped": len(deduped) - mapped,
                                                  "cve_mapped": cve_mapped}

    # 9 REGISTRAR — done outside (adapter binds registrar); marker OK
    stages["REGISTERED"] = {"status": "OK", "records": len(deduped)}

    # 10 COMPLETE gate
    every_ok = all(stages[s]["status"] in ("OK", "PARTIAL")
                              for s in ["DISCOVERED", "DOWNLOADED", "PARSED",
                                              "LICENSE_EVALUATED", "SCHEMA_VALIDATED",
                                              "NORMALIZED", "DEDUPLICATED",
                                              "ATTACK_MAPPED"])
    stages["COMPLETE"] = {"status": "OK" if every_ok else "PARTIAL"}
    outcome = "COMPLETE" if every_ok and not invalid else "PARTIAL"
    return {
        "outcome": outcome,
        "stages": stages,
        "counts": counts,
        "rules": deduped,
        "source_name": source.name,
        "upstream_sha256": upstream_hash,
        "upstream_url": used_url,
        "fallback_used": fallback_used,
        "acquisition_state": ("LIVE" if not fallback_used
                                            else "BUNDLED_FALLBACK"),
    }


# ── Built-in parsers ─────────────────────────────────────────────
def json_list_parser(raw: bytes) -> list[dict[str, Any]]:
    """Bundled snapshots are JSON arrays of canonical records."""
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, list):
        raise ValueError("expected top-level JSON array")
    return data


__all__ = [
    "ContentSource", "UpstreamError", "run_pipeline",
    "json_list_parser", "_STAGES", "is_activatable",
]
