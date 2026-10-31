"""
SigmaHQ ingestion — Phase 1 of the Detection Content Supply Chain.

This module performs the DISCOVERY + PARSED + VALID stages of the
pipeline.  The remaining stages (SUPPORTED · ENGINE_BOUND ·
TEST_PASSED · EXECUTION_READY · ENABLED · ACTIVE) are subsequent
slices and MUST NOT be granted here.

Entry points:
    ingest_sigmahq(repo_dir, dry_run) → CompatibilityReport
        walks the repo, parses each YAML with pysigma (when
        available) or a minimal YAML fallback, upserts one
        `detection_content` document per rule, appends milestone
        state transitions, returns a per-milestone count summary.
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .model import (
    COLLECTION, ContentSource, LifecycleState,
    new_content_doc,
)
from .sigma_strict import strict_parse, StrictParseStatus, is_pysigma_available


def _hash_content(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()


def _load_yaml(text: str) -> Any:
    """Prefer pysigma-friendly YAML load; fall back to PyYAML."""
    import yaml  # type: ignore
    return yaml.safe_load(text)


def _extract_rule_meta(y: dict) -> dict:
    """
    Extract common Sigma metadata into the canonical fields the
    supply chain cares about at this stage — data sources, log
    sources, ATT&CK tags, level, platform.
    """
    logsource = y.get("logsource", {}) or {}
    tags = y.get("tags", []) or []
    attack_tags = [t.replace("attack.", "").upper() for t in tags
                       if isinstance(t, str) and t.startswith("attack.t")]
    return {
        "title":         y.get("title") or "(untitled)",
        "description":   y.get("description"),
        "author":        y.get("author"),
        "level":         y.get("level"),
        "product":       logsource.get("product"),
        "category":      logsource.get("category"),
        "service":       logsource.get("service"),
        "attack_tags":   attack_tags,
        "raw_tags":      tags,
    }


def _canonical_platform(product: str | None) -> list[str]:
    if not product:
        return []
    p = str(product).lower()
    if p == "windows":  return ["windows"]
    if p == "linux":    return ["linux"]
    if p == "macos":    return ["macos"]
    if p == "azure":    return ["cloud", "azure"]
    if p == "aws":      return ["cloud", "aws"]
    if p == "gcp":      return ["cloud", "gcp"]
    return [p]


def _looks_like_supported(y: dict) -> tuple[bool, str | None]:
    """
    Heuristic first-pass: NivXRay currently has parsers for
    powershell, cmd, generic Windows sysmon (process_creation),
    and a normalizer library.  Everything else is honestly
    UNSUPPORTED at this stage of the supply chain.

    Returns (supported, reason_when_not).
    """
    ls = (y.get("logsource") or {})
    product  = str(ls.get("product") or "").lower()
    category = str(ls.get("category") or "").lower()

    # Currently supported by NivXRay engine fabric.
    if product == "windows" and category in {
        "process_creation", "ps_module", "ps_script",
        "powershell", "amsi",
    }:
        return (True, None)
    # No product → too generic to bind to an engine at this stage.
    if not product:
        return (False, "logsource.product missing")
    return (False, f"NivXRay does not yet support product={product} category={category}")


def _record_state(doc: dict, state: LifecycleState, reason: str | None = None):
    hist = doc.setdefault("state_history", [])
    if state.value not in hist:
        hist.append(state.value)
    prov = doc.setdefault("provenance", {})
    key = {
        LifecycleState.DISCOVERED:      "discovered_at",
        LifecycleState.PARSED:          "parsed_at",
        LifecycleState.VALID:           "validated_at",
    }.get(state)
    if key:
        prov[key] = datetime.now(timezone.utc).isoformat()
    if reason:
        doc["state_reason"] = reason


def ingest_sigmahq(
    repo_dir: str | os.PathLike,
    *,
    limit: int | None = None,
    dry_run: bool = True,
    mongo_db=None,
) -> dict:
    """
    Walk a cloned SigmaHQ tree under `repo_dir` and produce a real
    compatibility report.  When `dry_run=True` the run inspects
    and reports without writing.  When False, upserts into the
    canonical `detection_content` collection (if `mongo_db` is
    provided).

    Returns a report dict compatible with the P0 spec:

        {
          "source":      "SIGMAHQ",
          "repo_dir":    "...",
          "totals": {
            "discovered": int, "parsed": int, "invalid": int,
            "valid": int, "supported": int, "unsupported": int,
            "attack_mapped": int, "with_data_source": int,
            "field_mapping_missing": int, "engine_unbound": int,
          },
          "products":     { "windows": int, "linux": int, ... },
          "unsupported_reasons": { reason: count, ... },
          "samples":      [ up to 20 example documents ],
        }
    """
    root = Path(repo_dir)
    totals = {
        "discovered": 0, "parsed": 0, "invalid": 0, "valid": 0,
        "supported": 0, "unsupported": 0,
        "attack_mapped": 0,
        "with_data_source": 0,
        "field_mapping_missing": 0,
        "engine_unbound": 0,
        # P0.2b strict-parse breakdown
        "strict_parsed":     0,
        "strict_parse_error":   0,
        "strict_compile_error": 0,
        "strict_lib_missing":   0,
    }
    products: dict[str, int] = {}
    unsupported_reasons: dict[str, int] = {}
    parse_errors: list[dict] = []       # up to N samples for the API
    samples: list[dict] = []

    if not root.exists():
        return {
            "source": "SIGMAHQ", "repo_dir": str(root),
            "error": f"Repository directory not found: {root}",
            "totals": totals, "products": products,
            "unsupported_reasons": unsupported_reasons, "samples": [],
        }

    yaml_files = sorted([p for p in root.rglob("*.yml")
                          if "/deprecated/" not in str(p)])
    if limit:
        yaml_files = yaml_files[:limit]

    for path in yaml_files:
        totals["discovered"] += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            totals["invalid"] += 1
            continue

        # ---- P0.2b · Strict pySigma parse ------------------------
        result = strict_parse(text)
        if result.status == StrictParseStatus.LIB_MISSING:
            totals["strict_lib_missing"] += 1
        elif result.status == StrictParseStatus.PARSE_ERROR:
            totals["strict_parse_error"] += 1
            if len(parse_errors) < 30:
                parse_errors.append({
                    "path":           str(path.relative_to(root)),
                    **result.to_dict(),
                })
            totals["invalid"] += 1
            continue
        elif result.status == StrictParseStatus.COMPILE_ERROR:
            totals["strict_compile_error"] += 1
            if len(parse_errors) < 30:
                parse_errors.append({
                    "path":           str(path.relative_to(root)),
                    **result.to_dict(),
                })
            totals["invalid"] += 1
            continue
        else:
            totals["strict_parsed"] += 1

        # Legacy YAML re-parse purely for the metadata surface —
        # cheap after the strict parse has already succeeded.
        import yaml as _yaml
        try:
            y = _yaml.safe_load(text)
        except Exception:
            totals["invalid"] += 1
            continue
        if not isinstance(y, dict) or "detection" not in y:
            continue
        totals["parsed"] += 1

        meta = _extract_rule_meta(y)
        rule_id = str(y.get("id") or path.stem)
        body_hash = _hash_content(text)

        doc = new_content_doc(
            source=ContentSource.SIGMAHQ,
            source_rule_id=rule_id,
            title=meta["title"],
            rule_type="sigma",
            source_repository="https://github.com/SigmaHQ/sigma",
            source_version=y.get("modified") or y.get("date"),
            license=None,  # SigmaHQ is DRL-1.1, applied via governance layer
            author=str(meta["author"] or "unknown"),
            description=meta["description"],
            raw_body=text,
            canonical_content_hash=body_hash,
        )
        # PARSED milestone
        _record_state(doc, LifecycleState.PARSED)

        # Basic validity: has title + detection + logsource.
        has_logsource = bool((y.get("logsource") or {}))
        if meta["title"] and has_logsource:
            _record_state(doc, LifecycleState.VALID)
            totals["valid"] += 1
        else:
            _record_state(doc, LifecycleState.INVALID, "missing title or logsource")
            totals["invalid"] += 1
            continue

        # Product distribution
        prod = str(meta["product"] or "unknown").lower()
        products[prod] = products.get(prod, 0) + 1
        doc["platform"] = _canonical_platform(prod)

        # ATT&CK mapping
        if meta["attack_tags"]:
            doc["mitre_attack"] = meta["attack_tags"]
            totals["attack_mapped"] += 1

        # Tags
        doc["tags"]     = [t for t in (meta["raw_tags"] or []) if isinstance(t, str)]
        doc["severity"] = meta["level"]

        # Log sources → captured for future data-source binding.
        ls = y.get("logsource") or {}
        doc["log_sources"] = [{
            "product":  ls.get("product"),
            "category": ls.get("category"),
            "service":  ls.get("service"),
        }]

        # Required fields — pull from the detection map when
        # trivially extractable (best-effort at this stage).
        req_fields: set[str] = set()
        det = y.get("detection") or {}
        for k, v in det.items():
            if not isinstance(v, dict):
                continue
            for sub in v.keys():
                # `Image|endswith`, `CommandLine|contains|all`, etc.
                field = str(sub).split("|", 1)[0].strip()
                if field:
                    req_fields.add(field)
        doc["required_fields"] = sorted(req_fields)

        # Support determination (heuristic first pass — honest).
        supported, reason = _looks_like_supported(y)
        if supported:
            _record_state(doc, LifecycleState.SUPPORTED)
            totals["supported"] += 1
            if not doc["required_fields"]:
                _record_state(doc, LifecycleState.FIELD_MAPPING_MISSING,
                                 "detection block yielded no required fields")
                totals["field_mapping_missing"] += 1
        else:
            _record_state(doc, LifecycleState.UNSUPPORTED, reason)
            totals["unsupported"] += 1
            if reason:
                unsupported_reasons[reason] = unsupported_reasons.get(reason, 0) + 1

        # Engine binding — deferred to a subsequent slice.
        _record_state(doc, LifecycleState.ENGINE_UNBOUND,
                             "engine binding phase not yet run")
        totals["engine_unbound"] += 1

        if doc["log_sources"]:
            totals["with_data_source"] += 1

        if not dry_run and mongo_db is not None:
            mongo_db[COLLECTION].update_one(
                {"content_id": doc["content_id"]},
                {"$set":         {k: v for k, v in doc.items() if k != "state_history"},
                 "$addToSet":    {"state_history": {"$each": doc["state_history"]}}},
                upsert=True,
            )

        if len(samples) < 20:
            samples.append({
                "content_id":     doc["content_id"],
                "title":          doc["title"],
                "product":        prod,
                "state_history":  doc["state_history"],
                "attack":         doc["mitre_attack"][:4],
                "required_fields": doc["required_fields"][:6],
            })

    return {
        "source":               "SIGMAHQ",
        "repo_dir":             str(root),
        "totals":               totals,
        "products":             products,
        "unsupported_reasons":  unsupported_reasons,
        "parse_errors":         parse_errors,
        "pysigma_available":    is_pysigma_available(),
        "samples":              samples,
    }
