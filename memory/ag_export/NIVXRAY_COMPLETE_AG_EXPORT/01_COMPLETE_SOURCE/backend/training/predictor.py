"""LLM-driven process-tree predictor.

Uses the Emergent LLM key + Claude Sonnet 4.5 (via `deps.llm_json`) to convert
a (raw + decoded) payload pair into a validated ProcessTree.

Anti-hallucination stack:
    1. Strict system prompt (`training.system_prompt`)
    2. Schema-typed parse (`training.schema`)
    3. Post-parse citation validator (`training.validator`)
"""
from __future__ import annotations
import asyncio
import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import HTTPException
from llm_provider import llm_json
from training.schema import ProcessTree, ProcessNode, SocRationale, ProcessEvidence
from training.system_prompt import NIVXRAY_PROCESS_TREE_SYSTEM
from training.validator import validate_and_prune


def _heuristic_tree(raw: str, decoded: str, reason: str) -> ProcessTree:
    """v1.5.8 — Heuristic fallback when the LLM is unavailable or times out.
    Builds a minimal but useful process tree from LOLBINs, IOCs, and MITRE
    hits extracted deterministically from the decoded payload. Never blank.
    """
    try:
        from operations import extract_iocs, mitre_map
        from lolbas import scan_lolbas
    except Exception:
        return _insufficient(reason)
    text = (decoded or "") + "\n" + (raw or "")
    iocs   = extract_iocs(text) or {}
    lolbas = scan_lolbas(text) or []
    mitre  = mitre_map(text) or []
    ips    = list(iocs.get("ipv4") or [])[:5]
    urls   = list(iocs.get("url")  or [])[:5]
    domains= list(iocs.get("domain") or [])[:5]
    files  = list(iocs.get("file_path") or iocs.get("filename") or [])[:5]
    hits   = [(l.get("binary") or l.get("name") or "?") for l in lolbas][:5]
    mitre_ids = [m.get("id") for m in mitre if m.get("id")][:8]

    # Root = the FIRST LOLBIN found (best guess at initial process); else "cmd.exe"
    root_proc = hits[0] if hits else ("powershell.exe" if "powershell" in text.lower() else "cmd.exe")
    root_action = "Deterministic tree — LLM unavailable, tree built from LOLBIN + IOC + MITRE evidence."

    children = []
    for lb in hits[1:]:
        children.append(ProcessNode(
            process=lb, action="Invoked LOLBIN",
            evidence=ProcessEvidence(citation=lb, inferred=True, confidence=0.4),
        ))
    for url in urls:
        children.append(ProcessNode(
            process="net.request", action=f"HTTP request → {url}",
            evidence=ProcessEvidence(citation=url, inferred=True, confidence=0.5),
        ))
    for f in files:
        children.append(ProcessNode(
            process="file.io", action=f"File operation → {f}",
            evidence=ProcessEvidence(citation=f, inferred=True, confidence=0.4),
        ))
    root = ProcessNode(
        process=root_proc, action=root_action,
        evidence=ProcessEvidence(citation=(hits[0] if hits else "heuristic"),
                                  inferred=True, confidence=0.35),
    )
    root.children = children

    from training.schema import SocRationale
    rationale = SocRationale(
        verdict=("Suspicious" if (urls or files or hits) else "Unknown"),
        severity=("medium" if (urls or hits) else "low"),
        mitre_ids=mitre_ids,
        summary=f"Heuristic fallback tree ({reason}). "
                f"{len(hits)} LOLBIN(s), {len(urls)} URL(s), {len(ips)} IP(s), "
                f"{len(domains)} domain(s), {len(files)} file(s).",
    )
    return ProcessTree(
        platform="windows",
        root=root,
        rationale=rationale,
        evidence_source="heuristic-fallback",
        warnings=[f"LLM unavailable — used deterministic evidence only ({reason})"],
    )


def _insufficient(reason: str) -> ProcessTree:
    return ProcessTree(
        root=ProcessNode(process="(insufficient)", action=reason,
                         evidence=ProcessEvidence(citation="", inferred=True, confidence=0.0)),
        evidence_source="insufficient",
        warnings=[reason],
    )


def _build_node(d: dict) -> ProcessNode:
    if not isinstance(d, dict):
        return ProcessNode(process="(malformed)", action="LLM returned non-dict node")
    d = {k: v for k, v in d.items() if v is not None}
    kids = d.pop("children", []) or []
    ev = d.pop("evidence", None) or {}
    node_kwargs = {
        k: v for k, v in d.items()
        if k in ProcessNode.model_fields and k not in ("children", "evidence")
    }
    node = ProcessNode(
        **node_kwargs,
        evidence=ProcessEvidence(**{k: v for k, v in ev.items() if k in ProcessEvidence.model_fields}),
    )
    node.children = [_build_node(c) for c in kids if isinstance(c, dict)]
    return node


async def predict_process_tree(raw: str, decoded: str,
                               session_id: Optional[str] = None) -> ProcessTree:
    """Predict + validate a process tree for the given raw/decoded pair."""
    if not (decoded or raw):
        return _insufficient("empty input")

    sid = session_id or f"ptp-{datetime.now(timezone.utc).timestamp()}"
    user_prompt = (
        f"RAW_INPUT:\n{(raw or '')[:4000]}\n\n"
        f"DECODED_OUTPUT:\n{(decoded or '')[:6000]}\n\n"
        "Emit strict JSON per the schema. Cite every node."
    )

    try:
        # v1.5.8 — hard timeout so PREDICT TREE never hangs the frontend
        # (frontend has 60s axios cap; give LLM 40s and reserve 20s for
        # heuristic fallback + serialisation on the way back).
        _pt_deadline = float(os.environ.get("NIVX_PREDICT_TREE_DEADLINE_S", "40"))
        data = await asyncio.wait_for(
            llm_json(sid, NIVXRAY_PROCESS_TREE_SYSTEM, user_prompt, retries=1),
            timeout=_pt_deadline,
        )
    except asyncio.TimeoutError:
        return _heuristic_tree(raw, decoded,
                               f"LLM timed out (>{int(_pt_deadline)}s) — heuristic tree emitted")
    except HTTPException as e:
        return _heuristic_tree(raw, decoded, f"LLM upstream unavailable ({e.detail})")
    except Exception as e:
        return _heuristic_tree(raw, decoded, f"LLM error: {e}")

    if not isinstance(data, dict) or "root" not in data:
        return _heuristic_tree(raw, decoded, "LLM returned malformed JSON")

    try:
        tree = ProcessTree(
            platform=data.get("platform", "windows"),
            root=_build_node(data.get("root") or {}),
            rationale=SocRationale(
                **{k: v for k, v in (data.get("rationale") or {}).items()
                   if k in SocRationale.model_fields}
            ),
            evidence_source=data.get("evidence_source", "decoded"),
            warnings=list(data.get("warnings", [])),
        )
    except Exception as e:
        return _heuristic_tree(raw, decoded, f"schema build error: {e}")

    validated, _dropped = validate_and_prune(tree, decoded or "", raw or "")
    return validated
