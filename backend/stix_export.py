"""NivXRay — Minimal STIX 2.1 bundle exporter for a single decoded investigation.

Produces a valid STIX 2.1 bundle containing:
  - identity            (the analyst producing this bundle)
  - indicators          (URLs / IPs / domains / file hashes)
  - attack-patterns     (MITRE techniques with external references)
  - observed-data       (raw extracted IOCs referenced by indicators)
  - report              (top-level container tying everything together)

Reference: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
"""
from __future__ import annotations
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List


def _uid(kind: str, seed: str) -> str:
    """Deterministic UUIDv5 based on kind+seed for stable STIX ids across runs."""
    ns = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # standard NAMESPACE_DNS
    return f"{kind}--{uuid.uuid5(ns, f'nivxray/{kind}/{seed}')}"


def _iso(dt: datetime | None = None) -> str:
    return (dt or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def build_investigation_bundle(
    *,
    analyst_email: str,
    input_preview: str,
    output_preview: str,
    engine: str | None,
    confidence: int | None,
    trace: List[Dict[str, Any]],
    iocs: Dict[str, List[str]],
    mitre: List[Dict[str, Any]],
    verdict: Dict[str, Any] | None,
) -> Dict[str, Any]:
    """Return a STIX 2.1 bundle dict ready to json.dumps()."""
    ts = _iso()
    objects: List[Dict[str, Any]] = []

    # -- identity ---------------------------------------------------------- #
    identity_id = _uid("identity", analyst_email or "unknown-analyst")
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": ts, "modified": ts,
        "name": analyst_email or "unknown-analyst",
        "identity_class": "individual",
        "sectors": ["technology"],
    })

    ref_ids: List[str] = []

    # -- indicators for URLs / IPs / domains ------------------------------- #
    def _indicator(kind: str, value: str, pattern: str, label: str) -> Dict[str, Any]:
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": _uid("indicator", f"{kind}:{value}"),
            "created": ts, "modified": ts,
            "created_by_ref": identity_id,
            "name": f"{label}: {value}",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": ts,
            "labels": ["malicious-activity", "nivxray-decoded"],
            "confidence": confidence if confidence is not None else 75,
        }

    for u in iocs.get("urls") or []:
        ind = _indicator("url", u, f"[url:value = '{u}']", "Malicious URL")
        objects.append(ind); ref_ids.append(ind["id"])
    for ip in iocs.get("ips") or []:
        ind = _indicator("ipv4-addr", ip, f"[ipv4-addr:value = '{ip}']", "Malicious IPv4")
        objects.append(ind); ref_ids.append(ind["id"])
    for d in iocs.get("domains") or []:
        ind = _indicator("domain-name", d, f"[domain-name:value = '{d}']", "Malicious Domain")
        objects.append(ind); ref_ids.append(ind["id"])
    for h in iocs.get("md5") or []:
        ind = _indicator("file-md5", h, f"[file:hashes.MD5 = '{h}']", "Malicious File (MD5)")
        objects.append(ind); ref_ids.append(ind["id"])
    for h in iocs.get("sha1") or []:
        ind = _indicator("file-sha1", h, f"[file:hashes.'SHA-1' = '{h}']", "Malicious File (SHA-1)")
        objects.append(ind); ref_ids.append(ind["id"])
    for h in iocs.get("sha256") or []:
        ind = _indicator("file-sha256", h, f"[file:hashes.'SHA-256' = '{h}']", "Malicious File (SHA-256)")
        objects.append(ind); ref_ids.append(ind["id"])

    # -- attack-patterns for MITRE techniques ----------------------------- #
    for m in mitre or []:
        tid = m.get("id") or ""
        if not tid: continue
        ap = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": _uid("attack-pattern", f"mitre:{tid}"),
            "created": ts, "modified": ts,
            "created_by_ref": identity_id,
            "name": m.get("technique") or tid,
            "description": m.get("evidence") or "",
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": tid,
                "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
            }],
            "kill_chain_phases": ([{
                "kill_chain_name": "mitre-attack",
                "phase_name": (m.get("tactic") or "unknown").lower().replace(" ", "-"),
            }] if m.get("tactic") else []),
        }
        objects.append(ap); ref_ids.append(ap["id"])

    # -- note object describing the decode chain -------------------------- #
    chain_summary = " → ".join([t.get("op", "?") for t in trace or []])
    note = {
        "type": "note",
        "spec_version": "2.1",
        "id": _uid("note", "chain:" + hashlib.sha1(chain_summary.encode()).hexdigest()),
        "created": ts, "modified": ts,
        "created_by_ref": identity_id,
        "abstract": f"NivXRay decode chain ({engine or 'deterministic'}): {chain_summary}",
        "content": (
            f"Engine: {engine or 'unknown'}  ·  Confidence: {confidence if confidence is not None else '?'}%\n"
            f"Chain: {chain_summary}\n\n"
            f"Input preview:\n{(input_preview or '')[:500]}\n\n"
            f"Decoded output preview:\n{(output_preview or '')[:500]}"
        ),
        "object_refs": ref_ids or [identity_id],
    }
    objects.append(note); ref_ids.append(note["id"])

    # -- top-level report ------------------------------------------------- #
    verdict_label = (verdict or {}).get("verdict") or "Unverified"
    report = {
        "type": "report",
        "spec_version": "2.1",
        "id": _uid("report", f"{analyst_email}:{ts}:{chain_summary}"),
        "created": ts, "modified": ts,
        "created_by_ref": identity_id,
        "name": f"NivXRay Investigation · {verdict_label} · {chain_summary or 'plaintext'}",
        "description": (verdict or {}).get("summary")
                        or f"Decoded via NivXRay {engine or 'deterministic'} engine.",
        "published": ts,
        "report_types": ["threat-report", "attack-pattern"],
        "labels": ["nivxray", verdict_label.lower()],
        "object_refs": ref_ids or [identity_id],
    }
    objects.append(report)

    return {
        "type": "bundle",
        "id": _uid("bundle", f"{analyst_email}:{ts}"),
        "objects": objects,
    }
