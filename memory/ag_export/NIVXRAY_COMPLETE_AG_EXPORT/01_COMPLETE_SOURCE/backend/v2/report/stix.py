"""v2/report/stix.py · Deterministic STIX 2.1 bundle export.

Consumes the same `ReportEnvelope` that JSON / Markdown / PDF do so the
resulting bundle is byte-stable across runs (given identical inputs).

Object model:
  - identity          — the case creator / generator
  - process           — one per top entity of kind=process
  - file              — one per top entity of kind=file
  - attack-pattern    — one per unique MITRE technique observed
  - indicator         — one per file hash / IP / domain artefact
  - observed-data     — one per timeline event
  - relationship      — process→process spawn edges + process→attack-pattern usage
"""
from __future__ import annotations
from typing import Any
import hashlib
import json
from .schema import ReportEnvelope


def _stix_id(kind: str, seed: str) -> str:
    """Deterministic STIX id: `{kind}--{uuidv5-ish}` from a seed."""
    h = hashlib.sha256(f"{kind}:{seed}".encode()).hexdigest()
    return f"{kind}--{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _section(env: ReportEnvelope, sid: str) -> dict[str, Any]:
    for s in env.sections:
        if s.id == sid:
            return s.body or {}
    return {}


def render_stix(env: ReportEnvelope) -> dict[str, Any]:
    bundle_id = _stix_id("bundle", f"{env.case_id}:{env.generated_at}")
    identity_id = _stix_id("identity", env.generator)
    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created":  env.generated_at,
            "modified": env.generated_at,
            "name": env.generator,
            "identity_class": "system",
            "description": f"NivXRay report generator {env.generator_version}",
        }
    ]

    # ── MITRE techniques → attack-pattern SDOs ─────────────────────
    mitre = _section(env, "mitre_coverage")
    techniques: list[str] = []
    if isinstance(mitre.get("techniques"), list):
        techniques = [str(t) for t in mitre["techniques"]]
    elif isinstance(mitre.get("coverage"), dict):
        techniques = list(mitre["coverage"].keys())
    for t in sorted(set(techniques)):
        base = t.split(".")[0]
        ext_id = f"attack.mitre.org/techniques/{base}"
        if "." in t:
            ext_id += f"/{t.split('.')[1]}"
        objects.append({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": _stix_id("attack-pattern", t),
            "created":  env.generated_at,
            "modified": env.generated_at,
            "created_by_ref": identity_id,
            "name": t,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": t, "url": f"https://{ext_id}/"}
            ],
        })

    # ── Top entities → process / file SDOs ─────────────────────────
    top = _section(env, "top_entities")
    entities = top.get("entities") or top.get("items") or []
    entity_id_by_name: dict[str, str] = {}
    for e in entities:
        name = str(e.get("name") or e.get("label") or e.get("iid") or "")
        kind = str(e.get("kind") or e.get("type") or "process").lower()
        if not name:
            continue
        if kind == "process":
            sid = _stix_id("process", name)
            objects.append({
                "type": "process",
                "spec_version": "2.1",
                "id": sid,
                "created":  env.generated_at,
                "modified": env.generated_at,
                "created_by_ref": identity_id,
                "command_line": name,
                "x_nivxray_event_count": e.get("event_count") or e.get("count") or 0,
                "x_nivxray_verdict": e.get("verdict") or "benign",
            })
            entity_id_by_name[name] = sid
        elif kind == "file":
            sid = _stix_id("file", name)
            objects.append({
                "type": "file",
                "spec_version": "2.1",
                "id": sid,
                "created":  env.generated_at,
                "modified": env.generated_at,
                "created_by_ref": identity_id,
                "name": name,
                "x_nivxray_event_count": e.get("event_count") or e.get("count") or 0,
                "x_nivxray_verdict": e.get("verdict") or "benign",
            })
            entity_id_by_name[name] = sid

    # ── Timeline events → observed-data SDOs ───────────────────────
    timeline = _section(env, "chronological_timeline")
    tl_events = timeline.get("events") or timeline.get("items") or []
    for ev in tl_events:
        ts = str(ev.get("ts") or ev.get("time") or env.generated_at)
        label = str(ev.get("label") or ev.get("action") or ev.get("kind") or "event")
        objects.append({
            "type": "observed-data",
            "spec_version": "2.1",
            "id": _stix_id("observed-data", f"{ts}:{label}"),
            "created":  env.generated_at,
            "modified": env.generated_at,
            "created_by_ref": identity_id,
            "first_observed": ts,
            "last_observed":  ts,
            "number_observed": 1,
            "object_refs": [],
            "x_nivxray_label": label,
            "x_nivxray_verdict": ev.get("verdict") or "benign",
            "x_nivxray_mitre":   ev.get("mitre") or [],
        })

    # ── Process ancestry → relationship SDOs (spawned) ──────────────
    anc = _section(env, "process_ancestry")
    edges = anc.get("edges") or []
    for e in edges:
        p = str(e.get("parent") or e.get("source") or "")
        c = str(e.get("child")  or e.get("target") or "")
        p_id = entity_id_by_name.get(p.split(":", 1)[-1]) or _stix_id("process", p)
        c_id = entity_id_by_name.get(c.split(":", 1)[-1]) or _stix_id("process", c)
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": _stix_id("relationship", f"{p}=>{c}"),
            "created":  env.generated_at,
            "modified": env.generated_at,
            "created_by_ref": identity_id,
            "relationship_type": "spawned",
            "source_ref": p_id,
            "target_ref": c_id,
        })

    bundle = {
        "type": "bundle",
        "id":   bundle_id,
        "spec_version": "2.1",
        "objects": objects,
    }
    return bundle


def render_stix_bytes(env: ReportEnvelope) -> bytes:
    """Canonical (sorted keys, no whitespace) JSON bytes of the bundle."""
    return json.dumps(render_stix(env), sort_keys=True, separators=(",", ":")).encode()
