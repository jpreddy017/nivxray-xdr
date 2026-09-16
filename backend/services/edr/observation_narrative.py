"""Observation Narrative Composer — evidence-gated prose for one endpoint
observation.

Why this is a separate composer from
``nivxforge/investigation/analyst_narrative.py``:
    ``compose_analyst_narrative()`` accepts a **CIO** (Canonical
    Investigation Object) built by the decode/interpretation pipeline.
    A ``v2_shadow_observations`` document is NOT a CIO — it carries no
    decode trace, no verdict stage and no entities digest.  Synthesising
    a CIO wrapper around a single observation in order to reuse that
    function would mean inventing the very fields the narrative reads,
    which is exactly the fabrication the Honest State rule forbids.

    This module therefore applies the *same discipline* (one sentence
    per fact, a sentence is skipped when its evidence is absent, no LLM,
    no template filler) to the observation contract instead.

Unknowns are STATED, never blanked — see the AMP reference notes in
``docs/uiux/NIVXFORGE_EDR_TARGET_UX_ARCHITECTURE.md``
("Unknown disposition. Unknown parent disposition.").
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

_KIND_VERB = {
    "process_create":     "was executed",
    "file_create":        "created a file",
    "file_write":         "wrote to a file",
    "file_delete":        "deleted a file",
    "registry_value_set": "set a registry value",
    "network_connect":    "opened an outbound connection",
    "network_listen":     "began listening",
    "service_install":    "installed a service",
    "memory_alloc":       "allocated memory",
    "kernel_event":       "raised a kernel event",
    "cloud_iam_action":   "performed a cloud IAM action",
}


def _short(h: Optional[str]) -> Optional[str]:
    if not h or len(h) < 20:
        return h
    return f"{h[:8]}…{h[-8:]}"


def _type_tag(path: Optional[str]) -> str:
    if not path or "." not in str(path).rsplit("\\", 1)[-1]:
        return "[NO EXTENSION OBSERVED]"
    return "[" + str(path).rsplit(".", 1)[-1].upper()[:8] + "]"


def compose(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Return ``{"sentences": [...], "unknowns": [...], "provenance": {...}}``.

    Every sentence is emitted only when the fields it names are present
    in the persisted observation.
    """
    ev = doc.get("event") if isinstance(doc.get("event"), dict) else {}
    raw = ev.get("raw") if isinstance(ev.get("raw"), dict) else {}
    proc = ev.get("process") if isinstance(ev.get("process"), dict) else {}

    kind = ev.get("kind") or doc.get("kind") or ""
    name = proc.get("name") or raw.get("entity")
    image = proc.get("image")
    sha = next((f.get("sha256") for f in (
                   (ev.get("artefacts") or {}).get("file") or [])
                   if isinstance(f, dict) and f.get("sha256")), None)
    input_digest = raw.get("sha256") or doc.get("input_sha256")
    user = raw.get("user")
    host = raw.get("computer") or raw.get("hostname")
    device_iid = ev.get("device_iid")
    ts = ev.get("ts") or doc.get("captured_at")
    target = raw.get("target")
    cmdline = raw.get("command_line") or raw.get("text")
    parent_name = proc.get("parent_name") or raw.get("parent_image")
    parent_iid = proc.get("parent_iid")
    mitre = [m for m in (ev.get("mitre") or []) if m]
    labels = [l for l in (ev.get("labels") or []) if l]

    sentences: List[str] = []
    unknowns: List[str] = []

    # 1 — the primary fact.
    if name:
        subject = f"`{name}`"
        if image:
            subject += f", {image}"
        if sha:
            subject += f" (`{_short(sha)}`){_type_tag(image or name)}"
        verb = _KIND_VERB.get(str(kind).lower(), f"produced a `{kind}` observation")
        clause = f"{subject} {verb}"
        if target:
            clause += f" — target `{target}`"
        if host or device_iid:
            clause += f" on {host or 'an unnamed host'}"
            if device_iid:
                clause += f" (`{device_iid}`)"
        clause += f" as {user}" if user else ""
        if ts:
            clause += f" at {ts}"
        sentences.append(clause + ".")

    # 2 — lineage, stated exactly as observed.
    if parent_name or parent_iid:
        claim = "Its record claims a parent"
        if parent_name:
            claim += f" `{parent_name}`"
        if parent_iid:
            claim += f" (`{parent_iid}`)"
        claim += ("; that parent identity was not itself observed in this "
                  "substrate, so no lineage edge is drawn.")
        sentences.append(claim)
    else:
        unknowns.append("No parent identity was recorded on this observation.")

    # 3 — disposition is absent from the substrate by contract.
    unknowns.append("Unknown disposition. Unknown parent disposition.")

    # 4 — command line.
    if cmdline:
        sentences.append(f"Command line: `{cmdline}`.")
    elif str(kind).lower() == "process_create":
        unknowns.append("No command line was captured for this execution.")

    # 5 — technique attribution (adapter-asserted, not re-derived here).
    if mitre:
        sentences.append("ATT&CK techniques asserted by the ingest adapter: "
                         + ", ".join(mitre) + ".")
    if labels:
        sentences.append("Labels carried on the observation: "
                         + ", ".join(str(l) for l in labels) + ".")

    # 6 — provenance sentence.
    prov = ev.get("provenance") if isinstance(ev.get("provenance"), dict) else {}
    src_bits = []
    if raw.get("provider"):
        src_bits.append(str(raw["provider"]))
    if raw.get("event_id") is not None:
        src_bits.append(f"event {raw['event_id']}")
    if prov.get("adapter") or ev.get("adapter"):
        src_bits.append(f"adapter {prov.get('adapter') or ev.get('adapter')}")
    if src_bits:
        sentences.append("Source: " + " · ".join(src_bits) + ".")
    if input_digest:
        sentences.append(
            f"Evidence integrity: the ingested observation record digests to "
            f"`{_short(input_digest)}` — that is the record's digest, not the "
            f"digest of any file it describes.")

    if not sha:
        unknowns.append("No file content digest was captured: "
                        "artefacts.file[].sha256 is empty on this record.")

    return {
        "sentences": sentences,
        "unknowns":  unknowns,
        "provenance": {
            "substrate":   "v2_shadow_observations",
            "event_iid":   ev.get("iid"),
            "case_id":     doc.get("case_id"),
            "sequence":    ev.get("sequence"),
            "origin":      prov.get("origin"),
            "normalizer":  prov.get("normalizer"),
            "input_sha256": doc.get("input_sha256"),
        },
        "composer": "services.edr.observation_narrative (deterministic · no LLM)",
    }
