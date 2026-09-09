"""Fleet File Trajectory · P1.8 — multi-endpoint artifact spread.

Cisco Secure Endpoint's File Trajectory is SHA-256 keyed.  This
substrate cannot be, and the difference is reported rather than papered
over:

    * `event.raw.sha256` is ALWAYS identical to the document's
      `input_sha256` (verified across all 639 records).  It is the
      digest of the ingested observation record — an evidence-integrity
      digest — NOT the digest of a file's contents.
    * `event.artefacts.file[].sha256` is the only field that would carry
      a real content digest, and it is empty on all 53 file artefacts.

So a hash-keyed query is supported and answers honestly (usually with
zero content-digest matches), and a NAME/PATH-keyed query is offered as
the observable correlation, explicitly labelled as such: identical names
do not prove identical content.

Counting rule: `event.iid` is deduplicated first (the golden corpus
replays the same event under several case ids), provenance is unioned,
and both figures are returned — `unique_events` (authoritative) and
`raw_observations` (all provenance copies).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from services.edr.device_identity import _obs, _event_of, _hostname  # noqa: F401

KEY_TYPES = ("sha256", "name", "path")


def _leaf(p: Optional[str]) -> Optional[str]:
    if not p:
        return None
    return str(p).replace("/", "\\").split("\\")[-1]


def _file_artefacts(ev: Dict[str, Any]) -> List[Dict[str, Any]]:
    art = ev.get("artefacts") if isinstance(ev.get("artefacts"), dict) else {}
    files = art.get("file") if isinstance(art.get("file"), list) else []
    return [f for f in files if isinstance(f, dict)]


def _matches(ev: Dict[str, Any], doc: Dict[str, Any],
             key_type: str, key: str) -> Tuple[bool, str]:
    """Return (matched, matched_on)."""
    proc = ev.get("process") if isinstance(ev.get("process"), dict) else {}
    raw = ev.get("raw") if isinstance(ev.get("raw"), dict) else {}
    k = key.lower()

    if key_type == "sha256":
        for f in _file_artefacts(ev):
            if (f.get("sha256") or "").lower() == k:
                return True, "artefacts.file[].sha256"
        return False, ""

    if key_type == "path":
        for f in _file_artefacts(ev):
            if (f.get("path") or "").lower() == k:
                return True, "artefacts.file[].path"
        if (proc.get("image") or "").lower() == k:
            return True, "process.image"
        return False, ""

    # name — leaf of a path, a process name, or the recorded entity
    if (proc.get("name") or "").lower() == k:
        return True, "process.name"
    if (_leaf(proc.get("image")) or "").lower() == k:
        return True, "process.image (leaf)"
    for f in _file_artefacts(ev):
        if (_leaf(f.get("path")) or "").lower() == k:
            return True, "artefacts.file[].path (leaf)"
    if (raw.get("entity") or "").lower() == k:
        return True, "raw.entity"
    return False, ""


def fleet_trajectory(key_type: str, key: str) -> Dict[str, Any]:
    if key_type not in KEY_TYPES:
        return {"ok": False, "reason": "unsupported_key_type",
                "key_type": key_type, "key": key}

    unique: Dict[str, Dict[str, Any]] = {}
    raw_count = 0
    matched_on: Dict[str, int] = {}

    for doc in _obs.find({}, {"_id": 0}):
        ev = _event_of(doc)
        if not ev:
            continue
        ok, on = _matches(ev, doc, key_type, key)
        if not ok:
            continue
        raw_count += 1
        matched_on[on] = matched_on.get(on, 0) + 1
        iid = ev.get("iid") or f"{doc.get('case_id')}:{ev.get('sequence')}"
        row = unique.get(iid)
        if row is None:
            proc = ev.get("process") if isinstance(ev.get("process"), dict) else {}
            raw = ev.get("raw") if isinstance(ev.get("raw"), dict) else {}
            files = _file_artefacts(ev)
            unique[iid] = {
                "event_iid":     iid,
                "timestamp":     ev.get("ts") or doc.get("captured_at"),
                "kind":          ev.get("kind"),
                "device_iid":    ev.get("device_iid"),
                "hostname":      _hostname(ev),
                "process":       proc.get("name"),
                "process_image": proc.get("image"),
                "process_iid":   ev.get("process_iid") or proc.get("iid"),
                "parent_name":   proc.get("parent_name") or raw.get("parent_image"),
                "user":          raw.get("user") or None,
                "provider":      raw.get("provider"),
                "command_line":  raw.get("command_line"),
                "target":        raw.get("target"),
                "file_paths":    [f.get("path") for f in files if f.get("path")],
                "file_sha256":   [f.get("sha256") for f in files if f.get("sha256")],
                "input_digest":  doc.get("input_sha256") or raw.get("sha256"),
                "mitre":         [m for m in (ev.get("mitre") or []) if m],
                "labels":        [l for l in (ev.get("labels") or []) if l],
                "case_refs":     [],
                "occurrences":   0,
                "matched_on":    on,
            }
            row = unique[iid]
        row["occurrences"] += 1
        cid = doc.get("case_id")
        if cid and cid not in row["case_refs"]:
            row["case_refs"].append(cid)
        for m in (ev.get("mitre") or []):
            if m and m not in row["mitre"]:
                row["mitre"].append(m)

    events = sorted(unique.values(), key=lambda e: str(e.get("timestamp") or ""))

    # ── per-endpoint rollup ─────────────────────────────────────────
    endpoints: Dict[str, Dict[str, Any]] = {}
    for e in events:
        dev = e.get("device_iid") or "__unbound__"
        row = endpoints.get(dev)
        if row is None:
            row = endpoints[dev] = {
                "device_iid":   e.get("device_iid"),
                "device_ref":   e.get("device_iid") or e.get("hostname"),
                "hostname":     e.get("hostname"),
                "identity_confidence": "authoritative" if e.get("device_iid") else "inferred",
                "unique_events": 0,
                "raw_observations": 0,
                "first_seen":   None,
                "last_seen":    None,
                "providers":    [],
                "users":        [],
                "case_refs":    [],
                "kinds":        {},
                "attributed":   0,
            }
        row["unique_events"] += 1
        row["raw_observations"] += e["occurrences"]
        ts = e.get("timestamp")
        if ts:
            if row["first_seen"] is None or str(ts) < str(row["first_seen"]):
                row["first_seen"] = ts
            if row["last_seen"] is None or str(ts) > str(row["last_seen"]):
                row["last_seen"] = ts
        for f, v in (("providers", e.get("provider")), ("users", e.get("user"))):
            if v and v not in row[f]:
                row[f].append(v)
        for c in e["case_refs"]:
            if c not in row["case_refs"]:
                row["case_refs"].append(c)
        k = e.get("kind") or "unknown"
        row["kinds"][k] = row["kinds"].get(k, 0) + 1
        if e["mitre"] or e["labels"]:
            row["attributed"] += 1

    endpoint_rows = sorted(endpoints.values(),
                           key=lambda r: (-r["unique_events"],
                                          str(r.get("first_seen") or "")))

    # ── entry point(s) — earliest observation, all ties kept ────────
    entry_points: List[Dict[str, Any]] = []
    if endpoint_rows:
        earliest = min(str(r.get("first_seen") or "~") for r in endpoint_rows)
        entry_points = [
            {"device_iid": r["device_iid"], "hostname": r["hostname"],
             "first_seen": r["first_seen"]}
            for r in endpoint_rows if str(r.get("first_seen") or "~") == earliest
        ]

    # ── creators — only where a write/create was actually observed ──
    creators: List[Dict[str, Any]] = []
    for e in events:
        if e.get("kind") not in ("file_create", "file_write"):
            continue
        if not e.get("process"):
            continue
        sig = (e["process"], e.get("device_iid"))
        if any(c["process"] == sig[0] and c["device_iid"] == sig[1] for c in creators):
            continue
        creators.append({
            "process":     e["process"],
            "image":       e.get("process_image"),
            "device_iid":  e.get("device_iid"),
            "hostname":    e.get("hostname"),
            "timestamp":   e.get("timestamp"),
            "observed_on": e.get("kind"),
        })

    names, paths, digests = [], [], []
    for e in events:
        for p in e["file_paths"]:
            if p not in paths:
                paths.append(p)
            leaf = _leaf(p)
            if leaf and leaf not in names:
                names.append(leaf)
        if e.get("process") and e["process"] not in names:
            names.append(e["process"])
        for s in e["file_sha256"]:
            if s and s not in digests:
                digests.append(s)

    # Does the supplied key exist as an evidence-integrity digest?
    integrity_hits = 0
    if key_type == "sha256":
        integrity_hits = _obs.count_documents({"input_sha256": key.lower()})

    return {
        "ok": True,
        "key_type": key_type,
        "key": key,
        "substrate": "v2_shadow_observations",
        "unique_events": len(events),
        "raw_observations": raw_count,
        "affected_endpoints": len([r for r in endpoint_rows if r["device_iid"]]),
        "endpoint_rows": endpoint_rows,
        "first_observed": events[0]["timestamp"] if events else None,
        "last_observed": events[-1]["timestamp"] if events else None,
        "entry_points": entry_points,
        "creators": creators,
        "observed_names": names,
        "observed_paths": paths,
        "content_digests": digests,
        "events": events,
        "matched_on": matched_on,
        "digest_state": {
            "content_digests_available": len(digests) > 0,
            "file_artefacts_with_sha256": len(digests),
            "note": ("event.artefacts.file[].sha256 is the only content-digest "
                     "field in this contract and it is unpopulated, so hash-keyed "
                     "fleet correlation cannot be performed on file contents."),
            "integrity_digest_hits": integrity_hits,
            "integrity_note": ("event.raw.sha256 is identical to the document's "
                               "input_sha256 on every record: it is the digest of "
                               "the ingested observation, not of a file."),
        },
        "tenant_boundary": ("v2_shadow_observations carries no tenant_id; this view "
                            "is validation / golden-corpus substrate visibility only. "
                            "No tenant is assigned to historic observations."),
        "correlation_caveat": (
            "PATH/NAME-KEYED CORRELATION — identical names or paths do not prove "
            "identical file contents, and no runtime behaviour is inferred across "
            "hosts beyond what each host's own observations record."
            if key_type in ("name", "path") else
            "CONTENT-DIGEST-KEYED CORRELATION over artefacts.file[].sha256."),
    }


def spread_index() -> Dict[str, Any]:
    """Every observable artifact name and the endpoints it appears on —
    the honest replacement for a hash-keyed fleet index."""
    idx: Dict[str, Dict[str, Any]] = {}
    for doc in _obs.find({}, {"_id": 0}):
        ev = _event_of(doc)
        if not ev:
            continue
        dev = ev.get("device_iid")
        if not dev:
            continue
        proc = ev.get("process") if isinstance(ev.get("process"), dict) else {}
        cands = set()
        if proc.get("name"):
            cands.add(proc["name"])
        for f in _file_artefacts(ev):
            leaf = _leaf(f.get("path"))
            if leaf:
                cands.add(leaf)
        for name in cands:
            row = idx.setdefault(name, {"name": name, "devices": {}, "events": set()})
            row["devices"].setdefault(dev, set()).add(ev.get("iid"))
            row["events"].add(ev.get("iid"))
    rows = [{
        "name": r["name"],
        "endpoints": len(r["devices"]),
        "unique_events": len(r["events"]),
        "device_iids": sorted(r["devices"].keys()),
    } for r in idx.values()]
    rows.sort(key=lambda r: (-r["endpoints"], -r["unique_events"], r["name"]))
    return {"ok": True, "count": len(rows), "rows": rows,
            "substrate": "v2_shadow_observations",
            "note": ("Keyed on observed process names and file-path leaves because "
                     "no content digests are populated in this substrate.")}
