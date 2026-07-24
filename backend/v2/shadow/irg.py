"""v2/shadow/irg.py · Investigation Relationship Graph enricher.

Builds the canonical relationship model (P1) from the raw shadow frames.
Vendor-neutral. Every investigation view — Device Trajectory, Process
Ancestry, File / Registry / Network Trajectory, Attack Chain, Report
Generator — consumes the same schema after this pass.

Schema: /app/memory/design/INVESTIGATION_RELATIONSHIP_GRAPH.md
"""
from __future__ import annotations
from typing import Any, Iterable
import hashlib
import re

# ── Deterministic entity iid ──────────────────────────────────────
def entity_iid(kind: str, name: str) -> str:
    """Stable, opaque, human-inspectable id."""
    name = (name or "").lower()
    h = hashlib.blake2s(f"{kind}:{name}".encode(), digest_size=6).hexdigest()
    return f"ent_{kind}_{h}"

# ── Filename detection ────────────────────────────────────────────
_EXE_RE = re.compile(r"([A-Za-z0-9_.\-]+\.(?:exe|dll|msi|ps1|bat|cmd|sys|com))",
                      re.IGNORECASE)

def _extract_binary(text: str) -> str | None:
    if not text:
        return None
    m = _EXE_RE.search(text)
    return m.group(1) if m else None

# ── Deterministic relationship-type inference ─────────────────────
def _relationship_for(frame: dict) -> str:
    """Map (lane, action) → canonical relationship type."""
    lane = (frame.get("lane") or "").lower()
    act  = (frame.get("action") or "").lower()
    if lane == "network":  return "CONNECTED"
    if lane == "registry": return "REGISTRY_WRITE"
    if lane == "file":
        if "delete" in act:    return "DELETED"
        if "rename" in act:    return "RENAMED"
        if "read"   in act:    return "READ"
        if "write"  in act or "create" in act or "drop" in act:
            return "WROTE"
        return "MODIFIED"
    # process lane
    if "create" in act or "spawn" in act or "start" in act:
        return "SPAWNED"
    if "load"   in act:  return "LOADED"
    if "inject" in act:  return "INJECTED"
    if "thread" in act:  return "THREAD_CREATE"
    return "SPAWNED"

# ── Root-detection heuristic ──────────────────────────────────────
_KNOWN_ROOTS = {"explorer.exe", "services.exe", "svchost.exe", "winlogon.exe"}
_FIRST_LEVEL_LAUNCHERS = {"msiexec.exe", "rundll32.exe", "regsvr32.exe",
                          "consent.exe", "adgnsy.exe", "rustdesk.exe"}
_SECOND_LEVEL = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
                 "cscript.exe", "mshta.exe", "wmic.exe"}

def enrich(frames: list[dict]) -> list[dict]:
    """Enrich frames with canonical IRG fields · idempotent · cycle-safe.

    Called from the trajectory + ancestry routers. Input frames may already
    carry `entity.iid` / `parent.iid` (from an adapter that emits them);
    those values are preserved and this pass only fills the gaps.
    """
    if not frames:
        return frames

    # 1 · Establish an entity per unique labelled binary + lane.
    entity_first_seen: dict[str, float] = {}
    entity_last_seen:  dict[str, float] = {}
    def _resolve_entity(f: dict) -> tuple[str, str, str]:
        """Return (kind, name, iid) for the entity this frame is *about*."""
        # Priority: existing entity.iid → labelled binary → process.iid → lane bucket.
        ent = f.get("entity") or {}
        if ent.get("iid"):
            return (ent.get("type", "process"), ent.get("name", ""), ent["iid"])
        label = f.get("label") or f.get("action") or ""
        bin_name = _extract_binary(label) or _extract_binary(f.get("action") or "")
        lane = (f.get("lane") or "").lower()
        if bin_name:
            kind = "process" if lane in ("process", "system") else "file"
            return (kind, bin_name.lower(), entity_iid(kind, bin_name))
        if lane == "network":
            addr = (f.get("network") or {}).get("dst") or "unknown-endpoint"
            return ("network", str(addr), entity_iid("network", str(addr)))
        if lane == "registry":
            key = (f.get("registry") or {}).get("key") or "HKLM"
            return ("registry", key, entity_iid("registry", key))
        proc_iid = (f.get("process") or {}).get("iid") or ""
        return ("process", proc_iid or "unknown", entity_iid("process", proc_iid or "unknown"))

    # 2 · Two-pass: first collect timing per entity, then build graph.
    for f in frames:
        _, _, iid = _resolve_entity(f)
        try:
            ts_ms = _ts_ms(f.get("ts"))
        except Exception:
            continue
        if iid not in entity_first_seen or ts_ms < entity_first_seen[iid]:
            entity_first_seen[iid] = ts_ms
        if iid not in entity_last_seen  or ts_ms > entity_last_seen[iid]:
            entity_last_seen[iid]  = ts_ms

    # 3 · Deterministic ancestry rule: chronological process launches thread
    #     together as a chain, with well-known launchers (msiexec / rundll32
    #     / RustDesk / consent) attached under a synthetic explorer.exe root.
    root_iid = entity_iid("process", "explorer.exe")
    # Order process entities by first-seen for the ancestry walk.
    process_entities: list[tuple[float, str, str]] = []   # (first_seen_ms, name, iid)
    seen_iids: set[str] = set()
    for f in frames:
        kind, name, iid = _resolve_entity(f)
        if kind != "process" or iid in seen_iids:
            continue
        seen_iids.add(iid)
        process_entities.append((entity_first_seen[iid], name, iid))
    process_entities.sort(key=lambda x: x[0])

    # Parent-map: iid → parent iid, with cycle guard.
    parent_of: dict[str, str] = {}
    last_second_level_iid: str | None = None       # last cmd/powershell seen — for grandchildren
    last_launcher_iid: str | None = None
    for ts_ms, name, iid in process_entities:
        if name in _KNOWN_ROOTS:
            parent_of[iid] = root_iid  # even known roots attach to explorer.exe synthetic root
            continue
        if name in _FIRST_LEVEL_LAUNCHERS:
            parent_of[iid] = root_iid
            last_launcher_iid = iid
            continue
        if name in _SECOND_LEVEL:
            parent_of[iid] = last_launcher_iid or root_iid
            last_second_level_iid = iid
            continue
        # Everything else is a grandchild of the most recent cmd/powershell.
        parent_of[iid] = last_second_level_iid or last_launcher_iid or root_iid

    # Cycle detection (defensive)
    for iid, pid in list(parent_of.items()):
        seen = set()
        cur = pid
        while cur and cur not in seen:
            seen.add(cur)
            cur = parent_of.get(cur)
        if cur is not None:
            # cycle detected — drop this parent link
            parent_of[iid] = root_iid

    # 4 · Depth from root
    def _depth(iid: str, memo: dict[str, int] = {}) -> int:
        if iid in memo: return memo[iid]
        if iid == root_iid: memo[iid] = 0; return 0
        p = parent_of.get(iid)
        if p is None: memo[iid] = 0; return 0
        memo[iid] = 1 + _depth(p, memo)
        return memo[iid]

    # 5 · Second pass — attach canonical fields to every frame.
    for f in frames:
        kind, name, iid = _resolve_entity(f)
        ent_start = entity_first_seen.get(iid)
        ent_end   = entity_last_seen.get(iid)
        pid = parent_of.get(iid) if kind == "process" else _process_parent_for_non_process(f, parent_of, root_iid)
        # Non-mutating merge — preserve caller-set fields.
        existing_entity = f.get("entity") or {}
        f["entity"] = {
            **existing_entity,
            "iid":   existing_entity.get("iid")   or iid,
            "type":  existing_entity.get("type")  or kind,
            "name":  existing_entity.get("name")  or name,
            "start": existing_entity.get("start") or _iso(ent_start),
            "end":   existing_entity.get("end")   or _iso(ent_end),
        }
        existing_parent = f.get("parent") or {}
        # For non-process events (files / network / registry), the parent is the
        # process that touched them (nearest ancestor process at that timestamp).
        f["parent"] = {
            "iid":  existing_parent.get("iid")  or pid,
            "type": existing_parent.get("type") or ("process" if pid else None),
            # Preserve caller-supplied parent binary name — critical for the
            # frozen v3.1b Verdict Engine's SUSPICIOUS_PARENT detector, which
            # reads `parent.name` when the iid isn't a bare filename.
            "name": existing_parent.get("name") or "",
        }
        f["root"] = {"iid": root_iid}
        f["relationship"] = {
            "type":      _relationship_for(f),
            "direction": "parent->child",
            "reason":    (f.get("label") or f.get("action") or "")[:200],
        }
        try:
            ts_ms = _ts_ms(f.get("ts"))
        except Exception:
            ts_ms = None
        f["execution"] = {
            "process_start": ent_start,
            "process_end":   ent_end,
            "session":       None,
            "depth":         _depth(iid) if kind == "process" else _depth(pid) + 1,
        }
        # Evidence linkage
        f["evidence"] = {
            "artifact":    (f.get("evidence") or {}).get("artifact"),
            "observation": {"iid": f.get("observation_iid") or f.get("frame_iid")},
            "case":        {"iid": f.get("case_id")},
        }
        # Preserve legacy `event` mirror
        f.setdefault("event", {})
        f["event"] = {
            "iid":        f["event"].get("iid")        or f.get("frame_iid"),
            "timestamp":  f["event"].get("timestamp")  or f.get("ts"),
            "type":       f["event"].get("type")       or f.get("action"),
            "source":     f["event"].get("source")     or (f.get("provenance") or {}).get("adapter"),
            "confidence": f["event"].get("confidence") or (f.get("provenance") or {}).get("confidence"),
        }

    return frames


# ── Non-process events attach to the nearest process ancestor via the ─
# ── originating command's process. Fallback: root. ────────────────────
def _process_parent_for_non_process(f: dict, parent_of: dict[str, str], root_iid: str) -> str:
    label = f.get("label") or f.get("action") or ""
    bin_name = _extract_binary(label)
    if bin_name:
        return entity_iid("process", bin_name.lower())
    # If we have a process.iid on the frame, use its entity iid.
    piid = (f.get("process") or {}).get("iid") or ""
    if piid:
        return entity_iid("process", piid)
    return root_iid

# ── ts helpers ────────────────────────────────────────────────────
def _ts_ms(ts: Any) -> float:
    if ts is None:
        raise ValueError("no ts")
    if isinstance(ts, (int, float)):
        return float(ts) if ts > 1e12 else float(ts) * 1000
    # ISO string
    import datetime as _dt
    s = str(ts)
    if s.endswith("Z"): s = s.replace("Z", "+00:00")
    return _dt.datetime.fromisoformat(s).timestamp() * 1000

def _iso(ms: float | None) -> str | None:
    if ms is None: return None
    import datetime as _dt
    return _dt.datetime.utcfromtimestamp(ms / 1000).isoformat(timespec="milliseconds") + "Z"
