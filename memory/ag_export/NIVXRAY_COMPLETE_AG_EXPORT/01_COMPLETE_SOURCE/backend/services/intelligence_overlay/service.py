"""Round 46 · Analyst Intelligence Overlay — governed edit layer.

Owner rule (locked):
  · Editable Intelligence ≠ editing evidence.
  · Canonical evidence, detections, ATT&CK, provenance stay immutable.
  · Analysts edit only the narrative/interpretation layer on top.
  · Overlays are a *subordinate* projection of the canonical model —
    they never replace it.

Data shape (per edited field):
    machine_value          — verbatim engine output
    machine_source_hash    — sha256(machine_value) at overlay creation
    analyst_value          — analyst-authored replacement (nullable)
    effective_value        — analyst_value ?? machine_value
    version                — monotonic per-field
    author_id · author_email · reason · updated_at

Every create / edit / revert emits an entry in the immutable audit
collection ``xdr_intelligence_overlay_audit``.  History is never
mutated or deleted.
"""
from __future__ import annotations
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


OVERLAY_COLL = "xdr_intelligence_overlays"
AUDIT_COLL   = "xdr_intelligence_overlay_audit"

ALLOWED_TARGETS = {"exec_summary", "attack_story", "finding"}
ALLOWED_FIELDS_BY_TARGET = {
    "exec_summary": {"content"},
    "attack_story": {"narrative"},
    "finding":      {"summary"},          # summary ONLY · identity locked
}


class OverlayError(Exception):
    """Domain error carrying an HTTP status + envelope."""
    def __init__(self, status: int, code: str, message: str,
                    extra: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.extra = extra or {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _key(target_kind: str, target_id: str, field_key: str) -> Dict[str, str]:
    return {"target_kind": target_kind,
              "target_id":   target_id,
              "field_key":   field_key}


def _validate_target(target_kind: str, field_key: str) -> None:
    if target_kind not in ALLOWED_TARGETS:
        raise OverlayError(400, "unsupported_target",
                                  f"target_kind {target_kind!r} not supported")
    if field_key not in ALLOWED_FIELDS_BY_TARGET[target_kind]:
        raise OverlayError(400, "unsupported_field",
                                  f"field {field_key!r} not editable on "
                                  f"{target_kind}")


def _require_reason(reason: Optional[str]) -> str:
    r = (reason or "").strip()
    if not r:
        raise OverlayError(400, "reason_required",
                                  "A reason is required for every create, edit "
                                  "or revert.")
    return r


def _require_analyst(author_id: Optional[str],
                          author_email: Optional[str]) -> Tuple[str, str]:
    if not author_id or not author_email:
        raise OverlayError(401, "analyst_required",
                                  "Overlay writes require an authenticated "
                                  "analyst identity (author_id + author_email).")
    return author_id, author_email


async def _write_audit(db, incident_id: str, key: Dict[str, str],
                              *, version: int, action: str,
                              author_id: str, author_email: str,
                              reason: str,
                              previous_value: Optional[str],
                              new_value: Optional[str]) -> None:
    await db[AUDIT_COLL].insert_one({
        "incident_id":   incident_id, **key,
        "version":       version, "action": action,
        "author_id":     author_id, "author_email": author_email,
        "at":            _now(),
        "reason":        reason,
        "previous_value": previous_value,
        "new_value":      new_value,
    })


def effective(overlay: Optional[Dict[str, Any]],
                  machine_value: str) -> str:
    """Deterministic effective-value resolution.

    An overlay is "active" only if `analyst_value` is present AND the
    stored `machine_source_hash` still matches the current machine
    value.  If the machine source has drifted since the overlay was
    created, the overlay is treated as MACHINE-SOURCE-UPDATED and the
    machine value is returned (the UI surfaces the drift honestly).
    """
    if not overlay or overlay.get("analyst_value") is None:
        return machine_value
    stored_hash = overlay.get("machine_source_hash")
    if stored_hash and stored_hash != _sha256(machine_value):
        return machine_value
    return overlay["analyst_value"]


def presentation_badge(overlay: Optional[Dict[str, Any]],
                              machine_value: str) -> Dict[str, Any]:
    """Return the presentation-layer badge for a field.

    Never claims analyst provenance for canonical evidence — the
    badge describes the *narrative*, not the underlying facts.
    """
    if not overlay or overlay.get("analyst_value") is None:
        return {"badge": "NIVXRAY GENERATED", "version": 1,
                    "drift": False}
    drift = overlay.get("machine_source_hash") != _sha256(machine_value)
    return {
        "badge":   "MACHINE SOURCE UPDATED" if drift else "ANALYST EDITED",
        "version": int(overlay.get("version") or 1),
        "drift":   bool(drift),
        "author":  overlay.get("author_email"),
        "updated_at": overlay.get("updated_at"),
    }


async def get_overlay(db, incident_id: str, target_kind: str,
                            target_id: str, field_key: str
                            ) -> Optional[Dict[str, Any]]:
    _validate_target(target_kind, field_key)
    doc = await db[OVERLAY_COLL].find_one(
        {"incident_id": incident_id,
          **_key(target_kind, target_id, field_key)}, {"_id": 0})
    return doc


async def list_overlays(db, incident_id: str) -> List[Dict[str, Any]]:
    return [d async for d in db[OVERLAY_COLL].find(
                {"incident_id": incident_id}, {"_id": 0})]


async def upsert_overlay(db, incident_id: str, target_kind: str,
                                    target_id: str, field_key: str, *,
                                    machine_value: str,
                                    analyst_value: str,
                                    reason: Optional[str],
                                    author_id: Optional[str],
                                    author_email: Optional[str],
                                    expected_version: Optional[int] = None,
                                    ) -> Dict[str, Any]:
    """Create or edit an overlay.  Concurrency-safe via
    ``expected_version``: if provided and mismatched, raises 409."""
    _validate_target(target_kind, field_key)
    reason = _require_reason(reason)
    author_id, author_email = _require_analyst(author_id, author_email)
    if analyst_value is None or not str(analyst_value).strip():
        raise OverlayError(400, "analyst_value_required",
                                  "analyst_value must be a non-empty string.")

    key = _key(target_kind, target_id, field_key)
    existing = await get_overlay(db, incident_id, target_kind,
                                              target_id, field_key)
    current_version = int((existing or {}).get("version") or 0)
    if expected_version is not None and expected_version != current_version:
        raise OverlayError(409, "conflict",
                                  "Your version is no longer current. Review "
                                  "the latest version before saving.",
                                  extra={"stored_version": current_version,
                                            "your_version":   expected_version})

    new_version = current_version + 1
    now = _now()
    doc = {
        "incident_id":         incident_id, **key,
        "machine_value":        machine_value,
        "machine_source_hash":  _sha256(machine_value),
        "analyst_value":        str(analyst_value),
        "version":              new_version,
        "author_id":            author_id,
        "author_email":         author_email,
        "reason":               reason,
        "updated_at":           now,
        "created_at":           (existing or {}).get("created_at") or now,
    }
    await db[OVERLAY_COLL].update_one(
        {"incident_id": incident_id, **key},
        {"$set": doc}, upsert=True)
    await _write_audit(
        db, incident_id, key,
        version=new_version,
        action="created" if not existing else "edited",
        author_id=author_id, author_email=author_email,
        reason=reason,
        previous_value=(existing or {}).get("analyst_value"),
        new_value=doc["analyst_value"])
    return doc


async def revert_overlay(db, incident_id: str, target_kind: str,
                                    target_id: str, field_key: str, *,
                                    machine_value: str,
                                    reason: Optional[str],
                                    author_id: Optional[str],
                                    author_email: Optional[str],
                                    expected_version: Optional[int] = None,
                                    ) -> Dict[str, Any]:
    """Revert to the machine value WITHOUT deleting history.

    We keep the overlay row so the version counter and machine hash
    stay coherent; ``analyst_value`` is cleared.  ``effective`` now
    returns the machine value.  A new audit event is emitted.
    """
    _validate_target(target_kind, field_key)
    reason = _require_reason(reason)
    author_id, author_email = _require_analyst(author_id, author_email)

    key = _key(target_kind, target_id, field_key)
    existing = await get_overlay(db, incident_id, target_kind,
                                              target_id, field_key)
    if not existing or existing.get("analyst_value") is None:
        raise OverlayError(404, "not_found",
                                  "No active analyst overlay to revert.")
    current_version = int(existing.get("version") or 0)
    if expected_version is not None and expected_version != current_version:
        raise OverlayError(409, "conflict",
                                  "Your version is no longer current.",
                                  extra={"stored_version": current_version,
                                            "your_version":   expected_version})
    new_version = current_version + 1
    doc = {
        **existing,
        "machine_value":       machine_value,
        "machine_source_hash": _sha256(machine_value),
        "analyst_value":       None,
        "version":             new_version,
        "author_id":           author_id,
        "author_email":        author_email,
        "reason":              reason,
        "updated_at":          _now(),
    }
    await db[OVERLAY_COLL].update_one(
        {"incident_id": incident_id, **key},
        {"$set": doc})
    await _write_audit(
        db, incident_id, key,
        version=new_version, action="reverted",
        author_id=author_id, author_email=author_email,
        reason=reason,
        previous_value=existing.get("analyst_value"),
        new_value=None)
    return doc


async def history(db, incident_id: str, target_kind: str,
                        target_id: str, field_key: str
                        ) -> List[Dict[str, Any]]:
    _validate_target(target_kind, field_key)
    cur = db[AUDIT_COLL].find(
        {"incident_id": incident_id,
          **_key(target_kind, target_id, field_key)},
        {"_id": 0}).sort("version", 1)
    return [d async for d in cur]
