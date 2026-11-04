"""Analyst Operations · Dashboard Lens Definitions.

Single source of truth for the ten operational lenses.  Every tile on
the Operations Dashboard and every filter on the Incident Queue MUST
consume the predicates defined here — anything else would drift into
fabricated counts.

Locked by owner directive (Phase 1 · 2026-02-31):

    Analyst Operations
        │
        ├─ Dashboard tile count      ← same Mongo predicate
        └─ Incident Queue filter     ← same Mongo predicate
              │
              ▼
        list_incidents(lens=...)

The predicates below deliberately share every field name with the
persisted extension schema so no client-side translation is required.

Fields honored on the ``workspace_cases`` document:
    incident_state           existing lifecycle state
    incident_assignee        existing ownership
    incident_priority        NEW · Phase 1 extension  (P1|P2|P3|P4|P5)
    incident_severity        NEW · Phase 1 extension  (critical|high|medium|low|info)
    high_fidelity            NEW · Phase 1 extension  (bool)
    customer_engaged         NEW · Phase 1 extension  (bool)
    on_hold_reason           NEW · Phase 1 extension  (str)
    on_hold_until            NEW · Phase 1 extension  (ISO datetime)
    sla_due_at               NEW · Phase 1 extension  (ISO datetime)
    updated_at / created_at  existing

All timestamps in the predicates are computed relative to
``datetime.now(timezone.utc)`` at request time.  No cached counters.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Tuple

# ── Lens definitions ────────────────────────────────────────────────
# Ordered tuple (id, group, label, description, predicate_builder,
#                default_sort_field, default_sort_direction).
#
# ``predicate_builder`` is called with ``user_email`` and returns a
# Mongo filter dict.  It never mutates state.

Lens = Dict[str, Any]

LENS_GROUPS = ("triage", "ownership", "risk")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _open_states_clause() -> Dict[str, Any]:
    """Everything except resolved/closed is 'open'."""
    return {"incident_state": {"$nin": ["resolved", "closed"]}}


# ── Predicate builders ──────────────────────────────────────────────

def _pred_critical(email: str | None) -> Dict[str, Any]:
    q: Dict[str, Any] = {**_open_states_clause(),
                          "incident_priority": "P1"}
    return _scope(q, email)


def _pred_high_priority(email: str | None) -> Dict[str, Any]:
    q: Dict[str, Any] = {**_open_states_clause(),
                          "incident_priority": {"$in": ["P1", "P2"]}}
    return _scope(q, email)


def _pred_high_fidelity(email: str | None) -> Dict[str, Any]:
    q: Dict[str, Any] = {**_open_states_clause(),
                          "high_fidelity": True}
    return _scope(q, email)


def _pred_unassigned(email: str | None) -> Dict[str, Any]:
    q: Dict[str, Any] = {
        **_open_states_clause(),
        "$or": [
            {"incident_assignee": {"$exists": False}},
            {"incident_assignee": None},
            {"incident_assignee": ""},
        ],
    }
    return _scope(q, email)


def _pred_in_progress_mine(email: str | None) -> Dict[str, Any]:
    if not email:
        # Honest empty state — no user, no personal queue.
        return {"__never_matches__": True}
    q: Dict[str, Any] = {
        "incident_state": "in_progress",
        "incident_assignee": email,
    }
    return _scope(q, email)


def _pred_customer_response(email: str | None) -> Dict[str, Any]:
    q: Dict[str, Any] = {**_open_states_clause(),
                          "customer_engaged": True,
                          "incident_state": "on_hold"}
    return _scope(q, email)


def _pred_on_hold(email: str | None) -> Dict[str, Any]:
    return _scope({"incident_state": "on_hold"}, email)


def _pred_aging(email: str | None) -> Dict[str, Any]:
    """SLA at risk: sla_due_at is in the past OR within the next 4 h,
    and the incident is not resolved/closed."""
    horizon = _iso(_now() + timedelta(hours=4))
    q: Dict[str, Any] = {
        **_open_states_clause(),
        "sla_due_at": {"$exists": True, "$ne": None, "$lte": horizon},
    }
    return _scope(q, email)


def _pred_recently_created(email: str | None) -> Dict[str, Any]:
    since = _iso(_now() - timedelta(hours=24))
    return _scope({"created_at": {"$gte": since}}, email)


def _pred_recently_updated(email: str | None) -> Dict[str, Any]:
    since = _iso(_now() - timedelta(hours=24))
    return _scope({"updated_at": {"$gte": since}}, email)


def _scope(q: Dict[str, Any], email: str | None) -> Dict[str, Any]:
    """Attach the analyst's tenant scope.  Only saved cases (with a
    persisted name) are surfaced — matches list_incidents contract."""
    q.setdefault("name", {"$exists": True, "$ne": ""})
    if email:
        q["user_email"] = email
    return q


LENSES: Tuple[Lens, ...] = (
    # ── TRIAGE ──────────────────────────────────────────────────────
    {"id": "critical",           "group": "triage",
     "label": "Critical",        "description": "Open P1 incidents.",
     "predicate": _pred_critical,
     "tone": "red"},
    {"id": "high_priority",      "group": "triage",
     "label": "High Priority",   "description": "Open P1 + P2 incidents.",
     "predicate": _pred_high_priority,
     "tone": "amber"},
    {"id": "high_fidelity",      "group": "triage",
     "label": "High Fidelity",   "description": "Open incidents flagged high-fidelity by the detection engine.",
     "predicate": _pred_high_fidelity,
     "tone": "cyan"},
    # ── OWNERSHIP ───────────────────────────────────────────────────
    {"id": "unassigned",         "group": "ownership",
     "label": "Unassigned",      "description": "Open incidents with no assignee.",
     "predicate": _pred_unassigned,
     "tone": "amber"},
    {"id": "in_progress_mine",   "group": "ownership",
     "label": "In Progress — Mine",
     "description": "Incidents in progress that are assigned to me.",
     "predicate": _pred_in_progress_mine,
     "tone": "mint"},
    {"id": "customer_response",  "group": "ownership",
     "label": "Customer Response",
     "description": "Incidents on hold, awaiting a customer response.",
     "predicate": _pred_customer_response,
     "tone": "cyan"},
    # ── RISK ────────────────────────────────────────────────────────
    {"id": "on_hold",            "group": "risk",
     "label": "On Hold",         "description": "Incidents currently on hold for any reason.",
     "predicate": _pred_on_hold,
     "tone": "amber"},
    {"id": "aging",              "group": "risk",
     "label": "SLA / Aging Risk",
     "description": "Open incidents with an SLA due within 4 hours or already breached.",
     "predicate": _pred_aging,
     "tone": "red"},
    {"id": "recently_created",   "group": "risk",
     "label": "Recently Created",
     "description": "Incidents created in the last 24 hours.",
     "predicate": _pred_recently_created,
     "tone": "cyan"},
    {"id": "recently_updated",   "group": "risk",
     "label": "Recently Updated",
     "description": "Incidents updated in the last 24 hours.",
     "predicate": _pred_recently_updated,
     "tone": "mint"},
)


LENS_IDS: Tuple[str, ...] = tuple(l["id"] for l in LENSES)


def get_lens(lens_id: str) -> Lens | None:
    for l in LENSES:
        if l["id"] == lens_id:
            return l
    return None


def build_predicate(lens_id: str, email: str | None) -> Dict[str, Any]:
    """Return the Mongo filter for a lens.  Raises KeyError for
    unknown lenses — callers must translate to HTTP 400."""
    lens = get_lens(lens_id)
    if not lens:
        raise KeyError(lens_id)
    return lens["predicate"](email)


def is_never_match(predicate: Dict[str, Any]) -> bool:
    """The '__never_matches__' sentinel lets a lens honestly return
    zero without hitting the database (e.g. `in_progress_mine` for an
    unauthenticated caller)."""
    return predicate.get("__never_matches__") is True
