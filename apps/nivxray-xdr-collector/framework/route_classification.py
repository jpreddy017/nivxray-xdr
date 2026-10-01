"""The ONE classification of every collector-plane operation.

Collector Auth P0. The plane was mounted into the NivXRay backend with no
authentication dependency of any kind: 22 operations, 9 of them anonymously
mutating and 9 anonymously leaking. Tenant convergence answered *which
customer*; nothing answered *who* and *what may they do*.

Four classes, closed set:

  HUMAN_CONTROL     an operator/admin action. Requires, IN THIS ORDER:
                    authentication -> permission -> explicit authoritative
                    tenant -> capability.
  MACHINE           a vendor/machine credential owns the request. Today this
                    is exactly one route: the inbound webhook, authenticated
                    by the per-connector HMAC in `framework.webhook.verify`.
                    An analyst JWT must NEVER be put in front of it.
  TEST_PLANE        synthetic-payload injection. Authenticated + permitted +
                    explicitly enabled by a non-production flag.
  PRODUCT_METADATA  product truth, identical for every tenant, carrying no
                    tenant data. Authentication + permission still required;
                    an explicit tenant is not.

Keys are ``(HTTP method, mount-relative path)`` so the map is independent of
where the plane is mounted (``/api/xdr/collector`` in the landed backend,
``/api/xdr`` in the standalone deployment).

A live operation that is ABSENT from this map is refused at request time and
fails the regression gate. That is the clause that would have caught this
gap: a route added six months from now cannot be anonymous by accident.
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple

HUMAN_CONTROL = "HUMAN_CONTROL"
MACHINE = "MACHINE"
TEST_PLANE = "TEST_PLANE"
PRODUCT_METADATA = "PRODUCT_METADATA"

CLASSES = {HUMAN_CONTROL, MACHINE, TEST_PLANE, PRODUCT_METADATA}

#: (method, relative_path) -> (class, required permission or None)
COLLECTOR_ROUTE_CLASSIFICATION: Dict[Tuple[str, str], Tuple[str, Optional[str]]] = {
    # ── routes/connectors.py ──────────────────────────────────────────
    ("GET", "/source-types"): (PRODUCT_METADATA, "collectors.read"),
    ("GET", "/connectors"): (HUMAN_CONTROL, "collectors.read"),
    ("POST", "/connectors"): (HUMAN_CONTROL, "collectors.create"),
    ("GET", "/connectors/{cid}"): (HUMAN_CONTROL, "collectors.read"),
    ("PATCH", "/connectors/{cid}"): (HUMAN_CONTROL, "collectors.update"),
    ("DELETE", "/connectors/{cid}"): (HUMAN_CONTROL, "collectors.delete"),
    ("POST", "/connectors/{cid}/test"): (HUMAN_CONTROL, "collectors.test"),
    ("POST", "/connectors/{cid}/start"): (HUMAN_CONTROL, "collectors.enable"),
    ("POST", "/connectors/{cid}/stop"): (HUMAN_CONTROL, "collectors.disable"),
    # Synthetic evidence entering the canonical pipeline. A header the caller
    # sets is not a control, so the debug header is kept AND a deployment flag
    # is required AND `collectors.test` is required.
    ("POST", "/connectors/{cid}/inject"): (TEST_PLANE, "collectors.test"),
    # ── routes/collectors.py ──────────────────────────────────────────
    ("GET", "/collectors"): (HUMAN_CONTROL, "collectors.read"),
    ("GET", "/collectors/{collector_id}"): (HUMAN_CONTROL, "collectors.read"),
    # ── routes/outbox.py ──────────────────────────────────────────────
    ("GET", "/outbox/health"): (HUMAN_CONTROL, "collectors.read"),
    ("GET", "/outbox"): (HUMAN_CONTROL, "collectors.read"),
    ("GET", "/outbox/{rid}"): (HUMAN_CONTROL, "collectors.read"),
    ("POST", "/outbox/{rid}/replay"): (HUMAN_CONTROL, "collectors.update"),
    ("POST", "/outbox/drain-once"): (HUMAN_CONTROL, "collectors.update"),
    # ── single-operation routers ──────────────────────────────────────
    ("GET", "/data-sources"): (HUMAN_CONTROL, "collectors.read"),
    ("GET", "/telemetry-health"): (PRODUCT_METADATA, "collectors.read"),
    ("POST", "/ingest-preflight"): (HUMAN_CONTROL, "collectors.test"),
    ("POST", "/webhooks/{secret_id}"): (MACHINE, None),
    # ── landing echo (backend mount only) ─────────────────────────────
    ("GET", "/landing"): (PRODUCT_METADATA, "collectors.read"),
}


def relative_path(full_path: str, prefix: str) -> str:
    """The mount-relative path used as the classification key."""
    if prefix and full_path.startswith(prefix):
        return full_path[len(prefix):] or "/"
    return full_path


def classify(method: str, rel_path: str) -> Optional[Tuple[str, Optional[str]]]:
    """``(class, permission)`` for an operation, or ``None`` when undeclared.

    ``None`` means FAIL CLOSED — never "allow".
    """
    return COLLECTOR_ROUTE_CLASSIFICATION.get(((method or "").upper(), rel_path))
