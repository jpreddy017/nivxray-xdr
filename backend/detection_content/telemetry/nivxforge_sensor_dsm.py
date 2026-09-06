"""NivXForge Linux endpoint sensor DSM · P0-F.

This is the endpoint plane's CONTRIBUTION to the authoritative NivXRay XDR
detection fabric. It creates no engine, no second canonical schema and no
parallel rule model: it teaches the EXISTING DSM registry how to recognise
a NivXForge sensor event so that `process_event_through_pipeline` can
carry it through the same parser → normalizer → canonical → detection →
IUE → ICE → VEEE → incident chain every other source uses.

Two deliberate decisions:

* **The canonical projection is not duplicated.** `select_parser()`
  delegates to `edr_plane.canonical_bridge.parse`, which is already the
  single source of truth for sensor JSON → canonical evidence. Copying it
  here would create two schemas that drift, which is exactly what the
  ownership audit told us to avoid.
* **Nothing is invented to satisfy the pipeline.** A field the sensor did
  not observe stays absent and its epistemic state travels with the
  event, so a rule that requires evidence we do not have simply does not
  match — it never matches on a fabricated default.
"""
from __future__ import annotations

from typing import Any, Dict

DSM_ID = "nivxforge-linux-sensor"
PARSER_ID = "nivxforge-linux-sensor-parser"
NORMALIZER_ID = "nivxforge-linux-sensor-normalizer"
SENSOR_ACTIVITIES = ("PROCESS", "FILE", "NETWORK")


class NivXForgeSensorParseError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


class NivXForgeSensorParser:
    id = PARSER_ID

    def parse(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        from edr_plane.canonical_bridge import parse as sensor_parse
        import json as _json
        if not isinstance(ev, dict):
            raise NivXForgeSensorParseError(
                "INVALID_EVENT", "sensor event is not a JSON object")
        try:
            canonical = sensor_parse(_json.dumps(ev))
        except Exception as e:  # noqa: BLE001
            raise NivXForgeSensorParseError("SENSOR_PARSE_FAILED",
                                            str(e)[:200]) from None
        return {"parser_id": self.id, "raw": ev, "canonical": canonical,
                "event_type": ev.get("activity")}


class NivXForgeSensorNormalizer:
    id = NORMALIZER_ID

    def normalize(self, parsed: Dict[str, Any], dsm_id: str = DSM_ID,
                  collector_id: str = "", integration_id: str = "",
                  trace_id: str = "",
                  tenant_id: str = "default") -> Dict[str, Any]:
        """The parser already produced the authoritative canonical shape;
        normalization only stamps provenance so a detection can be traced
        back to the exact endpoint event that produced it."""
        canonical = dict(parsed["canonical"])
        if not str(tenant_id or "").strip():
            raise ValueError("tenant_id is required: NO tenant fallback "
                             "permitted")
        canonical["tenant_id"] = str(tenant_id).strip()
        # The canonical id is derived from the immutable raw event, so the
        # same endpoint event always yields the same canonical identity.
        canonical.setdefault("event_id", f"cev_{trace_id}_pl")
        canonical["provenance"] = {
            **(canonical.get("provenance") or {}),
            "trace_id": trace_id or (canonical.get("provenance")
                                     or {}).get("trace_id"),
            "collector_id": collector_id,
            "integration_id": integration_id,
            "normalizer_id": self.id,
            "dsm_id": dsm_id,
        }
        extra = dict(canonical.get("additional_fields") or {})
        extra.setdefault("normalizer_id", self.id)
        extra.setdefault("dsm_id", dsm_id)
        canonical["additional_fields"] = extra
        return canonical


class NivXForgeSensorDSM:
    id = DSM_ID
    vendor = "NivXForge"
    product = "LinuxSensor"
    version = "1.0"
    source_type = "endpoint"

    def supports(self, ev: Any) -> bool:
        if not isinstance(ev, dict):
            return False
        # An endpoint event is identified by its own declared activity plus
        # the sensor's collection method. A bare dict with an `activity`
        # key is NOT claimed — that would let an unrelated source be
        # attributed to an endpoint.
        return (ev.get("activity") in SENSOR_ACTIVITIES
                and bool(ev.get("collection_method") or ev.get(
                    "sensor_version")))

    def select_parser(self):
        return NivXForgeSensorParser()

    def select_normalizer(self):
        return NivXForgeSensorNormalizer()

    def identity(self) -> Dict[str, Any]:
        return {"id": self.id, "vendor": self.vendor, "product": self.product,
                "version": self.version, "source_type": self.source_type}
