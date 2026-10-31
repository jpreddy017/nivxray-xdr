"""Stage 2 · Schema Understanding.

Given a ``ParsedInput`` (from Stage 2 parser), produce a
``SchemaFingerprint`` that describes the *structural shape* of the
telemetry — schema family, structural features, and the raw candidate
field names present in the records.

Contract (see NIVXRAY_ARCHITECTURE_VISION.md §Schema Understanding):

  1. **No semantic mapping.** This stage MUST NOT map fields to
     canonical concepts. That is the Semantic Field Mapper (Stage 3).
     Here we only surface ``candidate_fields`` verbatim.
  2. **No vendor branching.** Detection recognizes *open standards*
     (Elastic Common Schema, OpenTelemetry, CEF, LEEF, Windows Event
     XML) and *generic structural families* (generic_json, generic_csv,
     generic_kv, …). Vendor identity is metadata attached elsewhere.
  3. **Unknown is a success state.** ``unknown_structured`` is a
     first-class result whenever the parser succeeded but no known
     schema family matched. Downstream stages must accept it.
  4. **Distinct confidence axis.** ``schema_confidence`` describes
     how confident we are about the *schema family*; it is unrelated
     to semantic-mapping confidence or vendor confidence.
  5. **Reasons carry provenance.** ``reasons`` records the signals
     that led to the classification, in human-readable form.
  6. **Never raises.** All parsing/scanning is defensively bounded.

Output is fully deterministic and hashable-friendly (tuples).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .input_classification import InputClass
from .parser import ParsedInput
from .semantic_alias_registry import SEMANTIC_ALIAS_REGISTRY_VERSION


# ── Schema family enumeration ───────────────────────────────────────

class SchemaFamily:
    """Structural schema families recognised by Stage 2.

    Standards-based families (recognized by shape, not by vendor):
        - ``elastic_ecs``       Elastic Common Schema (host.name, …)
        - ``opentelemetry``     OTLP logs / traces (resourceLogs, …)
        - ``windows_event_xml`` Windows/Sysmon Event XML
        - ``cef``               ArcSight Common Event Format
        - ``leef``              IBM QRadar Log Event Extended Format
        - ``syslog_rfc5424``    Structured syslog

    Generic structural families (parser succeeded, no schema signature):
        - ``generic_json``
        - ``generic_ndjson``
        - ``generic_csv``
        - ``generic_xml``
        - ``generic_kv``
        - ``generic_yaml``   (reserved · parser to be added later)
        - ``generic_ini``    (reserved · parser to be added later)

    Non-record inputs:
        - ``command_line``   parsed as encoded_cmd / plain_command
        - ``unknown_unstructured``  plain-text without structure
        - ``empty``          input was empty

    Fallback:
        - ``unknown_structured``  parser produced records but none of
          the known families matched. This is a supported success state.
    """
    ELASTIC_ECS = "elastic_ecs"
    OPENTELEMETRY = "opentelemetry"
    WINDOWS_EVENT_XML = "windows_event_xml"
    CEF = "cef"
    LEEF = "leef"
    SYSLOG_RFC5424 = "syslog_rfc5424"

    GENERIC_JSON = "generic_json"
    GENERIC_NDJSON = "generic_ndjson"
    GENERIC_CSV = "generic_csv"
    GENERIC_XML = "generic_xml"
    GENERIC_KV = "generic_kv"
    GENERIC_YAML = "generic_yaml"
    GENERIC_INI = "generic_ini"

    COMMAND_LINE = "command_line"
    UNKNOWN_UNSTRUCTURED = "unknown_unstructured"
    UNKNOWN_STRUCTURED = "unknown_structured"
    EMPTY = "empty"


# ── Output type ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class SchemaFingerprint:
    """The single output of Schema Understanding.

    Every field is populated on every invocation — even for
    ``unknown_structured`` and ``unknown_unstructured``.
    """
    schema_family: str
    schema_version: Optional[str]
    schema_confidence: float
    candidate_fields: Tuple[str, ...]
    parser_features: Dict[str, Any]
    reasons: Tuple[str, ...]
    diagnostics: Tuple[str, ...]
    registry_version: str  # provenance link ONLY — no mapping is done here


# ── Structural signatures (open standards only) ─────────────────────

_ECS_ROOT_NAMESPACES = {
    "@timestamp", "event", "host", "source", "destination", "user",
    "process", "file", "network", "url", "agent", "ecs", "http", "tls",
    "observer", "log", "related", "client", "server",
}
# Fields that MUST appear (in dotted form OR as nested object roots)
# for a document to look like ECS.
_ECS_STRONG_HINTS = (
    "@timestamp", "event.category", "event.action", "ecs.version",
    "host.name", "source.ip", "destination.ip", "process.name",
    "agent.type", "log.level",
)

_OTEL_HINTS = {
    "resourcelogs", "scopelogs", "resource", "attributes",
    "trace_id", "span_id", "traceid", "spanid",
    "resourcespans", "scopespans",
}

_WINDOWS_EVENT_ROOT_KEYS = {
    "eventid", "provider", "channel", "eventrecordid", "computer",
    "task", "opcode", "level", "keywords", "systemtime", "processid",
}

_CEF_PREFIX = "cef:"
_LEEF_PREFIX = "leef:"


# ── Public entry point ─────────────────────────────────────────────

def understand_schema(parsed: ParsedInput) -> SchemaFingerprint:
    """Fingerprint the structural schema of a parsed input.

    Deterministic. Never raises. ``unknown_structured`` is a valid,
    successful result — do not treat it as an error.
    """
    diagnostics: List[str] = list(parsed.diagnostics or ())

    # ── Non-record inputs ───────────────────────────────────────────
    if parsed.kind == InputClass.EMPTY:
        return _fingerprint(
            SchemaFamily.EMPTY,
            schema_version=None,
            schema_confidence=1.0,
            candidate_fields=(),
            parser_features={"record_count": 0,
                             "input_class": parsed.kind},
            reasons=("input was empty",),
            diagnostics=tuple(diagnostics),
        )

    if parsed.kind in (InputClass.ENCODED_CMD, InputClass.PLAIN_COMMAND):
        return _fingerprint(
            SchemaFamily.COMMAND_LINE,
            schema_version=None,
            schema_confidence=1.0,
            candidate_fields=("command_line",),
            parser_features={"record_count": len(parsed.records),
                             "input_class": parsed.kind,
                             "length": len(parsed.text or "")},
            reasons=(f"input_class={parsed.kind} — command telemetry, "
                    f"not a record schema",),
            diagnostics=tuple(diagnostics),
        )

    if parsed.kind == InputClass.PLAIN_TEXT:
        text = parsed.text or ""
        stripped = text.strip()
        # CEF / LEEF / RFC5424 sniff inside plain_text.
        low = stripped[:16].lower()
        if low.startswith(_CEF_PREFIX):
            return _cef_fingerprint(text, diagnostics)
        if low.startswith(_LEEF_PREFIX):
            return _leef_fingerprint(text, diagnostics)
        if _looks_like_rfc5424(stripped):
            return _fingerprint(
                SchemaFamily.SYSLOG_RFC5424,
                schema_version="rfc5424",
                schema_confidence=0.75,
                candidate_fields=(),
                parser_features={"record_count": 1,
                                 "input_class": parsed.kind,
                                 "length": len(text)},
                reasons=("input begins with RFC5424 syslog prefix",),
                diagnostics=tuple(diagnostics),
            )
        return _fingerprint(
            SchemaFamily.UNKNOWN_UNSTRUCTURED,
            schema_version=None,
            schema_confidence=0.6,
            candidate_fields=(),
            parser_features={"record_count": 0,
                             "input_class": parsed.kind,
                             "length": len(text)},
            reasons=("parser returned plain_text with no known "
                    "structured signature",),
            diagnostics=tuple(diagnostics),
        )

    # ── Record inputs ──────────────────────────────────────────────
    records = list(parsed.records or ())
    candidate_fields = _extract_candidate_fields(records)
    features = _compute_parser_features(parsed, records, candidate_fields)

    # 1. Elastic Common Schema — check first (highest specificity)
    ecs_score, ecs_reasons = _score_ecs(candidate_fields, records)
    if ecs_score >= 0.6:
        return _fingerprint(
            SchemaFamily.ELASTIC_ECS,
            schema_version=_ecs_version(records),
            schema_confidence=min(1.0, ecs_score),
            candidate_fields=candidate_fields,
            parser_features=features,
            reasons=tuple(ecs_reasons),
            diagnostics=tuple(diagnostics),
        )

    # 2. OpenTelemetry
    otel_score, otel_reasons = _score_otel(candidate_fields, records)
    if otel_score >= 0.6:
        return _fingerprint(
            SchemaFamily.OPENTELEMETRY,
            schema_version=None,
            schema_confidence=min(1.0, otel_score),
            candidate_fields=candidate_fields,
            parser_features=features,
            reasons=tuple(otel_reasons),
            diagnostics=tuple(diagnostics),
        )

    # 3. Windows Event XML (already parsed by parser.py)
    if parsed.kind == InputClass.XML:
        winev_score, winev_reasons = _score_windows_event(candidate_fields,
                                                          records)
        if winev_score >= 0.5:
            return _fingerprint(
                SchemaFamily.WINDOWS_EVENT_XML,
                schema_version=None,
                schema_confidence=min(1.0, winev_score),
                candidate_fields=candidate_fields,
                parser_features=features,
                reasons=tuple(winev_reasons),
                diagnostics=tuple(diagnostics),
            )
        # Fell through — generic XML.
        return _fingerprint(
            SchemaFamily.GENERIC_XML,
            schema_version=None,
            schema_confidence=0.75,
            candidate_fields=candidate_fields,
            parser_features=features,
            reasons=("parser produced XML records but no Windows Event "
                    "signature matched",),
            diagnostics=tuple(diagnostics),
        )

    # 4. Generic families keyed by parser class
    if parsed.kind == InputClass.NDJSON:
        return _generic(SchemaFamily.GENERIC_NDJSON, 0.9,
                        candidate_fields, features, diagnostics,
                        reason="ndjson records with no known schema "
                               "signature")
    if parsed.kind == InputClass.CSV:
        return _generic(SchemaFamily.GENERIC_CSV, 0.9,
                        candidate_fields, features, diagnostics,
                        reason="csv records with no known schema "
                               "signature")
    if parsed.kind == InputClass.KEY_VALUE:
        return _generic(SchemaFamily.GENERIC_KV, 0.85,
                        candidate_fields, features, diagnostics,
                        reason="key=value records with no known schema "
                               "signature")
    if parsed.kind == InputClass.JSON:
        # Records-shaped JSON that didn't match ECS / OTEL — still
        # useful as generic_json. If shape looks non-log (e.g. empty
        # record set), drop confidence.
        conf = 0.85 if records else 0.5
        return _generic(SchemaFamily.GENERIC_JSON, conf,
                        candidate_fields, features, diagnostics,
                        reason="json records with no known schema "
                               "signature")

    # 5. Final graceful fallback — records exist but we can't say what.
    #    This is the mandated "success on unknown" contract.
    return _fingerprint(
        SchemaFamily.UNKNOWN_STRUCTURED,
        schema_version=None,
        schema_confidence=0.5,
        candidate_fields=candidate_fields,
        parser_features=features,
        reasons=(f"parser produced records (kind={parsed.kind!r}) but "
                f"no known schema family matched — unknown_structured "
                f"is a supported state",),
        diagnostics=tuple(diagnostics),
    )


# ── Helpers ────────────────────────────────────────────────────────

def _fingerprint(schema_family: str,
                 *,
                 schema_version: Optional[str],
                 schema_confidence: float,
                 candidate_fields: Tuple[str, ...],
                 parser_features: Dict[str, Any],
                 reasons: Tuple[str, ...],
                 diagnostics: Tuple[str, ...]) -> SchemaFingerprint:
    return SchemaFingerprint(
        schema_family=schema_family,
        schema_version=schema_version,
        schema_confidence=max(0.0, min(1.0, schema_confidence)),
        candidate_fields=candidate_fields,
        parser_features=parser_features,
        reasons=reasons,
        diagnostics=diagnostics,
        registry_version=SEMANTIC_ALIAS_REGISTRY_VERSION,
    )


def _generic(family: str,
             confidence: float,
             candidate_fields: Tuple[str, ...],
             features: Dict[str, Any],
             diagnostics: List[str],
             *,
             reason: str) -> SchemaFingerprint:
    return _fingerprint(
        family,
        schema_version=None,
        schema_confidence=confidence,
        candidate_fields=candidate_fields,
        parser_features=features,
        reasons=(reason,),
        diagnostics=tuple(diagnostics),
    )


_MAX_CANDIDATES = 256

MAX_SCHEMA_DEPTH: int = 3
"""Maximum nesting depth explored when extracting candidate field
paths from parsed records. Configurable per owner directive
2026-02-XX — most telemetry does not exceed depth 3."""


def _extract_candidate_fields(records: List[Dict[str, Any]]
                               ) -> Tuple[str, ...]:
    """Collect the raw field names appearing across all records.

    Preserves first-seen order. Records are flattened up to
    ``MAX_SCHEMA_DEPTH`` levels so dotted paths for deeply-nested
    telemetry (e.g. Cisco Secure Endpoint's ``file.identity.sha256``,
    Elastic ECS's ``file.hash.sha256``) surface as candidate fields
    without vendor-specific handling.
    """
    seen: Dict[str, None] = {}
    for rec in records[:200]:  # bound work on huge payloads
        if not isinstance(rec, dict):
            continue
        _walk(rec, "", seen, depth=0)
        if len(seen) >= _MAX_CANDIDATES:
            break
    return tuple(seen.keys())


def _walk(obj: Any,
          prefix: str,
          seen: Dict[str, None],
          *,
          depth: int) -> None:
    """Depth-bounded recursive walker that surfaces dotted field paths
    up to ``MAX_SCHEMA_DEPTH`` levels."""
    if not isinstance(obj, dict):
        return
    for key, val in obj.items():
        if not isinstance(key, str):
            continue
        path = f"{prefix}.{key}" if prefix else key
        if path not in seen:
            seen[path] = None
        if len(seen) >= _MAX_CANDIDATES:
            return
        if depth + 1 < MAX_SCHEMA_DEPTH and isinstance(val, dict):
            _walk(val, path, seen, depth=depth + 1)


def _compute_parser_features(parsed: ParsedInput,
                              records: List[Dict[str, Any]],
                              candidate_fields: Tuple[str, ...]
                              ) -> Dict[str, Any]:
    dotted = sum(1 for f in candidate_fields if "." in f)
    nested = sum(1 for rec in records[:50]
                 if isinstance(rec, dict)
                 and any(isinstance(v, dict) for v in rec.values()))
    has_arrays = any(
        isinstance(v, list)
        for rec in records[:50] if isinstance(rec, dict)
        for v in rec.values()
    )
    prefixes: Dict[str, int] = {}
    for f in candidate_fields:
        if "." in f:
            head = f.split(".", 1)[0]
            prefixes[head] = prefixes.get(head, 0) + 1
    common_prefixes = tuple(
        sorted(prefixes.items(), key=lambda kv: (-kv[1], kv[0]))[:8]
    )
    if dotted and not nested:
        key_style = "dotted"
    elif nested and not dotted:
        key_style = "nested"
    elif nested and dotted:
        key_style = "mixed"
    else:
        key_style = "flat"

    return {
        "record_count": len(records),
        "input_class": parsed.kind,
        "candidate_field_count": len(candidate_fields),
        "has_dotted_keys": bool(dotted),
        "has_nested_objects": bool(nested),
        "has_arrays": bool(has_arrays),
        "key_style": key_style,
        "common_prefixes": common_prefixes,
    }


# ── Elastic Common Schema scoring ─────────────────────────────────

def _score_ecs(candidate_fields: Tuple[str, ...],
               records: List[Dict[str, Any]]) -> Tuple[float, List[str]]:
    reasons: List[str] = []
    score = 0.0

    lc_fields = {f.lower() for f in candidate_fields}

    # Explicit ecs.version wins outright.
    if "ecs.version" in lc_fields or any(
        isinstance(r, dict) and isinstance(r.get("ecs"), dict)
        and "version" in r["ecs"] for r in records[:20]
    ):
        reasons.append("ecs.version present")
        score += 0.7

    strong_hits = [h for h in _ECS_STRONG_HINTS if h in lc_fields]
    if strong_hits:
        reasons.append(f"ECS strong hints: {', '.join(strong_hits[:6])}")
        score += 0.15 * len(strong_hits)

    # Nested-root form: {"host": {"name": ...}, "source": {"ip": ...}}
    nested_ns = set()
    for rec in records[:20]:
        if not isinstance(rec, dict):
            continue
        for k, v in rec.items():
            if isinstance(v, dict) and k in _ECS_ROOT_NAMESPACES:
                nested_ns.add(k)
    if len(nested_ns) >= 3:
        reasons.append(
            f"ECS nested namespaces present: "
            f"{', '.join(sorted(nested_ns)[:6])}"
        )
        score += 0.4

    # Dotted namespaces (>= 3 distinct ECS root heads)
    heads = {f.split(".", 1)[0] for f in candidate_fields if "." in f}
    ecs_heads = heads & _ECS_ROOT_NAMESPACES
    if len(ecs_heads) >= 3:
        reasons.append(
            f"ECS dotted namespaces present: "
            f"{', '.join(sorted(ecs_heads)[:6])}"
        )
        score += 0.4

    return score, reasons


def _ecs_version(records: List[Dict[str, Any]]) -> Optional[str]:
    for rec in records[:20]:
        if not isinstance(rec, dict):
            continue
        ecs = rec.get("ecs")
        if isinstance(ecs, dict):
            v = ecs.get("version")
            if isinstance(v, str) and v:
                return f"ecs-{v}"
        v = rec.get("ecs.version")
        if isinstance(v, str) and v:
            return f"ecs-{v}"
    return None


# ── OpenTelemetry scoring ─────────────────────────────────────────

def _score_otel(candidate_fields: Tuple[str, ...],
                records: List[Dict[str, Any]]) -> Tuple[float, List[str]]:
    reasons: List[str] = []
    score = 0.0
    lc = {f.lower() for f in candidate_fields}

    hits = _OTEL_HINTS & lc
    if hits:
        reasons.append(f"OTEL keys present: {', '.join(sorted(hits))}")
        score += 0.4 * min(3, len(hits))

    # Look for classic OTLP envelope shape.
    for rec in records[:5]:
        if not isinstance(rec, dict):
            continue
        if "resourceLogs" in rec or "resourceSpans" in rec:
            reasons.append("OTLP envelope (resourceLogs/resourceSpans)")
            score += 0.6
            break
        if "trace_id" in rec and "span_id" in rec:
            reasons.append("OTLP correlation ids (trace_id + span_id)")
            score += 0.4
            break

    return score, reasons


# ── Windows Event XML scoring ─────────────────────────────────────

def _score_windows_event(candidate_fields: Tuple[str, ...],
                          records: List[Dict[str, Any]]
                          ) -> Tuple[float, List[str]]:
    reasons: List[str] = []
    lc = {f.lower() for f in candidate_fields}
    hits = _WINDOWS_EVENT_ROOT_KEYS & lc
    score = 0.0
    if "eventid" in lc:
        reasons.append("EventID field present")
        score += 0.5
    if "provider" in lc:
        reasons.append("Provider field present")
        score += 0.2
    if hits - {"eventid", "provider"}:
        extras = sorted(hits - {"eventid", "provider"})
        reasons.append(f"Additional Windows Event fields: "
                       f"{', '.join(extras[:6])}")
        score += 0.1 * min(3, len(hits) - 1)
    return score, reasons


# ── CEF / LEEF / syslog fingerprints ──────────────────────────────

def _cef_fingerprint(text: str,
                     diagnostics: List[str]) -> SchemaFingerprint:
    # Extract CEF header pieces (defensive, no external parsing).
    stripped = text.strip()
    # CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SigId|Name|Sev|Extension
    header = stripped.split("|", 8)
    version = header[0].split(":", 1)[1] if ":" in header[0] else None
    fields: List[str] = []
    if len(header) >= 8:
        ext = header[7]
        for tok in ext.split(" "):
            if "=" in tok:
                fields.append(tok.split("=", 1)[0])
    return _fingerprint(
        SchemaFamily.CEF,
        schema_version=f"cef-{version}" if version else "cef",
        schema_confidence=0.95,
        candidate_fields=tuple(fields),
        parser_features={"record_count": 1,
                         "input_class": InputClass.PLAIN_TEXT,
                         "key_style": "kv-extension"},
        reasons=("input begins with 'CEF:' — ArcSight Common Event Format",),
        diagnostics=tuple(diagnostics),
    )


def _leef_fingerprint(text: str,
                      diagnostics: List[str]) -> SchemaFingerprint:
    stripped = text.strip()
    header = stripped.split("|", 5)
    version = header[0].split(":", 1)[1] if ":" in header[0] else None
    fields: List[str] = []
    if len(header) >= 5:
        ext = header[-1]
        for tok in ext.split("\t"):
            if "=" in tok:
                fields.append(tok.split("=", 1)[0])
        # LEEF may use a single-char delimiter declared in header slot 4
        if not fields:
            for tok in ext.split(" "):
                if "=" in tok:
                    fields.append(tok.split("=", 1)[0])
    return _fingerprint(
        SchemaFamily.LEEF,
        schema_version=f"leef-{version}" if version else "leef",
        schema_confidence=0.95,
        candidate_fields=tuple(fields),
        parser_features={"record_count": 1,
                         "input_class": InputClass.PLAIN_TEXT,
                         "key_style": "kv-extension"},
        reasons=("input begins with 'LEEF:' — QRadar Log Event Extended "
                "Format",),
        diagnostics=tuple(diagnostics),
    )


def _looks_like_rfc5424(stripped: str) -> bool:
    # RFC5424 header: "<PRI>VERSION TIMESTAMP HOST APP PID MSGID …"
    # Cheap check: starts with "<NNN>1 " or "<NN>1 "
    if not stripped.startswith("<"):
        return False
    end = stripped.find(">", 1)
    if end == -1 or end > 5:
        return False
    if not stripped[1:end].isdigit():
        return False
    rest = stripped[end + 1:]
    return rest.startswith("1 ") or rest.startswith("2 ")


__all__ = [
    "SchemaFamily",
    "SchemaFingerprint",
    "understand_schema",
]
