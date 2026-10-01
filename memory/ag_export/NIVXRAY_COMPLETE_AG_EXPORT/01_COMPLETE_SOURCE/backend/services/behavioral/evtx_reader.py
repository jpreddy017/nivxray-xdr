"""P2 Slice-3 · EVTX binary transport layer (ADR-0010s).

**Transport only.** This module accepts raw `.evtx` bytes and yields
Sysmon Event XML strings that the existing `normalize_sysmon_xml`
already accepts. It DOES NOT:

  · introduce new canonical fields
  · introduce new MITRE mappings
  · introduce new verdict logic
  · touch correlation, deduplication, or provenance
  · make outbound network calls

If a Sysmon-XML normalizer already consumes a given field, EVTX
delivers it exactly the same way. If a field only appears in EVTX,
the transport layer omits it — preserving Slice-1/Slice-2 scope.
"""
from __future__ import annotations

import io
import os
import re
from typing import Iterator, Tuple

# python-evtx (pure-Python parser, no native dependencies)
import Evtx.Evtx as _Evtx
import Evtx.Views as _Views


ADAPTER_ID = "sysmon.slice3.evtx@1.0"

# The default file-size cap. Deterministic; enforced BEFORE any parsing.
DEFAULT_MAX_EVTX_BYTES = 16 * 1024 * 1024   # 16 MiB
DEFAULT_MAX_EVTX_RECORDS = 10_000            # per ingest


class EvtxTransportError(ValueError):
    """Adapter refused the input. Carries a short machine code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# The python-evtx renderer produces XML like:
#     <?xml version="1.1" encoding="utf-8" standalone="yes" ?>
#     <Event xmlns=...> ... </Event>
# The existing `normalize_sysmon_xml` accepts a single `<Event>` or
# an `<Events>` wrapper. We wrap every record's XML into a single
# `<Events>` element preserving order and re-emit as UTF-8 text.
# ---------------------------------------------------------------------------
_XML_DECL_RE = re.compile(rb"<\?xml[^?]*\?>\s*", re.DOTALL)


def _strip_xml_decl(xml_bytes: bytes) -> bytes:
    return _XML_DECL_RE.sub(b"", xml_bytes, count=1)


def _yield_event_xml(evtx_bytes: bytes,
                     *, max_records: int) -> Iterator[str]:
    """Yield the per-record XML string for each record in the EVTX.

    The parser walks records in on-disk order which is stable for a
    given file — same input bytes produce the same sequence and thus
    the same downstream canonical evidence."""
    seen = 0
    # python-evtx expects a filesystem file. Use a temp buffer that
    # supports .fileno() by writing to a tempfile — this is the
    # documented usage.
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".evtx", delete=True) as tmp:
        tmp.write(evtx_bytes)
        tmp.flush()
        with _Evtx.Evtx(tmp.name) as log:
            for record in log.records():
                seen += 1
                if seen > max_records:
                    raise EvtxTransportError(
                        "evtx_record_cap_exceeded",
                        f"EVTX exceeded record cap (limit={max_records}, "
                        f"seen={seen}). Refusing to silently truncate.",
                    )
                # `record.xml()` returns a `str` containing an XML
                # declaration + one `<Event>` element.
                try:
                    xml_text = record.xml()
                except Exception as exc:  # noqa: BLE001
                    raise EvtxTransportError(
                        "evtx_record_parse_error",
                        f"record #{seen} failed to render: {exc}",
                    ) from exc
                # Strip the XML decl so records concatenate cleanly.
                clean = _strip_xml_decl(xml_text.encode("utf-8"))
                yield clean.decode("utf-8", errors="replace")


def decode_evtx_to_sysmon_xml(evtx_bytes: bytes,
                               *,
                               max_bytes: int = DEFAULT_MAX_EVTX_BYTES,
                               max_records: int = DEFAULT_MAX_EVTX_RECORDS,
                               ) -> Tuple[str, dict]:
    """Read `.evtx` bytes and return `(events_wrapper_xml, meta)`.

    `events_wrapper_xml` is a plain UTF-8 string containing
    `<Events> …one child <Event> per record… </Events>` — exactly
    the shape the existing `normalize_sysmon_xml` accepts.
    `meta` reports:
      · `transport`         = "sysmon.slice3.evtx@1.0"
      · `record_count`      = number of records rendered
      · `raw_bytes`         = size of the EVTX blob
      · `resource_limits`   = the caps in force for this call
    """
    if not isinstance(evtx_bytes, (bytes, bytearray)):
        raise EvtxTransportError("empty_input",
                                  "EVTX transport requires bytes input")
    if not evtx_bytes:
        raise EvtxTransportError("empty_input", "empty EVTX payload")
    if len(evtx_bytes) > max_bytes:
        raise EvtxTransportError(
            "evtx_payload_too_large",
            f"EVTX payload exceeds {max_bytes} bytes "
            f"(size={len(evtx_bytes)}). Refusing to parse.",
        )
    # EVTX header magic is the ASCII bytes `ElfFile\x00`.
    if not evtx_bytes.startswith(b"ElfFile\x00"):
        raise EvtxTransportError(
            "evtx_bad_magic",
            "not an EVTX file (magic mismatch — "
            "expected 'ElfFile\\x00' prefix)",
        )

    buf = io.StringIO()
    buf.write("<Events>")
    n = 0
    try:
        for xml_str in _yield_event_xml(evtx_bytes, max_records=max_records):
            buf.write(xml_str)
            n += 1
    except EvtxTransportError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise EvtxTransportError(
            "evtx_walk_error",
            f"EVTX chunk walk failed after {n} record(s): {exc}",
        ) from exc
    buf.write("</Events>")

    if n == 0:
        raise EvtxTransportError(
            "evtx_no_records",
            "EVTX file parsed but no records were rendered. The file "
            "may be corrupt, truncated, or contain no event data.",
        )

    return buf.getvalue(), {
        "transport":     ADAPTER_ID,
        "record_count":  n,
        "raw_bytes":     len(evtx_bytes),
        "resource_limits": {
            "max_bytes":   max_bytes,
            "max_records": max_records,
        },
    }
