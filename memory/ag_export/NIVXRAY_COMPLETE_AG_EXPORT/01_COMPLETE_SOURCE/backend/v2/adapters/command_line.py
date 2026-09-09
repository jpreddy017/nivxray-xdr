"""Adapter · Command Line (Phase 2b · shadow-mode observer).

**PARALLEL SHADOW PIPELINE ONLY.**

This adapter accepts a raw string / bytes command line and produces
CEM v1 events. It is NEVER invoked from RC5 code, NEVER modifies
`/api/rc5/parse`, NEVER influences RC5 verdicts, and NEVER touches
RC5 storage.

Gating:
    NIVX_FLAG_ADAPTERS=disabled → detect() returns 0.0, stream() empty.
    NIVX_FLAG_ADAPTERS=shadow   → detect() + stream() active. Output
                                   is consumed by v2 test harness /
                                   future v2 endpoints only.
    NIVX_FLAG_ADAPTERS=enabled  → same behaviour as shadow for now;
                                   promotion to authoritative happens
                                   in a later phase.

No import from `engine.*` is allowed — enforced by
`tests/test_v2_framework.py::TestIsolationFromRC5`.
"""
from __future__ import annotations

import hashlib
from typing import Iterator

from v2.adapters.base import BaseAdapter, RawEvent, Source
from v2.adapters.registry import register
from v2.flags import get as get_flag


@register
class CommandLineAdapter(BaseAdapter):
    name = "command_line"
    version = "0.2.0-shadow"
    supported_formats = ("text",)
    capabilities = frozenset({"single-shot"})
    cem_version = "v1"

    def _active(self) -> bool:
        return get_flag("ADAPTERS").observable()

    def detect(self, sample: bytes | str) -> float:
        """Return confidence this adapter can consume the sample.

        Rules (deterministic, no heuristics-with-side-effects):
          • Empty / non-text → 0.0
          • Non-printable dominated → 0.0
          • Any text under 32 KB → 0.75 (generic text confidence).
            More specific adapters (powershell/cmd/bash) will out-
            score this on real inputs once they gain logic.
        """
        if not self._active():
            return 0.0
        if sample is None:
            return 0.0
        if isinstance(sample, bytes):
            try:
                text = sample.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                return 0.0
        else:
            text = str(sample)
        if not text:
            return 0.0
        if len(text) > 32_768:
            return 0.0
        # Rough printable fraction — deterministic O(n).
        printable = sum(1 for c in text if c == "\n" or c == "\t" or 0x20 <= ord(c) < 0x7f or ord(c) >= 0x80)
        frac = printable / len(text)
        return 0.75 if frac >= 0.90 else 0.0

    def stream(self, source: Source, *, chunk_size: int = 4096) -> Iterator[RawEvent]:
        """Yield exactly one RawEvent per source (command-line inputs
        are single-shot; a 'stream' semantic is trivial here).

        Shadow discipline: this method is pure — no I/O, no writes,
        no calls out to RC5.
        """
        if not self._active():
            return iter(())
        if source.kind == "bytes":
            raw = source.ref
            if isinstance(raw, str):
                raw_bytes = raw.encode("utf-8")
                text = raw
            else:
                raw_bytes = bytes(raw)
                try:
                    text = raw_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    text = raw_bytes.decode("utf-8", errors="replace")
        elif source.kind == "path":
            # Read-only local file access. Enforced 32 KB cap so a
            # stray large file never balloons memory in shadow mode.
            with open(source.ref, "rb") as f:
                raw_bytes = f.read(32_768 + 1)
            if len(raw_bytes) > 32_768:
                raise ValueError("command_line adapter input exceeds 32 KB shadow cap")
            text = raw_bytes.decode("utf-8", errors="replace")
        else:
            raise ValueError(f"command_line adapter cannot handle source.kind={source.kind!r}")

        payload = {
            "text": text,
            "length": len(text),
            "sha256": hashlib.sha256(raw_bytes).hexdigest(),
            "hint_language": (source.hints or {}).get("language"),
        }
        yield RawEvent(
            adapter=self.name,
            sequence=0,
            payload=payload,
            raw_bytes=raw_bytes,
        )
