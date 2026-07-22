"""Normalizer · Command Line adapter → CEM v1 (Phase 2b · shadow).

Turns the single `RawEvent` emitted by `command_line` adapter into a
deterministic `CanonicalEvent` of kind `process_create` with a
`command_line` artefact.

Zero RC5 imports. Zero side effects.
"""
from __future__ import annotations

import hashlib
from typing import Iterator

from v2.adapters.base import RawEvent
from v2.cem.v1.schema import CanonicalEvent, Provenance, now_utc
from v2.flags import get as get_flag


class CommandLineNormalizer:
    adapter: str = "command_line"
    cem_version: str = "v1"

    def normalize(self, parsed_or_raw: RawEvent, *, case_id: str) -> Iterator[CanonicalEvent]:
        """Yield 0 or 1 CanonicalEvent.

        Yields nothing when ADAPTERS flag is disabled. Yields one
        `process_create` event with a synthetic `command_line`
        artefact iid derived from sha256 of the input — this makes
        the emission deterministic + idempotent.
        """
        if not get_flag("ADAPTERS").observable():
            return

        p = parsed_or_raw.payload
        text = str(p.get("text", ""))
        if not text:
            return

        sha = str(p.get("sha256") or hashlib.sha256(text.encode("utf-8")).hexdigest())
        # Deterministic iid space: cmd_<first-16-of-sha>. Not a ULID
        # (that requires time entropy which would break determinism).
        # ULID assignment happens later when events are persisted to
        # Mongo; the shadow observation carries a stable content-key
        # so identical inputs produce identical iids.
        evt_iid = f"evt_shadow_{sha[:16]}"
        cmd_iid = f"cmd_{sha[:16]}"
        proc_iid = f"proc_shadow_{sha[:16]}"

        ts = now_utc()
        prov = Provenance(
            origin="shadow-adapter",
            adapter=f"{self.adapter}@0.2.0-shadow",
            parser="universal-parser@0.0.0-shadow",
            normalization="cem@v1",
            correlation=(),
            evidence_source=(),
            confidence=1.0,
            observed_at=ts,
            ingested_at=ts,
            derived_at=ts,
            engine_versions={
                "adapter": "0.2.0-shadow",
                "cem": "v1",
            },
        )
        yield CanonicalEvent(
            iid=evt_iid,
            case_id=case_id,
            adapter=self.adapter,
            adapter_version="0.2.0-shadow",
            ts=ts,
            sequence=parsed_or_raw.sequence,
            kind="process_create",
            device_iid=None,
            actor_iid=None,
            session_iid=None,
            process_iid=proc_iid,
            artefacts_iids=(cmd_iid,),
            labels=(),
            mitre=(),
            raw={
                "text": text,
                "length": p.get("length", len(text)),
                "sha256": sha,
                "hint_language": p.get("hint_language"),
            },
            trust={"adapter_confidence": 0.75},
            provenance=prov,
        )
