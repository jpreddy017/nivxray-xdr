"""Normalizer · Command Line adapter → CEM v1 (Phase 2b + 3f).

Uses `v2.semantic.parser` to produce one or more `CanonicalEvent`s
per command line. Each emission carries deterministic provenance —
rule id, confidence, MITRE techniques — so the same event stream
drives Trajectory, MITRE mapper, reports, and (later) the graph.

Zero RC5 imports. Deterministic sha16 iids.
"""
from __future__ import annotations

import hashlib
from typing import Iterator

from v2.adapters.base import RawEvent
from v2.cem.v1.schema import CanonicalEvent, Provenance, now_utc
from v2.flags import get as get_flag
from v2.semantic import parse_command


class CommandLineNormalizer:
    adapter: str = "command_line"
    cem_version: str = "v1"

    def normalize(self, parsed_or_raw: RawEvent, *, case_id: str) -> Iterator[CanonicalEvent]:
        if not get_flag("ADAPTERS").observable():
            return

        p = parsed_or_raw.payload
        text = str(p.get("text", ""))
        if not text:
            return

        sha = str(p.get("sha256") or hashlib.sha256(text.encode("utf-8")).hexdigest())
        ts = now_utc()

        evidences = parse_command(text)
        if not evidences:
            evidences = [_fallback_process_create(text)]

        for idx, ev in enumerate(evidences):
            emission_key = f"{sha}|{ev.rule_id}|{ev.event_kind}|{ev.target}"
            emit_sha = hashlib.sha256(emission_key.encode()).hexdigest()[:16]
            evt_iid  = f"evt_shadow_{emit_sha}"
            proc_iid = f"proc_shadow_{emit_sha}"
            artefact_iid = _artefact_iid_for(ev.event_kind, emit_sha)

            prov = Provenance(
                origin="shadow-adapter",
                adapter=f"{self.adapter}@0.3.0-shadow",
                parser="command-line-semantic@1.0.0",
                normalization="cem@v1",
                correlation=(ev.rule_id,),
                evidence_source=(sha,),
                confidence={"high": 1.0, "medium": 0.75, "low": 0.5}.get(ev.confidence, 0.5),
                observed_at=ts,
                ingested_at=ts,
                derived_at=ts,
                engine_versions={"adapter": "0.3.0-shadow", "cem": "v1",
                                 "semantic": "1.0.0"},
            )
            yield CanonicalEvent(
                iid=evt_iid,
                case_id=case_id,
                adapter=self.adapter,
                adapter_version="0.3.0-shadow",
                ts=ts,
                sequence=parsed_or_raw.sequence + idx,
                kind=ev.event_kind,
                device_iid=None,
                actor_iid=None,
                session_iid=None,
                process_iid=proc_iid,
                artefacts_iids=(artefact_iid,) if artefact_iid else (),
                labels=(ev.confidence, ev.action),
                mitre=ev.mitre,
                raw={
                    "text": text,
                    "length": p.get("length", len(text)),
                    "sha256": sha,
                    "rule_id": ev.rule_id,
                    "rule_label": ev.label,
                    "action": ev.action,
                    "entity": ev.entity,
                    "target": ev.target,
                    "confidence": ev.confidence,
                    "matched_span": ev.matched_span,
                    "source": ev.source,
                },
                trust={"adapter_confidence": 0.75, "rule_confidence": ev.confidence},
                provenance=prov,
            )


def _artefact_iid_for(kind: str, sha16: str) -> str | None:
    if kind.startswith("file"):     return f"file_{sha16}"
    if kind.startswith("registry"): return f"reg_{sha16}"
    if kind.startswith("network"):  return f"net_{sha16}"
    if kind == "service_install":   return f"svc_{sha16}"
    if kind == "cloud_iam_action":  return f"iam_{sha16}"
    if kind == "memory_alloc":      return f"mem_{sha16}"
    if kind == "kernel_event":      return f"cmd_{sha16}"
    return None


def _fallback_process_create(text: str):
    from v2.semantic.parser import Evidence
    return Evidence(
        rule_id="BASE-000",
        event_kind="process_create",
        action="executed",
        target=text[:80],
        entity=(text.split()[0] if text.split() else "process"),
        confidence="low",
        mitre=(),
        source="fallback",
        matched_span=text[:200],
        label="unclassified command",
    )
