"""FamilyPlugin — shared base for RC2.1a malware family intelligence plugins.

Contract
--------
Subclasses declare:
    id             plugin id (e.g. "family-asyncrat")
    name           display name
    family_name    canonical family label (e.g. "AsyncRAT")
    aka            alternate names (e.g. ["AsyncRAT.NET"])
    signatures     tuple of `Signature` (pattern, weight, kind, description)
    calibration    sum-of-weights that maps to confidence == 1.0
    mitre          tuple of `MitreHint` — canonical for this family
    yara_seed_names YARA rule seed name (e.g. "APT_Meterpreter_Payload")
    atomic_red     optional ART test id (e.g. "T1055.012#T1055.012-1")

Behaviour
---------
- `detect()` runs the signature scan (cheap regex OR).  If total weight >= 0.15
  the plugin claims the payload with `confidence == 0.10 + (weight/cal * 0.15)`
  so the orchestrator will invoke `decode()` (which produces the definitive
  family hint).
- `decode()` computes final confidence = `min(1.0, total_weight / calibration)`,
  emits a `FamilyHint` populated with evidence_items, mitre_techniques,
  yara_suggestion (auto-derived from matched signatures) and (when set)
  atomic_red_hint.  `output` is unchanged.
- The plugin runs on any layer (family plugins register in the normal
  DecoderRegistry).  When the shellcode or config-block bytes appear at some
  intermediate layer, the plugin fires there; the orchestrator's
  `family-identified` terminal check picks it up on the next iteration.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from engine.decoder_base import BaseDecoder
from engine.models import (
    AnalysisContext,
    DetectResult,
    EvidenceItem,
    FamilyHint,
    Fingerprint,
    MitreHint,
    PluginResult,
    YaraRuleStub,
)


@dataclass(frozen=True)
class Signature:
    pattern: str       # regex source string; matched with re.IGNORECASE + re.DOTALL
    weight: float      # 0.0-1.0 contribution to confidence
    kind: str = "regex"   # "regex" | "string" | "bytes" | "opcode"
    description: str = ""

    def compile(self) -> re.Pattern:
        return re.compile(self.pattern.encode("latin-1"),
                          re.IGNORECASE | re.DOTALL)


class FamilyPlugin(BaseDecoder):
    """Base class — subclasses only declare data, no logic to override."""

    category = "intelligence"
    cost = 2
    tags: Tuple[str, ...] = ("family", "intelligence")
    schema_version = "1.0"

    # ---- Subclass fills these -------------------------------------------
    family_name: str = "unknown"
    aka: Tuple[str, ...] = ()
    signatures: Tuple[Signature, ...] = ()
    calibration: float = 1.0
    mitre: Tuple[MitreHint, ...] = ()
    yara_seed_name: str = "NivX_Family_Rule"
    atomic_red: str = ""

    # ---- Internal: compile signature patterns once ----------------------
    _compiled: List[Tuple[Signature, re.Pattern]] | None = None

    def _get_compiled(self) -> List[Tuple[Signature, re.Pattern]]:
        if self._compiled is None:
            self._compiled = [(s, s.compile()) for s in self.signatures]
        return self._compiled

    # ---- Signature scan --------------------------------------------------
    def _scan(self, payload: str) -> Tuple[List[EvidenceItem], float]:
        b = payload.encode("latin-1", errors="replace")
        evidence: List[EvidenceItem] = []
        total_weight = 0.0
        for sig, rx in self._get_compiled():
            m = rx.search(b)
            if not m:
                continue
            hit_pattern = (sig.description
                           or f"{sig.kind}: {sig.pattern[:64]}")
            location = f"offset=0x{m.start():x}"
            evidence.append(EvidenceItem(
                type=sig.kind,
                pattern=hit_pattern,
                location=location,
                weight=sig.weight,
            ))
            total_weight += sig.weight
        return evidence, total_weight

    # ---- detect() --------------------------------------------------------
    def detect(self, payload: str, fingerprint: Fingerprint,
               ctx: AnalysisContext) -> DetectResult:
        # Cheap cutoff — the smallest signature is usually >= 3 bytes
        if len(payload) < 8:
            return DetectResult(confidence=0.0, why="too short for family scan")
        _, w = self._scan(payload)
        if w < 0.15:
            return DetectResult(confidence=0.0,
                                why=f"no {self.family_name} signatures matched")
        # Emit a real detect confidence so the orchestrator considers us
        conf = min(0.95, 0.10 + (w / max(self.calibration, 0.01)) * 0.15)
        return DetectResult(
            confidence=conf,
            why=(f"{self.family_name} signature scan matched "
                 f"weight={w:.2f} / cal={self.calibration}"),
            args={"scan_weight": w},
        )

    # ---- decode() --------------------------------------------------------
    def decode(self, payload: str, args: Dict[str, Any],
               ctx: AnalysisContext) -> PluginResult:
        evidence, total = self._scan(payload)
        if not evidence:
            return PluginResult(output=payload)
        confidence = min(1.0, total / max(self.calibration, 0.01))
        matched_patterns = sorted(
            {e.pattern for e in evidence},
            key=lambda p: -next(e.weight for e in evidence if e.pattern == p),
        )
        yara = YaraRuleStub(
            name=self.yara_seed_name,
            strings=[f'$s{i} = /{sig.pattern}/ nocase' for i, sig in
                     enumerate([s for s, _ in self._get_compiled()
                                if any(e.pattern in (s.description or "")
                                       or e.pattern.endswith(s.pattern[:16])
                                       for e in evidence)][:6])],
            condition="2 of them",
            tags=[self.family_name.lower().replace("/", "_")
                  .replace(" ", "_"), "nivxray-auto"],
        )
        fam_hint = FamilyHint(
            family=self.family_name,
            confidence=confidence,
            evidence=(f"{len(evidence)} signature(s) matched "
                      f"(weight {total:.2f}/{self.calibration})"),
            aka=list(self.aka),
            evidence_items=evidence,
            mitre_techniques=list(self.mitre),
            yara_suggestion=yara,
            atomic_red_hint=self.atomic_red or None,
        )
        # Emit the same MITRE hints via mitre_hints too so they flow through
        # the trace aggregator into `findings.mitre_techniques`
        mitre_hints = [
            MitreHint(id=m.id, technique=m.technique, tactic=m.tactic,
                      evidence=f"{self.family_name} family match",
                      source="family")
            for m in self.mitre
        ]
        return PluginResult(
            output=payload,               # non-transforming
            family_hints=[fam_hint],
            mitre_hints=mitre_hints,
            notes=[f"family={self.family_name}",
                   f"confidence={confidence:.2f}",
                   f"matched={len(evidence)}"],
            explanation=(f"Identified {self.family_name} via {len(evidence)} "
                         f"signature match(es); confidence "
                         f"{confidence * 100:.0f}%."),
        )

    def explain(self, result: PluginResult) -> str:
        return result.explanation
