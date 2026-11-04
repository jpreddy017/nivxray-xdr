"""
NivXRay XDR — Unified Translation Manager.
Routes incoming detection query text to format-specific translators,
computes fidelity metrics, and prevents silent weakening.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .base import BaseTranslator, TranslationResult
from .sigma_translator import SigmaTranslator
from .spl_translator import SPLTranslator
from .kql_translator import KQLTranslator
from .eql_translator import EQLTranslator
from .yara_translator import YaraTranslator
from .ioc_translator import IOCTranslator
from .behavioral_translator import BehavioralTranslator
from .correlation_translator import CorrelationTranslator
from .hunting_translator import ThreatHuntingTranslator
from .anomaly_translator import AnomalyTranslator
from .mapping_translator import MappingTranslator
from ..canonical_ir.models import TranslationFidelity


class TranslationManager:
    def __init__(self):
        self._translators: Dict[str, BaseTranslator] = {
            "sigma": SigmaTranslator(),
            "spl": SPLTranslator(),
            "kql": KQLTranslator(),
            "eql": EQLTranslator(),
            "yara": YaraTranslator(),
            "ioc": IOCTranslator(),
            "ioc_rule": IOCTranslator(),
            "behavioral": BehavioralTranslator(),
            "correlation": CorrelationTranslator(),
            "hunting": ThreatHuntingTranslator(),
            "threat_hunting": ThreatHuntingTranslator(),
            "anomaly": AnomalyTranslator(),
            "baseline_anomaly": AnomalyTranslator(),
            "attck_mapping": MappingTranslator("attck_mapping"),
            "security_state_mapping": MappingTranslator("security_state_mapping"),
            "response_mapping": MappingTranslator("response_mapping"),
            "ot_ics": MappingTranslator("ot_ics"),
            "rmm_dual_use": MappingTranslator("security_state_mapping"),
            "adversarial_simulation": CorrelationTranslator(),
        }
        self._stats: Dict[str, int] = {
            "total": 0,
            "exact": 0,
            "strong": 0,
            "partial": 0,
            "unsupported": 0,
        }

    def detect_format(self, text: str) -> str:
        s = text.strip()
        if re.search(r'\brule\s+[A-Za-z0-9_]+\s*(?::[^{]+)?\s*\{', s) and "condition:" in s:
            return "yara"
        if "detection:" in s and ("logsource:" in s or "condition:" in s):
            return "sigma"
        if s.lower().startswith("sequence") or re.search(r'\b(process|network|file|registry)\s+where\b', s, re.I):
            return "eql"
        if any(table in s for table in ("DeviceProcessEvents", "DeviceNetworkEvents", "DeviceLogonEvents", "IdentityLogonEvents")) or " =~ " in s or " has " in s:
            return "kql"
        if s.lower().startswith("search") or "index=" in s or "sourcetype=" in s or "| where " in s or "| stats " in s:
            return "spl"
        if '"type":' in s and ('"indicator":' in s or '"value":' in s):
            return "ioc"
        if '"scenario_id":' in s or '"stages":' in s:
            return "correlation"
        if '"parent_process":' in s:
            return "behavioral"
        if '"hypothesis":' in s:
            return "hunting"
        if '"metric":' in s and '"threshold":' in s:
            return "anomaly"
        if '"mapping_kind":' in s:
            return "attck_mapping"
        return "unknown"

    def translate(
        self,
        source_text: str,
        format_hint: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> TranslationResult:
        # Handle case where caller passed (format, query) instead of (query, format)
        if source_text.lower() in self._translators and format_hint is not None:
            source_text, format_hint = format_hint, source_text.lower()

        fmt = (format_hint or self.detect_format(source_text)).lower()
        translator = self._translators.get(fmt)

        if not translator:
            return TranslationResult(
                success=False,
                fidelity=TranslationFidelity.UNSUPPORTED,
                errors=[f"Unsupported or unrecognized query format: '{fmt}'"],
                raw_source=source_text,
            )

        res = translator.translate(source_text, metadata)

        # Update stats
        self._stats["total"] += 1
        if res.fidelity == TranslationFidelity.EXACT:
            self._stats["exact"] += 1
        elif res.fidelity == TranslationFidelity.STRONG:
            self._stats["strong"] += 1
        elif res.fidelity == TranslationFidelity.PARTIAL:
            self._stats["partial"] += 1
        else:
            self._stats["unsupported"] += 1

        return res

    def get_stats(self) -> Dict[str, Any]:
        return dict(self._stats)


TRANSLATION_MANAGER = TranslationManager()
