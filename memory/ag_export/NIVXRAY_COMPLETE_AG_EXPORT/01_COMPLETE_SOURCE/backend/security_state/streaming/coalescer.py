"""Sliding Window Event Coalescer with Evidence-Driven Critical Milestone Bypass.

Buffers low-salience streaming events to prevent evaluation spam.
Immediately flushes (0ms delay) when an event introduces high-confidence
critical canonical evidence, capability change, or state-machine milestone.
"""
from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from .models import CoalescePolicy


class SlidingWindowCoalescer:
    """Buffers streaming events and flushes based on window, capacity, or security milestones."""

    def __init__(self, policy: Optional[CoalescePolicy] = None) -> None:
        self.policy = policy or CoalescePolicy()
        # Key: (tenant_id, case_id) -> list of (event_item, arrival_timestamp)
        self._buffer: Dict[Tuple[str, str], List[Tuple[Dict[str, Any], float]]] = {}

    def is_critical_security_milestone(self, event_data: Dict[str, Any]) -> Tuple[bool, str]:
        """Assess if an event represents a critical security milestone warranting immediate bypass.

        Driven by canonical evidence and security-state materiality, with ATT&CK
        being one supporting input rather than a hardcoded alert-rule trigger.
        """
        payload = event_data.get("payload", {})
        action = str(event_data.get("action", "")).lower()
        severity = str(event_data.get("severity_hint", "")).lower()

        # 1. Canonical Evidence Materiality / Epistemic Weight
        if event_data.get("is_critical") or payload.get("is_critical"):
            return True, "CRITICAL_EVIDENCE_FLAG"

        if severity in ("critical", "high"):
            return True, f"HIGH_SEVERITY_EVIDENCE ({severity})"

        # 2. Attacker Capability Advancement
        capability = str(payload.get("capability", "") or event_data.get("capability", "")).upper()
        if capability:
            for bypass_cap in self.policy.bypass_capabilities:
                if bypass_cap in capability:
                    return True, f"ATTACKER_CAPABILITY_MILESTONE ({capability})"

        # 3. Canonical Security Actions (State-changing operations)
        for prefix in self.policy.bypass_action_prefixes:
            if action.startswith(prefix) or prefix in action:
                return True, f"STATE_CHANGING_SECURITY_ACTION ({action})"

        # 4. Command Line / Behavior Signatures (e.g. shadow copy deletion, credential extraction)
        cmd = str(payload.get("command_line", "")).lower()
        if any(needle in cmd for needle in (
            "vssadmin delete shadows",
            "wmic shadowcopy delete",
            "sekurlsa::",
            "mimikatz",
            "invoke-mimikatz",
            "lsass.dmp",
            "procdump -ma lsass",
            "safetykatz",
            "rundll32.exe comsvcs.dll",
        )):
            return True, "DESTRUCTIVE_OR_CREDENTIAL_ACCESS_BEHAVIOR"

        # 5. ATT&CK Technique (as a supporting input)
        technique = str(payload.get("technique_id", "") or event_data.get("technique_id", "")).upper()
        if technique:
            for t_prefix in self.policy.bypass_techniques:
                if technique.startswith(t_prefix):
                    return True, f"CRITICAL_TECHNIQUE_CORROBORATION ({technique})"

        return False, "STANDARD_TELEMETRY"

    def push_event(
        self,
        tenant_id: str,
        case_id: str,
        event_data: Dict[str, Any],
    ) -> Tuple[Optional[List[Dict[str, Any]]], bool, str]:
        """Push an event into the coalescer.

        Returns:
            (events_to_evaluate_or_None, is_immediate_bypass, reason)
        """
        now = time.time()
        key = (tenant_id, case_id)

        is_critical, reason = self.is_critical_security_milestone(event_data)

        # IMMEDIATE MILESTONE BYPASS: Flush buffer immediately with zero delay
        if is_critical:
            events_to_flush = []
            if key in self._buffer:
                events_to_flush.extend([item[0] for item in self._buffer[key]])
                del self._buffer[key]
            events_to_flush.append(event_data)
            return events_to_flush, True, reason

        # Normal sliding window buffering
        if key not in self._buffer:
            self._buffer[key] = []

        self._buffer[key].append((event_data, now))
        window_events = self._buffer[key]

        # Check capacity threshold
        if len(window_events) >= self.policy.coalesce_max_events:
            events_to_flush = [item[0] for item in window_events]
            del self._buffer[key]
            return events_to_flush, False, f"MAX_CAPACITY_REACHED ({len(events_to_flush)} events)"

        # Check time window threshold
        oldest_ts = window_events[0][1]
        elapsed_ms = (now - oldest_ts) * 1000.0
        if elapsed_ms >= self.policy.coalesce_window_ms:
            events_to_flush = [item[0] for item in window_events]
            del self._buffer[key]
            return events_to_flush, False, f"WINDOW_ELAPSED ({elapsed_ms:.1f} ms)"

        # Event remains buffered
        return None, False, "BUFFERED"

    def flush_all(self, tenant_id: str, case_id: str) -> List[Dict[str, Any]]:
        """Forcibly flush any pending buffered events for a case."""
        key = (tenant_id, case_id)
        if key in self._buffer:
            events = [item[0] for item in self._buffer[key]]
            del self._buffer[key]
            return events
        return []

    def clear(self) -> None:
        """Clear all buffers."""
        self._buffer.clear()
