"""IUE intake router (STEP 3 §2.1 · STEP 4 §1.1 step 3).

**Single feature-flag read site** for `IUE_STRUCTURED_LANE`.  All other
IUE modules trust the intake decision — they never re-read the flag.

Wraps two existing classifiers:
  - services.ida.input_classifier.classify_artifact_input  (URL / file / ruleset)
  - services.die.input_understanding.classify              (21 IUE input types)

Precedence: `ida_class` wins for lane ∈ {url, file}; `iue_type` wins for
lane ∈ {structured, raw_text}.  No new classifier logic here.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field, asdict
from typing import List, Optional

from .failure import IUEFailure
from .tenancy import resolve_tenant, PREV_PUBLIC_TENANT


_STRUCTURED_KINDS = frozenset({
    "raw_json", "ndjson", "csv", "xml", "edr_report", "xdr_report",
    "siem_export", "cloud_log", "network_log", "security_alert",
})

_URL_LANE_IDA_CLASSES = frozenset({
    "threat_report_url", "code_snippet_url", "repository_url",
    "file_resource_url", "ioc_portal_url", "atomic_ioc_url",
})

_FILE_LANE_IDA_CLASSES = frozenset({
    "mixed_artifacts", "yara_ruleset", "sigma_ruleset",
})


@dataclass(frozen=True)
class IntakeDecision:
    kind: str
    lane: str                       # url | file | structured | raw_text
    confidence: float
    reasons: List[str]
    ida_class: Optional[str]
    iue_type: Optional[str]
    input_id: str
    tenant_id: str
    parent_input_id: Optional[str] = None
    discovery_depth: int = 0
    flag_state: str = "off"         # 'off' | 'on'

    def to_dict(self) -> dict:
        return asdict(self)


def _hash_input(payload) -> str:
    if isinstance(payload, str):
        b = payload.encode("utf-8", errors="ignore")
    elif isinstance(payload, bytes):
        b = payload
    else:
        b = repr(payload).encode()
    return hashlib.sha256(b).hexdigest()[:16]


def _flag_state() -> str:
    return "on" if os.environ.get("IUE_STRUCTURED_LANE", "off").lower() == "on" else "off"


def _detect_structured_kind(payload) -> Optional[str]:
    """Cheapest possible structured-kind sniff — used only when the flag
    is on.  Bytes → mime hint.  Text falls back to `unknown`."""
    if isinstance(payload, bytes):
        head = payload.lstrip()[:1]
        if head in (b"{", b"["):
            # decide JSON vs NDJSON by presence of newline-delimited objects
            if b"\n{" in payload[:4096] or b"\n[" in payload[:4096]:
                return "ndjson"
            return "raw_json"
        if head == b"<":
            return "xml"
        if b"," in payload[:512] and b"\n" in payload[:512]:
            return "csv"
    return None


def intake(payload,
            *,
            session_ctx: Optional[dict] = None,
            parent_input_id: Optional[str] = None,
            tenant_id: Optional[str] = None,
            discovery_depth: int = 0,
            allow_prev_fallback: bool = True):
    """Return an ``IntakeDecision`` or an ``IUEFailure``.

    Zero side effects.  Zero network I/O.  Zero content transformation."""
    reasons: List[str] = []
    input_id = _hash_input(payload)
    tenant = tenant_id or resolve_tenant(
        session_ctx, allow_prev_fallback=allow_prev_fallback)
    if not tenant:
        return IUEFailure(
            status="terminal", stage="intake",
            error_code="tenant_context_missing",
            message="Prod-mode requires a tenant_id",
            recoverable=False,
            input_id=input_id, tenant_id="",
        )

    flag = _flag_state()

    # Delegate to existing classifiers.
    ida_class: Optional[str] = None
    iue_type: Optional[str] = None

    if isinstance(payload, str):
        try:
            from services.ida.input_classifier import classify_artifact_input
            ida_res = classify_artifact_input(payload) or {}
            ida_class = ida_res.get("ida_class")
            if ida_class:
                reasons.append(f"ida:{ida_class}")
        except Exception as e:
            reasons.append(f"ida_error:{type(e).__name__}")

        try:
            from services.die.input_understanding import classify
            iue_res = classify(payload)
            # classify returns tuple (kind, label, confidence, reasons)
            if isinstance(iue_res, tuple) and iue_res:
                iue_type = iue_res[0]
                reasons.append(f"iue:{iue_type}")
        except Exception as e:
            reasons.append(f"iue_error:{type(e).__name__}")

    # Lane selection — precedence documented in STEP 3 §2.1.
    lane = "raw_text"
    kind = iue_type or "unknown"

    if ida_class in _URL_LANE_IDA_CLASSES:
        lane, kind = "url", ida_class
    elif ida_class in _FILE_LANE_IDA_CLASSES:
        lane, kind = "file", ida_class
    else:
        # Structured lane sniff only when flag is on.  When off we
        # demote to raw_text so production traffic is bit-identical.
        if flag == "on":
            sniffed = _detect_structured_kind(
                payload if isinstance(payload, bytes) else
                (payload or "").encode("utf-8", errors="ignore"))
            if sniffed in _STRUCTURED_KINDS:
                lane, kind = "structured", sniffed
                reasons.append(f"sniff:{sniffed}")
        else:
            reasons.append("structured_lane_disabled")

    return IntakeDecision(
        kind=kind,
        lane=lane,
        confidence=0.9 if ida_class else 0.5,
        reasons=reasons,
        ida_class=ida_class,
        iue_type=iue_type,
        input_id=input_id,
        tenant_id=tenant,
        parent_input_id=parent_input_id,
        discovery_depth=discovery_depth,
        flag_state=flag,
    )
