"""NivXRay — Pydantic request/response schemas.

Extracted from server.py during the Feb-2026 modularization refactor.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, EmailStr, Field


# --- Auth ---------------------------------------------------------------- #
class LoginIn(BaseModel):
    email: EmailStr
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    email: str


# --- Recipes / Ops ------------------------------------------------------- #
class RecipeStep(BaseModel):
    op: str
    args: Dict[str, Any] = Field(default_factory=dict)


class RunRecipeIn(BaseModel):
    input: str
    steps: List[RecipeStep] = Field(default_factory=list)


class RunRecipeOut(BaseModel):
    output: str
    steps_output: List[Dict[str, Any]] = Field(default_factory=list)
    detected_type: Optional[Dict[str, str]] = None
    errors: List[Dict[str, str]] = Field(default_factory=list)


class AutoIn(BaseModel):
    input: str
    disable_boost: bool = Field(False, description="Skip Learning-Feedback boost even if enabled")
    # Feb-2026: SOC-grade Corrupted-Container recovery mode.
    #   strict       — deterministic mode. Fail CRC/ISIZE → return Corrupted verdict; salvage
    #                  is stored on `corrupted_container.salvaged` for reference only.
    #   best_effort  — retain the salvaged plaintext as the primary output with a clear
    #                  ⚠ Integrity Warning. Verdict downgrades to Suspicious (not Corrupted).
    mode: str = Field("strict", description="strict | best_effort")


class MagicIn(BaseModel):
    input: str
    max_depth: int = 4
    max_branches: int = 3
    top_n: int = 3


class ShellcodeIn(BaseModel):
    input: str = Field(..., description="Hex, base64, or raw bytes to analyse")
    arch: Optional[str] = Field(None, description="Arch hint: x86 / x86_64 / arm / arm64 / thumb")
    max_insns: int = 300


class CommandAnalyzeIn(BaseModel):
    input: str = Field(..., description="Raw command line to semantically analyse")
    force_decode_span: Optional[str] = Field(
        None, description="If the previous /analyze/command call returned "
                          "needs_choice=true, resubmit with the chosen span here."
    )


# --- Analyze / Report --------------------------------------------------- #
class AnalyzeIn(BaseModel):
    input: str
    output: Optional[str] = None
    use_ai_verdict: bool = False
    enrich_osint: bool = True
    describe: bool = False
    persona_id: Optional[str] = None
    provider_id: Optional[str] = None


class TroubleshootIn(BaseModel):
    input: str
    steps: List[RecipeStep] = Field(default_factory=list)
    error: Optional[str] = None


class ShareIn(BaseModel):
    input: str
    steps: List[RecipeStep] = Field(default_factory=list)


class PlaybookFeedbackIn(BaseModel):
    vote: str = Field(..., description="'up', 'down' or 'none' (to retract)")
    reason: Optional[str] = None


# --- Admin --------------------------------------------------------------- #
class SettingsUpdateIn(BaseModel):
    keys: Dict[str, str] = Field(default_factory=dict)  # {service_id: api_key}


class ModelIn(BaseModel):
    kind: str
    name: str
    enabled: bool = True
    config: Dict[str, Any] = Field(default_factory=dict)


class ModelPatchIn(BaseModel):
    name: Optional[str] = None
    enabled: Optional[bool] = None
    config: Optional[Dict[str, Any]] = None


class ModelTestIn(BaseModel):
    sample: str


# --- Sample Library ------------------------------------------------------ #
class SampleIn(BaseModel):
    name: str
    raw_input: str
    expected_output: str
    categories: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    expected_mitre: Optional[List[str]] = None
    expected_iocs: Optional[List[str]] = None
    difficulty: Optional[str] = "medium"
    source_url: Optional[str] = None
    notes: Optional[str] = None


class SamplePatchIn(BaseModel):
    name: Optional[str] = None
    raw_input: Optional[str] = None
    expected_output: Optional[str] = None
    categories: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    expected_mitre: Optional[List[str]] = None
    expected_iocs: Optional[List[str]] = None
    difficulty: Optional[str] = None
    source_url: Optional[str] = None
    notes: Optional[str] = None


class SampleBulkIn(BaseModel):
    samples: List[SampleIn]
