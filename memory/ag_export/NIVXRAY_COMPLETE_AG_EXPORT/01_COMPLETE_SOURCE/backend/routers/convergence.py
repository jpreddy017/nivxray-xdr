"""
Convergence Certificate API · M7.

Exposes the Convergence Engine's machine-readable certificate as a
first-class analyst-audit surface. This is the emission surface the
owner asked for: iterations, passes, evidence, fingerprints, hashes,
canonical state — all in a single deterministic response.

Endpoints
---------

* ``POST /api/decode/certificate``
    Body: ``{"input": "<payload>"}``
    Returns the Convergence Certificate + human trace regardless of
    whether the engine ultimately reached canonical state. This is
    the audit endpoint: every response is deterministic and its
    fingerprint is hash-stable across identical inputs.

The endpoint is INTENTIONALLY thin — no IOC extraction, no MITRE
enrichment, no legacy pipeline. Callers wanting the full analyst
report should hit ``/api/decode/smart`` (which also carries the
certificate when the engine wins).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from routers.auth import get_current_user
from workspace.convergence import Artifact, converge
from workspace.convergence.selector import human_trace


router = APIRouter()


class CertificateIn(BaseModel):
    input: str = Field(..., description="Payload to run through the Convergence Engine.")


@router.post("/decode/certificate")
async def decode_certificate(body: CertificateIn, user=Depends(get_current_user)):
    """Run the Convergence Engine and emit the machine-readable
    certificate plus a human-readable trace.

    The response has this shape (deterministic + hash-stable)::

        {
          "engine":               "convergence",
          "input_hash":           "<sha256 of input>",
          "output":               "<final canonical artifact>",
          "canonical":            true | false,
          "terminated_reason":    "canonical_state" | "max_depth" | "interpreter_drift",
          "iterations_executed":  <int>,
          "convergence_certificate": { ... },  # full JSON certificate
          "certificate_fingerprint": "<sha256>",
          "human_trace":          "<multi-line analyst summary>",
          "iterations_detail": [
            { "iteration": 1, "passes": [ ... ] },
            ...
          ]
        }
    """
    payload = body.input or ""
    art = Artifact.from_input(payload)
    result = converge(art)
    return {
        "engine": "convergence",
        "input_hash": art.content_hash,
        "output": result.final_artifact.content,
        "canonical": result.canonical,
        "terminated_reason": result.terminated_reason,
        "iterations_executed": result.certificate.iterations_executed,
        "convergence_certificate": result.certificate.to_dict(),
        "certificate_fingerprint": result.certificate.fingerprint,
        "human_trace": human_trace(result),
        "iterations_detail": [it.to_dict() for it in result.iterations],
    }
