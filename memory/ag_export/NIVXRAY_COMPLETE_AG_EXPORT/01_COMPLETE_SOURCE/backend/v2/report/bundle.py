"""v2/report/bundle.py · Evidence Package export.

Zips together every deterministic artefact for a case:
    report.json         · canonical envelope
    report.md           · human-readable Markdown
    report.pdf          · pixel-stable PDF
    bundle.stix.json    · STIX 2.1 bundle
    manifest.json       · SHA-256 + HMAC-SHA256 signature per artefact

Chain-of-custody:
- Every artefact carries a `sha256` (content hash) AND an `hmac_sha256`
  signature made with `NIVXRAY_SIGNING_SECRET` (env). Anyone with the same
  secret can re-verify the bundle after redistribution.
- Manifest is itself signed with the same key so it cannot be tampered
  with in transit.
- Zip timestamps fixed to 1980-01-01 so identical inputs produce
  byte-identical zip output.
"""
from __future__ import annotations
import hashlib
import hmac
import io
import json
import os
import zipfile
from .schema import ReportEnvelope
from .markdown import render_markdown
from .pdf import render_pdf
from .stix import render_stix_bytes

_FIXED_TIME = (1980, 1, 1, 0, 0, 0)


def _signing_secret(case_id: str) -> bytes:
    """Return the HMAC key.

    Priority:
    1. `NIVXRAY_SIGNING_SECRET` env var (production / operator-controlled).
    2. Deterministic fallback derived from a fixed installation salt +
       the case_id so demos still emit stable signatures without leaking
       any real secret.
    """
    env = os.environ.get("NIVXRAY_SIGNING_SECRET")
    if env:
        return env.encode()
    salt = os.environ.get("NIVXRAY_INSTANCE_ID", "nivxray-default-instance")
    return hashlib.sha256(f"{salt}:{case_id}".encode()).digest()


def _key_id(secret: bytes) -> str:
    """Short public fingerprint of the signing key — first 12 hex of sha256."""
    return hashlib.sha256(secret).hexdigest()[:12]


def _sign(secret: bytes, data: bytes) -> str:
    return hmac.new(secret, data, hashlib.sha256).hexdigest()


def _add(zf: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(filename=name, date_time=_FIXED_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    zf.writestr(info, data)


def render_bundle(env: ReportEnvelope) -> bytes:
    """Return the signed evidence-package zip as bytes."""
    secret = _signing_secret(env.case_id)
    key_id = _key_id(secret)

    json_bytes = json.dumps(env.model_dump(), sort_keys=True, separators=(",", ":")).encode()
    md_bytes   = render_markdown(env).encode()
    pdf_bytes  = render_pdf(env)
    stix_bytes = render_stix_bytes(env)

    def entry(b: bytes) -> dict:
        return {
            "bytes":       len(b),
            "sha256":      hashlib.sha256(b).hexdigest(),
            "hmac_sha256": _sign(secret, b),
        }

    artefacts = {
        "report.json":       entry(json_bytes),
        "report.md":         entry(md_bytes),
        "report.pdf":        entry(pdf_bytes),
        "bundle.stix.json":  entry(stix_bytes),
    }

    manifest_body = {
        "case_id": env.case_id,
        "schema_version": env.schema_version,
        "generated_at": env.generated_at,
        "generator": env.generator,
        "generator_version": env.generator_version,
        "envelope_signature": env.signature,
        "signature": {
            "algorithm": "HMAC-SHA256",
            "key_id":    key_id,
            "hint":      "verify with NIVXRAY_SIGNING_SECRET; see README",
        },
        "artefacts": artefacts,
    }
    manifest_bytes = json.dumps(manifest_body, sort_keys=True,
                                separators=(",", ":")).encode()
    # Sign the manifest itself so a tampered manifest can be detected too.
    manifest_signed = {
        **manifest_body,
        "manifest_hmac_sha256": _sign(secret, manifest_bytes),
    }
    manifest_pretty = json.dumps(manifest_signed, sort_keys=True, indent=2).encode()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        _add(zf, "report.json",      json_bytes)
        _add(zf, "report.md",        md_bytes)
        _add(zf, "report.pdf",       pdf_bytes)
        _add(zf, "bundle.stix.json", stix_bytes)
        _add(zf, "manifest.json",    manifest_pretty)
    return buf.getvalue()
