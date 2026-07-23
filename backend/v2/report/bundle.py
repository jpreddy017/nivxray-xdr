"""v2/report/bundle.py · Evidence Package export.

Zips together every deterministic artefact for a case:
    report.json         · canonical envelope
    report.md           · human-readable Markdown
    report.pdf          · pixel-stable PDF
    bundle.stix.json    · STIX 2.1 bundle
    manifest.json       · SHA-256 of every artefact + generator metadata

The zip stream itself is written with fixed 1980-01-01 timestamps so two
runs on identical inputs produce byte-identical zip bytes.
"""
from __future__ import annotations
import hashlib
import io
import json
import zipfile
from .schema import ReportEnvelope
from .markdown import render_markdown
from .pdf import render_pdf
from .stix import render_stix_bytes

# ZipInfo `date_time` = (1980, 1, 1, 0, 0, 0) — earliest allowed value.
_FIXED_TIME = (1980, 1, 1, 0, 0, 0)


def _add(zf: zipfile.ZipFile, name: str, data: bytes) -> str:
    info = zipfile.ZipInfo(filename=name, date_time=_FIXED_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    zf.writestr(info, data)
    return hashlib.sha256(data).hexdigest()


def render_bundle(env: ReportEnvelope) -> bytes:
    """Return the evidence-package zip as bytes."""
    json_bytes = json.dumps(env.model_dump(), sort_keys=True, separators=(",", ":")).encode()
    md_bytes   = render_markdown(env).encode()
    pdf_bytes  = render_pdf(env)
    stix_bytes = render_stix_bytes(env)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        sha_json = _add(zf, "report.json",      json_bytes)
        sha_md   = _add(zf, "report.md",        md_bytes)
        sha_pdf  = _add(zf, "report.pdf",       pdf_bytes)
        sha_stix = _add(zf, "bundle.stix.json", stix_bytes)
        manifest = {
            "case_id": env.case_id,
            "schema_version": env.schema_version,
            "generated_at": env.generated_at,
            "generator": env.generator,
            "generator_version": env.generator_version,
            "envelope_signature": env.signature,
            "artefacts": {
                "report.json":       {"sha256": sha_json, "bytes": len(json_bytes)},
                "report.md":         {"sha256": sha_md,   "bytes": len(md_bytes)},
                "report.pdf":        {"sha256": sha_pdf,  "bytes": len(pdf_bytes)},
                "bundle.stix.json":  {"sha256": sha_stix, "bytes": len(stix_bytes)},
            },
        }
        _add(zf, "manifest.json",
             json.dumps(manifest, sort_keys=True, indent=2).encode())
    return buf.getvalue()
