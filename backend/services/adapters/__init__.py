"""Phase 3 · Evidence Adapter Layer.

Every adapter emits an :class:`~models.iep.IEP` via the common
:class:`~services.adapters.base.EvidenceAdapter` contract.

Adapter roster (built in the frozen 3A → 3B → 3C order):

  3A · Deterministic
    - text  (:class:`TextAdapter`)
    - url   (:class:`URLAdapter`)
    - pdf   (pending)
    - docx  (pending)
  3B · Recursive
    - eml   (pending)
    - zip   (pending)
  3C · Visual
    - image (pending)

See /app/memory/NIVXRAY_ARCHITECTURE_V1.md.
"""
from .base import EvidenceAdapter
from .docx_adapter import DOCXAdapter
from .pdf_adapter  import PDFAdapter
from .text_adapter import TextAdapter
from .url_adapter  import URLAdapter

# Order matters — first adapter whose `can_handle` returns True wins.
# DOCX before PDF (both start with distinctive magic but DOCX's ZIP
# `PK\x03\x04` is generic — verifying `word/document.xml` inside is
# what disambiguates), before raw ZIP, before URL/Text.
REGISTRY = [
    PDFAdapter(),
    DOCXAdapter(),
    URLAdapter(),
    TextAdapter(),
]


def adapt(raw, **ctx):
    """Route ``raw`` through the first adapter that can_handle it and
    return the resulting IEP.  ``ctx`` is forwarded to ``make_iep``
    (``source``, ``parent_iep_id``, ``pipeline_depth``, ``metadata``).
    """
    for a in REGISTRY:
        if a.can_handle(raw):
            return a.make_iep(raw, **ctx)
    # Fallback — everything is text.
    return TextAdapter().make_iep(raw, **ctx)


__all__ = ["EvidenceAdapter", "TextAdapter", "URLAdapter", "PDFAdapter",
              "DOCXAdapter", "REGISTRY", "adapt"]
