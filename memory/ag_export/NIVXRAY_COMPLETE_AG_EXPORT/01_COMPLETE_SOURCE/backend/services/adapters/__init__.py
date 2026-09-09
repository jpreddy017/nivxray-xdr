"""Phase 3 · Evidence Adapter Layer.

Every adapter emits an :class:`~models.iep.IEP` via the common
:class:`~services.adapters.base.EvidenceAdapter` contract.

Adapter roster (built in the frozen 3A → 3B → 3C order):

  3A · Deterministic
    - text  (:class:`TextAdapter`)
    - url   (:class:`URLAdapter`)
    - pdf   (:class:`PDFAdapter`)
    - docx  (:class:`DOCXAdapter`)
  3B · Recursive
    - eml   (:class:`EMLAdapter`)
    - zip   (:class:`ZIPAdapter`)
  3C · Visual
    - image (:class:`ImageAdapter`)

See /app/memory/NIVXRAY_ARCHITECTURE_V1.md.
"""
from .base import EvidenceAdapter
from .docx_adapter  import DOCXAdapter
from .eml_adapter   import EMLAdapter
from .image_adapter import ImageAdapter
from .pdf_adapter   import PDFAdapter
from .text_adapter  import TextAdapter
from .url_adapter   import URLAdapter
from .zip_adapter   import ZIPAdapter

# Order matters — first adapter whose `can_handle` returns True wins.
# ZIP is placed before PDF/DOCX because DOCX is itself a ZIP; the
# DOCXAdapter's can_handle looks for the OOXML content-type marker
# inside the archive, so it must run first for .docx.  ZIP catches
# every OTHER ZIP-shaped input.
REGISTRY = [
    DOCXAdapter(),
    ZIPAdapter(),
    PDFAdapter(),
    ImageAdapter(),
    EMLAdapter(),
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
              "DOCXAdapter", "EMLAdapter", "ZIPAdapter", "ImageAdapter",
              "REGISTRY", "adapt"]
