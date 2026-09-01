"""Round 37 · Investigation Report package."""
from .service import (
    compose, add_block, edit_block, remove_block,
    suppress_system_block, TechnicalSummaryReadOnly,
    ANALYST_WRITABLE_SECTIONS, SECTIONS, REPORT_BLOCKS_COLL,
)

__all__ = ["compose", "add_block", "edit_block", "remove_block",
              "suppress_system_block", "TechnicalSummaryReadOnly",
              "ANALYST_WRITABLE_SECTIONS", "SECTIONS", "REPORT_BLOCKS_COLL"]
