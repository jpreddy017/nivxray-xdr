"""Universal Investigation Engine (UIE) — locked architectural entry point.

Per the 2026-02 operator directive, the Input Understanding Engine
(IUE) has been renamed to the **Universal Investigation Engine (UIE)**
because it is the sole entry point for every investigation, not just
a classifier. The full pipeline it fronts is:

    Paste Input
        │
        ▼
    Identify → Validate → Normalize → Decode (conditional)
        │
        ▼
    Extract → Correlate → Investigate
        │
        ▼
    Generate CIO
        │
        ▼
    Render Workspace / Lab 2 lenses

This module is a thin re-export that preserves backward compatibility
with the older `input_understanding` module — every caller that used
`understand()` still works, and new callers should import
`run_uie` from here.
"""
from nivxforge.investigation.input_understanding import understand, INPUT_TYPES

# Semantic alias — new code should call `run_uie(text)`.
run_uie = understand

__all__ = ["run_uie", "understand", "INPUT_TYPES"]
