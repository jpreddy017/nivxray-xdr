"""
Universal Input Layer (UIL) · 2026-03-02
─────────────────────────────────────────
The Workspace's smart front door.  Sits BEFORE the existing
IDA → DIE → ICE → IOC pipeline and never touches its internals.

Architectural rule (locked):
    The Workspace must never contain file-type-specific logic.
    Every input flows through the UIL first.

Public entry points:

    classify(payload, filename) → InputKind
    normalize(payload, kind)    → NormalizedInput (text + metadata)
    split_mixed(text)           → List[TypedFragment]

The router (routers/uil.py) exposes POST /api/uil/investigate which
accepts multipart uploads OR text, runs classify → normalize → split,
then delegates to the existing session pipeline unchanged.
"""
from .classifier   import classify, InputKind, KIND_LABEL      # noqa: F401
from .preprocess   import normalize, NormalizedInput           # noqa: F401
from .mixed        import split_mixed, TypedFragment           # noqa: F401
