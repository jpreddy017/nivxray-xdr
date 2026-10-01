"""
DIE · Preprocessor (Structured Input Understanding)
───────────────────────────────────────────────────
Owner-locked 2026-02-28 · P0 architectural fix.

Deterministic upstream layer that decomposes any analyst paste
(Talos IR / Mandiant / CrowdStrike / Microsoft Defender / SecureX /
SOC notes / mixed markdown) into structured artifacts BEFORE the
frozen v1.1 DIE / DKP / Attack-Story core touches it.

Pipeline (strict, ordered):

    Raw Input
        ↓
    Input Normalizer          (unicode quotes, wrap, markdown, bullets)
        ↓
    Artifact Extractor        (commands · exes · registry · paths · URLs · IPs · hashes · services · env vars · UNC)
        ↓
    Artifact Classifier       (assigns type / subtype)
        ↓
    Artifact Router           (routes each artifact to its analyzer)
        ↓
    Command Normalizer        (lossless join of comma-split / wrapped tokens)
        ↓
    Family Recognizer         (option-pattern → sync/rclone, reverse-ssh …)
        ↓
    Stage Builder             (one stage per command / family / registry …)
        ↓
    Process Relationship      (inferred edges w/ evidence + confidence)

The output — a ``PreprocessResult`` — becomes the SSOT for the
downstream DIE / DKP / Attack Story / Narrative / Confidence /
Report / IDA / IVE consumers.  The frozen v1.1 core does not change.
"""
from .pipeline import preprocess, PreprocessResult
from .models import Artifact, Stage, ProcessEdge

__all__ = [
    "preprocess",
    "PreprocessResult",
    "Artifact",
    "Stage",
    "ProcessEdge",
]
