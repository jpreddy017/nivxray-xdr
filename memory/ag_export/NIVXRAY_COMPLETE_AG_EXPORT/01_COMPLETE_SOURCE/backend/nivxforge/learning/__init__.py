"""NivXRay Learning Engine — one reusable service every composer queries
for analyst-derived knowledge that applies to the current investigation.

See `engine.py` for the full API."""
from .engine import (
    Fingerprint, SimilarMatch, LearningContext,
    fingerprint_cio, similarity, retrieve_similar, learning_context,
)

__all__ = [
    "Fingerprint", "SimilarMatch", "LearningContext",
    "fingerprint_cio", "similarity", "retrieve_similar", "learning_context",
]
