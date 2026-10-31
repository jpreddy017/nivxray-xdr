"""Input Understanding Stage — the entry point to the Investigation
Brain.

Answers only four questions:
    1. What artefact(s) am I looking at?
    2. How confident am I?
    3. What evidence supports that conclusion?
    4. Which analysis capabilities should run next?

Does NOT perform semantic analysis or threat assessment. Its
responsibility ends once the Workspace knows what it is analyzing
and which capabilities should execute.
"""
from .engine import classify
from .models import ArtefactClassification, ArtefactType, Capability

__all__ = ["classify", "ArtefactClassification", "ArtefactType", "Capability"]
