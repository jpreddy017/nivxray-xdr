"""
ICE · Investigation Correlation Engine.

Rule R21 · Correlation Happens Once.  Every projection consumes
`SSOT.ice`; no consumer computes its own relationships.
"""
from .correlate import correlate, tactic_for  # noqa: F401
