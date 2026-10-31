"""Workspace — production, frozen, isolated from Shared.

Per ADR-0015 (Workspace Recovery Directive · Feb 2026):

    * Workspace behavioural components live here and NOWHERE else.
    * Shared (`backend/decoders/`, `backend/nivxforge/`, `operations.py`)
      may evolve independently — Workspace no longer consumes Shared
      *behaviour*, only utility helpers (base64 / hex / XOR / crypto /
      schemas / auth).
    * X-Lab experiments cannot regress Workspace via a shared import.

Slice 1 (this commit) delivers the interpreter-ownership engine —
the single most consequential behavioural surface, and the one that
carries the currently-observed bug. Remaining behavioural modules
migrate in follow-up slices.
"""
