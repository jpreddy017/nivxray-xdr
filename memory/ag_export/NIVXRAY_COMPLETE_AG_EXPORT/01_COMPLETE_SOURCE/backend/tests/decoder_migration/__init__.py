"""Gate 2D-B3 · Decoder Migration Parity Harness.

Reusable, deterministic parity harness for validating that the
migrated Plane-A codec runtime in `services/decoder/base/*` and
`services/analyzers/*` produces the same observable behaviour as
the pre-migration reference implementation in
`services/die/preprocessor/recursive_decoder`.

B3.0 (this checkpoint): capture the pre-migration baseline only.
B3.1+          : replay via the harness against migrated candidates.

Non-goals: implementation change, verdict change, corpus expansion,
mal-20 modification.
"""
