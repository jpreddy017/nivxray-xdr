# Backend acceptance recovery — 2026-11-04

Tested source: 9e2b92abead03ac1a39ecc1e4943b1630bf2070a, archived to an isolated directory from GitHub. Existing /app edits were not reset or included.

56 tests passed:
- test_file_identity.py + test_global_file_index.py: 11 passed.
- test_file_facts_coverage.py: 3 passed.
- test_v3_presentation.py + test_global_file_recovery.py: 42 passed.

Interpreter: /root/.venv/bin/python. mongomock installed into isolated test-deps only.
Command pattern: PYTHONPATH=test-deps:backend /root/.venv/bin/python -m pytest -o required_plugins= -o addopts= <test paths> -q.

The three new regression tests cover unresolved evidence, hash lookup isolation from path matching, and incomplete results at the scan budget.

These checks do not establish production readiness. Remaining gates: production backend and supervised worker deployment, derived-index retention/source-deletion behavior, and production-target build and smoke checks. The integration preview uses a candidate API route and must not be promoted directly as the production artifact.
