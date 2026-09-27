# Proposal (FIX 5) — classify EDR tests by MARKER, not by filename

Not implemented in the hardening commit. Owner asked for the proposal only;
the 10 already-reviewed live exclusions stay as-is for this remediation.

## The problem with the current gate selector

The deterministic GitHub step names 10 files with `--ignore`. Every new live
suite must be remembered and added by hand, and a forgotten one turns the
authoritative gate red for an environmental reason — exactly the failure class
this remediation just removed. The ignore list also encodes no contract: a
reader cannot tell WHY a file is excluded.

## Proposed contract

Four markers, registered in `backend/pytest.ini` (`markers =` section only —
`addopts` stays untouched per the in-file instruction):

| Marker | Meaning | Runs in the GitHub gate |
|---|---|---|
| `unit` | pure Python, no I/O beyond the repo | yes |
| `integration` | needs the CI MongoDB, no network | yes |
| `live` | authenticates against a running preview/prod edge | no |
| `slow` | >5 s, benchmark-class | opt-in job |

Default (unmarked) = `unit`, so nothing silently escapes the gate.

Selection becomes:

```
python -m pytest tests/edr -m "not live and not slow"
```

## Migration path (separate, reviewable, no behaviour change)

1. Add the `markers =` block to `pytest.ini`.
2. Put `pytestmark = pytest.mark.live` at module scope in the 10 known live
   suites (`test_p0_f10_live_api.py`, `test_p0_f7_live_api.py`,
   `test_p0a_response_authority_live.py`, `test_p0c_durable_findings_live.py`,
   `test_p0_a2_adversarial_live.py`, `test_p1_10_live_contract.py`,
   `test_wave0_api_smoke.py`, `test_p0_f6_response_ui_backend.py`,
   `test_iteration_82_activation.py`, `test_iter107_p0_3_freshness_review.py`).
3. Mark the Mongo-dependent suites `integration`.
4. Swap the workflow's 10 `--ignore` flags for `-m "not live and not slow"`.
5. Add a guard test: a module importing `requests`/`httpx` at top level and
   hitting an external base URL must carry `live`. That makes the contract
   enforced rather than remembered.

Steps 1-3 are mechanical and reviewable in isolation; step 4 is the only one
that changes what CI runs, and it should land alone so a regression is
attributable.
