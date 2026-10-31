# Phase 4 · Narrow Bisect · `window_a`

- Predicate       : `s001_writehost`
- Original window : `5cab99e2b8` .. `51666219ed` (80 commits)
- Bisect steps    : 6

## Verdict
- **Last Known Good** : `8baa7aa467` · 2026-07-20 17:06:46 +0000
- **First Bad**       : `26099be990` · 2026-07-20 17:42:10 +0000

## Files changed in the First Bad commit
```
  .github/workflows/rc23_quality_gate.yml.retired
  .github/workflows/rc4x_quality_gate.yml
  .tok
  backend/decoders/ps_alias_normalizer.py
  backend/decoders/ps_backtick_normalizer.py
  backend/magic_decoder.py
  backend/routers/ops.py
  backend/server.py
  backend/tests/test_engine_phase_a.py
  backend/tests/test_ps_alias_normalizer.py
  backend/tests/test_ps_backtick_normalizer.py
  backend/tests/test_rc22_xor8_lolbas_stix.py
  backend/tests/test_rc45_iteration26.py
  test_reports/iteration_26.json
  test_reports/pytest/iter26_results.xml
```

## Diff stat
```
26099be 2026-07-20 17:42:10 +0000 auto-commit for 9c15ea3a-452e-4164-83a8-a1afa345741d

 ...lity_gate.yml => rc23_quality_gate.yml.retired} |   0
 .github/workflows/rc4x_quality_gate.yml            | 114 ++++++++
 .tok                                               |   2 +-
 backend/decoders/ps_alias_normalizer.py            | 298 +++++++++++++++++++++
 backend/decoders/ps_backtick_normalizer.py         | 225 ++++++++++++++++
 backend/magic_decoder.py                           |  12 +
 backend/routers/ops.py                             |  94 ++++++-
 backend/server.py                                  |   2 +
 backend/tests/test_engine_phase_a.py               |   6 +-
 backend/tests/test_ps_alias_normalizer.py          | 165 ++++++++++++
 backend/tests/test_ps_backtick_normalizer.py       | 130 +++++++++
 backend/tests/test_rc22_xor8_lolbas_stix.py        |   5 +-
 backend/tests/test_rc45_iteration26.py             | 186 +++++++++++++
 test_reports/iteration_26.json                     |  44 +++
 test_reports/pytest/iter26_results.xml             |  18 ++
 15 files changed, 1288 insertions(+), 13 deletions(-)

```

## Bisect trace
| SHA | Result |
|---|:-:|
| `5cab99e2b8` | ✅ |
| `51666219ed` | ❌ |
| `e97bb46ec2` | ✅ |
| `831424e148` | ❌ |
| `6b73970eec` | ✅ |
| `c902b2b6e7` | ❌ |
| `26099be990` | ❌ |
| `8baa7aa467` | ✅ |