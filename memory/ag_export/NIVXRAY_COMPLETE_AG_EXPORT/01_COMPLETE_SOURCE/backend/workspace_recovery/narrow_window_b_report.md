# Phase 4 · Narrow Bisect · `window_b`

- Predicate       : `corpus_10_of_10`
- Original window : `09a556701a` .. `42d7dffd1d` (80 commits)
- Bisect steps    : 7

## Verdict
- **Last Known Good** : `194d6ca8e9` · 2026-07-29 03:46:13 +0000
- **First Bad**       : `069bd23f77` · 2026-07-29 04:20:10 +0000

## Files changed in the First Bad commit
```
  backend/engine/models.py
  backend/engine/orchestrator.py
  backend/rc22_adapter.py
  backend/tests/fixtures/adversarial_corpus.jsonl
  backend/tests/test_phase1a_plain_text_cli.py
  backend/v2/investigation/analyst_report/builder.py
  backend/v2/investigation/verdict/__init__.py
  backend/v2/semantic/ps_semantic.py
  frontend/src/components/investigation/InvestigationBrainPanel.jsx
  memory/PRD.md
```

## Diff stat
```
069bd23 2026-07-29 04:20:10 +0000 auto-commit for 39621d44-1b6e-4a3c-a67f-e6a45fd64275

 backend/engine/models.py                           |   1 +
 backend/engine/orchestrator.py                     |  62 +++++++-
 backend/rc22_adapter.py                            |   4 +
 backend/tests/fixtures/adversarial_corpus.jsonl    |   1 +
 backend/tests/test_phase1a_plain_text_cli.py       | 174 +++++++++++++++++++++
 backend/v2/investigation/analyst_report/builder.py |  14 +-
 backend/v2/investigation/verdict/__init__.py       |  40 ++++-
 backend/v2/semantic/ps_semantic.py                 |   7 +-
 .../investigation/InvestigationBrainPanel.jsx      |  11 +-
 memory/PRD.md                                      |  44 ++++++
 10 files changed, 339 insertions(+), 19 deletions(-)

```

## Bisect trace
| SHA | Result |
|---|:-:|
| `09a556701a` | ✅ |
| `42d7dffd1d` | ❌ |
| `ed31e39d54` | ❌ |
| `1128d66f93` | ❌ |
| `069bd23f77` | ❌ |
| `a91bc7718d` | ✅ |
| `76173f44bd` | ✅ |
| `c1481c49b5` | ✅ |
| `194d6ca8e9` | ✅ |