# Deployment Blueprints, Docker, Vercel & Tooling Configurations

**Category Directory**: `14_DEPLOYMENT_CONFIG/`  
**Authoritative Source Reference**: All source files referenced herein reside authoritatively in [`../01_COMPLETE_SOURCE/`](../01_COMPLETE_SOURCE/).  
**Total Associated Files**: 27 files  
**Total Category Size**: 0.36 MB  
**Total Lines of Code / Documentation**: 8,178 lines  

---

## Purpose & Scope

Containerization, cloud deployment configurations, shell scripts, and workspace metadata.

## Deployment Infrastructure

1. **Deployment Blueprints**: `deploy/` — Deployment templates and environment specifications.
2. **Vercel Configuration**: `vercel.json` — Serverless deployment routes and security headers.
3. **CI/CD Workflows**: `.github/` — Continuous integration workflows and issue templates.
4. **Scripts**: `scripts/` — Project maintenance, benchmark execution, and verification scripts.
5. **Workspace Configurations**: `Projects.code-workspace`, `design_guidelines.json`.


---

## Associated File Index (Authoritative Paths in `01_COMPLETE_SOURCE/`)

| Relative Source Path | Size (Bytes) | Lines | Type | Status |
| :--- | :---: | :---: | :---: | :---: |
| [`01_COMPLETE_SOURCE/.github/workflows/docs-screenshots.yml`](../01_COMPLETE_SOURCE/.github/workflows/docs-screenshots.yml) | 5,463 | 141 | `configuration` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/.github/workflows/rc4x_quality_gate.yml`](../01_COMPLETE_SOURCE/.github/workflows/rc4x_quality_gate.yml) | 5,301 | 139 | `configuration` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/.github/workflows/rc5_gates.yml`](../01_COMPLETE_SOURCE/.github/workflows/rc5_gates.yml) | 7,694 | 162 | `configuration` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/.github/workflows/rc5_golden_corpus_gate.yml`](../01_COMPLETE_SOURCE/.github/workflows/rc5_golden_corpus_gate.yml) | 7,866 | 194 | `fixture` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/Projects.code-workspace`](../01_COMPLETE_SOURCE/Projects.code-workspace) | 60 | 0 | `other` | `MODIFIED_BY_AG` |
| [`01_COMPLETE_SOURCE/deploy/.env.example`](../01_COMPLETE_SOURCE/deploy/.env.example) | 1,754 | 0 | `other` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/deploy/README.md`](../01_COMPLETE_SOURCE/deploy/README.md) | 4,282 | 100 | `documentation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/deploy/docker-compose.yml`](../01_COMPLETE_SOURCE/deploy/docker-compose.yml) | 3,164 | 110 | `configuration` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/scripts/build_audit_pdf.py`](../01_COMPLETE_SOURCE/scripts/build_audit_pdf.py) | 2,365 | 57 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/scripts/build_customer_deck.py`](../01_COMPLETE_SOURCE/scripts/build_customer_deck.py) | 51,344 | 979 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/scripts/build_nivxray_docs.py`](../01_COMPLETE_SOURCE/scripts/build_nivxray_docs.py) | 9,339 | 223 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/scripts/build_source_export.py`](../01_COMPLETE_SOURCE/scripts/build_source_export.py) | 10,147 | 224 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/scripts/fine_tune.sh`](../01_COMPLETE_SOURCE/scripts/fine_tune.sh) | 4,056 | 104 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/scripts/generate_capability_registry.py`](../01_COMPLETE_SOURCE/scripts/generate_capability_registry.py) | 43,012 | 741 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/scripts/generate_investor_deck_v1_2.py`](../01_COMPLETE_SOURCE/scripts/generate_investor_deck_v1_2.py) | 50,175 | 1,064 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/scripts/rc40_batch_500.py`](../01_COMPLETE_SOURCE/scripts/rc40_batch_500.py) | 33,431 | 746 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/scripts/rc41_crypto_corpus.py`](../01_COMPLETE_SOURCE/scripts/rc41_crypto_corpus.py) | 42,040 | 962 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/scripts/rc41_crypto_runner.py`](../01_COMPLETE_SOURCE/scripts/rc41_crypto_runner.py) | 14,474 | 354 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/scripts/rc43_ai_vs_det.py`](../01_COMPLETE_SOURCE/scripts/rc43_ai_vs_det.py) | 13,952 | 320 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/scripts/rc43_generate_pdf.py`](../01_COMPLETE_SOURCE/scripts/rc43_generate_pdf.py) | 16,558 | 327 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/scripts/rc43_generate_ppt.py`](../01_COMPLETE_SOURCE/scripts/rc43_generate_ppt.py) | 11,402 | 225 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/scripts/rc44_open_benchmark.py`](../01_COMPLETE_SOURCE/scripts/rc44_open_benchmark.py) | 18,330 | 458 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/scripts/rc454_backfill_case_confidence.py`](../01_COMPLETE_SOURCE/scripts/rc454_backfill_case_confidence.py) | 2,389 | 79 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/scripts/rc45_prev_prod_parity.py`](../01_COMPLETE_SOURCE/scripts/rc45_prev_prod_parity.py) | 7,840 | 191 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/scripts/rc5_delta_report.py`](../01_COMPLETE_SOURCE/scripts/rc5_delta_report.py) | 4,994 | 129 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/scripts/v1_5_0_release_metrics.py`](../01_COMPLETE_SOURCE/scripts/v1_5_0_release_metrics.py) | 5,201 | 134 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/vercel.json`](../01_COMPLETE_SOURCE/vercel.json) | 440 | 15 | `configuration` | `PRE_EXISTING` |
