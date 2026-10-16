# Stage 2B Part 3 — backend build blocker repair

Date: 2026-06
Branch: `engineering/e3-stage2b-package`
Disposition: **nothing deployed, merged, pushed or published.** No image was
built here (no Docker). Production remains **NO-GO**; all HOLDs preserved.

---

## 1 · Root cause

`backend/requirements.txt` pinned `emergentintegrations==0.2.0`, a package that
**does not exist on PyPI**. The build only ever succeeded inside an Emergent
pod, where `/root/.config/pip/pip.conf` supplies

```
global.extra-index-url='https://d33sy5i8bnduwe.cloudfront.net/simple/'
```

Resolution therefore depended on **ambient host configuration that the
repository never declared**. Reproduced exactly, with the host config
neutralised:

```
$ PIP_CONFIG_FILE=/dev/null pip download --no-deps \
    --index-url https://pypi.org/simple emergentintegrations==0.2.0
ERROR: Could not find a version that satisfies the requirement
       emergentintegrations==0.2.0 (from versions: none)
```

This is the same class of defect as the checkout-coupled `sys.path` bug fixed
in P1: the build was coupled to its environment rather than declaring its
inputs. The Hetzner host was correct; the package was not portable.

Not a cause, ruled out: the `litellm` direct-URL pin. It already carries
`#sha256=adf398c5…` and its host answers (`HTTP 206`), which is why the operator's
build reached `emergentintegrations` before failing.

## 2 · Audit of every import

| Site | Behaviour | Posture |
|---|---|---|
| `deps.new_chat` / `llm_json` / `llm_text` | lazy import inside the function | **was the only 500 risk** — fixed |
| `llm_provider.EmergentClaudeProvider` | catches everything, falls through to the offline provider, ends at 502 | already fail-closed |
| `llm_decoder.py`, `reasoning/llm_tiebreaker.py`, `routers/decode_feedback.py`, `routers/docs.py`, `routers/lab.py`, `docs/automation.py` | already catch `ImportError` and degrade with a stated reason | already fail-closed |
| `routers/ai.py` autodecode, `routers/decode_guidance.py` | catch `HTTPException` and fall back to the deterministic decoder / flagged ensemble | degrade with disclosure |
| `engine/detectors/*`, `mitre_*`, `rc5` diag | never import it; locked by existing tests | unaffected |
| `workspace_recovery/tree_worker.py` | installs its own stub for A/B determinism | unaffected |

**No module-scope import exists anywhere**, so the package being absent can
never prevent the application from starting — only specific LLM calls fail.

## 3 · Can the authentic package be obtained with verified provenance?

**Integrity: yes. Attributable provenance: no — and I will not overstate it.**

Obtained from Emergent's private index over HTTPS:
`emergentintegrations-0.2.0-py3-none-any.whl`, 29,463 bytes,
SHA-256 `1822c409e24817689541891784b8ec3ff4dfed845ce8cd09fd4feb91ba3a4bdd`,
pure-python (`py3-none-any`, nothing compiled).

Honest limitations: the artefact is **unsigned**, there is no Sigstore or
PGP attestation, no reproducible build, and the metadata is anonymous
(`Author: Developer`, `developer@example.com`). Hash pinning gives
*integrity* — the bytes cannot change without the build failing — but it
does not establish *authorship*. Treat the digest as the trust anchor and
re-review it on any version bump.

Its declared dependencies are also notable: it pulls `litellm` from a direct
`customer-assets.emergentagent.com` URL plus `openai`, `google-genai`,
`google-generativeai`, `pillow`, `stripe` and `requests` — including
payments code this product never uses.

## 4 · Repair

A **declared, hash-verified, optional integration tier** — not a removal.

1. `backend/requirements-integrations.txt` (new) declares the index in-repo and
   pins the artefact by hash. Installed `--no-deps`, which is reviewed and
   safe: every transitive dependency is **already pinned** in
   `requirements.txt`, so the tier adds **zero** unreviewed surface. Installing
   with dependencies would instead re-resolve `litellm` from its direct URL and
   could float the pinned versions.
2. `backend/requirements.txt` no longer carries the private name, so the public
   closure resolves on any host.
3. `deps._chat_module()` converts a missing wheel into an explicit
   **503 `LLM integration unavailable`**. Previously `llm_text` and
   `new_chat` called the import *outside* their `try`, so an absent wheel
   surfaced as a **500 with a stack trace** — the one genuine fail-open gap.
4. The image build chooses a posture explicitly: `NIVXRAY_INTEGRATIONS=included`
   (default, functionality preserved) or `excluded`. Any other value **stops the
   build**. The posture is labelled `io.nivxray.integrations` and then
   *proven* by interrogating the image itself.

Preserved unchanged: deterministic investigation, API contracts,
authentication, tenant isolation and every fail-closed boundary. Nothing was
silently removed — with the tier excluded, routes that own a deterministic
fallback degrade **and say so**, and purely LLM-dependent routes return 503.

## 5 · Changed files

### Application — candidate `593b3e9f` / tree `54d6e4c2`

| File | Change |
|---|---|
| `backend/requirements.txt` | private pin replaced by a pointer comment (−1/+3) |
| `backend/requirements-integrations.txt` | **new** — declared index, hash pin, rationale |
| `backend/deps.py` | `_chat_module()` guard; three call sites rerouted |
| `backend/tests/test_integration_boundary.py` | **new** — 14 regression tests |
| `tools/rocket-validation/run.py` | new suite added to the `boundaries` gate |

### Packaging — HEAD `cd2b8b92` / tree `15a13aa6`

`backend.Dockerfile`, `acceptance/host_acceptance.sh`, `test_package.py`,
`test_acceptance_scripts.py`, `source.json`, `README.md`.
`diff(593b3e9f, HEAD)` is six files, **all** under `deploy/stage1-staging/` —
the packaging-only admission control still holds.

## 6 · Test results

| Gate | Tests | Result |
|---|---|---|
| `boundaries` (incl. 14 new) | 136 | 0 failures |
| `tenant` | 104 | 0 failures |
| `response` | 39 | 0 failures |
| `decoder` | 147 | 0 failures, 6 skipped |
| `command` | 372 | 0 failures |
| **Backend total** | **798** | **0 failures, 0 errors, 6 skipped** |
| Staging package + acceptance scripts | 38 | 0 failures (was 33) |

The new tests prove: 503 (never 500) from `_chat_module`, `new_chat`,
`llm_json` and `llm_text` with the wheel blocked; no API key in the detail;
`llm_provider` still closes at 502; guidance degrades with `_error`;
deterministic detectors still import; no module-scope import anywhere; the
public closure is free of the private name; and the artefact is hash-pinned.

Two pre-existing failures in `test_design_principles_lock.py`
(`test_depth_cap_default`, `test_stops_at_family_identified`) are **unrelated**
to this change — verified by `git stash`: they fail identically on the previous
commit under bare `pytest` and pass under the validation runner, which supplies
the gate environment.

## 7 · Clean-build evidence

| Check | Result |
|---|---|
| Full 218-pin closure resolves from **PyPI alone**, host pip config neutralised | **PASS** — `Would install … litellm-1.80.0 …`, all 218 collected |
| Private wheel resolves from the declared index with `--require-hashes` | **PASS** |
| **Tampered digest is refused** | **PASS** — `THESE PACKAGES DO NOT MATCH THE HASHES` |
| Offline install from a local wheelhouse, then `import emergentintegrations` | **PASS** |
| Export carries `backend/requirements-integrations.txt`; 2,132 files | **PASS** |
| **`docker build`** | **BLOCKED — never executed, no Docker here** |

> The Docker build is **not** claimed as passing. What is proven is that the
> step which actually failed on Hetzner — dependency resolution — now succeeds
> without any private index for the main closure, and with hash verification
> for the optional tier.

## 8 · New immutable candidate

| Item | Value |
|---|---|
| Application commit | `593b3e9fdd6008b67e5cc353c29e413560778fda` |
| Application tree | `54d6e4c28ac564af32f4e0dca59a90214cb0b1bc` |
| Packaging HEAD | `cd2b8b92d785bee2f88432d3202367bbd51508c0` |
| Packaging tree | `15a13aa6a5fe562895efaecabc11b4e434c8505f` |
| Bundle | `/app/rocket-evidence/e3/nivxray-e3-stage2b-part3.bundle` — 23,532,611 bytes |
| SHA-256 | `98e4adba8ec497411e21b6fa3e9ad11aebcd5d5a2b915e592f2aa42c6747fdfa` |
| Re-verified | fresh clone: tip/tree match, 12 commits, no alternates, `fsck` clean, both acceptance scripts `100755` |
| Ancestry | descends from E3 `1dc4e358…`; `prepare.py --verify-only` → "Pinned source verified" |

## 9 · Host instructions

```bash
sha256sum nivxray-e3-stage2b-part3.bundle    # expect 98e4adba…fdfa
git clone -b engineering/e3-stage2b-package nivxray-e3-stage2b-part3.bundle nivxray-stage2b
cd nivxray-stage2b && git rev-parse HEAD 'HEAD^{tree}'   # cd2b8b92… / 15a13aa6…
export STAGING_ROOT=$PWD STAGING_SECRETS=/opt/stage1-secrets STAGING_EVIDENCE=/opt/stage1-evidence
export PYTHON_BASE=python@sha256:<reviewed digest>
./deploy/stage1-staging/acceptance/host_acceptance.sh prereq
./deploy/stage1-staging/acceptance/host_acceptance.sh provenance
NIVXRAY_INTEGRATIONS=included ./deploy/stage1-staging/acceptance/host_acceptance.sh build
```

The `build` phase needs outbound HTTPS to PyPI, `customer-assets.emergentagent.com`
and the integration index. Runtime egress denial is unaffected — it applies to
the started staging network, not to the builder. A host without access to the
index can either point `INTEGRATIONS_INDEX_URL` at a reviewed local mirror, or
build with `NIVXRAY_INTEGRATIONS=excluded` and accept 503 on LLM routes.

## 10 · Remaining blockers

1. **Phases 3–13 remain BLOCKED** — unchanged by this repair. Only `provenance`
   has ever passed, plus a partial `preflight`.
2. **Kernel-enforced egress denial is still unproven.** Phase 8 has never run.
3. **`docker build` unverified here.** First real execution is on the host.
4. **The wheel is unsigned.** Integrity is pinned; authorship is not attested.
5. **Registry access** is still needed before any image carries an immutable digest.
6. Two pre-existing `test_design_principles_lock.py` failures under bare pytest
   should be reconciled with the gate environment at some point. Not a blocker
   for this slice and not caused by it.

Release status: **NO-GO until independently verified.**
