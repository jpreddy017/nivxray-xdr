# Local package validation — 2026-10-13

Application commit/tree: `ff66afe36efff3c0396b6e92ebaf21cae05d649a` /
`c2cdaf83a3ec7824f937ecc50bfd634637f0d632`. Packaging branch:
`engineering/stage1-staging-package`. All application paths remain unchanged.

| Executed gate | PASS | FAIL | SKIP | Evidence / limit |
|---|---:|---:|---:|---|
| Packaging unittest suite | 10 | 0 | 0 | Negative production-origin/Mongo/root/shared-key/mutable-image/config cases; private-network manifest; two independent matching context exports |
| Focused unchanged backend tests | 194 | 0 | 0 | Ownership, correlation/response boundary, ATT&CK isolation, decoder resource limits, command staging contract, selected-customer RBAC, RC1-P1 scope authority |
| Native frontend tests | 124 | 0 | 0 | Ten unchanged suites; existing verified dependencies reused locally |
| Native staging-target build and original build guard | PASS | 0 | 0 | Yarn 1.22.22, Vite 5.4.21; 174 inspected compiled files plus build-info.json; scope xdr, no cross-product origins |
| Source ancestry/tree and application diff | PASS | 0 | 0 | Exact pinned application source, no Stage2A source; export has 1,936 selected application files |
| YAML parsing, Mongo init JavaScript syntax, diff whitespace | PASS | 0 | 0 | Static checks only; not Docker/NGINX acceptance |

Backend command is identical to the preservation job with `MONGO_URL=''` and
`PYTHONPATH=backend`, using the existing unchanged command test requirements.
One Starlette/anyio deprecation warning remains visible. The separate full 519
Stage1 and 647 NCI suites were not repeated or claimed as new package results.

First build attempt failed because `yarn` was absent from PATH. The retry used
the same supported Yarn 1.22.22 via npx and passed without changing package.json,
yarn.lock, scripts or guards. No new frozen install was claimed locally; CI
performs the frozen install. Application runtime requirements contain non-exact
dependencies and require resolved-wheel/base-image review for reproducibility.

Build artifact identity for the local unused synthetic HTTPS API target:
`2354b7fe1cba926dc491b9e51e5648240a3f391f46520d32b6bbad60c7714f49` is the
SHA256 of the sorted, compact JSON mapping of 175 dist paths to file SHA256s.
The existing build-info timestamp means this is one artifact's identity, not a
claim that timestamped builds are byte-identical. No artifact was deployed.

BLOCKED / NOT RUN: Docker image build and compose config/runtime validation;
NGINX config execution; Mongo startup/index/credential acceptance; host firewall,
CPU/RSS/PID/descendant acceptance; authenticated native browser/API flow; hosted
CI completion at publication time; private Emergent target capabilities. Docker
and NGINX are not installed in this Work environment. No failure was waived.

Current disposition: GO for owner package review; HOLD for provisioning/startup,
live feature admission and production. See README.md for all retained HOLDs.
