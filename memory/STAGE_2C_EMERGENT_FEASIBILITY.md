# Emergent staging feasibility check — NivXRay XDR Stage 2B acceptance

Date: 2026-06
Baseline: `engineering/e3-stage2b-package` @ `1efa6dc8f7164bc6c1278e7e3891cd618843e220`
Package: `deploy/stage1-staging/` · Script: `acceptance/host_acceptance.sh` (13 phases)
Disposition: **assessment only.** Nothing deployed, published, provisioned or purchased.
Production `nivxray.nivxforge.com` untouched. No HOLD waived. No blocked check marked PASS.

Written outside the source tree so the working tree stays clean and the
`provenance` phase (`git status --porcelain` must be empty) still passes.

---

## Verdict

| Question | Answer |
|---|---|
| **Emergent staging for this acceptance** | **NO** |
| Docker Compose support | **NO** — verified absent in this environment; documented unsupported platform-wide |
| Network isolation support (`internal: true` + kernel egress denial) | **NO** — verified unobtainable |
| Database isolation support | **PARTIAL** — per-app Mongo exists, but not the four-service private-network topology the package requires |
| Full 13-phase acceptance feasibility | **NO** — 2 of 13 phases could run, 11 remain BLOCKED |
| Recommended next action | Provision one disposable external Linux host (H1–H10) |

---

## Evidence — directly verified in this environment

| Probe | Result |
|---|---|
| `command -v docker docker-compose podman nerdctl buildah` | all absent |
| `/var/run/docker.sock` | does not exist |
| `CapBnd` | `00000000a80405fb` — `cap_net_admin`, `cap_sys_admin`, `cap_net_raw` **not in the bounding set** |
| `unshare -n` | `Operation not permitted` |
| `ip link add dummy0 type dummy` | `RTNETLINK answers: Operation not permitted` |
| `nft list tables` | `Operation not permitted` |
| `iptables` | not installed |
| Seccomp | mode 2, 1 filter active |
| Runtime | unprivileged Kubernetes pod (cgroup v2 `0::/`), uid 0 inside namespace only |
| MongoDB | single supervisor-managed `mongod`, shared with the preview app |

The capability result is decisive: the missing bits are absent from the
**bounding set**, not merely from the effective set. No action inside the pod —
not `sudo`, not re-exec, not a setuid helper — can raise them. Nested Docker
would additionally need `CAP_SYS_ADMIN` to mount its own cgroup/overlay tree.

## Evidence — platform documentation (via Emergent support knowledge base)

Authoritative per Emergent, not independently reproducible by me:

- No Docker daemon, Docker-in-Docker or Compose is exposed to users on **any**
  tier, preview or deployed. The platform uses Docker internally to build
  deployment images; users cannot invoke it.
- Deployments are restricted to the managed template (React/Next + FastAPI/Node
  + MongoDB). Arbitrary multi-container Compose stacks with custom private
  networks are not supported.
- No privileged containers, namespaces or `nftables`/`iptables` control on any tier.
- No user-configurable egress or network policy on deployed apps. Fixed
  **outbound** IPs are published for allowlisting *by* third parties — that is
  the inverse of what the package needs, which is outbound default-deny.
- Multiple apps per account are isolated (own URL, own database), so a second
  app would not affect `nivxray.nivxforge.com`.
- Deployed Mongo is persistent and per-app; **preview** Mongo is ephemeral and
  resets on pod recycle.
- Cost: first deploy ≥ 50 ECU (waived for Pro), then monthly tier; preview is
  included in the subscription.

---

## Phase-by-phase feasibility

| # | Phase | On Emergent | Why |
|---|---|---|---|
| 1 | `prereq` | **BLOCKED** | fails at line 39, `command -v docker` |
| 2 | `provenance` | **CAN RUN** | pure git + `prepare.py --verify-only` + 16 packaging tests — already passing here |
| 3 | `build` | **BLOCKED** | `docker build` |
| 4 | `digests` | **BLOCKED** | no local image store to digest |
| 5 | `preflight` | **PARTIAL** | config/secret-file checks run; container assertions do not |
| 6 | `up` | **BLOCKED** | `docker compose up` |
| 7 | `health` | **BLOCKED** | no containers to probe |
| 8 | **`egress`** | **BLOCKED** | needs `internal: true` + host firewall; outbound internet is reachable here and cannot be denied |
| 9 | `internal` | **BLOCKED** | needs the private Compose network |
| 10 | `trace` | **MISLEADING IF RUN** | the 25-check trace passes here against supervisor services, but that proves application logic, **not** staged-container acceptance |
| 11 | `response` | **BLOCKED** | must assert simulation-only inside the hardened container |
| 12 | `evidence` | **BLOCKED** | collects `docker logs` / `inspect` output |
| 13 | `down` | **BLOCKED** | nothing to tear down |

**2 runnable (1 fully, 1 partially), 11 blocked.** Phase 8 is the decisive one
and is the least substitutable: it exists precisely to prove that isolation
holds at the kernel, using raw sockets, `/proc/net/route` and
`docker network inspect` — all chosen so no application-level guard can
influence the outcome. Simulating it in-pod would prove nothing and would
violate the rule against marking blocked checks as passed.

### Can an Emergent deployment be reused instead?

Reuse is **safe but useless**. A second Emergent app is genuinely isolated from
`nivxray.nivxforge.com`, so it would not endanger production — but it would be
a managed single-backend app, not the four-service hardened Compose topology:
no `internal: true` network, no `read_only` root filesystem with `cap_drop:
[ALL]`, no unexposed response engine, no named `response-state` volume, no
egress denial, and no way to record image digests. It would also mean
*deploying*, which this task forbids and which costs ECU. Not recommended.

---

## Minimum external host requirements (unchanged from Part 2, H1–H10)

Linux kernel ≥ 5.10 with `nftables`/`iptables` available to the runtime ·
Docker Engine ≥ 24 with Compose v2 · single architecture (ARM64 **or** AMD64) ·
4 vCPU / 8 GB RAM / 40 GB disk (8/16 for comfortable builds) · root or full
`sudo` · host-enforced default-deny egress for the staging bridge, proven
independently · local-disk named volumes (`mongo-data`, `response-state`), no
NFS, no bind mount into the clone · secrets directory outside the clone at
`0700` with four `0600` files · a reviewed private registry for digest
references · key-only SSH, no root login, no agent forwarding · **no route,
DNS entry, tunnel, VPN or credential to any production system**.

Containers still receive **no** extra capabilities — `CAP_NET_ADMIN` is needed
by the *daemon* only, and `test_acceptance_scripts.py` fails the package if
`--privileged`, `--cap-add`, host networking or `sudo` ever appears.

Any disposable VM meeting the above works; nothing in the package is
cloud-provider specific.

---

## Recommended next action

Provision **one** disposable external Linux VM to H1–H10, transfer
`nivxray-e3-stage2b-part2.bundle`
(SHA-256 `704d0561052ac9e2e8d770e326c417bab0269c28b6094f7f143297ff8cf799f0`),
and run the 13 phases there. Interim, Emergent remains correct for what it
already does well: source-side gates (`provenance`), the full 774-test
validation suite, frontend tests/build, and the synthetic trace as an
*application-logic* signal — explicitly not as staging acceptance.

Stopping after the feasibility assessment, as instructed.
