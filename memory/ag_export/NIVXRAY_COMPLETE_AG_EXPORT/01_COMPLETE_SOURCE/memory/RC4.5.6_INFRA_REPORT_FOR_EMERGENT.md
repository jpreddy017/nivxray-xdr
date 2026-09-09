# Infrastructure Investigation Request — NivXRay Production

**To:** Emergent Support
**From:** NivXRay engineering
**Date:** Feb 21, 2026
**Priority:** Medium (user-visible impact, mitigation deployed)
**Environments:**
- Preview: `https://greeting-app-5782.preview.emergentagent.com`
- Production: `https://nivxray.nivxforge.com`

---

## TL;DR

Production is consistently ~6× slower than Preview on CPU-bound work, while network and non-CPU work run at parity. Evidence strongly suggests a CPU-allocation or worker-configuration delta between the two environments. We've deployed a defensive mitigation on our side (raised an internal timeout), but request that you verify Prod's CPU allocation, worker configuration, and runtime parity with Preview to permanently resolve the underlying difference.

---

## Timing measurements — Preview vs Production

All measurements are HTTP round-trip from an internal client (no browser cache, sequential, warm containers, same code).

### 1. Non-CPU work (control — should be parity)

| Endpoint | Preview | Production | Ratio |
|---|---|---|---|
| `GET /api/` (health check) | 141 ms | 115 ms | **0.8×** (Prod slightly faster) |

**Interpretation:** Network path, ingress, TLS termination, and auth-free routing are all healthy on both. This rules out DNS, TLS, ingress, or general HTTP-layer regressions.

### 2. Trivial CPU work (no decoder candidates)

| Payload | Preview | Production | Ratio |
|---|---|---|---|
| `"hello world"` | 5.1 s | 5.8 s | **1.14×** |

**Interpretation:** The pipeline has a ~5 s fixed overhead (unrelated to this ticket — separate investigation). BOTH environments hit it. Ratio is normal.

### 3. Medium CPU work (base64 decode only)

| Payload | Preview | Production | Ratio |
|---|---|---|---|
| `powershell -EncodedCommand SQBFAFgAKAAiA...` (small `-Enc`) | 288 ms | 1,870 ms | **6.5×** |

### 4. Heavy CPU work (base64 + XOR-brute + shellcode family detection)

| Payload | Preview | Production | Ratio |
|---|---|---|---|
| 1,170-char PowerShell shellcode loader | 4,800 ms | ~30,000 ms | **6.25×** |

### 5. In-process baseline (measured on Preview pod, no HTTP)

| Stage | Duration |
|---|---|
| `deterministic_best_decode()` — core decoder pipeline | 1,801 ms |
| `extract_iocs(text)` — regex-based IOC lift | 0 ms |
| `mitre_map(text)` — MITRE technique mapping | 36 ms |
| `shellcode_analyzer.extract_iocs(bytes)` — binary IOC lift | 48 ms |
| **Total in-process** | **1,886 ms** |

**Interpretation:** Actual decode work is 1.9 seconds on our pod. Everything above 1.9s is HTTP-layer overhead, and the Prod overhead is dominated by CPU-bound work running slowly.

---

## What this evidence proves and does NOT prove

### Proven
1. Non-CPU work is at parity between Preview and Prod (health endpoint).
2. CPU-bound work is consistently ~6× slower on Prod.
3. The ratio scales linearly with payload complexity — this is textbook CPU-throttling behaviour, not an algorithmic explosion.
4. The regression is NOT caused by application code — same commit runs on both environments, and Preview handles the same payload correctly.

### Not yet proven (requires infra-side visibility)
1. **Exact cause** of the 6× CPU delta.
2. Whether Prod's container has:
   - Lower CPU allocation / lower core count?
   - CPU throttling / cgroup limits?
   - Different Python runtime version?
   - Different `uvicorn` worker configuration?
   - Different Linux kernel / scheduler?
   - CPU contention with another workload on the same node?
3. Whether Prod has any environment variables or feature flags that trigger heavier code paths.

---

## Requests

Could you please verify:

1. **CPU allocation** — Does the Prod container have the same CPU request/limit as Preview? Ideally, share the k8s deployment spec (or equivalent) for both so we can compare directly.

2. **CPU throttling** — Are cgroup CPU throttles being hit? Check `container_cpu_cfs_throttled_seconds_total` or equivalent for the Prod pod.

3. **Worker configuration** — Confirm `uvicorn` (or gunicorn) worker count matches between environments.

4. **Python version + built extensions** — Confirm Prod and Preview run identical Python versions and no fallback-to-pure-Python for compiled extensions (`bcrypt`, `regex`, `motor`, etc.).

5. **Environment variables** — Diff Prod vs Preview env vars for any Prod-only feature flags that could enable heavier work.

6. **Node co-tenancy** — Check whether Prod's node has heavy co-tenants causing CPU contention.

7. **CPU frequency scaling** — Some cloud VMs run at lower base frequencies unless burst credits are available. Verify Prod isn't a burstable instance running out of credits.

---

## What we've done on our side

- **Investigated internally first.** Confirmed no recent code change causes the regression (RC4.x Quality Gate 134/134 GREEN on the same commit that's deployed to Prod).
- **Deployed a defensive mitigation** (RC4.5.6): raised our internal hard-ceiling from 15s → 45s so legitimate Prod decodes complete instead of triggering a safe-fallback. This is a **temporary bandaid** — the real fix is CPU parity.
- **Documented rollback procedure.** If CPU parity is restored, we can lower the ceiling back to 15s in one line.

---

## Contact

Please reply on this ticket with findings. If you need our commit SHA, deployment IDs, or additional evidence, we can provide immediately.

Thank you.
