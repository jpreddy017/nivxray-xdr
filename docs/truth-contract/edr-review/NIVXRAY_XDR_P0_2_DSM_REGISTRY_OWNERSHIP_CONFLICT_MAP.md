# NivXRay XDR · P0-2 · DSM REGISTRY OWNERSHIP & CONFLICT MAP

> **Mode:** STRICT READ-ONLY. No code, config or runtime changed. Owner-authorised prerequisite artifact for P0-2. **Implementation is NOT authorised by this document.**
> **Branch:** `feature/rc2-alignment` @ `869f7336`. **Date:** 2026-09-05.
> **Rule:** NO EVIDENCE → NO CLAIM. Every line reference below was read from source.

---

# 0 · HEADLINE FINDING

There are two DSM registries. **One of them is dead in production.**

| Registry | Symbol | Defined at | Used in production? |
|---|---|---|---|
| **A · Pipeline registry** | `DSM_REGISTRY` (`DSMRegistry`) | `detection_content/xdr_pipeline.py:51-74` | ✅ **YES — this is the only registry the product uses** |
| **B · AG "unified" registry** | `TELEMETRY_DSM_REGISTRY` (`TelemetryDSMRegistry`) | `detection_content/telemetry/registry.py:14-39` | 🔴 **NO — zero production consumers** |

Registry B's own docstring claims the role Registry A actually performs:

```python
# backend/detection_content/telemetry/registry.py:1-4
"""
NivXRay XDR — Telemetry DSM Registry.
Unified Device Support Module registry supporting network, endpoint, and cloud telemetry.
"""
```

It is **not** unified (it holds no network DSM), and it is **not** used. Every production consumer goes to Registry A.

**Worse:** Registry B does not know about the Sysmon DSM. `TelemetryDSMRegistry.__init__` (`registry.py:16-20`) lists exactly `WindowsSecurityDSM`, `LinuxAuditdDSM`, `AWSCloudTrailDSM`. `SysmonDSM` is absent. Its `register_dsm()` method (`registry.py:22-24`) — the only mechanism by which Sysmon *could* be added — **is never called anywhere in the codebase** (production or test).

---

# 1 · OWNERSHIP MAP

## 1.1 · Registry A — `DSM_REGISTRY` (PRODUCTION)

```python
# backend/detection_content/xdr_pipeline.py:51-74
class DSMRegistry:                                              # :51
    def __init__(self):                                         # :52
        self._dsms: list = [SnortEveDSM()]                      # :53
        try:                                                    # :54
            from .telemetry import WindowsSecurityDSM, LinuxAuditdDSM, AWSCloudTrailDSM   # :55
            self._dsms.extend([WindowsSecurityDSM(), LinuxAuditdDSM(), AWSCloudTrailDSM()])# :56
        except Exception:                                       # :57
            pass                                                # :58   ← SILENT #1
        try:                                                    # :59
            from .telemetry.sysmon_dsm import SysmonDSM         # :60
            self._dsms.append(SysmonDSM())                      # :61
        except Exception:                                       # :62
            pass                                                # :63   ← SILENT #2

    def resolve(self, ev: dict):                                # :65
        for d in self._dsms:                                    # :66
            if d.supports(ev): return d                         # :67   ← NO try/except
        return None                                             # :68

    def list(self):                                             # :70
        return [d.identity() for d in self._dsms]               # :71

DSM_REGISTRY = DSMRegistry()                                    # :74
```

**Composition when all imports succeed (5 DSMs, priority order):**

| Order | DSM | Domain | Origin | Registration mechanism |
|---|---|---|---|---|
| 1 | `SnortEveDSM` | network IDS | **PRE-AG** | hard-coded literal, `:53` |
| 2 | `WindowsSecurityDSM` | endpoint | **AG** | try-import + `extend`, `:55-56` |
| 3 | `LinuxAuditdDSM` | endpoint | **AG** | try-import + `extend`, `:55-56` |
| 4 | `AWSCloudTrailDSM` | cloud | **AG** | try-import + `extend`, `:55-56` |
| 5 | `SysmonDSM` | endpoint | **POST-AG-EMERGENT** (`869f7336`) | separate try-import + `append`, `:60-61` |

**Production consumers (complete):**

| Consumer | file:line | Purpose |
|---|---|---|
| Canonical pipeline | `detection_content/xdr_pipeline.py:237` `dsm = DSM_REGISTRY.resolve(raw_event)` | **the** DSM resolution for every ingested event |
| Content-supply-chain admin API | `routers/content_supply_chain.py:43` (import), `:907` `return {"dsms": DSM_REGISTRY.list()}` | the **only** API that reports DSM inventory to an operator |

## 1.2 · Registry B — `TELEMETRY_DSM_REGISTRY` (DEAD IN PRODUCTION)

```python
# backend/detection_content/telemetry/registry.py:14-39
class TelemetryDSMRegistry:                                     # :14
    def __init__(self):                                         # :15
        self._dsms: List[Any] = [                               # :16
            WindowsSecurityDSM(),                               # :17
            LinuxAuditdDSM(),                                   # :18
            AWSCloudTrailDSM(),                                 # :19
        ]                                                       # :20

    def register_dsm(self, dsm: Any):                           # :22
        # Insert at beginning so specialized DSMs take priority # :23
        self._dsms.insert(0, dsm)                               # :24   ← NEVER CALLED

    def resolve(self, ev: Dict[str, Any]) -> Optional[Any]:     # :26
        for d in self._dsms:                                    # :27
            try:                                                # :28
                if d.supports(ev):                              # :29
                    return d                                    # :30
            except Exception:                                   # :31
                continue                                        # :32   ← SILENT #3
        return None                                             # :33

TELEMETRY_DSM_REGISTRY = TelemetryDSMRegistry()                 # :39
```

**Consumers (complete):**

| Consumer | file:line | Type |
|---|---|---|
`detection_content/telemetry/__init__.py:18,40` | re-export | **module plumbing only** |
`tests/test_phase2_telemetry_normalization.py:12,32,77,114,142,184` | 6 `resolve()` calls | **test** |
`tests/test_phase2_1_field_normalization_adversarial.py:23,98,129` | 3 `resolve()` calls | **test** |
`tests/test_phase2_1_scale_microbenchmark.py:31` | import | **test** |

**Zero production consumers.** Note `backend/nivxforge/cim/*` matches on `telemetry_registry` / `telemetry.registry` (`unknowns.py:77`, `models.py:39`, `fact_substrate.py:95`) are an **unrelated CIM fact-substrate namespace** — not this registry. Confirmed by reading each site.

## 1.3 · Import side-effect

`detection_content/telemetry/__init__.py:18` imports `registry`, so **any** import of `.telemetry` instantiates `TELEMETRY_DSM_REGISTRY` (`registry.py:39`) as a module-level singleton. Since Registry A imports `.telemetry` at `xdr_pipeline.py:55`, **both registries are instantiated in every production process** — and one of them is never consulted. Two live objects, one truth.

---

# 2 · CONFLICT MATRIX

| # | Conflict | Evidence | Consequence | Severity |
|---|---|---|---|---|
| **C-1** | **Two registries, one used** | `xdr_pipeline.py:74` vs `registry.py:39`; Registry B has 0 production consumers | Any DSM registered into B — the API that *looks* like the right one, and is *named* "Unified" — is silently ignored by the pipeline. This is a latent trap for the next engineer | **P0** |
| **C-2** | **`SysmonDSM` missing from Registry B** | `registry.py:16-20` lists 3 DSMs; `sysmon_dsm.SysmonDSM` absent | The 9 AG telemetry tests that resolve through Registry B **cannot see Sysmon**. Sysmon has test coverage only via the pipeline path. A regression in Sysmon would not be caught by the telemetry test suite | **P1** |
| **C-3** | **`register_dsm()` is dead code** | `registry.py:22-24`; grep for `register_dsm` → **0 call sites** anywhere | The only dynamic-registration mechanism in the product is unreachable. All registration is by hard-coded literal inside `DSMRegistry.__init__` | **P1** |
| **C-4** | **Asymmetric `resolve()` failure semantics** | A: `xdr_pipeline.py:66-67` calls `d.supports(ev)` **unguarded** · B: `registry.py:28-32` wraps it and `continue`s | A DSM whose `supports()` raises will **crash the production pipeline** but be silently skipped in tests. **Tests are strictly more forgiving than production** — the worst possible direction for this asymmetry | **P0** |
| **C-5** | **Registry A composition cannot be inspected** | `_dsms` built inside `__init__` from literals + try-imports; no config, no manifest, no ordering declaration | Priority order (Snort first, Sysmon last) is an accident of code layout, not a decision. `SnortEveDSM.supports()` (`xdr_pipeline.py:36-39`) matches any dict with `event_type` **and** `src_ip` — a **broad** predicate sitting in **first** priority | **P1** |
| **C-6** | **Only Registry A is observable** | `/api/admin/content-supply-chain/…/dsms` → `DSM_REGISTRY.list()` (`content_supply_chain.py:907`) | Correct today (A is the real one) but the endpoint reports a list built from swallowed try-imports, so **it reports what loaded, never what failed to load** | **P0** (see §3) |

### C-5 detail — priority-order hazard

`SnortEveDSM.supports()`:
```python
# xdr_pipeline.py:36-39
def supports(self, ev: dict) -> bool:
    if not isinstance(ev, dict): return False
    # Suricata-EVE alerts carry event_type and an alert sub-object.
    return "event_type" in ev and "src_ip" in ev
```
Registry A returns the **first** match (`:66-67`). Because Snort is index 0 and its predicate is only two key-presence checks, any future DSM whose events also carry `event_type` + `src_ip` will be **shadowed by Snort**. Registry B's `register_dsm()` explicitly comments *"Insert at beginning so specialized DSMs take priority"* (`registry.py:23`) — **Registry B understood this hazard; Registry A does not implement any mitigation.** This is directly relevant to P0-3, whose first live source is Suricata EVE and therefore lands on exactly this predicate.

---

# 3 · EXHAUSTIVE SILENT-FAILURE INVENTORY (telemetry load & resolve path)

Owner-requested (option 4-a). Every swallow is listed with the exact failure mode it hides.

## 3.1 · TRUE SILENT FAILURES — no log, no metric, no surface

| ID | Site | Code | What it hides | Blast radius |
|---|---|---|---|---|
| **S-1** | `xdr_pipeline.py:57-58` | `except Exception: pass` after importing 3 AG DSMs (`:55-56`) | `ImportError` (module missing/renamed) · `SyntaxError` in **any** of `windows_security_dsm.py`, `linux_auditd_dsm.py`, `aws_cloudtrail_dsm.py`, `models.py`, `registry.py` (all pulled in by `telemetry/__init__.py`) · `TypeError` from any of the three constructors | **Registry silently drops from 5 DSMs to 2.** Windows, Linux **and** cloud telemetry all become "no DSM in registry supports this event". The pipeline then reports `dsm: BLOCKED` per event — honest at the *event* level, but the operator is never told that **three DSMs failed to load**. Because the three imports share one `try`, **one broken file disables all three** |
| **S-2** | `xdr_pipeline.py:62-63` | `except Exception: pass` after importing `SysmonDSM` (`:60-61`) | Same failure classes, scoped to `sysmon_dsm.py` | **Sysmon silently disappears.** Since `telemetry/__init__.py` does **not** import `sysmon_dsm`, this is the only load path for Sysmon in the entire product. A single typo in `sysmon_dsm.py` removes Sysmon with zero signal |
| **S-3** | `telemetry/registry.py:31-32` | `except Exception: continue` inside `resolve()` | Any exception raised by a DSM's `supports()` | Registry B only → **test-path only** today. Its real harm is C-4: it makes the test path more forgiving than production |

## 3.2 · SEMI-SILENT — degrades behaviour, no operator surface

| ID | Site | Code | What it hides |
|---|---|---|---|
| **S-4** | `xdr_pipeline.py:193-196` | `try: golden_matched = bool(nx_evaluate(...)) / except Exception: golden_matched = False` | A crash in golden-rule evaluation becomes an indistinguishable **"no match"**. Detection silently degrades to a false negative with no stage record. *(Adjacent to `mal-20` — recorded, NOT investigated, per standing directive.)* |
| **S-5** | `routers/xdr_collector_landing.py:159-160`, `:163-164` | `except Exception: pass  # noqa: BLE001` in the FastAPI `shutdown` handler (`runtime.stop(inst)`, `runtime.outbox.close()`) | Collector-shutdown and outbox-close failures. **Assessed BENIGN** — shutdown-path best-effort cleanup is a legitimate use of a bare swallow. Listed for completeness; **no change recommended** |

## 3.3 · CORRECTLY HANDLED — do not "fix" these

| ID | Site | Behaviour | Why it is right |
|---|---|---|---|
| **H-1** | `v2/routers/ingestion.py:166-167` | `except Exception as pe:` → appends `{"trace_id":…, "error": f"{type(pe).__name__}: …"}` into `pipeline_results` | Failure is **captured and surfaced per trace** |
| **H-2** | `v2/routers/ingestion.py:169-170` | `except Exception as e:` → `metrics.pipeline_error = f"{type(e).__name__}: …"` with comment *"surfaced honestly to owner"* | Failure is **surfaced on the metrics object** |
| **H-3** | `xdr_pipeline.py:245-250` | `except ParserError as pe:` → `_s("parser","FAILED", code=pe.code, error=pe.message, parser_id=…)` and returns `blocker: "parser"` | **Typed** exception, explicit stage record, honest halt. This is the pattern the DSM load path should follow |
| **H-4** | `xdr_pipeline.py:102-105` | `except Exception: raise ParserError("INVALID_TIMESTAMP", …)` | Converts a broad exception into a **typed, surfaced** one |
| **H-5** | `xdr_pipeline.py:237-241` | `if not dsm: _s("dsm","BLOCKED", reason="no DSM in registry supports this event")` | Honest per-event refusal. **But note:** it cannot distinguish *"no DSM matches this event"* from *"the matching DSM failed to load at import time"* — S-1/S-2 make these two states indistinguishable to the operator. **This is the precise mechanism by which a telemetry source can appear configured while its DSM never loaded.** |

## 3.4 · The owner's stated concern, confirmed exactly

> *"Two registries + silent `except: pass` can cause telemetry sources to appear configured while their DSM failed to load."*

**CONFIRMED, with the mechanism identified:**

1. An operator configures a data source (`/api/xdr/data-sources`) — the source row exists and reports as configured.
2. `sysmon_dsm.py` (or any of the three AG DSM modules) fails to import.
3. **S-2** (or **S-1**) swallows it. Nothing logs. Nothing increments.
4. `/api/admin/content-supply-chain/…/dsms` calls `DSM_REGISTRY.list()` (`content_supply_chain.py:907`), which iterates `self._dsms` — **the list of DSMs that loaded**. The missing DSM is simply absent; there is no "failed to load" entry.
5. Events arrive and every one records `dsm: BLOCKED · "no DSM in registry supports this event"` — which reads like a **data problem** (wrong event shape), not a **code problem** (DSM never loaded).

**There is no observable difference between "unsupported event" and "DSM crashed at import".** That is the P0.

---

# 4 · WHAT MUST BE PRESERVED (regression guard for the implementation turn)

Functional behaviour that must be **byte-identical** after unification:

| # | Invariant | Evidence |
|---|---|---|
| P-1 | 5 DSMs resolvable: `snort-eve`, `windows_security`, `linux_auditd`, `aws_cloudtrail`, `sysmon` | `xdr_pipeline.py:53,56,61` |
| P-2 | **Snort remains first in priority** (changing order changes which DSM claims Suricata EVE — and P0-3 is Suricata) | `xdr_pipeline.py:53` |
| P-3 | `DSM_REGISTRY.list()` continues to return `[d.identity() for d in …]` — the shape `/api/admin/content-supply-chain/…/dsms` publishes | `xdr_pipeline.py:70-71`, `content_supply_chain.py:907` |
| P-4 | `resolve()` still returns the **first** supporting DSM, or `None` | `xdr_pipeline.py:65-68` |
| P-5 | `dsm: BLOCKED` stage record semantics unchanged for genuinely unsupported events | `xdr_pipeline.py:238-239` |
| P-6 | The 9 AG telemetry tests that use `TELEMETRY_DSM_REGISTRY.resolve()` must keep passing | `test_phase2_telemetry_normalization.py`, `test_phase2_1_field_normalization_adversarial.py` |
| P-7 | `DSM_REGISTRY` import in `routers/content_supply_chain.py:43` must keep working | `content_supply_chain.py:43` |
| P-8 | Sysmon's fail-closed contract: unsupported EventIDs return `False` from `supports()` | `sysmon_dsm.py:18` |

---

# 5 · RECOMMENDED UNIFICATION SHAPE (scoping only — NOT authorised)

Presented for the owner's review. No code will be written until authorised.

| Step | Change | Preserves | Risk |
|---|---|---|---|
| 1 | **Choose Registry A's class as the survivor** (it is the one in production, has the network DSM, and owns both API consumers). Registry B's *class* becomes an alias of A; `TELEMETRY_DSM_REGISTRY` becomes the **same object** as `DSM_REGISTRY` so the 9 AG tests exercise the production registry | P-6, and **fixes C-2** — Sysmon becomes visible to the telemetry test suite | LOW |
| 2 | **Replace the two try-import blocks with explicit, individual registration** — one `try` per DSM, and on failure record a structured entry (`dsm_id`, `status: LOAD_FAILED`, `error`) instead of `pass` | P-1, P-2 | LOW |
| 3 | **Make load failures observable**: `DSM_REGISTRY.list()` returns loaded DSMs **plus** `load_failures[]`, so `/api/admin/content-supply-chain/…/dsms` can honestly report "4 loaded, 1 FAILED: SysmonDSM — ImportError: …". **This is the change that closes the owner's stated concern** | P-3 (additive only) | LOW |
| 4 | **Log loudly** at ERROR on any DSM load failure, with the DSM id and exception type | — | NONE |
| 5 | **Resolve C-4**: make `resolve()` semantics identical in both paths — wrap `supports()`, and on exception record a structured `SUPPORTS_ERROR` rather than silently `continue`. Production must not crash, and tests must not be more forgiving than production | P-4, P-5 | LOW |
| 6 | **Activate `register_dsm()`** (C-3) as the single registration entry point, honouring the priority comment at `registry.py:23`, and make priority **explicit** rather than positional (C-5) | P-2 | MEDIUM — touches ordering; needs a parity check against Suricata EVE fixtures **before** P0-3 |
| 7 | Leave **S-4** (golden-rule swallow) and **mal-20** untouched | — | NONE |
| 8 | Leave **S-5** (shutdown handlers) untouched — benign | — | NONE |

**Sequencing note for P0-3:** step 6 changes which DSM claims a Suricata EVE event. Since P0-3's first live source **is** Suricata, step 6 must be parity-checked against EVE fixtures **before** the live-source proof begins, or the two changes will confound each other.

---

# 6 · UNKNOWN

| # | Unknown | Why unresolvable read-only |
|---|---|---|
| U-1 | Whether all 5 DSMs are currently loaded in the **running** process. `/api/admin/content-supply-chain/…/dsms` would answer it, but calling it proves only what loaded — never what failed (that is the defect itself) | Structural: the endpoint cannot report absence-by-failure |
| U-2 | Whether S-1/S-2 have **ever** fired in this environment | No log, no metric, no persisted record. **Unrecoverable by design** — this is the strongest argument for step 3 |
| U-3 | Whether `WindowsSecurityDSM.supports()` and `SysmonDSM.supports()` overlap on Windows event shapes (both are endpoint DSMs; Windows-Security is index 2, Sysmon index 5, so Windows-Security would win any tie) | Requires executing both predicates against real event fixtures |
| U-4 | Whether any DSM's `supports()` can raise on real input — which would crash production via C-4 | Requires execution against adversarial fixtures |

---

# 7 · AUDIT INTEGRITY

Read-only confirmed: `git status` after delivery lists Markdown artifacts only. No code, config, DB or runtime change. `mal-20` untouched. Truth Contract unamended. No UBAE, Sandbox, Stage-4, Gap-B or Stage-11 work performed. No implementation authorised by this document.

## END · P0-2 DSM Registry Ownership & Conflict Map · awaiting owner authorisation for §5
