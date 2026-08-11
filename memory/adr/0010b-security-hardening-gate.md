# ADR-0010b — P0 Security Hardening Gate · Evidence Report

**Status**: Accepted · 2026-08-11 · Session-10
**Author**: E1 (agent) under owner directive at PRD.md head
**Baseline**: ADR-0007 · 0008 · 0009 · 0010 · 0011 · determinism CI · PRD.md
**Verdict**: 🟢 **PASS** — all 7 P0 controls implemented, tested, regression-proven. Ready to open P1 Server-Side File Mode.

---

## §1 · Scope

Seven bounded controls, exactly as specified in PRD.md P0 directive:

1. Explicit CORS origins (remove unsafe wildcard + credentials combo)
2. Login / authentication rate-limit
3. Zip / decompression-bomb protection
4. Archive recursion / depth limit
5. Archive file-count limit
6. Archive expanded-size limit
7. Fail-loud / safe archive failure handling

Nothing else was implemented. Discovery loop stayed closed.

## §2 · Threat model

NivXRay intentionally receives potentially hostile input:

```
UNTRUSTED INPUT  →  UPLOAD  →  ARCHIVE EXTRACTION  →  PARSER / ANALYZER  →  EVIDENCE
```

Threats addressed by this gate:
- Decompression bombs (unbounded expansion)
- Recursive archive processing (ZIP-in-ZIP-…)
- Excessive file-count exhaustion
- Oversized individual entries
- Path-traversal (`../`, absolute paths, backslash traversal)
- Malformed / hostile archive parser crashes
- Credential-stuffing / brute-force on `/api/auth/login`
- CORS wildcard + credentials misconfiguration

Threats **explicitly out of scope** (documented as residual risk in §9):
- Same-process parser isolation (PE / DOCX / RC4 / capstone still in-process)
- Multi-tenant privacy (single-tenant today)
- Prompt-injection via LLM narrate path

## §3 · Before state

| Control | State on entry |
|---|---|
| CORS | `allow_origins=["*"]` + `allow_credentials=True` — spec-invalid combination |
| Login rate-limit | None — unlimited login attempts per (email, IP) |
| Archive-bomb guard | None — raw `zipfile.ZipFile(io.BytesIO(raw))` walked all members unconditionally |
| Archive recursion | Uncontrolled — no depth cap |
| Archive file-count | Uncontrolled — no cap |
| Archive expanded-size | Uncontrolled — no cap on total or per-entry |
| Fail-loud archive | Silent — `except Exception: pass` swallowed errors |

## §4 · Implemented controls

### 4.1 · CORS explicit-origin policy
- New module: `backend/security/cors.py` — `resolve_cors_policy(env)`.
- Wildcard (`*` or unset) → **credentials FORCED OFF** (browser-spec compliant).
- Explicit comma-separated list → credentials ON, whitespace / trailing-`/` stripped.
- Wired at `backend/server.py` L415-431 — logged at startup: `CORS policy: origins=N wildcard=… credentials=…`.

### 4.2 · Login rate-limit (sliding window + soft lockout)
- New module: `backend/security/rate_limit.py` — `SlidingWindowLimiter`.
- Keyed by `(email, client_ip)` — protects against single-account probing AND single-attacker fan-out.
- Configurable via env:
  - `NIVX_LOGIN_RATE_MAX_FAILS=5`
  - `NIVX_LOGIN_RATE_WINDOW_SEC=300`   (5 min)
  - `NIVX_LOGIN_RATE_LOCKOUT_SEC=900`  (15 min)
- Response on breach: HTTP **429** with structured `{ error, reason, retry_after_seconds }` and a `Retry-After` header.
- Successful login clears the counter.
- Wired at `backend/routers/auth.py::login` (unchanged auth logic — only guard added around it).

### 4.3 – 4.6 · Archive extraction guards
- New module: `backend/security/archive_guard.py` — `safe_iter_zip_members` + `ArchiveGuardError`.
- Enforced BEFORE reading member bytes (walks the ZipInfo table first).
- Guards, in order:
  1. **Depth**: `depth < max_depth` (default 3).
  2. **Malformed archive**: `zipfile.BadZipFile` → `ArchiveGuardError("malformed_archive")`.
  3. **Entry count**: `len(infos) ≤ max_entries` (default 512).
  4. **Path safety** (per member): reject absolute (`/...`, `C:...`), traversal (`../`, `..\\`), or empty segments → `unsafe_member_name`.
  5. **Per-entry expanded size**: `info.file_size ≤ max_entry_bytes` (default 16 MB).
  6. **Compression ratio**: `file_size / compress_size ≤ max_compression_ratio` (default 200).
  7. **Running total expanded size**: `Σ file_size ≤ max_total_bytes` (default 50 MB).
- Structured error surface: `ArchiveGuardError.to_dict()` → `{error: "archive_guard", reason: <token>, …}`.
- Wired at `backend/routers/ops.py::upload` — inline `zipfile.ZipFile(...)` block replaced. On breach, upload returns HTTP 200 with structured `archive_refused` block (fail-loud without disrupting the analyst-facing upload response contract).

### 4.7 · Fail-loud archive failure handling
- Every guard raises `ArchiveGuardError` with a stable snake_case reason and diagnostic detail.
- Response includes exact refused member (truncated to 200 chars), measured size / ratio, and configured limit.
- No partial-extract state left behind (in-memory only; no filesystem writes on user input — see §9 residual).

## §5 · Exact limits (as shipped)

| Control | Env var | Default |
|---|---|---|
| CORS credentials in wildcard mode | (forced) | `False` |
| Login max failures | `NIVX_LOGIN_RATE_MAX_FAILS` | `5` |
| Login window | `NIVX_LOGIN_RATE_WINDOW_SEC` | `300` s |
| Login lockout | `NIVX_LOGIN_RATE_LOCKOUT_SEC` | `900` s |
| Archive max depth | `NIVX_ARCHIVE_MAX_DEPTH` | `3` |
| Archive max entries | `NIVX_ARCHIVE_MAX_ENTRIES` | `512` |
| Archive max total expanded bytes | `NIVX_ARCHIVE_MAX_TOTAL_BYTES` | `50 * 1024 * 1024` (50 MB) |
| Archive max per-entry expanded bytes | `NIVX_ARCHIVE_MAX_ENTRY_BYTES` | `16 * 1024 * 1024` (16 MB) |
| Archive max compression ratio | `NIVX_ARCHIVE_MAX_COMPRESSION_RATIO` | `200` |

Rationale: existing `/api/upload` client cap is 256 KB, existing middleware body cap is 512 KB default / 50 MB whitelisted. Setting max_total_bytes = 50 MB matches the largest legitimate upload path. Max_entries = 512 covers Office documents (typical DOCX ~15 entries, complex PPTX ~120). Ratio cap 200:1 rejects any plausible zip-bomb while comfortably allowing DEFLATE-heavy text (typical ratio 3-10:1).

## §6 · Affected files / modules

New:
- `backend/security/__init__.py`
- `backend/security/cors.py`
- `backend/security/rate_limit.py`
- `backend/security/archive_guard.py`
- `backend/tests/canonical/api/test_p0_security_hardening.py`

Modified (minimal, focused):
- `backend/server.py` — CORS middleware wiring (L415-431)
- `backend/routers/auth.py` — login handler adds rate-limit guard
- `backend/routers/ops.py` — `/api/upload` archive-extract replaced with `safe_iter_zip_members` + `archive_refused` in response

No other file touched.

## §7 · Security test cases (22 tests · all passing)

| Class | Tests | Result |
|---|---:|---|
| `TestCorsPolicy` — wildcard forces credentials-off, explicit allow-list grants credentials, whitespace strip | 4 | ✅ |
| `TestSlidingWindowLimiter` — normal, repeated-failures, success-clears, lockout-expires, independent-keys | 5 | ✅ |
| `TestArchiveGuard` — normal zip, malformed, entry-count, total-size, entry-too-large, ratio, traversal (absolute / relative / backslash), depth, defaults conservative, guard-error dict, hostile-doesn't-crash-worker | 13 | ✅ |

Command: `pytest backend/tests/canonical/api/test_p0_security_hardening.py` → **22 passed in 1.52 s**.

## §8 · Regression tests

Full canonical API suite: **136 passed · 5 skipped · 0 failed in 184.77 s** (previous baseline: 114 pass / 5 skip → +22 new tests, zero regressions).

Suites explicitly verified:
- P0.2 evidence chain
- P0.3 payload firewall (10-key allowlist)
- Sample1 immutability guard
- Workspace isolation guard
- Investigation-results payload shape
- DIE Timeline MVP
- DIE Query/Hunt
- Report determinism (Markdown + STIX + envelope signature)

## §9 · Attack-case runtime evidence

Executed against the live pod at `https://greeting-app-5782.preview.emergentagent.com`.

### 9.1 · Login brute-force
```
attempt 1 → HTTP 401 (invalid credentials)
attempt 2 → HTTP 401
attempt 3 → HTTP 401
attempt 4 → HTTP 401
attempt 5 → HTTP 429  { "error": "rate_limited", "reason": "throttled", "retry_after_seconds": 900 }
attempt 6 → HTTP 429  { "error": "rate_limited", "reason": "locked", ... }
attempt 7 → HTTP 429
```
✅ Backend healthy after burst (`/api/health → 200`).

### 9.2 · Archive attacks

| Fixture | Expected | Observed |
|---|---|---|
| `clean.zip` (1 entry, 129 B) | pass | ✅ `archive_refused: None` |
| `tiny_bomb.zip` (700 tiny entries) | refused | ✅ `entry_count_exceeded` (`entries=700, max_entries=512`) |
| `ratio_bomb.zip` (5 MB zeros → 4988 B compressed, ratio ≈ 1026:1) | refused | ✅ `compression_ratio_exceeded` (`ratio=1025.85, max_ratio=200`) |
| `trav.zip` (member `../../etc/passwd`) | refused | ✅ `unsafe_member_name` |

Backend `/api/health → 200` after all four uploads.

## §10 · Protected surfaces — confirmation

| Surface | State |
|---|---|
| RC5/DIE canonical pipeline (`services/die/*`, `canonical/*`) | 🟢 UNCHANGED |
| Workspace behaviour (`WorkspacePage.jsx`, `/api/die/*` contract) | 🟢 UNCHANGED |
| IKG (`backend/v2/investigation/ikg.py`) | 🟢 UNCHANGED |
| Verdict Engine v3 (`backend/v2/verdict/*`) | 🟢 UNCHANGED |
| Case Engine (`backend/v2/case_engine/*`) | 🟢 UNCHANGED |
| Adapters (`backend/v2/routers/ingest.py`) | 🟢 UNCHANGED |
| Artifact Store (`backend/v2/artifact_store/*`) | 🟢 UNCHANGED |
| Routes — 466 method-routes total | 🟢 UNCHANGED (no add / delete / rename / deprecation) |
| Mongo schemas — 64 collections | 🟢 UNCHANGED |
| Feature flags (`NIVX_FLAG_*`) | 🟢 UNCHANGED (no new flags introduced; env vars used) |
| Deterministic-report contract | 🟢 UNCHANGED (determinism CI still green) |
| Report semantics | 🟢 UNCHANGED |
| Existing TI functionality | 🟢 UNCHANGED |
| Existing investigation flows | 🟢 UNCHANGED |

## §11 · Residual risks (documented, not implemented)

- **Same-process parser isolation** — PE (`pefile`), DOCX/PPTX/XLSX (`zipfile` + XML), shellcode (`capstone` disassembly), RC4 / crypto peels all execute inline in the FastAPI event loop. A malformed binary can still panic the parser and consume the worker. Sandbox / subprocess isolation is its own P2+ session.
- **Backup / retention TTL** — Mongo has no TTL indices verified; unbounded growth is possible. Owner-side operations concern.
- **Multi-tenant** — single-tenant. Not in scope.
- **Prompt-injection via LLM narrate** — LLM prompts include analyst input; LLM narrate is `object.narrative` only and CANNOT introduce new ATT&CK techniques (P0.2 chain still gates). But the narrative text itself is untrusted.
- **In-memory rate-limit state** — single-worker uvicorn today makes this authoritative; a future multi-worker deployment needs Redis-backed shared state. Interface stable.
- **Nested-archive recursion beyond depth-1** — `safe_iter_zip_members` accepts `depth` from the caller. The current `/api/upload` only calls it at `depth=0` (never recurses into a member archive). If a future path chooses to recurse, it must pass `depth+1`.
- **Zip64 large-archives** — supported by Python `zipfile`; caps still apply on ZipInfo metadata BEFORE bytes are read.

## §12 · Follow-up items intentionally NOT implemented

- Server-Side File Mode (P1)
- Sysmon / EVTX Adapter (P2)
- Sandbox / subprocess isolation for hostile-input parsers
- Multi-tenant / SSO / SAML
- Structured logging + Prometheus / OTEL
- Deletion of DEPRECATED / DUPLICATE routes (owner sign-off pending)
- PDF determinism normaliser
- Route classification 2nd-pass (87 UNKNOWNs)
- TweetFeed integration
- Any `NIVX_FLAG_*` change

## §13 · Explicit PASS / FAIL verdict

**🟢 P0 SECURITY HARDENING GATE: PASS**

All seven controls implemented, all seven verified with unit tests, all four runtime attack cases produced the expected refusal, canonical API suite unchanged at 136 pass / 5 skip / 0 fail, protected surfaces confirmed unchanged.

## §14 · P1 readiness

**Is NivXRay now ready to begin P1 Server-Side File Mode?**

**YES.**

Why:
- The archive-bomb / recursion / count / size / ratio / path-traversal boundary is now enforced. Expanding the input surface (larger files, telemetry adapters) inherits the same `safe_iter_zip_members` primitive.
- The CORS surface is spec-compliant.
- Brute-force resistance on `/api/auth/login` is measurable.
- The determinism contract still holds — Markdown + STIX + envelope signature byte-identical across re-renders.
- No shadow subsystem was promoted; no route was changed; no schema was altered.

The next implementation session can open on **P1 Server-Side File Mode** (ADR-0008 §5.2) without carrying an ingestion-boundary risk debt into it.

---

## §15 · Completion Report (for owner review)

### STATUS
🟢 **P0 SECURITY HARDENING GATE — PASS**

### CHANGES
```
NEW:
  backend/security/__init__.py
  backend/security/cors.py
  backend/security/rate_limit.py
  backend/security/archive_guard.py
  backend/tests/canonical/api/test_p0_security_hardening.py

MODIFIED:
  backend/server.py         (CORS middleware, +7 lines)
  backend/routers/auth.py   (login rate-limit guard, +45 lines)
  backend/routers/ops.py    (/api/upload safe-extract swap, ~35 lines)
```

### SECURITY CONTROLS
| Control | Implemented | Tested | Evidence |
|---|---|---|---|
| Explicit CORS origins | ✅ | ✅ | `test_p0_security_hardening.py::TestCorsPolicy` + startup log `CORS policy: origins=1 wildcard=True credentials=False` |
| Login rate-limit | ✅ | ✅ | `TestSlidingWindowLimiter` (5 tests) + runtime attack §9.1 |
| Zip decompression-bomb protection | ✅ | ✅ | `test_compression_ratio_exceeded` + runtime `ratio_bomb.zip` §9.2 |
| Archive recursion / depth | ✅ | ✅ | `test_depth_limit_enforced` |
| Archive file-count | ✅ | ✅ | `test_entry_count_exceeded` + runtime `tiny_bomb.zip` §9.2 |
| Archive expanded-size | ✅ | ✅ | `test_total_size_exceeded` + `test_entry_too_large` |
| Fail-loud / safe failure | ✅ | ✅ | `test_malformed_archive_fails_loud` + `test_hostile_archive_does_not_crash_worker` + runtime `trav.zip` §9.2 |

### EXACT LIMITS
Listed in §5 above.

### SECURITY TESTS
- Added: 22
- Passed: 22
- Failed: 0
- Skipped: 0

### REGRESSION TESTS
Full canonical API suite: **136 passed · 5 skipped · 0 failed** (was 114 / 5 before this session). Zero regression.

### PROTECTED SURFACES
See §10 — all UNCHANGED.

### ATTACK CASE RESULTS
See §9.1 (login) and §9.2 (archive). All four expected outcomes matched observed.

### RESIDUAL RISKS
See §11. Same-process parser isolation is the most significant remaining risk; documented for a future P2+ session.

### P1 READINESS
See §14. **YES.**

*End of ADR-0010b · Session-10 P0 close.*
