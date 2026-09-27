# WINDOWS INSTALLER · RUN 36297148790 FAILURE — INVESTIGATION + FIX

Mode: source + CI + tests only. No production backend/DB/data change, no
token minted or consumed, no re-enrolment, no endpoint action,
`ep_1989031c8c1d0085812f` untouched. No acceptance assertion weakened.

## 1 · What the failed run tells us (read-only)

```
RUN 36297148790   job 108558003276   commit ba980ca4651aab1534e01ecb3ae492e96dc1ee87
 4 Build installer                                          success  31s
 5 Verify artifact contract                                  success   3s
 6 Service host unpacks from the installer                   success   2s
 7 SCM command line is recognised (not the installer CLI)    success   1s
 8 Real Windows SCM lifecycle (acceptance gate)              FAILURE  61s
 9 Remove the CI service if the gate failed                  success   1s
10 upload-artifact                                          skipped   (correct — nothing published)
check-run annotation: "Process completed with exit code 1"  (no detail)
```

Job logs are **403** to me (`Must have admin rights to Repository`), so the
failing assertion text is NOT in my hands and is not quoted here.

Inference from the step budget, which is exact: the two `sc.exe query` polls
allow **90 s**, the two `service.log` polls allow **60 s**. The step lasted
**61 s**, so a 60 s *service.log* poll expired and no 90 s poll did.
Therefore:

- CREATE, START and **RUNNING were reached** (fast — `sc query` matched).
- The failure is `service.log` **not present / not complete at the path CI
  checked** (`%ProgramData%\NivXForge\sensor\service.log`).

## 2 · Root cause (hypothesis, mechanism verified in documentation)

`nivxforge_sensor.STATE_DIR` was resolved at import from
`os.environ["ProgramData"]`, with `/var/lib` as fallback.

- The **installer** runs elevated in an interactive session, where
  `ProgramData` exists → `C:\ProgramData\NivXForge\sensor`. `identity.json`
  was written there.
- The **service** runs as **LocalSystem**, inheriting its environment from
  `services.exe`. Microsoft's guidance is explicit that a service does not
  reliably carry the variables an interactive session has, and that
  ProgramData should not be located via the environment block.
- With the variable missing, `Path("/var/lib/NivXForge/sensor")` on Windows
  is **drive-relative** → `C:\var\lib\NivXForge\sensor`. The service would
  write `service.log` there — exactly the observed symptom.

**Why this matters far more than a log file:** the same divergence moves
`identity.json`, `outbox.jsonl`, `outbox.offset`, `channels.json`,
`policy.json` and the exclusion journal. The endpoint would have shown a
service in RUNNING state that could never find its credential and would
silently deliver nothing. The mandatory-diagnostics gate caught a
production-blocking defect one step before deployment.

This remains a **hypothesis** until the next run's evidence dump confirms
it; it is not presented as proven.

## 3 · Fix (deterministic, no gate relaxed)

`nivxforge_sensor.py`
- `_default_state_root()`: `ProgramData` → `ALLUSERSPROFILE` →
  `%SystemDrive%\ProgramData` → `/var/lib` (defence in depth).
- `use_state_dir(path)`: re-points **every** state path from one root —
  `identity.json`, `outbox.jsonl`, `outbox.offset`, `channels.json`,
  `policy.json`, `exclusion_enforcement.json` — not just the log.

`nivxforge_setup.py`
- `_install_service` now writes `--state-dir "<installer-resolved dir>"`
  into the service binPath. The installer decides; the service is told.
  Only a DIRECTORY is passed — no token, credential or secret ever reaches
  the command line.
- `_run_as_service` applies `sensor.use_state_dir()` **first**, before the
  diagnostics log, identity load, heartbeat, collection, policy sync and
  journal/queue access. It then records
  `state dir: <path> (explicit=True)`.
- `_argv_value()` shared by the service argv parsing; quotes stripped so a
  path containing spaces survives.
- `version` reports `state_dir` so the installer's answer can be compared
  externally.

## 4 · CI: evidence dump + two new proofs (existing contract unchanged)

Still mandatory, unchanged:
`CREATE → START → RUNNING → mandatory diagnostics → STOP → STOPPED →
mandatory stop diagnostics → DELETE`.

Added:
- the smoke script prints `INSTALLER_STATE_DIR=…`, and the gate fails if it
  is not the directory CI checks;
- **evidence dump printed BEFORE any log assertion**: `sc query`, `sc qc`,
  the expected `service.log` path, and a search for `service.log` under
  `%SystemDrive%\ProgramData\NivXForge`, `%SystemDrive%\var`,
  `System32\NivXForge`, `SysWOW64\NivXForge` and `%ProgramFiles%\NivXForge`
  — so a state-path failure is distinguishable from a service-state failure
  from the log alone. No credential content is read or printed;
- the gate fails unless the service's own diagnostics contain
  `state dir: <installer dir>` **and** `(explicit=True)`, i.e.
  **installer state dir == service state dir**, proved rather than assumed.

## 5 · Regression tests (92 passing in the installer suites, 13 new)

- binPath carries `--state-dir` = the installer's resolved dir; the service
  command line contains no secret shape and no `--token`.
- `_run_as_service` writes its diagnostics into the passed dir, proving the
  re-point happens before the first state-dependent line.
- every state path follows the root (identity, queue, offset, bookmarks,
  policy, enforcement journal) — "repointing only the log" is regressed
  explicitly.
- LocalSystem-like environments: `ProgramData` absent → `ALLUSERSPROFILE`;
  both absent → `%SystemDrive%\ProgramData`; bare env → `/var/lib`.
- explicit `--state-dir` beats the environment.
- CI contract: `INSTALLER_STATE_DIR`, the equality assertion, the
  `explicit=True` proof, and that the evidence dump precedes the assertions.

## 6 · Status

Committed locally; awaiting "Save to Github" and the rerun. No endpoint
instructions, no artifact download recommended — the previous artifact was
correctly not published.
