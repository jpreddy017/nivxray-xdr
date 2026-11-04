# TRACK B | E3 DETERMINISTIC DETECTION HARDENING — next step, EID5-independent

EID 5 is a bounded capability gap. Nothing below needs process termination,
and nothing below weakens `termination_state = UNKNOWN`.

Measured today against the runtime registry (`RUNTIME_DETECTION_RULES`,
read-only, no behaviour changed):

| measurement | value |
|---|---|
| runtime rules | 37 (Windows 23 · Linux 6 · Cloud 4 · Identity 3 · Hypervisor 1) |
| rules that DECLARE the fields they evaluate | 28 / 37 |
| rules declaring NOTHING (frozen `DECLARATION_DEBT`) | **9** — every detection they raise carries `declaration_state = NOT_DECLARED` and therefore **no citation** |
| declaration validation errors among declared rules | 0 |
| fixtures | 60 positive · 66 negative · every rule has both |
| rules that fire on a fully-empty canonical event | **0** (no fail-open at total absence) |
| rules that raise on a fully-empty canonical event | 0 |

## E3-A · close the declaration debt (P0 of E3)

`DET-EX-001, DET-IA-002, DET-DE-001, DET-DE-003, DET-LM-002, DET-IM-004,
DET-EM-002, DET-CC-002` evaluate real canonical fields but declare none, so
they can fire without being able to say WHY. Declare them against fields
that already exist, prove each declaration explains its own positive
fixtures (`citation_proof`), and shrink the ledger from 9 to 1.

`DET-PE-002` (AD CS 4886/4887) has no DSM and no source: it stays on the
ledger with its reason stated. A gap is closed by adding evidence, never by
weakening a declaration.

## E3-B · partial-absence negative controls (the real fail-closed proof)

The 66 existing negative fixtures test **wrong values**. They do not test
**absent** values. For every declared rule, take its positive fixture and
blank exactly the decisive declared field, then assert NO_MATCH — proving
an unobserved field can never behave as a match. This is the same principle
`termination_state = UNKNOWN` rests on, applied to every rule input.

## E3-C · collected-telemetry coverage map

A rule count is not coverage. Publish, per rule, `EVALUABLE_TODAY` or
`BLOCKED_ON_TELEMETRY(<class>)` against what the acceptance endpoint
actually collects (EID 1/3/11/12/13/22 on Windows; the Linux sensor lanes),
with EID 5 recorded as NOT_COLLECTED. Any rule that would need process exit
must declare that dependency rather than quietly under-firing.

Scope: server-side only. No endpoint change, no deployment, no detection
behaviour change without an owner review of the diff.
