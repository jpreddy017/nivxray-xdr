# W1 · PHASE 2.3 LOGGING-FORMAT HOTFIX

**Phase 2.3 real-Windows DryRun result accepted.** The substantive path is
proven on the genuine host: corrected artifact, SHA256 integrity, 5.1 parse,
5.1 **execution**, genuine Sysmon EventLog read, real EID 11 extraction,
envelope construction, top-level contract, verbatim raw evidence, 5-envelope
DryRun JSON — with credential read, network transmission and bookmark
advancement correctly NOT ATTEMPTED.

The logging defect is real and was mine. Root cause and the full blast radius
below.

---

## 1 · ROOT CAUSE

PowerShell's `-f` operator binds **tighter than `+`**, so

```powershell
Write-ForwarderLog WARN ("GAP RECORDED: records {0}..{1} were not delivered - " +
                "raise -MaxEvents or shorten -PollSeconds" -f
                ($AfterRecordId + 1), ($firstId - 1))
```

parses as

```powershell
"GAP RECORDED: records {0}..{1} were not delivered - " +
  ("raise -MaxEvents or shorten -PollSeconds" -f $a, $b)
```

`-f` is applied to the **second** literal, which has no placeholders, so the
arguments are silently swallowed and the first literal's `{0}..{1}` is printed
verbatim. Exactly what your run showed.

## 2 · BLAST RADIUS — three sites, not the two you saw

An AST sweep of every format expression in the file found the construct in
**three** places. The third is the one that mattered most:

| line | message | status |
| --- | --- | --- |
| 231 | `GAP RECORDED: records {0}..{1} …` | broken (you saw it) |
| 318 | `DRY RUN - {0} envelope(s) written to {1} …` | broken (you saw it) |
| 368 | `sent={0} accepted={1} duplicates={2} resumed={3} routing_blocked={4} reasoned={5} refused_recorded={6} collector_state={7}` | **broken, and never yet executed** |

That third line is the **receipt line for every authenticated batch** — the
one that reports accepted/duplicate/routing-blocked counts and the collector
state. Had we entered Phase 3 without this fix, the first real transmission
would have logged eight literal placeholders, i.e. no auditable record of
what the server actually accepted. The other eight format expressions in the
file were already correct and are unchanged.

All three are fixed by parenthesising the concatenation before `-f`. Rendered
with real values:

```
GAP RECORDED: records 4712..8999 were not delivered - raise -MaxEvents or shorten -PollSeconds
DRY RUN - 5 envelope(s) written to C:\ProgramData\NivXRay\state\dryrun-20260916T190000Z.json. Nothing was sent, no key was read, the bookmark was not moved.
sent=200 accepted=198 duplicates=2 resumed=0 routing_blocked=0 reasoned=198 refused_recorded=0 collector_state=CONNECTED
```

## 3 · TWO FINDINGS YOUR RUN ALSO EXPOSED (small, adjacent, flagged for your judgement)

Your output was `pending records after bookmark 0: 5000` **and** a GAP
warning. That combination revealed a second-order defect in the same code
path, so I corrected it rather than hand you a gap log that cries wolf. Both
changes are diagnostics-only — delivery, exactly-once and bookmark semantics
are untouched.

1. **False gap on a first run.** The gap test was
   `count >= MaxEvents AND firstId > bookmark + 1`. On a first run the
   bookmark is 0 and your channel's oldest surviving record is ~53 000
   (58 467 records, already rolled), so records "1..firstId-1" were reported
   as *not delivered* when they had **rolled out of the channel before the
   forwarder ever existed**. A gap must mean "we had a bookmark and the
   records after it are gone". With no bookmark it now logs the honest
   statement instead:
   `first run, no bookmark: the channel's earliest available record is 53467
   and the fetch window is 5000. Records before 53467 were never available to
   this forwarder and are NOT counted as a gap.`
2. **A dry run was writing `gap.jsonl`.** `-DryRun` must leave no state. The
   gap-file write is now guarded by `-not $DryRun`; the warning is still
   printed either way.

If you would rather revert either of these and keep this commit strictly to
the format strings, say so and I will split them out.

## 4 · THE REGRESSION GATE

`scripts/windows/Test-ForwarderFormatStrings.ps1` walks the AST of each `.ps1`
and fails on:

* a `+` whose right operand is a format expression (the precedence bug);
* `-f` applied to a string containing no `{n}`;
* a placeholder/argument count mismatch (e.g. `{0}..{7}` with 7 arguments);
* **and then renders every format string with synthetic arguments and fails
  if any `{n}` survives.**

Negative control — run against the **previous committed artifact**, it
reports precisely the three defects:

```
old_forwarder.ps1:231 FORMAT_BINDS_TO_RIGHT_OPERAND_ONLY
old_forwarder.ps1:318 FORMAT_BINDS_TO_RIGHT_OPERAND_ONLY
old_forwarder.ps1:368 FORMAT_BINDS_TO_RIGHT_OPERAND_ONLY
```

Against the corrected artifact and all three helper scripts: `FORMAT_OK`.
A test asserts the gate itself fails on a deliberately broken snippet — a
gate nobody has seen fail is not a gate.

## 5 · UNCHANGED (asserted by the source gate)

HTTPS-only guard · TLS 1.2 floor with the 1.3 attempt · no
certificate-validation callback · key-file ACL refusal · key absent from every
log/throw line · tenant authority · `declared_source: microsoft-sysmon` · the
7 supported event ids · verbatim EventData · `_nivx*` refusal ·
`source_event_id` format · bookmark advances only after the server accounted
for the chunk · `refused.jsonl` · receipt `data` unwrapping · exactly-once.

## 6 · RESULTS

```
W1 forwarder source/compatibility gate   24 passed   (was 16; +8 format/render/negative-control)
Forwarder contract test                  24 PASS / 0 FAIL
Regression (W1 field preservation, DCR-1, p0_f3, N1, N2.1, X1, source gate)
                                        191 passed, 1 skipped
```

## 7 · CORRECTED ARTIFACT

```
path              scripts/windows/NivXRay-SysmonForwarder.ps1
bytes             16214
lines             416
encoding          ASCII (0 non-ASCII bytes), no BOM, LF (0 CR bytes)
SHA256 (LF)       71c5c5949c470b9ae918b34ad6916877b3da86d3b66a0c7f432731b75d135cd3
SHA256 (CRLF)     3798cc8556188976ea4a7da05437e941c80bc9e059e2830053134f0b937ea7e6
SHA256 (CRLF+BOM) 0f5010808c7f3af154e4102b28177925c566794b7f166e59e990260bda395f92
supersedes        c969d5e0092dc5178ad522ec102979313c7864a3ff9264fd809724a1e0eacc5b
```

No collector, API credential, tenant configuration, `forwarder.json` or
`ingest.key` was created. `_COLLECTED_PRODUCTS` remains `{"linux"}`.

**STOP — corrected artifact handed off. W1 remains NOT CLOSED.**
