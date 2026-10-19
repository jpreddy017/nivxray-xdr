# B4 · reopened, then CLOSED — and the defect was in my own check

**Resolution: B4 HOLDS. `ProcessorId BFEBFBFF000806C1` does reproduce
`ep_1989031c8c1d0085812f`. The recovery is safe to execute.**

This file is kept rather than deleted, because the wrong version of it was
circulated and because the mistake is worth not repeating.

## What I got wrong

I wrote a PowerShell snippet for the execution checklist that hashed the
**raw** ProcessorId:

```
sha256( tenant ␟ "hw" ␟ "BFEBFBFF000806C1" )[:20]  ->  ep_814199c05cfa49595311   WRONG
```

and, when it did not match the recorded id, I halted the recovery and
reported that the identity must be `machine_guid`-derived. The arithmetic was
right; **the input was not**. The sensor never sends the raw ProcessorId.
`nivxforge_sensor._machine_facts()` sends a digest of it:

```python
processor = _wmic("cpu", "ProcessorId")
"processor_id": hashlib.sha256(processor.encode()).hexdigest()[:24] if processor else None
```

So the value the platform mints from is the **24-hex SHA-256 prefix**, and
the real chain is two hashes deep:

```
raw ProcessorId        BFEBFBFF000806C1
sensor sends           166b4c9c1060a787586b119a      = sha256(raw)[:24]
platform mints         sha256( tenant ␟ "hw" ␟ 166b4c9c1060a787586b119a )[:20]
                    ->  ep_1989031c8c1d0085812f
recorded            ->  ep_1989031c8c1d0085812f       MATCH
```

Verified twice: by hand, and by calling `EndpointIdentity.mint()` — the
platform's own function — with the digest the sensor would send.

## Why the elimination argument looked so convincing

Every independent fact I had was true, and every one of them was consistent
with the wrong conclusion:

* `device_iid` is null on the endpoint → not iid-derived. (True.)
* the stored hostname `DESKTOP-A9HGFJJ` does not reproduce the id → not
  host-derived. (True.)
* the raw ProcessorId does not reproduce the id → "not hw-derived". **This
  was the false step** — it excluded the right answer by testing the wrong
  input.
* `guid` was then the only kind left, so the conclusion followed cleanly from
  a premise that was wrong.

The deployer's read-only query agreed that nothing in the database records
the minting attribute, which is accurate and was no help: with the attribute
unrecorded, the only way to identify it is to reproduce it, and I was
reproducing it from the wrong value. A confirming data point from the
platform would not have caught this; only re-reading the agent's own code
did.

## What this invalidates

* The HOLD I placed on the recovery — **lifted**.
* The claim that the identity is `machine_guid`-derived — **withdrawn**.
* The proposal to add an agent-side attribute-selection preflight, a new
  Windows build and a CI run — **withdrawn as unnecessary**. The stock 0.3.0
  artifact, with Gate 4 PASS on run 39144147851, re-mints the correct
  identity.
* The deployer's suggested fallback of a production data migration to
  re-attribute `edr_raw_events` from a newly minted endpoint back onto the
  old one — **not needed, and should not be done.** No new endpoint will be
  created.

## What it does NOT change

B1, B2, B5 and the B3 assessment are untouched. `ep_814199c05cfa49595311`
has never appeared in `edr_raw_events` and never will, because it is an
artefact of my mis-stated formula, not an identity the sensor can produce.

## The corrected pre-flight check

`EXECUTION_CHECKLIST.md` step A2 now hashes twice, in the order the system
does. The check is still mandatory and still the only guard before the token
is spent — it simply now computes what the sensor actually sends.

## The one genuine finding left from this detour

`edr_endpoints.event_count` is **157,226** while `edr_raw_events` holds
**157,199** rows for this endpoint — **27 fewer**. Pre-existing, unrelated to
the recovery, and not explained: the counter and the stored rows disagree.
Candidates are acknowledged-but-dropped events, a dedup path that increments
before insert, or rows aged out. Worth a look afterwards; it does not block.

Also observed, for context: the other endpoint in the tenant,
`ep_a67be48d5b4e01d4d9e8`, holds 1,719,950 of the 1,877,149 raw events and
accounts for nearly all of the processing-queue depth.
