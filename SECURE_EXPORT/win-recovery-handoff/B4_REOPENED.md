# B4 REOPENED · the recorded endpoint id is not derivable from the ProcessorId

**Status: HOLD. Do not run the enrolment.** Found 2026-10-19 while verifying
that the PowerShell identity-recomputation snippet in the execution checklist
actually reproduces the platform's arithmetic. It does — and the result
contradicts the accepted baseline.

## The arithmetic

The platform mints the identity server-side, in
`backend/edr_plane/contracts/identity.py`:

```python
def _iid(prefix, *parts):
    digest = hashlib.sha256("\x1f".join(... parts ...).encode()).hexdigest()
    return f"{prefix}_{digest[:20]}"

# precedence: hw (processor_id) > guid (machine_guid) > iid (device_iid) > host
return _iid("ep", tenant_id, kind, val)
```

Applied to the verified facts:

```
tenant      ten_e759b7288598bd882e3dcac49d
ProcessorId BFEBFBFF000806C1          (owner-verified on the laptop)

EndpointIdentity.mint(tenant_id=…, processor_id="BFEBFBFF000806C1")
  ->  ep_814199c05cfa49595311

recorded endpoint in the production store
  ->  ep_1989031c8c1d0085812f          (event_count 157,226)

MATCH: NO
```

Exhausted variants, all NO: processor id upper/lower case, trailing `\r`,
`\n`, `\r\n`, leading/trailing spaces; hostname `DESKTOP-A9HGFJJ` in
upper/lower case and with a dotted suffix; each of the four kind tokens
(`hw`, `guid`, `iid`, `host`) against each of those values; digest truncation
at 16/20/24/32; reversed part order; and the separator as `\x1f`, `|`, `:`,
`-` and empty.

`identity.py` has **one** commit in its entire history (2026-09-06) and has
not been modified since, so no older formula can explain the gap either. The
endpoint enrolled on **2026-09-27**, three weeks after that formula was
frozen.

## What that means

The recorded identity was almost certainly minted from **`machine_guid`** (or
`device_iid`) — which, given the precedence, means **`processor_id` was empty
or unreadable at the original enrolment** on 2026-09-27. The ProcessorId the
owner read today is genuine; it simply was not the attribute that minted this
endpoint.

The 0.3.0 sensor sends `processor_id` AND `machine_guid` in the same enrolment
body (`nivxforge_sensor.py:487-492`). The platform prefers `hw`. So running
the recovery today would:

1. spend the single-use token,
2. mint **`ep_814199c05cfa49595311`** — a new, empty endpoint,
3. take `edr_endpoints` from 2 to **3**,
4. write `identity.json` pointing at the new identity, and
5. drain the 1.99 GB backlog **into the new endpoint**, while
   `ep_1989031c8c1d0085812f` keeps its 157,226 events and stays silent
   forever.

That is exactly failure mode R4 in the checklist — and it would be caused by
the procedure, not caught by it. Step A2 is the gate that detects this, and
it currently FAILS.

## What this does NOT change

B1 (Gate 4 PASS), B2 (serving image and enrolment code identity) and B5 (the
production store, and the endpoint's presence in it with 157,226 events) are
unaffected. B3 is still prepared and still not a prerequisite. The installer
and the backend are fine — the open question is purely *which durable
attribute names this computer*.

## To resolve — read-only, in this order

**1 · Read the laptop's MachineGuid** (registry read, changes nothing):

```powershell
(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
```

Then recompute with the `guid` kind and compare:

```powershell
$t = "ten_e759b7288598bd882e3dcac49d"
$g = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
$b = [Text.Encoding]::UTF8.GetBytes("$t`u{1F}guid`u{1F}$g")
"ep_" + ([BitConverter]::ToString(
  [Security.Cryptography.SHA256]::Create().ComputeHash($b)
).Replace("-","").ToLower()).Substring(0,20)
```

If that prints `ep_1989031c8c1d0085812f`, the hypothesis is confirmed: the
identity is guid-derived.

**2 · Ask the platform what it recorded** (requested from the deployer,
read-only, pending): both endpoint ids in the tenant and whether either is
`ep_814199c05cfa49595311`; whether `device_iid` is populated on the recorded
endpoint; whether an enrolment audit record carries the machine attributes
used; and whether `edr_raw_events.endpoint_ref` has ever carried a third
identity.

## If the identity is guid-derived, the recovery needs a change first

The stock 0.3.0 installer **cannot** preserve a guid-derived identity: it
always sends `processor_id`, and the platform always prefers it. Options, in
increasing order of intrusiveness, none of them started:

* **Agent preflight (smallest correct fix).** On a re-enrolment where
  `identity.json` exists, compute the candidate ids locally from each
  available attribute — the mint needs no secret — and send only the
  attribute set that reproduces the RECORDED `endpoint_id`, refusing to enrol
  if none does. This also turns the silent-split hazard into a refusal for
  every future endpoint, not just this one. Cost: a source change, a new
  Windows build and a Gate 0-4 CI run.
* **Platform-side identity continuity.** Let enrolment recognise that a
  presented attribute set includes the guid that already names an enrolled
  endpoint in that tenant, and keep the existing identity. More invasive; it
  touches the identity contract and needs its own security review.
* **Do not re-enrol; retire and re-adopt.** Accept a new identity, keep the
  old record as history, and lose continuity of the 157,226 events against
  the live computer. Only if the owner decides the history need not follow
  the machine.

**Nothing above has been implemented.** The decision is the owner's once
step 1 confirms which attribute names this computer.
