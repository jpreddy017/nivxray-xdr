# W2-1B · Security + PowerShell canonical evidence (2026-06)

Lane authorised by the owner alongside W2-R0: *"the real Windows validation
will soon begin producing Security and PowerShell telemetry — be ready to
turn that acquired telemetry into canonical evidence rather than merely
prove transport."*

## The gap that was actually blocking this

The W2-1 adapter delivers what Windows produced:
`Envelope.raw = {"xml": <EvtRender(EvtRenderEventXml)>, "channel": ...}`.

Every Windows DSM in `backend/detection_content/telemetry/` reads a
**decoded** document. So before this change:

* the rendered XML reached `supports()` as an opaque string;
* no DSM claimed it — including the Sysmon DSM, which was already marked
  analysis-supported but had only ever received flat JSON from the W1
  forwarder;
* `windows_security` / `windows_powershell` (the `declared_source` strings
  in `framework/windows_eventlog.py :: CHANNELS`) were absent from
  `services/source_routing.SOURCE_CATALOG`, so a delivery from those
  channels would have been refused `UNSUPPORTED_SOURCE`.

A channel could therefore be genuinely RECEIVING and report `NO_DSM`
forever. That is the failure this lane removes.

## What was built

| Component | File | Role |
|---|---|---|
| EVTX XML decoder | `backend/detection_content/telemetry/evtx_xml.py` | the ONE place rendered Windows XML becomes JSON. Interprets nothing, invents nothing, discards nothing (verbatim XML stays the authority) |
| Ingest decode gate | `backend/routers/xdr_ingest.py :: _document_for_pipeline` | decodes once, records the outcome under `_nivx.evtx_decode` so "not a Windows record" can never be confused with "a Windows record we could not read" |
| Security DSM widening | `backend/detection_content/telemetry/windows_security_dsm.py` | accepts rendered XML; coverage extended to 4648, 4672, 4720, 4726, 4732, 4776, 4698, 1102 (on top of 4688/4768/4769/4624/4625/4657). 1102 is normalized from `UserData`, not `EventData` |
| PowerShell DSM (new) | `backend/detection_content/telemetry/windows_powershell_dsm.py` | 4103/4104/4105/4106 + classic 400/403/500/501/600/800. `ContextInfo` and the classic positional `Data` block are both parsed |
| Registry + routing | `telemetry/registry.py`, `services/source_routing.py` | `windows-powershell-evd` registered; `windows_security` / `windows_powershell` / `powershell` resolve as ALIASES to the one catalog key permitted to interpret them |
| Two-state honesty | `apps/nivxray-xdr-collector/framework/windows_eventlog.py` | `ANALYSIS_SUPPORTED`: Security → normalization SUPPORTED / detection PARTIAL; PowerShell → normalization SUPPORTED / detection NOT AVAILABLE. Collection support and analysis support remain separate facts |

## Invariants deliberately preserved

* **No activity time is manufactured.** Neither the Security channel nor
  the PowerShell ETW channels carry an activity-occurrence field, so both
  DSMs declare `OBSERVATION_TIME` and leave `activity_occurred_at`
  `NOT_OBSERVED`. Guarded by `tests/test_d12_cross_dsm_activity_time.py`.
* **Command Intelligence stays PAUSED.** 4104 `ScriptBlockText` is carried
  verbatim as evidence. No decoding, deobfuscation or scoring happens in
  the DSM; CI remains a downstream consumer and is not invoked.
* **No attribution from a PID.** `System/Execution/ProcessID` is recorded
  as `PID_ONLY_NOT_AUTHORITATIVE`.
* **Actor ≠ target.** 4720/4726/4732/4698 keep the acting principal in
  `identity` and the account/group/task acted upon in
  `additional_fields`.
* **Tenant authority unchanged.** The authenticated delivery decides the
  tenant; a payload claim is recorded and not believed.
* **No fabricated telemetry.** Every test fixture is a format fixture and
  is labelled as one. Nothing claims to be real endpoint evidence.

## Verification (self-tested, no testing agent — owner instruction)

```
backend:   pytest tests/test_w2_windows_channel_dsms.py          33 passed
           pytest tests/test_d12_cross_dsm_activity_time.py
                  tests/test_p0_3_windows_logon_coverage.py     119 passed (with the above)
           pytest tests/test_d11 d13 d15 d21 phase2 telemetry
                  n1_zeek w1_forwarder                          229 passed, 14 skipped
collector: pytest tests                                         134 passed
```

Pre-existing failures NOT caused by this lane (verified by
`git stash`): `tests/test_xdr_data_sources_collectors.py` (20 setup
errors — owner-bootstrap auth unavailable in this pod).

Fixed while here: `test_d12`'s own guard
(`test_every_registered_dsm_is_covered_by_this_suite`) was already red —
`m365-unified-audit` had no temporal sample. It now has one.

End-to-end shape proof (`_raw_event_for_pipeline` on a real envelope):

```
DOCUMENT
4688 Security 'whoami /priv'
_nivx.evtx_decode = {'decoded': True, 'decoder_id': 'evtx-xml-decoder/1.0.0'}
malformed record   = {'decoded': False, 'code': 'EVTX_MISSING_EVENT_ID', ...}
```

## Still open in this lane

* Detection content for Security/PowerShell canonical evidence
  (`detection_coverage` is PARTIAL / NOT AVAILABLE and says so).
* DSMs for Defender, Task Scheduler, WMI-Activity, AppLocker, System,
  Application — acquired and preserved, reported `NOT YET SUPPORTED`.
* A real-endpoint proof of this chain is gated on W2-R2…W2-R6.
