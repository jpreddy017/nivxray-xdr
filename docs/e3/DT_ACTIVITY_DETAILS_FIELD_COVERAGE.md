# DT V3 — Activity Details field coverage (2026-10-02)

Source of truth: `apps/nivxray-xdr/src/nivxforge/trajectory_v3/amp/fields.js` (`buildSections`, reasons `R.*`).
Any field without a value goes into **"Not collected for this event (N)"** with one exact reason. It is never left blank, and never defaulted to "Clean" or "Malicious".

Legend for "Day one":
- **KUSHU** = present in the production page's own `/api/edr/endpoints/{id}/trajectory` rows today, so it populates from a read-only KUSHU export with no E1 change.
- **E1-PRJ** = present in the raw observation but dropped by E1's normalizer/projection. E1 must add it to the projection.
- **S-n** = sensor telemetry gap. Canonical S-1..S-7 are in `DT_AMP_PARITY_GAP_AUDIT.md` §3; S-8..S-12 are added here.
- **TI** = needs the E1 TI live switch-on (`DT_I1E_TI_DESIGN.md`). Until then it shows "provider not configured" and disposition stays `Unknown`.
- **E1-RESP** = needs response-plane evidence (enforcement/quarantine records).
- **WIN** = derived from another event (e.g. the process_create); only available when that event is inside the loaded window.

## File (execute / create / modify / delete / move)
| Field | Day one | Reason when absent |
|---|---|---|
| File name, Full path | KUSHU | not provided by source |
| SHA-256 (executed image) | KUSHU (`raw.process_image_hashes.sha256`, Sysmon 1) | not provided by source |
| SHA-256 (file event) | S-3 | not collected by sensor (S-3) |
| SHA-1, MD5 | S-11 | not collected by sensor (S-11: hash config is SHA-256 only) |
| File size | S-10 | not collected by sensor (S-10) |
| File type | derived from name/extension (UI) | — |
| Signer / publisher, Signature status | S-8 | not collected by sensor (S-8) |
| First seen on this device, Prevalence | preview read `/trajectory/file-facts`; E1 must serve an equivalent read over the authoritative store | not provided by source |
| Created / dropped by | WIN | not provided by source (creating event outside the loaded window) |

## File disposition
| Field | Day one | Note |
|---|---|---|
| Disposition, Source, Assessed at, Provenance, History | TI | Shows `Unknown` + "provider not configured" until TI is live. The preview uses a **synthetic TI fixture**, labelled as such. History rows are retrospective; the original observation is unchanged. |

## Process / Parent process
| Field | Day one | Reason when absent |
|---|---|---|
| Name, PID, Process instance, Image path, User, Command line | KUSHU | not provided by source |
| Start time, Integrity level, Current directory, Image SHA-256 | KUSHU on process_create; WIN on other events | creating event outside the loaded window |
| End time | S-7 | not collected by sensor (S-7) |
| Session | E1-PRJ (Sysmon 1 `LogonId`/`TerminalSessionId`) | E1 normalizer drops it |
| Parent name/PID/instance/image path | KUSHU | not provided by source |
| Parent SHA-256 | WIN | parent creation outside the loaded window |
| Causal state | derived (PROVEN / CORRELATED / UNRESOLVED) | — |
| Image / parent disposition | TI | `Unknown` |

## Child processes & activity
Derived from the loaded window only (counts and jump links). No external data.

## Detection
| Field | Day one | Reason when absent |
|---|---|---|
| Name, Engine, Rule ID, Rule version, Confidence, Matched evidence | KUSHU when the page row carries detection/findings; the export snippet also captures `observation-narrative` for detection events (`e3_prod_detail`) | not provided by source |
| Behavioral Analytics (edr_ml) | E3 ML (TESTING) | not emitted for this event |
| Exploit Prevention, System Process Protection, Malicious Activity Protection | S-12 | not collected by sensor (S-12) |

## MITRE ATT&CK
Rule metadata (KUSHU when present). Links go to `attack.mitre.org/techniques/Txxxx/yyy/`. Shows the note "A technique mapping is not a malicious verdict." No rule mapped → "not provided by source (no rule mapped this event)".

## Action taken / outcome
E1-RESP. With no evidence: "No enforcement/response evidence recorded." Quarantine/blocked wording appears **only** from an enforcement record. Approval requests made on this page show `APPROVAL_REQUESTED (not executed)`.

## IOC / threat intel
TI. The preview overlay is a synthetic fixture. With no match: "No indicator match recorded".

## Network
| Field | Day one | Reason when absent |
|---|---|---|
| Protocol, Remote IP:port | KUSHU | not provided by source |
| Remote host / domain | KUSHU when Sysmon 3 `DestinationHostname` is present; otherwise correlated from a DNS answer in the window, labelled "(correlated DNS)" | not provided by source |
| Direction (`Initiated`), Local IP:port | E1-PRJ | E1 normalizer drops it |
| URL | not provided by source (Sysmon 3 has no URL) | not provided by source |
| Start / end / duration, Bytes in / out | S-9 | not collected by sensor (S-9) |
| Connections from this process to this destination | derived (window) | — |
| Reputation | TI | `Unknown` |

## DNS
Query name, answers, TLD and queried-by come from KUSHU (Sysmon 22). Record type is not provided by source (`QueryType` isn't projected; it's E1-PRJ).

## Registry
Key path, value name and data (truncated at 120 characters, with "more") come from KUSHU (Sysmon 13). The operation is `SetValue`, the only admitted registry event.

## Device control / USB
Class, vendor/product, serial, connect/disconnect and allowed/blocked. **No USB events on the current sensor.** The section renders only when a `usb_connect`/`usb_disconnect` event exists. Allowed/blocked needs enforcement evidence. Unit test: `tools/e3ui/fields.test.mjs`.

## System / sensor event
Event, previous/new value, policy/version, status and source for `policy_update`, `sensor_update`, `isolation_status`, `scan`, `reboot` and `sensor_service_status`. **None of these are emitted to the trajectory today.** The section renders only when one exists.

## Device context
Hostname, OS, sensor version and tenant come from KUSHU (computer header). Policy / mode is not provided by source.

## New sensor items (extend the gap audit §3)
- **S-8** Signer / signature status: Sysmon 1 has no signature fields. Needs Sysmon 7 `Signed/Signature/SignatureStatus` or a sensor Authenticode check.
- **S-9** Network bytes / duration: Sysmon 3 is connection-start only. Needs a flow-end/ETW network provider.
- **S-10** File size: Sysmon 11 has no size. The sensor must stat the file on create.
- **S-11** SHA-1 / MD5: the Sysmon hash config is SHA-256 only. Add `SHA1,MD5` to `HashAlgorithms` if wanted.
- **S-12** Exploit Prevention / System Process Protection / Malicious Activity Protection: there are no such engines on the NivXForge sensor.
