# G1 · STEP 2 reviewed-code manifest (content identity)

`Save to Github` does not guarantee that local commit SHAs survive,
so a commit id is not a reliable anchor for "the Windows host is
running the reviewed code". These SHA-256 content hashes are.

**This manifest supersedes nothing.** The Step 1 manifest
(`G1_REVIEWED_CODE_MANIFEST.md`, 10 files) remains the historical
evidence for the read-only pre-flight that already ran. This one
covers the 26 files G1 **Step 2** depends on, including the
owner-accepted S1-S5 correctness closure.

Generated 2026-09-22T15:00:33.311928+00:00 · local branch `feature/rc2-alignment`
· local HEAD `9b8a9d65c1c9baf863733268753019131f605723`.

## Windows pre-flight (Step 1 code, unchanged)

| SHA-256 | Path |
|---|---|
| `3D43E6235BBBEB631EAC11B96AF10C5AF14B6227C93ABDBCD88F966CAD9C4AF7` | `scripts/windows/g1/Get-NivXRayG1Preflight.ps1` |
| `055A28E5FA8EBDBAA25ABE97E33B2C776E347CEC20DD536D4479942132EF598C` | `scripts/windows/g1/README_G1_STEP1_PREFLIGHT.md` |

## Native Windows acquisition (NivXForge EDR)

| SHA-256 | Path |
|---|---|
| `EC747671ED0156C3814C458A2A07C41B98901620E506842040E77C04F72A39E6` | `apps/nivxray-xdr-collector/framework/windows_eventlog.py` |
| `C0B480269387541804196ACEDBC89E1880A8BD92F9C22BFA866D756EED63179B` | `apps/nivxray-xdr-collector/framework/windows_bookmarks.py` |
| `B5ED4F5524A89C53D9CBF2BA8E6852C15C09C94AABC2F3EB4C199EBEAA4AB280` | `apps/nivxray-xdr-collector/framework/collector_identity.py` |
| `EA61D2F36A2A50567E3CC9647E0A3D1A7895CC814CE1AA8FE67741FC07E131B1` | `apps/nivxray-xdr-collector/framework/runtime.py` |
| `2E764F049893CCD7DD94DE485C8E0BE254CE00B64274E008FB3F93610C30F147` | `apps/nivxray-xdr-collector/framework/scheduler.py` |
| `985EF41B94E978925B0716A61C008A8230AD307BB1C4426CE3CDEDE6B8C34250` | `apps/nivxray-xdr-collector/framework/outbox.py` |
| `0D19BF66FD362516DCE0E248F501715CE9E049ADC57FA5277E74E1CDA5C88045` | `apps/nivxray-xdr-collector/framework/delivery.py` |
| `2E456FF2EBD68B01447937188F2EB5E74F42524135A27B18B4E2D2D3FB0FCCA7` | `apps/nivxray-xdr-collector/framework/delivery_worker.py` |
| `F88D42097645C603B4263D0321BF51A34B9C4B9018CE4BA76F77EB0E20597357` | `apps/nivxray-xdr-collector/framework/store.py` |
| `A58717A87D907495904E94D7D8651CE63DD35BD9444D4AB3D9C22100D9566FE8` | `apps/nivxray-xdr-collector/framework/authz.py` |
| `A4A308FA8A6DDDE2DDB4A4901E8DF9745B1A634CDFE2A2D88257B276B08A8F6B` | `apps/nivxray-xdr-collector/main.py` |
| `7917C53D96BCC9F4117D76FA8F028A0F35B6B2ECD2E375760C8340755F68CB20` | `apps/nivxray-xdr-collector/routes/connectors.py` |

## S3/S4/S5 · Windows runtime + state contract

| SHA-256 | Path |
|---|---|
| `28DAEBC7FEE8BED509E6F25724B92C467580E48CFF5E157BA956E898793910A2` | `apps/nivxray-xdr-collector/framework/state_paths.py` |
| `3FAD9D24C681C95D0A16A6A6A19D829D7E448BE6F4FC0B7D4EEF8442766E2665` | `apps/nivxray-xdr-collector/requirements.txt` |
| `F0ED4BD460AA1066E3F800F37A904BCB8CCFBF0D6AEEBB41649182F0F98446DD` | `apps/nivxray-xdr-collector/requirements-windows.txt` |
| `74E829EFDA2FB84A00205562E5BA3CC3885A62EA14188326A6D809B6858FEB74` | `apps/nivxray-xdr-collector/WINDOWS_RUNTIME.md` |
| `1D3E6DE9CB63AFFC06D01609C8B6B66F1F15EE922DF3EC4E557D10656F542FA4` | `apps/nivxray-xdr-collector/tests/test_g1_windows_runtime_contract.py` |
| `754764F133895435844DB4D7E795B052B7C5E9368371C159E901A3D1037847B3` | `apps/nivxray-xdr-collector/tests/test_g1_evtsubscribe_contract.py` |

## S1 · three-clock independence (server)

| SHA-256 | Path |
|---|---|
| `EEEC91EC55707BD9846BCF6568EA2D5A38BD880EDF7AF3892B8384F8A5B28913` | `backend/services/ingest_provenance.py` |
| `B3D43A2A0401B2434B5D2CF2636E2D31957E55BD85F0DCF59A6508B2A6FC3D3C` | `backend/tests/test_g1_s1_clock_independence.py` |

## S2 · windows-eventlog protocol identity (server)

| SHA-256 | Path |
|---|---|
| `D898C793C048DD1100E227415BECF83BA426CE46964A7F6AF4A2B68D8D1893ED` | `backend/routers/xdr_collectors.py` |
| `BFA551FEBFB5FCD548A05C278E515610534DE8A3C77423716780CF07D3DCD586` | `backend/routers/xdr_data_sources.py` |
| `32935FE2AD85A24B0822EF65A24FC689A12FFF2D12E32704976E8F3EC21E9B61` | `backend/lib/collector_catalog.py` |
| `EB94E38DA8ECFCF342E58072ECDE1125EA6DB690EAABC17B5770FD12842E817C` | `backend/tests/test_g1_s2_windows_eventlog_protocol.py` |

## Verify on the Windows host (read-only, before anything runs)

The handoff block does this automatically and STOPS on any MISSING
or MISMATCH. The machine-readable form used there:

```json
{
  "scripts/windows/g1/Get-NivXRayG1Preflight.ps1": "3D43E6235BBBEB631EAC11B96AF10C5AF14B6227C93ABDBCD88F966CAD9C4AF7",
  "scripts/windows/g1/README_G1_STEP1_PREFLIGHT.md": "055A28E5FA8EBDBAA25ABE97E33B2C776E347CEC20DD536D4479942132EF598C",
  "apps/nivxray-xdr-collector/framework/windows_eventlog.py": "EC747671ED0156C3814C458A2A07C41B98901620E506842040E77C04F72A39E6",
  "apps/nivxray-xdr-collector/framework/windows_bookmarks.py": "C0B480269387541804196ACEDBC89E1880A8BD92F9C22BFA866D756EED63179B",
  "apps/nivxray-xdr-collector/framework/collector_identity.py": "B5ED4F5524A89C53D9CBF2BA8E6852C15C09C94AABC2F3EB4C199EBEAA4AB280",
  "apps/nivxray-xdr-collector/framework/runtime.py": "EA61D2F36A2A50567E3CC9647E0A3D1A7895CC814CE1AA8FE67741FC07E131B1",
  "apps/nivxray-xdr-collector/framework/scheduler.py": "2E764F049893CCD7DD94DE485C8E0BE254CE00B64274E008FB3F93610C30F147",
  "apps/nivxray-xdr-collector/framework/outbox.py": "985EF41B94E978925B0716A61C008A8230AD307BB1C4426CE3CDEDE6B8C34250",
  "apps/nivxray-xdr-collector/framework/delivery.py": "0D19BF66FD362516DCE0E248F501715CE9E049ADC57FA5277E74E1CDA5C88045",
  "apps/nivxray-xdr-collector/framework/delivery_worker.py": "2E456FF2EBD68B01447937188F2EB5E74F42524135A27B18B4E2D2D3FB0FCCA7",
  "apps/nivxray-xdr-collector/framework/store.py": "F88D42097645C603B4263D0321BF51A34B9C4B9018CE4BA76F77EB0E20597357",
  "apps/nivxray-xdr-collector/framework/authz.py": "A58717A87D907495904E94D7D8651CE63DD35BD9444D4AB3D9C22100D9566FE8",
  "apps/nivxray-xdr-collector/main.py": "A4A308FA8A6DDDE2DDB4A4901E8DF9745B1A634CDFE2A2D88257B276B08A8F6B",
  "apps/nivxray-xdr-collector/routes/connectors.py": "7917C53D96BCC9F4117D76FA8F028A0F35B6B2ECD2E375760C8340755F68CB20",
  "apps/nivxray-xdr-collector/framework/state_paths.py": "28DAEBC7FEE8BED509E6F25724B92C467580E48CFF5E157BA956E898793910A2",
  "apps/nivxray-xdr-collector/requirements.txt": "3FAD9D24C681C95D0A16A6A6A19D829D7E448BE6F4FC0B7D4EEF8442766E2665",
  "apps/nivxray-xdr-collector/requirements-windows.txt": "F0ED4BD460AA1066E3F800F37A904BCB8CCFBF0D6AEEBB41649182F0F98446DD",
  "apps/nivxray-xdr-collector/WINDOWS_RUNTIME.md": "74E829EFDA2FB84A00205562E5BA3CC3885A62EA14188326A6D809B6858FEB74",
  "apps/nivxray-xdr-collector/tests/test_g1_windows_runtime_contract.py": "1D3E6DE9CB63AFFC06D01609C8B6B66F1F15EE922DF3EC4E557D10656F542FA4",
  "apps/nivxray-xdr-collector/tests/test_g1_evtsubscribe_contract.py": "754764F133895435844DB4D7E795B052B7C5E9368371C159E901A3D1037847B3",
  "backend/services/ingest_provenance.py": "EEEC91EC55707BD9846BCF6568EA2D5A38BD880EDF7AF3892B8384F8A5B28913",
  "backend/tests/test_g1_s1_clock_independence.py": "B3D43A2A0401B2434B5D2CF2636E2D31957E55BD85F0DCF59A6508B2A6FC3D3C",
  "backend/routers/xdr_collectors.py": "D898C793C048DD1100E227415BECF83BA426CE46964A7F6AF4A2B68D8D1893ED",
  "backend/routers/xdr_data_sources.py": "BFA551FEBFB5FCD548A05C278E515610534DE8A3C77423716780CF07D3DCD586",
  "backend/lib/collector_catalog.py": "32935FE2AD85A24B0822EF65A24FC689A12FFF2D12E32704976E8F3EC21E9B61",
  "backend/tests/test_g1_s2_windows_eventlog_protocol.py": "EB94E38DA8ECFCF342E58072ECDE1125EA6DB690EAABC17B5770FD12842E817C"
}
```

Line endings: these hashes are of the bytes Git stores (LF). Run
`git config --global core.autocrlf false` BEFORE cloning, or every
`.py`/`.ps1` hash will differ legitimately and the gate will stop
you for the wrong reason.

A proof taken on unreviewed code is not a proof.
