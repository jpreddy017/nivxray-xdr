# CEM Parity Report · Semantic vs Vendor Normalizers

Fixtures compared: 13

## Aggregate

| Metric | Value |
|---|---|
| Matches | 18 |
| New (semantic-only) | 15 |
| Lost (vendor-only) | 6 |
| Value mismatches | 1 |
| Ambiguous | 0 |
| Mean parity rate | 35.1% |
| Mean confidence drift | -0.100 |

## Cut-over criteria

| Criterion | Target | Current |
|---|---|---|
| Mapping parity | ≥ 99.5% | 35.1% ⏸ |
| Unexplained confidence regressions | 0 | 1 ⏸ |
| Ambiguous mapping increase | 0 | 0 ✅ |

## Per-fixture detail

### `cisco_secure_endpoint`

- vendor route: `cisco_secure_endpoint` · schema: `generic_json`
- vendor fields: 10 · semantic fields: 7
- matches: **6** · new: 1 · lost: 4 · mismatches: 0 · ambiguous: 0
- parity: **60.0%** · confidence drift: +0.093
- field deltas:
  - ➖ `file.hash_md5` vendor='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' · semantic=None · semantic path did not populate a vendor entity
  - ➖ `file.hash_sha256` vendor='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' · semantic=None · semantic path did not populate a vendor entity
  - ✅ `file.name` vendor='invoice.exe' · semantic='invoice.exe'
  - ✅ `file.path` vendor='C:/Users/John/Downloads/invoice.exe' · semantic='C:/Users/John/Downloads/invoice.exe'
  - ➕ `host.ip` vendor=None · semantic='198.51.100.7' · semantic path resolved a field the vendor route did not populate
  - ✅ `host.name` vendor='WKS-42' · semantic='WKS-42'
  - ✅ `network.dst_ip` vendor='198.51.100.7' · semantic='198.51.100.7'
  - ✅ `network.dst_port` vendor=443 · semantic=443
  - ✅ `network.url` vendor='http://bad.com/p1' · semantic='http://bad.com/p1'
  - ➖ `process.hash_sha256` vendor='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' · semantic=None · semantic path did not populate a vendor entity
  - ➖ `process.image` vendor='C:/Users/John/Downloads/invoice.exe' · semantic=None · semantic path did not populate a vendor entity

### `sysmon_process_create`

- vendor route: `sysmon` · schema: `generic_json`
- vendor fields: 5 · semantic fields: 4
- matches: **3** · new: 0 · lost: 1 · mismatches: 1 · ambiguous: 0
- parity: **60.0%** · confidence drift: -0.100
- field deltas:
  - ✅ `host.name` vendor='host-a' · semantic='host-a'
  - ✅ `process.command_line` vendor='cmd.exe /c whoami' · semantic='cmd.exe /c whoami'
  - ➖ `process.hash_sha256` vendor='dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd' · semantic=None · semantic path did not populate a vendor entity
  - ✅ `process.image` vendor='C:/Windows/System32/cmd.exe' · semantic='C:/Windows/System32/cmd.exe'
  - ⚠️ `user.name` vendor='alice' · semantic='CORP\\alice' · different values across pipelines

### `sysmon_dns_query`

- vendor route: `sysmon` · schema: `generic_json`
- vendor fields: 2 · semantic fields: 1
- matches: **1** · new: 0 · lost: 1 · mismatches: 0 · ambiguous: 0
- parity: **50.0%** · confidence drift: -0.100
- field deltas:
  - ➖ `dns.query` vendor='malicious.example' · semantic=None · semantic path did not populate a vendor entity
  - ✅ `host.name` vendor='h1' · semantic='h1'

### `sysmon_network_connect`

- vendor route: `sysmon` · schema: `generic_json`
- vendor fields: 6 · semantic fields: 7
- matches: **6** · new: 1 · lost: 0 · mismatches: 0 · ambiguous: 0
- parity: **85.7%** · confidence drift: -0.100
- field deltas:
  - ➕ `host.ip` vendor=None · semantic='10.0.0.1' · semantic path resolved a field the vendor route did not populate
  - ✅ `host.name` vendor='h1' · semantic='h1'
  - ✅ `network.dst_ip` vendor='1.2.3.4' · semantic='1.2.3.4'
  - ✅ `network.dst_port` vendor=443 · semantic=443
  - ✅ `network.protocol` vendor='tcp' · semantic='tcp'
  - ✅ `network.src_ip` vendor='10.0.0.1' · semantic='10.0.0.1'
  - ✅ `network.src_port` vendor=5555 · semantic=5555

### `generic_fallback_cmdline`

- vendor route: `generic` · schema: `generic_json`
- vendor fields: 1 · semantic fields: 1
- matches: **1** · new: 0 · lost: 0 · mismatches: 0 · ambiguous: 0
- parity: **100.0%** · confidence drift: -0.500
- field deltas:
  - ✅ `process.command_line` vendor='certutil -urlcache -f x y' · semantic='certutil -urlcache -f x y'

### `encoded_powershell_command`

- vendor route: `generic` · schema: `command_line`
- vendor fields: 1 · semantic fields: 1
- matches: **1** · new: 0 · lost: 0 · mismatches: 0 · ambiguous: 0
- parity: **100.0%** · confidence drift: -0.500
- field deltas:
  - ✅ `process.command_line` vendor='powershell -EncodedCommand SGVsbG8=' · semantic='powershell -EncodedCommand SGVsbG8='

### `elastic_ecs_process`

- vendor route: `generic` · schema: `elastic_ecs`
- vendor fields: 0 · semantic fields: 6
- matches: **0** · new: 6 · lost: 0 · mismatches: 0 · ambiguous: 0
- parity: **0.0%** · confidence drift: -0.481
- field deltas:
  - ➕ `host.ip` vendor=None · semantic='10.0.0.1' · semantic path resolved a field the vendor route did not populate
  - ➕ `host.name` vendor=None · semantic='web-01' · semantic path resolved a field the vendor route did not populate
  - ➕ `network.dst_ip` vendor=None · semantic='10.0.0.2' · semantic path resolved a field the vendor route did not populate
  - ➕ `network.src_ip` vendor=None · semantic='10.0.0.1' · semantic path resolved a field the vendor route did not populate
  - ➕ `process.image` vendor=None · semantic='nginx' · semantic path resolved a field the vendor route did not populate
  - ➕ `user.name` vendor=None · semantic='alice' · semantic path resolved a field the vendor route did not populate

### `key_value_syslog_style`

- vendor route: `generic` · schema: `generic_kv`
- vendor fields: 0 · semantic fields: 5
- matches: **0** · new: 5 · lost: 0 · mismatches: 0 · ambiguous: 0
- parity: **0.0%** · confidence drift: -0.487
- field deltas:
  - ➕ `host.ip` vendor=None · semantic='10.0.0.1' · semantic path resolved a field the vendor route did not populate
  - ➕ `host.name` vendor=None · semantic='host01' · semantic path resolved a field the vendor route did not populate
  - ➕ `network.dst_ip` vendor=None · semantic='10.0.0.2' · semantic path resolved a field the vendor route did not populate
  - ➕ `network.protocol` vendor=None · semantic='tcp' · semantic path resolved a field the vendor route did not populate
  - ➕ `network.src_ip` vendor=None · semantic='10.0.0.1' · semantic path resolved a field the vendor route did not populate

### `alien::cloud_native_proprietary`

- vendor route: `generic` · schema: `generic_json`
- vendor fields: 0 · semantic fields: 0
- matches: **0** · new: 0 · lost: 0 · mismatches: 0 · ambiguous: 0
- parity: **0.0%** · confidence drift: -0.180

### `alien::ics_ot_scada`

- vendor route: `generic` · schema: `generic_json`
- vendor fields: 0 · semantic fields: 1
- matches: **0** · new: 1 · lost: 0 · mismatches: 0 · ambiguous: 0
- parity: **0.0%** · confidence drift: +0.150
- field deltas:
  - ➕ `file.hash_sha256` vendor=None · semantic='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' · semantic path resolved a field the vendor route did not populate

### `alien::iot_edge_telemetry`

- vendor route: `generic` · schema: `generic_json`
- vendor fields: 0 · semantic fields: 0
- matches: **0** · new: 0 · lost: 0 · mismatches: 0 · ambiguous: 0
- parity: **0.0%** · confidence drift: +0.200

### `alien::legacy_mainframe_smf`

- vendor route: `generic` · schema: `generic_json`
- vendor fields: 0 · semantic fields: 0
- matches: **0** · new: 0 · lost: 0 · mismatches: 0 · ambiguous: 0
- parity: **0.0%** · confidence drift: +0.500

### `alien::saas_audit_log`

- vendor route: `generic` · schema: `generic_json`
- vendor fields: 0 · semantic fields: 1
- matches: **0** · new: 1 · lost: 0 · mismatches: 0 · ambiguous: 0
- parity: **0.0%** · confidence drift: +0.200
- field deltas:
  - ➕ `network.url` vendor=None · semantic='https://audit.example.com/records/INV-2026-00483' · semantic path resolved a field the vendor route did not populate

---

*Regenerated on every pytest run of `test_cem_parity.py`. Cut-over decisions require owner review of this report.*