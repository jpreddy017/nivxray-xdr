# Phase 4 · Historical Bisect (S001-anchored) — Runtime Evidence

Every row below is the result of **checking out a real git SHA** and
running the full corpus against it — no source-code inference. Baseline
fingerprint = v1.5.6 (`fff5897`, Jul 28 16:10 UTC) as recorded in Phase 3.
**Exception**: S001 is fingerprinted against the OWNER-SPECIFIED expected
output `Write-Host "tweet, tweet!"`, not the v1.5.6 fingerprint — because
v1.5.6 itself did NOT decode S001 correctly, and the bisect must therefore
search the entire visible history for a revision that did.

## Per-Revision PASS/FAIL Matrix

| SHA | Date | Note | S001 ps writehost tweet | S01 ps b64 utf16le | S02 bash xxd b64 rev | S03 cmd caret escaped | S04 ps alias heavy | S05 nested b64 gzip | S06 xor obfuscated | S07 rc4 openssl | S08 unicode obfuscation | S09 hex b64 gzip chain | S10 bash with powershell comment |
|---|---|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| `5767e4072c` | 2026-07-09 12:24:15 +0000 | pre-v1.5.6 | ERR | ERR | ERR | ERR | ERR | ERR | ERR | ERR | ERR | ERR | ERR |
| `02715be1cd` | 2026-07-15 08:58:42 +0000 | pre-v1.5.6 | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `43d4400410` | 2026-07-17 01:47:58 +0000 | pre-v1.5.6 | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `53f6076eae` | 2026-07-18 09:54:11 +0000 | pre-v1.5.6 | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `20d0cb88bb` | 2026-07-19 07:00:46 +0000 | pre-v1.5.6 | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `5cab99e2b8` | 2026-07-20 03:06:27 +0000 | pre-v1.5.6 | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `51666219ed` | 2026-07-21 09:07:02 +0000 | pre-v1.5.6 | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ |
| `009d149768` | 2026-07-22 08:31:22 +0000 | pre-v1.5.6 | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ |
| `521535d702` | 2026-07-24 07:30:07 +0000 | pre-v1.5.6 | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ |
| `7f147f8fc1` | 2026-07-27 16:41:06 +0000 | pre-v1.5.6 | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ |
| `fff5897b17` | 2026-07-28 16:10:16 +0000 | v1.5.6 anchor (Certified Baseline) | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `09a556701a` | 2026-07-29 02:20:21 +0000 | post-v1.5.6 | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `42d7dffd1d` | 2026-07-30 13:30:41 +0000 | post-v1.5.6 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| `9d680addc1` | 2026-08-01 09:06:52 +0000 | post-v1.5.6 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| `1a07de3775` | 2026-08-02 14:59:01 +0000 | HEAD | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |

## S001 · Per-Anchor Stage Breakdown (runtime evidence)

| SHA | Date | Note | Interp | -EncodedCmd | Extract | Base64 | UTF-16LE | Write-Host | 1st missing stage |
|---|---|---|:-:|:-:|:-:|:-:|:-:|:-:|---|
| `5767e4072c` | 2026-07-09 12:24:15 +0000 | pre-v1.5.6 | ERR | ERR | ERR | ERR | ERR | ERR | — |
| `02715be1cd` | 2026-07-15 08:58:42 +0000 | pre-v1.5.6 | — | ❌ | ✅ | ✅ | ❌ | ✅ | interpreter |
| `43d4400410` | 2026-07-17 01:47:58 +0000 | pre-v1.5.6 | — | ❌ | ✅ | ✅ | ✅ | ✅ | interpreter |
| `53f6076eae` | 2026-07-18 09:54:11 +0000 | pre-v1.5.6 | — | ❌ | ✅ | ✅ | ✅ | ✅ | interpreter |
| `20d0cb88bb` | 2026-07-19 07:00:46 +0000 | pre-v1.5.6 | — | ❌ | ✅ | ✅ | ✅ | ✅ | interpreter |
| `5cab99e2b8` | 2026-07-20 03:06:27 +0000 | pre-v1.5.6 | — | ❌ | ✅ | ✅ | ✅ | ✅ | interpreter |
| `51666219ed` | 2026-07-21 09:07:02 +0000 | pre-v1.5.6 | powershell | ❌ | ✅ | ✅ | ❌ | ❌ | encodedcommand_recognition |
| `009d149768` | 2026-07-22 08:31:22 +0000 | pre-v1.5.6 | powershell | ❌ | ✅ | ✅ | ❌ | ❌ | encodedcommand_recognition |
| `521535d702` | 2026-07-24 07:30:07 +0000 | pre-v1.5.6 | powershell | ❌ | ✅ | ✅ | ❌ | ❌ | encodedcommand_recognition |
| `7f147f8fc1` | 2026-07-27 16:41:06 +0000 | pre-v1.5.6 | powershell | ❌ | ✅ | ✅ | ❌ | ❌ | encodedcommand_recognition |
| `fff5897b17` | 2026-07-28 16:10:16 +0000 | v1.5.6 anchor (Certified Baseline) | powershell | ❌ | ✅ | ✅ | ❌ | ❌ | encodedcommand_recognition |
| `09a556701a` | 2026-07-29 02:20:21 +0000 | post-v1.5.6 | powershell | ❌ | ✅ | ✅ | ❌ | ❌ | encodedcommand_recognition |
| `42d7dffd1d` | 2026-07-30 13:30:41 +0000 | post-v1.5.6 | powershell | ❌ | ✅ | ✅ | ❌ | ❌ | encodedcommand_recognition |
| `9d680addc1` | 2026-08-01 09:06:52 +0000 | post-v1.5.6 | powershell | ❌ | ✅ | ✅ | ❌ | ❌ | encodedcommand_recognition |
| `1a07de3775` | 2026-08-02 14:59:01 +0000 | HEAD | powershell | ❌ | ✅ | ✅ | ❌ | ❌ | encodedcommand_recognition |

## S001 Verdict

**S001 PASSES on at least one historical revision.** Restoration is a valid strategy.
- Earliest known-good SHA: `02715be1cd` (2026-07-15 08:58:42 +0000) — `pre-v1.5.6`
- Latest known-good SHA  : `5cab99e2b8` (2026-07-20 03:06:27 +0000) — `pre-v1.5.6`
- Recommended action     : binary-search between the last-good and the first-bad neighbouring commit to pinpoint the regression, then Phase 4 disable/swap/restore on the responsible module.

## Per-Sample Regression Windows (excluding S001)

For every corpus sample other than S001, the fingerprint is v1.5.6.
A sample transitioning from ✅ at revision N to ❌ at revision N+1 pinpoints
the regression window for that sample. This directly informs Phase 4.

### `S01_ps_b64_utf16le`
- `FAIL` → `PASS` at `51666219ed` (2026-07-21 09:07:02 +0000)
- `PASS` → `FAIL` at `42d7dffd1d` (2026-07-30 13:30:41 +0000)

### `S02_bash_xxd_b64_rev`
- `FAIL` → `PASS` at `51666219ed` (2026-07-21 09:07:02 +0000)
- `PASS` → `FAIL` at `42d7dffd1d` (2026-07-30 13:30:41 +0000)

### `S03_cmd_caret_escaped`
- `FAIL` → `PASS` at `51666219ed` (2026-07-21 09:07:02 +0000)
- `PASS` → `FAIL` at `42d7dffd1d` (2026-07-30 13:30:41 +0000)

### `S04_ps_alias_heavy`
- `FAIL` → `PASS` at `51666219ed` (2026-07-21 09:07:02 +0000)
- `PASS` → `FAIL` at `42d7dffd1d` (2026-07-30 13:30:41 +0000)

### `S05_nested_b64_gzip`
- `FAIL` → `PASS` at `fff5897b17` (2026-07-28 16:10:16 +0000)
- `PASS` → `FAIL` at `42d7dffd1d` (2026-07-30 13:30:41 +0000)

### `S06_xor_obfuscated`
- `FAIL` → `PASS` at `51666219ed` (2026-07-21 09:07:02 +0000)

### `S07_rc4_openssl`
- `FAIL` → `PASS` at `51666219ed` (2026-07-21 09:07:02 +0000)
- `PASS` → `FAIL` at `42d7dffd1d` (2026-07-30 13:30:41 +0000)

### `S08_unicode_obfuscation`
- `FAIL` → `PASS` at `51666219ed` (2026-07-21 09:07:02 +0000)
- `PASS` → `FAIL` at `42d7dffd1d` (2026-07-30 13:30:41 +0000)

### `S09_hex_b64_gzip_chain`
- `FAIL` → `PASS` at `fff5897b17` (2026-07-28 16:10:16 +0000)
- `PASS` → `FAIL` at `42d7dffd1d` (2026-07-30 13:30:41 +0000)

### `S10_bash_with_powershell_comment`
- `FAIL` → `PASS` at `51666219ed` (2026-07-21 09:07:02 +0000)
- `PASS` → `FAIL` at `42d7dffd1d` (2026-07-30 13:30:41 +0000)
