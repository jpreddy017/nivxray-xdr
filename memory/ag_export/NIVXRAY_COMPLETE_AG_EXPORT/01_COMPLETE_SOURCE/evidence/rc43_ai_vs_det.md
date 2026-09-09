# RC4.3 · Big-Whale AI-vs-Deterministic Showdown

Three real-world multi-layer whales run through both engines. Same payload, same expected keywords, side-by-side scoring.

| Whale | Expected keywords | Det hits | Det latency | LLM hits | LLM latency |
| --- | --- | --- | --- | --- | --- |
| `whale-1-emotet-ps-encoded` | 185.243.219.72, emotet, downloadstring, webclient | 2/4 | 1511 ms | 4/4 | 10780 ms |
| `whale-2-empire-rc4-inline` | mimikatz, 185.220.100.5, invoke-mimikatz | 3/3 | 514 ms | 0/3 | 11629 ms |
| `whale-3-cmd-substr-cascade` | certutil, exfil.evil.io, x.exe | 3/3 | 941 ms | 3/3 | 7619 ms |

**Determinism** — NivXRay stable across 3 identical runs: **True**. LLM stable across 3 identical runs: **False**.

## whale-1-emotet-ps-encoded

**Deterministic** (2/4 hits · 1511ms · chain=['extract-payload', 'base64-decode', 'utf16le-or-utf8-decode', 'extract-payload', 'ioc-extract', 'family-emotet'])
- Verdict: `Malicious` @ 90
- URLs: `['http://185.243.219.72/emotet/e1.ps1']`
- Hosts: `['185.243.219.72', '27.912.342.581']`
- LOLBins: `['powershell.exe']`
- MITRE: `['T1059.001', 'T1027.010', 'T1105', 'T1027', 'T1566.001']`
- Crypto hints: `None`

**LLM** (4/4 hits · 10780ms · verdict `malicious`)
- URLs: `['http://185.243.219.72/emotet/e1.ps1']`
- Hosts: `['185.243.219.72']`
- LOLBins: `['powershell.exe']`
- MITRE: `['T1059.001', 'T1027', 'T1140', 'T1086', 'T1105', 'T1564.003']`
- Family: `Emotet`
- Notes: Multi-stage PowerShell downloader with classic Emotet indicators. The command uses Base64 encoding (-EncodedCommand) to obfuscate a PowerShell payload that executes with hidden window (-w hidden). The decoded payload uses IEX (Invoke-Expression) to execute a remote PowerShell script downloaded via Net.WebClient from a known malicious IP. The URL path '/emotet/e1.ps1' explicitly references Emotet m

## whale-2-empire-rc4-inline

**Deterministic** (3/3 hits · 514ms · chain=['rc4-inline-decrypt', 'crypto-detect', 'ioc-extract'])
- Verdict: `Suspicious` @ 65
- URLs: `[]`
- Hosts: `['185.220.100.5', '5.001.022.581']`
- LOLBins: `[]`
- MITRE: `['T1003.001', 'T1059.001', 'T1140', 'T1027.013', 'T1588.002', 'T1027']`
- Crypto hints: `[{'algorithm': 'RC4', 'key_source': 'inline', 'recovery': 'static-complete', 'mitre': ['T1027', 'T1140'], 'why': '`0..255` + `-bxor`'}]`

**LLM** (0/3 hits · 11629ms · verdict `malicious`)
- URLs: `['http://192.168.1.100:8080/stage2']`
- Hosts: `['192.168.1.100']`
- LOLBins: `['powershell.exe', 'IEX']`
- MITRE: `['T1059.001', 'T1027', 'T1140', 'T1573.001', 'T1071.001', 'T1105']`
- Family: `PowerShell Empire`
- Notes: This is a classic PowerShell Empire stager implementation. The script implements RC4 stream cipher decryption using the hardcoded key 'EmpireSecret' (a known default Empire key). The RC4 algorithm is manually implemented with key scheduling (KSA) and pseudo-random generation (PRGA) phases. The encrypted payload is base64-encoded, then RC4-decrypted, and executed via IEX. The decrypted content down

## whale-3-cmd-substr-cascade

**Deterministic** (3/3 hits · 941ms · chain=['batch-envvar-substitute', 'ioc-extract'])
- Verdict: `Malicious` @ 90
- URLs: `['https://exfil.evil.io/x.exe']`
- Hosts: `['exfil.evil.io']`
- LOLBins: `['certutil.exe']`
- MITRE: `['T1105']`
- Crypto hints: `None`

**LLM** (3/3 hits · 7619ms · verdict `malicious`)
- URLs: `['https://exfil.evil.io/x.exe']`
- Hosts: `['exfil.evil.io']`
- LOLBins: `['certutil.exe']`
- MITRE: `['T1105', 'T1027', 'T1140', 'T1218']`
- Family: `Generic downloader/dropper using certutil`
- Notes: Multi-stage obfuscation using environment variable concatenation. The URL is obfuscated by inserting underscores between each character, which are removed via string substitution (%u:_=%). Certutil downloads executable from suspicious domain 'exfil.evil.io' to temp directory, then immediately executes it. Classic LOLBin abuse pattern for malware delivery. MITRE mappings: T1105 (Ingress Tool Transf
