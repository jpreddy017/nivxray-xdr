# NivXRay · Daily Regression Report · 2026-07-18

- **Total cases**: 52
- **Runtime**: 13.3s (0.25s per case)

## Verdict distribution
- Malicious : **19** / 52
- Suspicious : **16** / 52
- Reached shellcode : **0** / 52
- Zero-MITRE (excluding benign controls) : **1** ← detection gaps
- Benign false positives (H* got MITRE tags) : **0** ← noise

## Per-case results

| # | Label | Verdict | Score | MITRE ct | Chain (first 3) | Shellcode |
|---|---|---|---|---|---|---|
| 1 | A1 · PS -EncodedCommand short | suspicious | 100 | 2 | `extract-b64→utf16le-or-utf8-decode` | — |
| 2 | A2 · PS -Enc IEX DownloadString | malicious | 100 | 4 | `extract-b64→utf16le-or-utf8-decode` | — |
| 3 | A3 · PS -e DownloadFile+Start-Process | malicious | 100 | 5 | `extract-b64→utf16le-or-utf8-decode` | — |
| 4 | A4 · PS AMSI reflection short | undecoded | 45 | 1 | `extract-payload` | — |
| 5 | A5 · CMD /c PS chain | malicious | 100 | 4 | `—` | — |
| 6 | B1 · b64 → utf16le → PS concat AMSI | malicious | 100 | 2 | `extract-b64→utf16le-or-utf8-decode` | — |
| 7 | B2 · b64 → gzip → shell curl | malicious | 100 | 1 | `extract-b64→base64-gzip→download-shell-bg` | — |
| 8 | B3 · CS byte-array shellcode loader | suspicious | 100 | 5 | `extract-payload→base64-decode→hex-or-b64-decode` | — |
| 9 | B4 · Nested b64 double-wrap | suspicious | 100 | 2 | `extract-b64→utf16le-or-utf8-decode→extract-b64` | — |
| 10 | B5 · Bash flock + wget + b64 | malicious | 88 | 3 | `—` | — |
| 11 | B6 · CMD→PS→IEX→download→exec | malicious | 100 | 7 | `env-expand` | — |
| 12 | B7 · PS bxor loop XOR | undecoded | 58 | 2 | `—` | — |
| 13 | B8 · PS char-code assembly | suspicious | 100 | 1 | `extract-int-array→chr-decode` | — |
| 14 | C1 · Fragment -EncodedCommand | undecoded | 45 | 1 | `—` | — |
| 15 | C2 · Fragment /c rundll32 comsvcs | undecoded | 71 | 4 | `—` | — |
| 16 | C3 · Fragment certutil -urlcache | suspicious | 57 | 1 | `xor` | — |
| 17 | C4 · Fragment bitsadmin transfer | malicious | 72 | 2 | `—` | — |
| 18 | C5 · Fragment schtasks | undecoded | 50 | 1 | `—` | — |
| 19 | C6 · Fragment reg run key | undecoded | 55 | 1 | `—` | — |
| 20 | C7 · Fragment vssadmin | undecoded | 60 | 1 | `—` | — |
| 21 | C8 · Fragment comsvcs ordinal | undecoded | 56 | 3 | `—` | — |
| 22 | D1 · Linux curl | bash | malicious | 100 | 1 | `download-shell-bg` | — |
| 23 | D2 · Linux wget | sh | malicious | 100 | 1 | `download-shell-bg` | — |
| 24 | D3 · Linux nohup bg | suspicious | 43 | 1 | `xor` | — |
| 25 | D4 · Linux crontab persistence | suspicious | 60 | 1 | `xor` | — |
| 26 | D5 · macOS osascript loader | malicious | 100 | 2 | `osascript-extract→applescript-decode→download-shell-bg` | — |
| 27 | D6 · macOS LaunchAgent load | suspicious | 50 | 1 | `env-expand→extract-payload` | — |
| 28 | D7 · Python b64 exec | suspicious | 55 | 1 | `extract-payload→base64-decode` | — |
| 29 | D8 · Perl reverse shell | undecoded | 49 | 1 | `—` | — |
| 30 | E1 · certutil download | malicious | 81 | 2 | `certutil-annotate→env-expand` | — |
| 31 | E2 · mshta remote | malicious | 100 | 2 | `mshta-annotate` | — |
| 32 | E3 · rundll32 JS | suspicious | 45 | 1 | `xor` | — |
| 33 | E4 · regsvr32 SCT | malicious | 100 | 2 | `regsvr32-annotate` | — |
| 34 | E5 · InstallUtil | undecoded | 69 | 1 | `—` | — |
| 35 | E6 · Msbuild inline | undecoded | 60 | 1 | `—` | — |
| 36 | E7 · Bitsadmin | malicious | 100 | 2 | `bitsadmin-annotate` | — |
| 37 | E8 · Wmic remote spawn | suspicious | 45 | 2 | `wmic-annotate→extract-payload` | — |
| 38 | F1 · Impact ransomware precursor | suspicious | 100 | 2 | `native-cmd-explain` | — |
| 39 | F2 · Lateral PsExec SMB | undecoded | 63 | 4 | `—` | — |
| 40 | F3 · Exfil IWR POST | malicious | 100 | 3 | `—` | — |
| 41 | F4 · Exfil aws s3 cp | suspicious | 44 | 2 | `xor→rot-n` | — |
| 42 | F5 · Collection archive + IWR | malicious | 67 | 3 | `xor→xor-brute` | — |
| 43 | F6 · Collection clipboard | undecoded | 56 | 2 | `—` | — |
| 44 | F7 · Exfil DNS tunnel | suspicious | 100 | 2 | `extract-payload→hex-or-b64-decode→xor-bruteforce-256` | — |
| 45 | G1 · GCP svc-account JWT | malicious | 89 | 1 | `jwt-decode` | — |
| 46 | G2 · AWS Cognito ID token | suspicious | 45 | 0 | `rot-n` | — |
| 47 | G3 · Ngrok tunnel C2 | undecoded | 45 | 2 | `—` | — |
| 48 | G4 · ClickFix Azure Blob | malicious | 100 | 3 | `—` | — |
| 49 | H1 · Benign hostname | undecoded | 45 | 0 | `—` | — |
| 50 | H2 · Benign echo | undecoded | 45 | 0 | `—` | — |
| 51 | H3 · Benign var assignment | suspicious | 45 | 0 | `xor` | — |
| 52 | H4 · JSON debris | undecoded | 32 | 0 | `—` | — |

## Detection gaps (zero-MITRE non-benign)
- `G2 · AWS Cognito ID token` — input: `eyJraWQiOiJmZDU3IiwiYWxnIjoiUlMyNTYifQ.eyJjb2duaXRvOnVzZXJuYW1lIjoidml`

## Benign false-positives (should be zero)