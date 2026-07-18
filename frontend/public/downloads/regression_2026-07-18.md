# NivXRay · Daily Regression Report · 2026-07-18

- **Total cases**: 52
- **Runtime**: 11.3s (0.22s per case)

## Verdict distribution
- Malicious : **0** / 52
- Suspicious : **0** / 52
- Reached shellcode : **0** / 52
- Zero-MITRE (excluding benign controls) : **6** ← detection gaps
- Benign false positives (H* got MITRE tags) : **0** ← noise

## Per-case results

| # | Label | Verdict | Score | MITRE ct | Chain (first 3) | Shellcode |
|---|---|---|---|---|---|---|
| 1 | A1 · PS -EncodedCommand short | — | — | 2 | `—` | — |
| 2 | A2 · PS -Enc IEX DownloadString | — | — | 4 | `—` | — |
| 3 | A3 · PS -e DownloadFile+Start-Process | — | — | 5 | `—` | — |
| 4 | A4 · PS AMSI reflection short | — | — | 0 | `—` | — |
| 5 | A5 · CMD /c PS chain | — | — | 4 | `—` | — |
| 6 | B1 · b64 → utf16le → PS concat AMSI | — | — | 2 | `—` | — |
| 7 | B2 · b64 → gzip → shell curl | — | — | 1 | `—` | — |
| 8 | B3 · CS byte-array shellcode loader | — | — | 5 | `—` | — |
| 9 | B4 · Nested b64 double-wrap | — | — | 2 | `—` | — |
| 10 | B5 · Bash flock + wget + b64 | — | — | 3 | `—` | — |
| 11 | B6 · CMD→PS→IEX→download→exec | — | — | 7 | `—` | — |
| 12 | B7 · PS bxor loop XOR | — | — | 2 | `—` | — |
| 13 | B8 · PS char-code assembly | — | — | 0 | `—` | — |
| 14 | C1 · Fragment -EncodedCommand | — | — | 1 | `—` | — |
| 15 | C2 · Fragment /c rundll32 comsvcs | — | — | 4 | `—` | — |
| 16 | C3 · Fragment certutil -urlcache | — | — | 1 | `—` | — |
| 17 | C4 · Fragment bitsadmin transfer | — | — | 2 | `—` | — |
| 18 | C5 · Fragment schtasks | — | — | 1 | `—` | — |
| 19 | C6 · Fragment reg run key | — | — | 1 | `—` | — |
| 20 | C7 · Fragment vssadmin | — | — | 1 | `—` | — |
| 21 | C8 · Fragment comsvcs ordinal | — | — | 3 | `—` | — |
| 22 | D1 · Linux curl | bash | — | — | 1 | `—` | — |
| 23 | D2 · Linux wget | sh | — | — | 1 | `—` | — |
| 24 | D3 · Linux nohup bg | — | — | 0 | `—` | — |
| 25 | D4 · Linux crontab persistence | — | — | 1 | `—` | — |
| 26 | D5 · macOS osascript loader | — | — | 2 | `—` | — |
| 27 | D6 · macOS LaunchAgent load | — | — | 1 | `—` | — |
| 28 | D7 · Python b64 exec | — | — | 1 | `—` | — |
| 29 | D8 · Perl reverse shell | — | — | 1 | `—` | — |
| 30 | E1 · certutil download | — | — | 2 | `—` | — |
| 31 | E2 · mshta remote | — | — | 2 | `—` | — |
| 32 | E3 · rundll32 JS | — | — | 1 | `—` | — |
| 33 | E4 · regsvr32 SCT | — | — | 2 | `—` | — |
| 34 | E5 · InstallUtil | — | — | 1 | `—` | — |
| 35 | E6 · Msbuild inline | — | — | 0 | `—` | — |
| 36 | E7 · Bitsadmin | — | — | 2 | `—` | — |
| 37 | E8 · Wmic remote spawn | — | — | 2 | `—` | — |
| 38 | F1 · Impact ransomware precursor | — | — | 2 | `—` | — |
| 39 | F2 · Lateral PsExec SMB | — | — | 4 | `—` | — |
| 40 | F3 · Exfil IWR POST | — | — | 3 | `—` | — |
| 41 | F4 · Exfil aws s3 cp | — | — | 2 | `—` | — |
| 42 | F5 · Collection archive + IWR | — | — | 3 | `—` | — |
| 43 | F6 · Collection clipboard | — | — | 2 | `—` | — |
| 44 | F7 · Exfil DNS tunnel | — | — | 2 | `—` | — |
| 45 | G1 · GCP svc-account JWT | — | — | 0 | `—` | — |
| 46 | G2 · AWS Cognito ID token | — | — | 0 | `—` | — |
| 47 | G3 · Ngrok tunnel C2 | — | — | 2 | `—` | — |
| 48 | G4 · ClickFix Azure Blob | — | — | 3 | `—` | — |
| 49 | H1 · Benign hostname | — | — | 0 | `—` | — |
| 50 | H2 · Benign echo | — | — | 0 | `—` | — |
| 51 | H3 · Benign var assignment | — | — | 0 | `—` | — |
| 52 | H4 · JSON debris | — | — | 0 | `—` | — |

## Detection gaps (zero-MITRE non-benign)
- `A4 · PS AMSI reflection short` — input: `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetFi`
- `B8 · PS char-code assembly` — input: `-join(([char[]](116,101,115,116)))`
- `D3 · Linux nohup bg` — input: `nohup /tmp/x >/dev/null 2>&1 &`
- `E6 · Msbuild inline` — input: `msbuild.exe C:\Users\Public\evil.csproj`
- `G1 · GCP svc-account JWT` — input: `eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJzdmMtYWNjb3VudEBteS1wcm9qZWN0LmlhbS5nc`
- `G2 · AWS Cognito ID token` — input: `eyJraWQiOiJmZDU3IiwiYWxnIjoiUlMyNTYifQ.eyJjb2duaXRvOnVzZXJuYW1lIjoidml`

## Benign false-positives (should be zero)