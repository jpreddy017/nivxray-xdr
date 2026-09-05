# UNIVERSAL_DECODER_COVERAGE_MATRIX.md

**P0-1B · Phase 1 · Coverage matrix (gap analysis) · owner-locked 2026-09-02.**

Companion documents: `UNIVERSAL_DECODER_SOURCE_INVENTORY.md`,
`UNIVERSAL_DECODER_LICENSE_MATRIX.md`.
Scope contract: `/app/memory/P0_1B_SCOPE.md`.

**Purpose:** expose gaps, not merely list capabilities. Each row
is a capability the XDR-owned Universal Decoder Engine must
address; each column reports its state in NivXRay today and in
each external harvest source. The rightmost column is the P0-1B
target.

Legend:
- ✅ · full runtime support
- 🟡 · partial (detected but not reconstructed / detected but no runtime plugin / present only in a specific idiom)
- ❌ · not present
- 📄 · test-corpus / documentation only (no runtime capability)
- ⛔ · dynamic-only (rejected under XDR static-safety rule)
- N/A · not applicable to that source

**Owner rule (repeated):** Adding more Plane-A codecs will not
close Plane-B gaps. Track F ("new semantic corpus") is a Phase-2
deliverable and must include at least ten samples per Plane-B row
below.

---

## Plane A · Generic decoding (codec / compression / crypto / encoding)

| Capability | NivXRay | CyberChef | Invoke-Obf | Invoke-DOS | PowerDecode | CMD-DeObf | batch_deobf | BatchAlchemy | **XDR target** |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Base16 (hex string) | 🟡 (ps_hex_escape only) | ✅ | ✅ (Encoding.Hex) | N/A | ✅ | N/A | N/A | N/A | ✅ Required |
| Base32 (RFC-4648) | 📄 (fixture only) | ✅ | ❌ | N/A | ❌ | N/A | N/A | N/A | ✅ Required |
| Base36 | ❌ | ✅ | ❌ | N/A | ❌ | N/A | N/A | N/A | 🟡 Optional |
| Base58 (Bitcoin-style) | ❌ | ✅ | ❌ | N/A | ❌ | N/A | N/A | N/A | 🟡 Optional |
| Base62 | ❌ | ✅ | ❌ | N/A | ❌ | N/A | N/A | N/A | 🟡 Optional |
| Base64 (RFC-4648) | ✅ | ✅ | ✅ | N/A | ✅ | N/A | N/A | N/A | ✅ Required |
| Base64 (URL-safe) | 🟡 (repair path) | ✅ | ❌ | N/A | ❌ | N/A | N/A | N/A | ✅ Required |
| Base64 (with UTF-16LE inner) | ✅ | ✅ | ✅ | N/A | ✅ | N/A | N/A | N/A | ✅ Required (this IS the PS `-EncodedCommand` shape) |
| Base85 / Ascii85 | ❌ | ✅ | ❌ | N/A | ❌ | N/A | N/A | N/A | 🟡 Optional |
| Hex bytes | 📄 (fixture) | ✅ | ✅ | N/A | ✅ | N/A | N/A | N/A | ✅ Required |
| Binary (0/1 stream) | ❌ | ✅ | ✅ | N/A | ❌ | N/A | N/A | N/A | 🟡 Optional |
| Octal ASCII | 📄 (fixture) | ✅ | ✅ | N/A | ❌ | N/A | N/A | N/A | ✅ Required |
| Decimal ASCII / char-code | 📄 (fixture) | ✅ | ✅ | N/A | ❌ | N/A | N/A | N/A | ✅ Required |
| URL encoding (`%XX`) | 📄 (fixture) · IOC-extractor only | ✅ | ❌ | N/A | ❌ | N/A | N/A | N/A | ✅ Required |
| Unicode escapes (`\u00XX`) | 📄 (fixture) | ✅ | ❌ | N/A | ❌ | N/A | N/A | N/A | ✅ Required |
| UTF-8 / UTF-16LE / UTF-16BE / UTF-32 | 🟡 (LE only) | ✅ | ✅ (LE) | N/A | ✅ (LE) | N/A | N/A | N/A | ✅ Required (all 4) |
| HTML / XML entities | 🟡 (base64 repair only) | ✅ | ❌ | N/A | ❌ | N/A | N/A | N/A | ✅ Required |
| ROT13 / ROT-N / Caesar | 📄 (fixture) | ✅ | ❌ | N/A | ❌ | N/A | N/A | N/A | ✅ Required |
| Reverse strings | 🟡 (op_ps_reverse_string) | ✅ | ✅ | ✅ | ✅ | N/A | N/A | N/A | ✅ Required |
| Gzip inflate | ✅ | ✅ | ✅ (DeflateStream) | N/A | ✅ | N/A | N/A | N/A | ✅ Required |
| Zlib inflate | ✅ | ✅ | ❌ | N/A | ❌ | N/A | N/A | N/A | ✅ Required |
| Deflate (raw) | 📄 (fixture · deflate_base64) | ✅ | ✅ | N/A | ✅ | N/A | N/A | N/A | ✅ Required |
| Brotli | ❌ | ❌ | ❌ | N/A | ❌ | N/A | N/A | N/A | 🟡 Optional (rare in commandline malware) |
| LZMA / XZ | ❌ | ✅ | ❌ | N/A | ❌ | N/A | N/A | N/A | 🟡 Optional |
| Zstandard | ❌ | ✅ | ❌ | N/A | ❌ | N/A | N/A | N/A | 🟡 Optional |
| ZIP / archive expand (static) | 🟡 (archive_recovery.py) | ✅ | ❌ | N/A | ❌ | N/A | N/A | N/A | ✅ Required |
| AES-CBC | ✅ | ✅ | ❌ | N/A | ❌ | N/A | N/A | N/A | ✅ Required |
| AES-GCM | ❌ | ✅ | ❌ | N/A | ❌ | N/A | N/A | N/A | 🟡 Optional |
| AES-ECB | ❌ | ✅ | ❌ | N/A | ❌ | N/A | N/A | N/A | 🟡 Optional |
| RC4 (fixed key) | ✅ | ✅ | ❌ | N/A | ❌ | N/A | N/A | N/A | ✅ Required |
| DES / 3DES | ❌ | ✅ | ❌ | N/A | ❌ | N/A | N/A | N/A | 🟡 Optional |
| Blowfish | ❌ | ✅ | ❌ | N/A | ❌ | N/A | N/A | N/A | 🟡 Optional |
| Single-byte XOR (brute) | ✅ | ✅ | ✅ | N/A | 🟡 | N/A | N/A | N/A | ✅ Required |
| Repeating-key XOR (brute) | 🟡 (byte_array only) | ✅ | ✅ | N/A | ❌ | N/A | N/A | N/A | ✅ Required |
| XOR with inline PS key | ✅ | ❌ | ✅ | N/A | ❌ | N/A | N/A | N/A | ✅ Required |
| Substitution / byte-map | ❌ | ✅ | ❌ | N/A | ❌ | N/A | N/A | N/A | 🟡 Optional |
| Shellcode ASCII scan | ✅ | 🟡 | N/A | N/A | ✅ | N/A | N/A | N/A | ✅ Required |
| PE detect / extract | ✅ | ✅ | N/A | N/A | ✅ | N/A | N/A | N/A | ✅ Required |
| PE static analyse | ✅ (pefile) | 🟡 | N/A | N/A | ✅ | N/A | N/A | N/A | ✅ Required |
| Crypto shape classifier | ✅ | 🟡 (Magic) | N/A | N/A | ❌ | N/A | N/A | N/A | ✅ Required |
| Magic-byte retype | ✅ | 🟡 | N/A | N/A | ❌ | N/A | N/A | N/A | ✅ Required |
| Recursive multi-layer peel | ✅ (peel_recursively) | ✅ (recipes) | N/A | N/A | ✅ | N/A | N/A | N/A | ✅ Required |
| "Magic" auto-classifier | ❌ | ✅ | N/A | N/A | ❌ | N/A | N/A | N/A | ✅ Required (biggest Plane-A gap) |

---

## Plane B · Command-language semantic reconstruction

**This is where tommy-aa.lol lives, and where NivXRay is weakest.**
Every row marked ❌ or 🟡 in the NivXRay column is a distinct
Phase-2 backlog item.

### B.1 · CMD / Batch (target: Windows cmd.exe semantics)

| Capability | NivXRay | Invoke-DOS (offensive) | CMD-DeObf | batch_deobf | BatchAlchemy | LOLBAS | **XDR target** |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Tokenisation (shlex-based) | 🟡 (posix=False, no carets) | N/A (generator) | ✅ | ✅ | ✅ (Tree-sitter) | N/A | ✅ Required |
| Caret escape stripping (`h^t^t^p`) | ❌ | 📄 (technique known) | ✅ | ✅ | ✅ | N/A | ✅ Required (mandatory for tommy-aa.lol) |
| Double-caret / triple-caret sequences | ❌ | 📄 | ✅ | 🟡 | ✅ | N/A | ✅ Required |
| Quote balancing / removal | 🟡 (shlex only) | 📄 | ✅ | ✅ | ✅ | N/A | ✅ Required |
| Leading `%COMSPEC%` / `%SystemRoot%\...\cmd.exe` normalisation | ✅ (leading token only) | N/A | ✅ | ✅ | ✅ | N/A | ✅ Required (extend to any position) |
| Arbitrary `%VAR%` expansion when defined in the same script | ❌ (listed as flag only) | 📄 | ✅ (`expand_inline`) | ✅ | ✅ | N/A | ✅ Required |
| `!VAR!` delayed-expansion when `/V:ON` or `SETLOCAL EnableDelayedExpansion` | ❌ (detected as flag only) | 📄 | ✅ (`delayed_expansion` mode) | ✅ | ✅ | N/A | ✅ Required (mandatory for tommy-aa.lol) |
| Substring expansion `%V:~n,m%` | ❌ | 📄 | ✅ | ✅ | 🟡 | N/A | ✅ Required |
| Search-replace expansion `%V:x=y%` | ❌ | 📄 | ✅ | ✅ | 🟡 | N/A | ✅ Required |
| `SET` reassembly (`SET a=power & SET b=shell & %a%%b%`) | ❌ | 📄 | ✅ | ✅ | ✅ | N/A | ✅ Required |
| `CALL` expansion (double-percent) | ❌ | 📄 | ✅ | ✅ | 🟡 | N/A | ✅ Required |
| `FOR /F "usebackq" %%i in ('cmd') DO %%i …` semantic reconstruction | ❌ | 📄 | 🟡 | 🟡 | 🟡 | N/A | ✅ Required (mandatory for tommy-aa.lol chain) |
| Nested `FOR` loops | ❌ | 📄 | ❌ | 🟡 | 🟡 | N/A | ✅ Required |
| Nested `cmd /c` / `cmd /k` peels | 🟡 (canonicalizer 4-level limit) | N/A | ✅ | 🟡 | ✅ | N/A | ✅ Required |
| `START /min` / `START /b` peel | 🟡 (start_wrapper rule) | 📄 | ✅ | ✅ | ✅ | N/A | ✅ Required |
| Pipe / redirection preserving semantics | 🟡 (chain heuristic in cmd_ast) | N/A | ✅ | ✅ | ✅ | N/A | ✅ Required |
| Wildcard-executable resolution (`c*d.e?e → cmd.exe`) | ❌ | 📄 | ❌ | ❌ | ❌ | ✅ (registry) | ✅ Required (mandatory for tommy-aa.lol) — knowledge from LOLBAS |
| PATH-based executable resolution | ❌ | N/A | ❌ | ❌ | ❌ | ✅ (registry) | ✅ Required — knowledge from LOLBAS |
| `where` builtin resolution | ❌ | 📄 | ❌ | ❌ | ❌ | ✅ (registry) | ✅ Required |
| Command concatenation `& && || |` normalisation | 🟡 (cmd_ast splits) | 📄 | ✅ | ✅ | ✅ | N/A | ✅ Required |
| Token fragmentation (`c""m""d`) | ❌ | 📄 | ✅ | ✅ | ✅ | N/A | ✅ Required |
| Payload reversal (`Invoke-DOSfuscation` primitive) | 🟡 (uaie/op_ps_reverse_string covers PS side) | 📄 | ❌ | ❌ | 🟡 | N/A | ✅ Required |

**tommy-aa.lol coverage assessment:** *0 of 6* required Plane-B
capabilities are ✅ in NivXRay today (caret · `!VAR!` · `SET`
reassembly · `FOR /F` · wildcard-exec · nested peel). This is why
the sample surfaces empty evidence — and this is what P0-1B
Phase 2 must deliver.

### B.2 · PowerShell (target: Windows PowerShell 5.1 / PowerShell 7)

| Capability | NivXRay | Invoke-Obf (offensive) | PowerDecode | PSDecode | CyberChef | **XDR target** |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| Tokenisation | ✅ (`powershell_ast._tokenize`) | 📄 | ✅ | ✅ | N/A | ✅ Required |
| Cmdlet extraction | ✅ | 📄 | ✅ | ✅ | N/A | ✅ Required |
| Alias resolution (`iex → Invoke-Expression`) | ✅ (ps_alias_normalizer) | 📄 | ✅ | ✅ | N/A | ✅ Required |
| Backtick escape normalisation | ✅ (ps_backtick_normalizer) | 📄 | ✅ | ❌ | N/A | ✅ Required |
| `-EncodedCommand` / `-enc` / `-e` peel | ✅ | 📄 | ✅ | ✅ | ✅ | ✅ Required |
| String concatenation folding (`'iex'+'x'`) | 🟡 (op_ps_semantic_mini) | 📄 | ✅ | 🟡 | N/A | ✅ Required |
| Character-array function assembly (`[char]105+[char]101+[char]120`) | ❌ | 📄 | ✅ | 🟡 | N/A | ✅ Required |
| `-join` / `-split` reconstruction | ❌ | 📄 | 🟡 | ❌ | N/A | ✅ Required |
| `[byte]` array reconstruction | ❌ | 📄 | 🟡 | ❌ | N/A | ✅ Required |
| `-replace` chain folding | 🟡 (op_ps_reverse_regex_swap) | 📄 | 🟡 | ❌ | N/A | ✅ Required |
| Format-string function assembly (`'{1}{0}' -f 'ex','i'`) | ❌ | 📄 | 🟡 | ❌ | N/A | ✅ Required |
| Variable indirection (`$a='iex'; &$a $x`) | ❌ | 📄 | 🟡 | ✅ | N/A | ✅ Required |
| `Invoke-Expression` / `iex` invocation resolution | 🟡 (structural detection) | 📄 | ✅ | ✅ | N/A | ✅ Required |
| Nested `-EncodedCommand` peel | ✅ (op_ps_encodedcommand_multilayer) | 📄 | ✅ | 🟡 | N/A | ✅ Required |
| Compression via `IO.Compression.DeflateStream` in-script | 🟡 (via gzip_inflate on decoded bytes) | 📄 | ✅ | ❌ | N/A | ✅ Required |
| Stdin-piped PS (`echo … | powershell -c -`) | ❌ | 📄 | ❌ | ❌ | N/A | ✅ Required |
| SecureString / BXOR PS encoding | ❌ | 📄 | 🟡 | ❌ | N/A | ✅ Required |
| Whitespace / comment obfuscation strip | 🟡 (op_ps_normalize) | 📄 | ✅ | 🟡 | N/A | ✅ Required |
| Type / member obfuscation (`[System.Convert]::['FromBase64String']`) | 🟡 | 📄 | 🟡 | 🟡 | N/A | ✅ Required |
| Launcher-family peel (`cmd/wmic/rundll32/mshta/clip++/var++/stdin++`) | 🟡 (canonicalizer covers cmd/mshta/rundll32/regsvr32/wscript/cscript) | 📄 | ❌ | ❌ | N/A | ✅ Required (extend) |

### B.3 · Bash / sh (target: bash + POSIX sh)

| Capability | NivXRay | CyberChef | Invoke-Obf | External | **XDR target** |
|---|:-:|:-:|:-:|:-:|:-:|
| Tokenisation | 🟡 (`bash_ast.parse_bash`) | N/A | N/A | ❌ | ✅ Required |
| Quoting removal (`'…'` / `"…"`) | 🟡 | N/A | N/A | ❌ | ✅ Required |
| ANSI-C quoting (`$'\x48\x54\x54\x50'`) | ❌ | ✅ (Unescape string) | N/A | ❌ | ✅ Required |
| Hex-escape (`\xNN`) | ❌ | ✅ | N/A | ❌ | ✅ Required |
| Octal-escape (`\0NN`) | ❌ | ✅ | N/A | ❌ | ✅ Required |
| Variable expansion (`$VAR`, `${VAR}`) | ❌ | N/A | N/A | ❌ | ✅ Required |
| Command substitution (`$(cmd)`) | ❌ | N/A | N/A | ❌ | ✅ Required |
| Backtick command substitution | ❌ | N/A | N/A | ❌ | ✅ Required |
| Pipe / redirection preserving semantics | 🟡 | N/A | N/A | ❌ | ✅ Required |
| Nested shell invocation (`bash -c 'sh -c …'`) | 🟡 (canonicalizer bash/sh peel) | N/A | N/A | ❌ | ✅ Required |
| `echo … | base64 -d | bash` cradle | 🟡 (tests/test_bash_echo_b64_pipe_decoder.py exists) | N/A | N/A | ❌ | ✅ Required |
| Bash `IFS=…` obfuscation | ❌ | N/A | N/A | ❌ | 🟡 Optional |
| `read`-eval loops | ❌ | N/A | N/A | ❌ | 🟡 Optional |

### B.4 · Recursive / multi-stage full-chain reconstruction

| Chain shape | NivXRay | External | XDR target |
|---|:-:|:-:|:-:|
| Base64 → UTF-16LE → PS text | ✅ | ✅ | ✅ Required |
| Base64 → GZIP → PE bytes | ✅ (workspace flagship) | ✅ | ✅ Required |
| Base64 → XOR → shellcode indicator | 🟡 (piecewise) | ✅ | ✅ Required |
| Base64 → GZIP → XOR → PowerShell | 🟡 (piecewise) | ✅ | ✅ Required |
| CMD caret → encoded PowerShell → compressed payload | ❌ | 📄 | ✅ Required |
| CMD variable reconstruction → URL (tommy-aa.lol shape) | ❌ | 📄 | ✅ Required (mandatory regression) |
| PowerShell string reconstruction → Base64 → payload | 🟡 (piecewise) | 📄 | ✅ Required |

### B.5 · Cross-cutting Plane-B knowledge bases

| Capability | NivXRay | Source | XDR target |
|---|:-:|:-:|:-:|
| LOLBAS registry (Windows binaries + ATT&CK) | 🟡 (`services/die/lolbas.py`) | LOLBAS Project (CC BY-SA-4.0) | ✅ Required — expand |
| GTFOBins registry (Unix binaries) | ❌ | GTFOBins (CC BY-NC-SA-4.0) | 🟡 Optional (Bash Phase 2) |
| LOOBins registry (macOS binaries) | ❌ | LOOBins (MIT) | 🟡 Optional (Mach-O phase) |
| Alias/cmdlet dictionary (PowerShell) | ✅ (op_ps_alias_normalizer) | PS docs (MIT-adjacent) | ✅ Required |
| CMD builtin verb list | ✅ (`cmd_ast._CMD_KEYWORDS`) | Windows docs | ✅ Required — expand |
| Bash builtin list | 🟡 | Bash manual (GPL) | ✅ Required (knowledge only, clean-room) |

---

## Column-wise summary — where each source is strong

- **CyberChef** — the strongest Plane-A reference (401 ops), the
  "Magic" auto-classifier is the single largest usable idea.
  Almost nothing on Plane B.
- **Invoke-Obfuscation / Invoke-DOSfuscation** — the offensive
  inverses. Every technique family becomes a reconstruction rule.
  Best source of *Plane B PowerShell/CMD test vectors*.
- **PowerDecode** — strong on Plane B PowerShell, but GPL-3.0
  prevents runtime import. Value = knowledge + published
  techniques.
- **PSDecode** — dynamic PowerShell interception; useful only as
  documentation because license is unspecified and its runtime
  model requires a sandbox.
- **CMD-DeObfuscator** — the single most-relevant Plane-B-CMD
  source. BSD-3 licensed.
- **batch_deobfuscator** (+ forks) — MIT-licensed CMD Plane-B
  reference. Can be studied and even directly re-used with
  attribution.
- **BatchAlchemy** — the Tree-sitter approach. Study for the
  grammar (Tree-sitter itself is heavy; do not import at runtime).
- **LOLBAS / GTFOBins / LOOBins** — knowledge bases for wildcard
  and PATH-based executable resolution.

---

## Row-wise summary — the critical Plane-B shortfalls

The following ordered list is the P0-1B Phase-2 backlog priority
by product value:

1. **CMD caret stripping** — mandatory for tommy-aa.lol.
2. **CMD `!VAR!` delayed-expansion resolution** — mandatory for
   tommy-aa.lol.
3. **CMD `SET` reassembly** — mandatory for obf-10-style samples.
4. **CMD `FOR /F` semantic reconstruction** — mandatory for the
   `for /f %i in ('cmd') DO %i …` chain in tommy-aa.lol.
5. **Wildcard-executable resolution** — mandatory for tommy-aa.lol
   (`c*d.e?e → cmd.exe`, `c*u*r*l.e?e → curl.exe`,
   `p*ell.exe → powershell.exe`).
6. **PATH-based / `where`-builtin resolution** — mandatory
   companion to (5).
7. **PowerShell character-array function-name assembly** — closes
   obf-07.
8. **PowerShell format-string function-name assembly** — closes
   obf-15.
9. **PowerShell variable indirection** — closes obf-06.
10. **PowerShell `-join` / `-split` reconstruction** — general.
11. **Stdin-piped PowerShell** — closes obf-14.
12. **URL encoding · Unicode escapes · HTML entities · UTF-16BE /
    UTF-8 / UTF-32 · Base32 · Octal / decimal ASCII** — Plane-A
    codec expansion so the existing fixtures stop being
    "test-only".
13. **CyberChef "Magic" auto-classifier** — recursive-decode
    intelligence upgrade.
14. **Bash ANSI-C / hex / octal / var expansion / cmd sub** —
    opens Bash Plane B.

**Anti-fixation rule:** items 1-6 close the tommy-aa.lol sample.
Do NOT stop there. Items 7-14 are non-negotiable — Phase-2
acceptance depends on ALL of them being either delivered or
explicitly deferred with owner sign-off.

---

## Coverage-index snapshot (Phase-1 numeric)

| Plane | Total tracked capabilities | NivXRay ✅ | NivXRay 🟡 | NivXRay ❌ | NivXRay 📄 (fixture-only) |
|---|---:|---:|---:|---:|---:|
| A (generic decoding) | 41 | 17 | 4 | 14 | 6 |
| B.1 CMD | 20 | 0 | 8 | 12 | 0 |
| B.2 PowerShell | 20 | 5 | 8 | 7 | 0 |
| B.3 Bash | 13 | 0 | 5 | 8 | 0 |
| B.4 Full-chain | 7 | 2 | 3 | 2 | 0 |
| B.5 Knowledge bases | 6 | 2 | 2 | 2 | 0 |
| **TOTAL** | **107** | **26** | **30** | **45** | **6** |

- **Fully covered:** 26/107 = 24%
- **Partial:** 30/107 = 28%
- **Missing:** 45/107 = 42%
- **Fixture-only:** 6/107 = 6% (worst-of-both: appears tested,
  not actually decoded)

**Coverage headline for owner:**
```
Universal Decoder Coverage
├── Plane A (generic decoding)              41 rows · 41% full · 15% fixture-only
└── Plane B (command-language semantics)    66 rows ·  8% full · 42% missing
                                                  ↑
                                        the actual product gap
```

**End of Phase 1 · Coverage Matrix. Next: LICENSE_MATRIX.**
