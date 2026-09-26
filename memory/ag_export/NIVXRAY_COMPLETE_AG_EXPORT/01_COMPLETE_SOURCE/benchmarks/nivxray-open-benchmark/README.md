# NivXRay Open Benchmark

**A reproducible obfuscated-command-line + crypto-payload benchmark for
malware analysis engines.**

- **Version:** 1.0 · February 2026
- **Fixtures:** 300 public, sanitised, deterministic
- **License:** CC-BY-4.0 (fixtures) · MIT (runner)
- **Provenance:** NivXRay RC4.0 (obfuscation) + RC4.1 (crypto) regression corpora
- **Why:** Community had no shared benchmark for command-intelligence engines.
  Marketing claims are cheap; reproducible numbers aren't.

## Categories

- `rc41_crypto/` — 100 cases spanning 28 algorithms (AES-CBC/GCM, RC4,
  ChaCha20, RijndaelManaged, DES/3DES, DPAPI, OpenSSL, GPG, MachineGuid,
  C2-fetched keys, multi-stage chains, benign administrative baselines).
- `rc40_obfuscation/` — 200 cases spanning 13 families (PowerShell
  -EncodedCommand, hex-CSV inline, byte-array XOR, reverse slices,
  regex-swap, batch envvar substitution, CMD substring pickers, LOLBAS
  wrappers, HTML smuggling, IEX-hidden Lemon_Duck patterns, gzip-hex-split
  loaders, JS custom-b64+XOR loaders).

## How to reproduce

```bash
# Run against a NivXRay instance
python run_benchmark.py --engine nivxray --api https://your.nivxray/api

# Run against CyberChef headless (community adapter)
python run_benchmark.py --engine cyberchef --api http://localhost:3001

# Run against a frontier LLM (Claude, GPT — via Emergent Universal Key)
python run_benchmark.py --engine llm --model claude-sonnet-4-5
```

Each run emits `results/<engine>_<ts>.md` with per-category pass rate and
latency percentiles.

## Scoring semantics

Every fixture ships an `expected/<id>.json` telling the runner what
constitutes a pass:

- **Obfuscation fixtures** — pass if ANY expected keyword surfaces
  anywhere in the engine response (output / iocs / mitre / lolbas). This
  is intentionally lenient because engines have wildly different output
  shapes.
- **Crypto fixtures** — pass if EITHER (a) the algorithm is correctly
  identified in the response AND at least one recoverable stage is
  surfaced, OR (b) the plaintext is recovered.

Crypto fixtures with `runtime-required` stages (DPAPI, C2-fetched
key, MachineGuid-derived) are considered PASS if the engine surfaces
the algorithm identifier and clearly states the recovery limitation.
This models *honest verdicts* — a good malware engine says "AES-256
with runtime key from HKLM\MachineGuid" instead of hallucinating a
plaintext.

## Baseline results (NivXRay RC4.1)

- 561 / 575 = **97.6 %** pass
- 200 ms median latency
- 100 % determinism (byte-for-byte identical across three re-runs)
- 0 false negatives · 1 documented false positive (LOLBAS heuristic)

Please submit your engine's numbers via pull request to `results/`.

## Sanitisation

Every URL and IP address outside the fixture's mathematical dependency has
been rewritten to `benchmark.example` / `192.0.2.10` (RFC 5737 doc range).
Fixtures whose ciphertext is a deterministic function of the plaintext
(RC4, XOR-multi, hex+XOR) are preserved untouched so mathematical
recovery still succeeds.

## Contact / attribution

- Corpus:  NivXRay · https://nivxray.com/benchmark
- Runner:  MIT license
- Fixtures: CC-BY-4.0 · attribute to *NivXRay Open Benchmark v1.0*
