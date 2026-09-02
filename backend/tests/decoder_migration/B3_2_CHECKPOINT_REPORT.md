# Gate 2D-B3.2 · Analyzer Separation + DDO Codec Wiring · CHECKPOINT REPORT

**Status:** ANALYZERS SEPARATED · DDO WIRED · FROZEN-FIXTURE PARITY PRESERVED — STOPPED FOR OWNER ACCEPTANCE
**Owner scope note:** B3.2 is a migration/separation gate, not feature-expansion.
**mal-20:** untouched.

---

## 1. PE analyzer separated

Authoritative implementation moved (byte-identical `cp`) from
`services/pe_analyzer.py` → `services/analyzers/pe.py`.

Legacy path `services/pe_analyzer.py` is now a **thin re-export
shim** — every public symbol (`analyze_pe`, `is_available`, plus
star-import) is re-exported. Identity check confirms:

```
services.pe_analyzer.analyze_pe   is   services.analyzers.pe.analyze_pe   →  True
```

Existing consumers unchanged:
- `services.uaie.plugins.pe_analyzer` (adapter) — loads OK, capability name `pe.analyzer`
- `services.uaie.plugins.pe_extractor`, `pe_dotnet_recognizer`,
  `validator_pe_bytes` — unaffected (all import via the shim).

## 2. Shellcode analyzer separated

Authoritative implementation moved (byte-identical `cp`) from
`/app/backend/shellcode_analyzer.py` → `services/analyzers/shellcode.py`.

Legacy path `shellcode_analyzer.py` is now a **thin re-export
shim**. Identity check confirms:

```
shellcode_analyzer.analyze         is   services.analyzers.shellcode.analyze         →  True
shellcode_analyzer.is_shellcode    is   services.analyzers.shellcode.is_shellcode    →  True
```

Existing consumers unchanged:
- `services.uaie.plugins.shellcode_analyzer` (adapter) — loads OK, capability name `shellcode.analyzer`
- `services.uaie.plugins.shellcode_string_scan`, `validator_shellcode_bytes` — unaffected.

## 3. Deterministic analyzer adapter package

`services/analyzers/__init__.py` now exposes:
- convenience re-exports (`pe`, `shellcode` submodules).
- `ANALYZER_INVARIANTS` — the invariant contract that MUST hold for every analyzer invocation:

```
static_only         = True
execution           = False
network_access      = False
attck_promotion     = False
provenance_required = True
```

Analyzers never *execute* an artifact; they read bytes, parse
structure, extract deterministic evidence, emit a report.

## 4. DDO signature dispatch — migrated codecs wired

`services/decoder/orchestrator.py` extended:
- Added 4 signature patterns for the migrated Plane-A codecs
  (existing 7 text-encoding codecs from B1 preserved verbatim):

| Signature name | Fires on |
|---|---|
| `base.ps_encodedcommand`   | `powershell -e[nc[odedcommand]] <base64>` |
| `base.byte_array_xor_loop` | `[Byte[]]$x = [Convert]::FromBase64String(...)` |
| `base.gzip`                | `@@RAWBYTES@@1f8b…` (sentinel + gzip magic) |
| `base.zlib`                | `@@RAWBYTES@@78{01,5e,9c,da}…` (sentinel + zlib magic) |

Signatures are **specific to the extent that they never fire on
benign text** — `@@RAWBYTES@@` is an XDR-internal sentinel emitted
only by the upstream `from_base64_string` peel, and the PS-EC
regex requires the literal `powershell` invocation token before
the base64 blob.

- Added `services/decoder/base/_ddo_adapter.py` — thin wrappers
  that map the codec return-shape `Optional[Tuple[str, dict]]` to
  the DDO's `Optional[str]` contract (drops the meta dict; DDO
  reads observability from provenance).

- `_DECODER_FNS` now contains 11 entries (7 encoding + 4 migrated
  Plane-A). Ordering is still fixed by `_SIGNATURES` — deterministic.

- Engine version bumped to `0.6.0-gate2d-b3.2` in provenance stamps.

Smoke test:
```
orchestrate('powershell -enc SQBFAFgAIABbAG4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAXQA=')
  → layers ['base.ps_encodedcommand']
  → final  'IEX [net.WebClient]'
```

## 5. Crypto plugins (RC4 / AES / xor_brute) — DDO integration status

The three `BaseDecoder`-shaped plugins (`Rc4Decoder`,
`AesCbcDecoder`, `XorBruteDecoder`) require a fundamentally
different invocation contract than the DDO (`detect(payload, fp, ctx)`
→ `DetectResult` + `decode(payload, args, ctx)` → `PluginResult`
with tradecraft flags + MITRE hints). Their authoritative
implementation already lives in `services/decoder/base/*` per
B3.1; they remain reachable via the existing plugin registry
(`engine.registry.DecoderRegistry` + UAIE plugin adapters).

**Not shoehorned into DDO in this gate.** Adding a plugin-shape
dispatch lane inside DDO would be feature expansion, which owner
directive explicitly forbids for B3. Documented honestly here.

---

## Byte-identical parity proof (both snapshots)

```
Snapshot #1  frozen at B3.0  : 12378d118ffdc7fd68cbad72547af81b3fe716abe61682652c36b58982308bac
Snapshot #1  post-B3.2       : 12378d118ffdc7fd68cbad72547af81b3fe716abe61682652c36b58982308bac  MATCH

Snapshot #2  frozen at B3.0  : 6427903eae774599f1c8e710223fb6d603276e5fae1a1fad1f8ecd453b297897
Snapshot #2  post-B3.2       : 6427903eae774599f1c8e710223fb6d603276e5fae1a1fad1f8ecd453b297897  MATCH
```

The wording clarification adopted per owner note:
**Frozen-fixture output parity verified cryptographically; no
observed behavioral regression within the migration parity corpus.**
SHA-256 identity proves parity of the frozen captured outputs, not
universal behavioural equivalence for every possible input.

---

## Regression gate

| Suite | Result |
|---|---|
| `tests/decoder_harness/` | 32 / 32 pass |
| `tests/corpus/` (excl. mal-20) | 76 / 76 pass |
| `tests/corpus/test_corpus.py::test_scenario[mal-20]` | fail (intentional) |
| `tests/test_decoder_bridge.py` + `test_intelligence_policy.py` + `test_phase2_final_gate.py` | 32 / 32 pass |
| **Combined** | **140 / 140** pass (excl. mal-20) |

UAIE plugin adapter smoke test — all 5 wrappers load and
functionality returns identity (`legacy_import is new_import`
returns True everywhere).

---

## Architectural invariants preserved

- `static_only=True · execution=False · network_access=False · attck_promotion=False` — structurally enforced on every DDO layer via `Provenance.__post_init__`.
- Analyzers never execute an artifact.
- No new codec / analyzer capabilities added.
- No verdict / IOC / ATT&CK / narration change.
- Fixtures + `.expected.txt` sidecars untouched.
- `tests/corpus/baseline_p0_1.json` untouched.
- mal-20 untouched.

**Interim architectural state after B3.2:**
- `services/decoder/base/*`  — 7 authoritative Plane-A codecs.
- `services/analyzers/{pe,shellcode}.py` — 2 authoritative artifact analyzers.
- `services/decoder/orchestrator.py` — DDO signature-dispatches all 11 codecs (7 encoding + 4 migrated Plane-A).
- Legacy paths (`recursive_decoder.py`, `decoders/{crypto_symmetric,xor_brute}.py`, `services/pe_analyzer.py`, `shellcode_analyzer.py`) — thin re-export shims, zero unique logic.

---

## Explicit deferrals

- **B3.3** — static import-graph + runtime dependency audit (CI-enforced test that fails if `services/decoder/*` or `services/analyzers/*` import a legacy module in production paths).
- **B3.4** — final validation gate (both harnesses + full pytest + median-based latency ≤5%).
- **Gate 2F** — real positive-fixture corpus for RC4 / AES-CBC / PE / shellcode (not part of B3).

---

## STOPPED for owner acceptance of B3.2 before B3.3 begins.
