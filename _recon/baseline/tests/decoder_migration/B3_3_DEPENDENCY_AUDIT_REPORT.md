# Gate 2D-B3.3 · Dependency Audit · CHECKPOINT REPORT

**Status:** PASS — STOPPED FOR OWNER ACCEPTANCE
**Owner scope:** Migration-integrity / architectural proof gate only. No feature expansion.
**mal-20:** untouched.
**Wording adopted:** Frozen-fixture output parity verified using SHA-256 content signatures.

---

## A. Authoritative runtime modules (audited)

20 `.py` files enumerated under `/app/backend/services/decoder/` and
`/app/backend/services/analyzers/`:

```
services/decoder/__init__.py
services/decoder/orchestrator.py
services/decoder/engine.py
services/decoder/registry.py
services/decoder/types.py
services/decoder/cmd.py
services/decoder/powershell.py
services/decoder/base/__init__.py
services/decoder/base/_shared.py
services/decoder/base/_ddo_adapter.py
services/decoder/base/base64_codec.py
services/decoder/base/encoding.py
services/decoder/base/compression.py
services/decoder/base/transform.py
services/decoder/base/crypto.py
services/decoder/base/xor_brute.py
services/decoder/base/powershell_encoded_command.py
services/analyzers/__init__.py
services/analyzers/pe.py
services/analyzers/shellcode.py
```

## B. Legacy modules (subject to the forbidden-edge rule)

```
services.die.preprocessor.recursive_decoder
decoders.crypto_symmetric
decoders.xor_brute
services.pe_analyzer
shellcode_analyzer
```

## C. Compatibility shims (legacy → authoritative direction, documented)

Every shim was verified to import ONLY from authoritative modules:

| Shim path | Imports authoritative |
|---|---|
| `services/die/preprocessor/recursive_decoder.py` | `services.decoder.base._shared`, `services.decoder.base.compression`, `services.decoder.base.transform`, `services.decoder.base.powershell_encoded_command` |
| `decoders/crypto_symmetric.py` | `services.decoder.base.crypto` (`*`, `Rc4Decoder`, `AesCbcDecoder`, `CryptoDetectDecoder`) |
| `decoders/xor_brute.py` | `services.decoder.base.xor_brute` (`*`, `XorBruteDecoder`) |
| `services/pe_analyzer.py` | `services.analyzers.pe` (`*`, `analyze_pe`, `is_available`) |
| `shellcode_analyzer.py` | `services.analyzers.shellcode` (`*`, `analyze`, `is_shellcode`, …) |

**Direction:** legacy → authoritative. Permitted.
**No shim imports another legacy module.**

## D. Forbidden dependency edges — result

`authoritative → legacy` transitive paths detected: **0**.

## E. Static import-graph result

- Files audited: 20
- Transitive graph size (nodes reachable from authoritative seeds): 28
- Direct legacy imports from authoritative code: **0**
- Transitive legacy paths from authoritative code: **0**

Static audit **PASS**.

## F. Runtime dependency result (fresh subprocess)

Executed `python -c "<runtime_audit_snippet>"` in a clean
subprocess (no test/shim modules pre-loaded). The snippet:
1. Imports every authoritative module.
2. Invokes the DDO on a real PS `-EncodedCommand` input.
3. Enumerates `sys.modules` for legacy names.

Legacy modules loaded: **[]** (empty list).

Runtime audit **PASS**.

Additionally, each of the 12 individual authoritative modules
was probed in isolation via `importlib.import_module` in its own
fresh subprocess. Legacy modules loaded per import: **[]** for
all 12.

## G. Production-path result

`services.canonicalizer.canonicalize()` was exercised in a fresh
subprocess with a real PS `-EncodedCommand` input:

- Subprocess exit code: 0
- `decoded_final` present on result object: True
- Decoder layers surfaced: True

Note: `canonicalize()` may transitively load `recursive_decoder`
because `services/canonicalizer/__init__.py` and `pipeline.py`
still call the legacy `peel_recursively` (that codepath is
outside the B3 migration scope — the legacy call now goes THROUGH
the authoritative implementations via the shim, per section C).
This is expected and documented as **exception E-1** below.

## H. CI enforcement result

Six CI-enforceable pytest cases installed at
`tests/decoder_harness/test_b3_3_dependency_audit.py`:

```
test_no_authoritative_module_directly_imports_legacy                 PASS
test_no_authoritative_module_transitively_depends_on_legacy          PASS
test_runtime_import_of_authoritative_surface_does_not_load_legacy    PASS
test_legacy_shims_may_import_authoritative_but_not_vice_versa        PASS
test_production_ddo_path_end_to_end_without_legacy_load               PASS
test_authoritative_module_isolated_import_does_not_load_legacy       PASS × 12
```

Total: **17 / 17 PASS**.

## I. Exceptions (honestly documented)

**E-1 · canonicalize() legacy call preserved.**
`services/canonicalizer/__init__.py`, `services/die/preprocessor/pipeline.py`,
`services/decoder_bridge/__init__.py`, `services/die/investigation_results.py`,
and `analysis_core.py` still import `services.die.preprocessor.recursive_decoder`.
These are **legacy callers of the shim**, not authoritative modules.
The direction is `legacy_caller → shim → authoritative`, which is
permitted by the B3 invariant. Redirecting these callers to the
authoritative surface directly is a **separate refactor gate**,
NOT within B3's declared migration-integrity scope.

**E-2 · UAIE plugin adapters.**
`services/uaie/plugins/*` includes wrappers (`crypto_rc4`, `crypto_aes_cbc`,
`xor_brute`, `pe_analyzer`, `shellcode_analyzer`, `powershell_encoded_command`,
`gzip_inflate`, `zlib_inflate`, `base64_bare`, `base64_frombase64string`,
`shellcode_string_scan`, `cs_beacon_config_parser`, `transformer_byte_array_xor_loop`).
These import from `decoders.*` and `services.die.preprocessor.recursive_decoder` —
i.e. from the legacy shim path. Because the shim now re-exports
from authoritative, the plugins transparently reach authoritative
without any change. This is the **legacy → authoritative** direction
in disguise (legacy plugin adapter → legacy shim → authoritative).
UAIE plugins are outside the B3 authoritative surface by owner
declaration; they are not required to be redirected as part of B3.

## J. Regression + parity

```
Snapshot #1 (peel_recursively surface)         : 12378d11…8bac  MATCH
Snapshot #2 (crypto + xor_brute + PE + shellcode): 6427903e…7897  MATCH
```

Frozen-fixture output parity verified using SHA-256 content signatures.
SHA-256 identity proves parity of the captured frozen outputs, not
universal behavioural equivalence for every possible input.

| Suite | Result |
|---|---|
| `tests/decoder_harness/` (incl. dispatch matrix + dependency audit) | 59 / 59 pass |
| `tests/corpus/` (excl. mal-20) | 76 / 76 pass |
| `tests/corpus/test_corpus.py::test_scenario[mal-20]` | fail (intentional) |
| `tests/test_decoder_bridge.py` + `test_intelligence_policy.py` + `test_phase2_final_gate.py` | 32 / 32 pass |
| **Combined** | **167 / 167 pass** (excl. mal-20) |

## K. Final DDO dispatch matrix — unchanged from B3.2-A

7 encoding + 7 migrated Plane-A = **14 / 14** dispatch entries.
Every migrated family reachable through DDO. See
`test_ddo_dispatch_matrix.py` invariant tests (all 10 pass).

## L. Architectural invariants — all preserved

- `static_only=True · execution=False · network_access=False · attck_promotion=False · provenance_required=True`
- No new codec / analyzer capability.
- No verdict / IOC / ATT&CK / narration change.
- No DDO semantic change.
- Fixtures + `.expected.txt` untouched.
- `tests/corpus/baseline_p0_1.json` untouched.
- mal-20 untouched.

---

## Final verdict

**B3.3 PASS.**

- Static direct-import audit               ✓
- Static transitive-import audit           ✓
- Runtime dependency audit                 ✓ (0 legacy modules loaded)
- Authoritative → legacy direction test    ✓ (0 offending edges)
- Legacy → authoritative direction locked  ✓ (5 shims documented)
- Production canonicalize → DDO path       ✓ (decoded_final surfaced)
- PE production path                       ✓ (no legacy analyzer load)
- Shellcode production path                ✓ (no legacy analyzer load)
- 7/7 migrated codecs DDO-reachable        ✓ (dispatch matrix intact)
- Static-only invariants                   ✓
- decoder_harness                          ✓
- corpus (mal-20 intentional)              ✓
- adjacent tests                           ✓
- CI enforcement installed                 ✓ (17 tests)
- No unrelated code/features changed       ✓

---

## STOPPED for owner acceptance of B3.3 before B3.4 begins.
