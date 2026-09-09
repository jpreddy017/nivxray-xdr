# Golden Fixture Framework · RC3.2a

Deterministic, per-plugin regression coverage. Every decoder / intelligence
plugin owns a single `<plugin_id>.jsonl` file in this directory. Each line
is one golden test case that the CI gate must reproduce byte-for-byte.

## Why per-plugin?

The `rc23_benchmark` corpus exercises the FULL orchestrator (chain routing
+ scoring + IOC extraction) and is our end-to-end floor. Golden plugin
fixtures are the complementary UNIT-level safety net — each plugin is
tested in isolation against a payload that is _guaranteed_ to be
plugin-consumable, so any refactor that silently breaks a single decoder
surfaces immediately, before it corrupts downstream chains.

## File format

Every `<plugin_id>.jsonl` is UTF-8, one JSON object per line, blank lines
and `# comments` allowed. Order does not matter.

```jsonc
{
  "case_id":                    "b64-plain-cmd",           // unique-within-file id
  "description":                "Standard b64 → plaintext cmd.exe",
  "input":                      "Y21kLmV4ZSAvYyBjYWxjLmV4ZQ==",
  "args":                       {},                        // optional plugin-args dict
  "detect_min_confidence":      0.5,                       // required floor for detect()
  "expected_output":            "cmd.exe /c calc.exe",     // exact match (rare)
  "expected_output_contains":   ["cmd.exe", "calc.exe"],   // substrings (preferred)
  "expected_mitre":             ["T1027"],                 // subset check
  "expected_tradecraft":        [],                        // subset check by flag name
  "expected_lolbas_binaries":   [],                        // subset check by binary name
  "must_produce_output":        true,                      // default true; set false for refuse-cases
  "notes":                      "Baseline case"            // free-form
}
```

## Runner

`tests/test_plugin_golden_fixtures.py` auto-discovers every `*.jsonl`
here and produces one parametrised pytest case per line. The test asserts:

1. Plugin is registered under `case.plugin_id`.
2. `detect()` returns confidence ≥ `detect_min_confidence`.
3. `decode()` returns a non-empty output (unless `must_produce_output` is false).
4. Every substring in `expected_output_contains` appears in the output.
5. Every MITRE technique / tradecraft flag / LOLBAS binary listed in the
   `expected_*` fields appears in the plugin result.

## Refuse-cases

Set `must_produce_output: false` and supply an `input` the plugin MUST
refuse (empty output). Useful for locking density-gates, entropy-gates
and printable-ratio safety valves so a refactor doesn't accidentally turn
a precision-first gate into a phantom decode.
