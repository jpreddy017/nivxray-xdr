/**
 * Unit tests for classifyStageBreak — the chain-break heuristic used by
 * ChainStageEditor to flag stages that failed / produced empty output /
 * ran with sub-40% confidence.
 *
 * Run with `node --test src/components/__tests__/classifyStageBreak.test.mjs`
 * or via CRA's test runner. Stand-alone so it doesn't need jsdom.
 */
import test from "node:test";
import assert from "node:assert/strict";

// Duplicate the classifier here so we don't need to compile ChainStageEditor
// (which imports React). This intentionally mirrors the JSX source 1-to-1;
// keep them in sync when the heuristic evolves.
function classifyStageBreak(stageResult) {
  if (!stageResult) return null;
  if (stageResult.error) {
    return { kind: "ERROR", severity: "high", message: `Stage errored: ${stageResult.error}`.slice(0, 200) };
  }
  const conf = Number.isFinite(stageResult.confidence) ? stageResult.confidence : null;
  const outLen = stageResult.output_length ?? (stageResult.output || "").length;
  const chainOps = Array.isArray(stageResult.chain) ? stageResult.chain.length : 0;
  const inputLen = stageResult.input_length ?? (stageResult.input_preview || "").length;
  if ((conf === 0 || conf === null) && chainOps === 0 && inputLen > 0) {
    return { kind: "DECODE_FAILED", severity: "high", message: "No known decoder matched · plain-text passthrough only" };
  }
  if (outLen === 0 && inputLen > 0 && (conf ?? 0) > 0) {
    return { kind: "EMPTY_OUTPUT", severity: "med", message: "Decoder ran but yielded 0 bytes · input may be plaintext or malformed" };
  }
  if (conf !== null && conf < 40 && chainOps > 0) {
    return { kind: "LOW_CONFIDENCE", severity: "low", message: `Confidence ${conf}/100 · below 40 % floor · verify output manually` };
  }
  return null;
}


test("null input returns null", () => {
  assert.equal(classifyStageBreak(null), null);
  assert.equal(classifyStageBreak(undefined), null);
});

test("server-side error → ERROR / high severity", () => {
  const b = classifyStageBreak({ error: "TimeoutError on decode/chain" });
  assert.equal(b.kind, "ERROR");
  assert.equal(b.severity, "high");
  assert.match(b.message, /TimeoutError/);
});

test("engine ran but no decoder matched (conf=0, empty chain, non-empty input) → DECODE_FAILED", () => {
  const b = classifyStageBreak({
    engine: "magic",
    confidence: 0,
    chain: [],
    input_preview: "some random text that is not base64",
    input_length: 34,
    output: "",
    output_length: 0,
  });
  assert.equal(b.kind, "DECODE_FAILED");
  assert.equal(b.severity, "high");
});

test("decoder ran successfully but produced empty output → EMPTY_OUTPUT", () => {
  const b = classifyStageBreak({
    engine: "magic",
    confidence: 72,
    chain: [{ op: "base64-decode" }],
    input_preview: "SGVsbG8=",
    input_length: 8,
    output: "",
    output_length: 0,
  });
  assert.equal(b.kind, "EMPTY_OUTPUT");
  assert.equal(b.severity, "med");
});

test("chain applied but confidence < 40 % → LOW_CONFIDENCE", () => {
  const b = classifyStageBreak({
    engine: "magic",
    confidence: 25,
    chain: [{ op: "xor-brute" }],
    input_preview: "abc",
    input_length: 3,
    output: "?!?",
    output_length: 3,
  });
  assert.equal(b.kind, "LOW_CONFIDENCE");
  assert.equal(b.severity, "low");
  assert.match(b.message, /25\/100/);
});

test("healthy stage (conf ≥ 40, non-empty output) → null (no break)", () => {
  assert.equal(classifyStageBreak({
    engine: "magic",
    confidence: 85,
    chain: [{ op: "base64-decode" }],
    input_length: 12,
    output_length: 8,
    output: "Hello!!",
  }), null);
});

test("edge — conf exactly 40 is NOT low-confidence", () => {
  assert.equal(classifyStageBreak({
    engine: "magic",
    confidence: 40,
    chain: [{ op: "hex-decode" }],
    input_length: 10,
    output: "abc", output_length: 3,
  }), null);
});

test("edge — high confidence with 0-byte output still flags EMPTY_OUTPUT", () => {
  const b = classifyStageBreak({
    engine: "magic",
    confidence: 99,
    chain: [{ op: "gzip-decompress" }],
    input_preview: "H4sIAAA...",
    input_length: 100,
    output: "",
    output_length: 0,
  });
  assert.equal(b.kind, "EMPTY_OUTPUT");
});

test("empty input + empty output + zero conf → null (nothing to analyse)", () => {
  assert.equal(classifyStageBreak({
    engine: null,
    confidence: 0,
    chain: [],
    input_length: 0,
    output_length: 0,
  }), null);
});
