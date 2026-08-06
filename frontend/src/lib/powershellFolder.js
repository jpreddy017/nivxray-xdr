/**
 * Minimal client-side PowerShell constant folder — DISPLAY ONLY.
 *
 * Full deterministic folding lives in
 * ``backend/services/normalization/powershell_folding.py``.  This is a
 * pared-down JS mirror covering the two obfuscation forms that show
 * up verbatim in the workspace chain-replay preview:
 *
 *   1. Adjacent quoted-literal concatenation:
 *        'S'+'ys'+'tem.N'+'et.W'+'ebC'+'lie'+'nt'   →   'System.Net.WebClient'
 *   2. Backtick escape inside identifiers:
 *        S`ys`tem.Net.WebClient                     →   System.Net.WebClient
 *
 * Idempotent — folding an already-folded string is a no-op.
 * Returns { text, changed }.  ``changed`` is used to display a
 * small NORMALIZED chip next to the stage header so the analyst
 * knows the render is a normalized view (raw is still on the backend).
 */

const _CONCAT_RE = /((?:'[^']*'|"[^"]*")(?:\s*\+\s*(?:'[^']*'|"[^"]*"))+)/g;

function _foldConcatOnce(text) {
  return text.replace(_CONCAT_RE, (chain) => {
    const parts = [...chain.matchAll(/'([^']*)'|"([^"]*)"/g)]
      .map((m) => m[1] !== undefined ? m[1] : m[2]);
    const merged = parts.join("");
    const outerQ = chain.trimStart().startsWith("'") ? "'" : '"';
    return `${outerQ}${merged}${outerQ}`;
  });
}

function _stripBackticks(text) {
  // Drop backticks that only obfuscate an identifier: `X where X is alnum/_
  return text.replace(/`(?=[A-Za-z0-9_])/g, "");
}

/**
 * Decode any -EncodedCommand / -enc / FromBase64String('…') blob found
 * inside `text` and append an "  ⇒ <decoded>" hint next to the original.
 *
 * Deterministic:
 *   • Only inline-annotates blobs of length ≥ 20 chars matching the
 *     base64 alphabet (avoids false positives on short strings).
 *   • Tries UTF-16 LE first (PowerShell -EncodedCommand default), then
 *     UTF-8.  Rejects results below a printable-ratio threshold.
 *   • Leaves the raw blob visible so the analyst can still audit it.
 */
const _B64_RE = /(?:-(?:e|enc|EncodedCommand)\s+)([A-Za-z0-9+/=]{20,})|FromBase64String\s*\(\s*['"]([A-Za-z0-9+/=]{20,})['"]/g;

function _base64ToBytes(s) {
  // Pad to a multiple of 4.
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  try {
    const bin = atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch { return null; }
}

function _decodeBlob(blob) {
  const bytes = _base64ToBytes(blob);
  if (!bytes) return null;
  // Prefer UTF-16 LE (default for `powershell -enc`).  A common tell:
  // every OTHER byte is 0x00 for ASCII strings.
  const zeros = Array.from(bytes.slice(0, Math.min(32, bytes.length)))
    .filter((_, i) => i % 2 === 1)
    .filter((b) => b === 0).length;
  const tryOrder = zeros >= 8 ? ["utf-16le", "utf-8"] : ["utf-8", "utf-16le"];
  for (const enc of tryOrder) {
    try {
      const s = new TextDecoder(enc, { fatal: true }).decode(bytes);
      // Require most of the content to be printable
      let printable = 0;
      for (const ch of s) {
        const c = ch.charCodeAt(0);
        if ((c >= 32 && c < 127) || c === 10 || c === 13 || c === 9) printable++;
      }
      if (printable >= Math.max(4, s.length / 2)) return s;
    } catch { /* try next */ }
  }
  return null;
}

function _annotateBase64(text) {
  let changed = false;
  const out = text.replace(_B64_RE, (match, encBlob, fbsBlob) => {
    const blob = encBlob || fbsBlob;
    const decoded = _decodeBlob(blob);
    if (!decoded) return match;
    changed = true;
    // Keep raw + append arrow with decoded text so both are visible.
    // Truncate very long decoded blobs to keep the display readable.
    const trimmed = decoded.length > 240 ? decoded.slice(0, 240) + "…" : decoded;
    return `${match}  ⇒  ${trimmed}`;
  });
  return { text: out, changed };
}

export function foldPowerShell(text) {
  if (typeof text !== "string" || !text) return { text: text || "", changed: false };
  let out = _stripBackticks(text);
  for (let i = 0; i < 5; i++) {
    const next = _foldConcatOnce(out);
    if (next === out) break;
    out = next;
  }
  // Recursive base64 annotation — attach the decoded UTF-16LE/UTF-8
  // text next to `-enc <blob>` / `FromBase64String('<blob>')` so the
  // analyst reads the peeled command directly.
  const b64 = _annotateBase64(out);
  return { text: b64.text, changed: (b64.text !== text) };
}

/** Convenience wrapper — just returns the folded text. */
export function foldText(text) {
  return foldPowerShell(text).text;
}
