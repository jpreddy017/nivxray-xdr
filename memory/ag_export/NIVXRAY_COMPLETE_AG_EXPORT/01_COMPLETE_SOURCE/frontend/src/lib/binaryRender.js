/**
 * Binary/text classifier + clean-summary builder for the OUTPUT panel.
 *
 * When the decoded payload is a PE / ELF / archive / high-entropy shellcode
 * blob, dumping raw bytes into a monospaced text panel produces the
 * ▓░▒▓@@#$%$ gibberish that analysts hate. This module classifies the
 * output and returns a structured summary the UI can render as a clean
 * analyst-friendly card (magic + strings + hex preview) — with the raw
 * bytes still available under a collapsible toggle for hex-view forensics.
 *
 * Zero backend round-trip — runs entirely in the browser on already-decoded
 * text.
 */

// Magic bytes → human-readable label
const MAGICS = [
  { prefix: "MZ",                label: "PE executable (Windows)",   ext: ".exe/.dll" },
  { prefix: "\x7fELF",           label: "ELF executable (Linux)",    ext: ".elf/.so"  },
  { prefix: "PK\x03\x04",        label: "ZIP archive",               ext: ".zip"      },
  { prefix: "%PDF-",             label: "PDF document",              ext: ".pdf"      },
  { prefix: "\x1f\x8b",          label: "Gzip archive",              ext: ".gz"       },
  { prefix: "BZh",               label: "Bzip2 archive",             ext: ".bz2"      },
  { prefix: "\xfd7zXZ",          label: "XZ / LZMA archive",         ext: ".xz"       },
  { prefix: "Rar!",              label: "RAR archive",               ext: ".rar"      },
  { prefix: "\x89PNG",           label: "PNG image",                 ext: ".png"      },
  { prefix: "\xff\xd8\xff",      label: "JPEG image",                ext: ".jpg"      },
  { prefix: "GIF8",              label: "GIF image",                 ext: ".gif"      },
  { prefix: "\xca\xfe\xba\xbe",  label: "Java class file",           ext: ".class"    },
  { prefix: "\xd0\xcf\x11\xe0",  label: "Microsoft OLE / DOC / XLS", ext: ".doc/.xls" },
];

// PE-specific tell-tale substring (present in almost every real PE payload)
const PE_MARKER = "This program cannot be run in DOS mode";

// Strip the backend's decorative header (`━━━━━━ ▼ DECODED OUTPUT ━━━━━━`)
// before we analyse — the banner is UI decoration, not forensic content.
function stripHeader(src) {
  if (!src) return "";
  // Remove leading run of box-drawing chars + the "▼ DECODED OUTPUT" marker
  // plus another box-drawing run and the trailing newline.
  let s = String(src);
  s = s.replace(/^[━─═▬▔▁▂▃▄▅▆▇█─\s]*[\u25bc\u25be\u25b6][^\n]*\n[━─═▬▔▁▂▃▄▅▆▇█─\s]*\n?/u, "");
  // Also drop the closing INVESTIGATION SUMMARY block, if present.
  const cut = s.indexOf("NIVXRAY INVESTIGATION SUMMARY");
  if (cut > 0) s = s.slice(0, cut);
  return s.trimStart();
}

// Convert a JS string to raw byte array via Latin-1 (each char → single
// byte). Malware bytes come to us via Python's `.decode("latin-1", errors=
// "replace")` on the raw shellcode, so char code == byte value. Using
// TextEncoder (UTF-8) here would inflate `\x90` → `c2 90`, producing the
// misleading "off-by-one" hex previews forensic analysts hate.
function toBytes(text) {
  const src = String(text || "");
  const arr = new Uint8Array(src.length);
  for (let i = 0; i < src.length; i++) arr[i] = src.charCodeAt(i) & 0xff;
  return arr;
}

// Extract ASCII strings of length ≥ minLen — mimics the Unix `strings` tool
function extractStrings(text, minLen = 4, cap = 40) {
  const out = [];
  let cur = "";
  const src = stripHeader(text);
  for (let i = 0; i < src.length && out.length < cap; i++) {
    const c = src.charCodeAt(i);
    if (c >= 0x20 && c <= 0x7e) {
      cur += src[i];
    } else {
      if (cur.length >= minLen) out.push(cur);
      cur = "";
    }
  }
  if (cur.length >= minLen) out.push(cur);
  return out;
}

// Simple Shannon entropy over the byte distribution (0..8, higher = more random)
function entropy(text) {
  if (!text) return 0;
  const bytes = toBytes(stripHeader(text));
  const n = Math.min(bytes.length, 4096);
  if (!n) return 0;
  const freq = new Array(256).fill(0);
  for (let i = 0; i < n; i++) freq[bytes[i]]++;
  let h = 0;
  for (let i = 0; i < 256; i++) {
    if (!freq[i]) continue;
    const p = freq[i] / n;
    h -= p * Math.log2(p);
  }
  return h;
}

// Printable ratio (space + ASCII printables + \n \r \t)
function printableRatio(text) {
  if (!text) return 1;
  const bytes = toBytes(stripHeader(text));
  const n = Math.min(bytes.length, 4096);
  if (!n) return 1;
  let printable = 0;
  for (let i = 0; i < n; i++) {
    const c = bytes[i];
    if ((c >= 0x20 && c <= 0x7e) || c === 0x09 || c === 0x0a || c === 0x0d) printable++;
  }
  return printable / n;
}

function detectMagic(text) {
  if (!text) return null;
  const clean = stripHeader(text);
  for (const m of MAGICS) {
    if (clean.startsWith(m.prefix)) return m;
  }
  if (clean.includes(PE_MARKER) || text.includes(PE_MARKER)) {
    return { prefix: "", label: "PE executable (Windows)", ext: ".exe/.dll" };
  }
  return null;
}

// Compact hex-preview: proper UTF-8 bytes with " |  ASCII gutter".
function hexPreview(text, bytes = 128) {
  if (!text) return "";
  const src = toBytes(stripHeader(text));
  const rows = [];
  for (let off = 0; off < Math.min(src.length, bytes); off += 16) {
    const chunk = Array.from(src.slice(off, off + 16));
    const hex = chunk.map((b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = chunk.map((b) => (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : ".").join("");
    rows.push(`${off.toString(16).padStart(4, "0")}   ${hex.padEnd(47, " ")}  ${ascii}`);
  }
  return rows.join("\n");
}

/**
 * analyzeOutput(text)
 *   Returns:
 *     {
 *       kind:            "plaintext" | "binary" | "partial",
 *       printableRatio:  0..1,
 *       entropy:         0..8,
 *       magic:           {label, ext} | null,
 *       hexPreview:      string,
 *       strings:         string[],   // extracted printable strings
 *       byteLen:         number,
 *       reason:          human-readable classifier explanation,
 *     }
 */
export function analyzeOutput(text) {
  const raw = String(text || "");
  const clean = stripHeader(raw);
  const byteLen = toBytes(clean).length;
  const pr = printableRatio(raw);
  const h = entropy(raw);
  const magic = detectMagic(raw);

  let kind = "plaintext";
  let reason = "Fully printable — safe to display as text.";

  // High-confidence binary — known magic OR very low printable ratio
  if (magic) {
    kind = "binary";
    reason = `Recognised ${magic.label} header — displaying as structured binary summary.`;
  } else if (pr < 0.55 || h >= 6.5) {
    kind = "binary";
    reason = `Non-printable ratio ${(1 - pr).toFixed(2)} · entropy ${h.toFixed(2)} — payload is binary/encrypted.`;
  } else if (pr < 0.85) {
    kind = "partial";
    reason = `Mostly printable (${pr.toFixed(2)}) but ${((1 - pr) * 100).toFixed(0)}% of the terminal layer is still garbled — likely one more decode layer required.`;
  }

  return {
    kind,
    printableRatio: pr,
    entropy: h,
    magic,
    hexPreview: kind === "binary" ? hexPreview(raw, 128) : "",
    strings: kind === "binary" || kind === "partial" ? extractStrings(raw, 5, 24) : [],
    byteLen,
    reason,
  };
}

/**
 * outputEqualsInput(input, output) — permissive equality that ignores
 * the DECODED-OUTPUT header the backend prepends. Used by the frontend
 * to detect "OUTPUT=INPUT" (no real decode happened) and swap the UI
 * into the "PATTERN NOT RECOGNISED · RE-INVESTIGATE" state.
 */
export function outputEqualsInput(input, output) {
  if (!input || !output) return false;
  const clean = (output || "").replace(/^━+\s*▼ DECODED OUTPUT\s*━+\s*/i, "").trim();
  return clean === (input || "").trim();
}
