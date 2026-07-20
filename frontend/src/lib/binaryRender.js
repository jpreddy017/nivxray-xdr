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

// Extract ASCII strings of length ≥ minLen — mimics the Unix `strings` tool
function extractStrings(text, minLen = 4, cap = 40) {
  const out = [];
  let cur = "";
  for (let i = 0; i < text.length && out.length < cap; i++) {
    const c = text.charCodeAt(i);
    if (c >= 0x20 && c <= 0x7e) {
      cur += text[i];
    } else {
      if (cur.length >= minLen) out.push(cur);
      cur = "";
    }
  }
  if (cur.length >= minLen) out.push(cur);
  return out;
}

// Simple Shannon entropy over the char code distribution (0..8, higher = more random)
function entropy(text) {
  if (!text) return 0;
  const freq = new Array(256).fill(0);
  const n = Math.min(text.length, 4096);   // cap for perf
  for (let i = 0; i < n; i++) freq[text.charCodeAt(i) & 0xff]++;
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
  const n = Math.min(text.length, 4096);
  let printable = 0;
  for (let i = 0; i < n; i++) {
    const c = text.charCodeAt(i);
    if ((c >= 0x20 && c <= 0x7e) || c === 0x09 || c === 0x0a || c === 0x0d) printable++;
  }
  return printable / n;
}

function detectMagic(text) {
  if (!text) return null;
  for (const m of MAGICS) {
    if (text.startsWith(m.prefix)) return m;
  }
  // PE-specific: sometimes the MZ header has been trimmed but the DOS-stub message remains.
  if (text.includes(PE_MARKER)) return { prefix: "", label: "PE executable (Windows)", ext: ".exe/.dll" };
  return null;
}

// Compact hex-preview: first `bytes` chars → "4d 5a 90 00 03 00 00 00  |  MZ......"
function hexPreview(text, bytes = 96) {
  if (!text) return "";
  const rows = [];
  for (let off = 0; off < Math.min(text.length, bytes); off += 16) {
    const chunk = text.slice(off, off + 16);
    const hex = Array.from(chunk).map((c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join(" ");
    const ascii = Array.from(chunk).map((c) => {
      const cc = c.charCodeAt(0);
      return (cc >= 0x20 && cc <= 0x7e) ? c : ".";
    }).join("");
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
  const src = String(text || "");
  const byteLen = new Blob([src]).size;
  const pr = printableRatio(src);
  const h = entropy(src);
  const magic = detectMagic(src);

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
    hexPreview: kind === "binary" ? hexPreview(src, 128) : "",
    strings: kind === "binary" || kind === "partial" ? extractStrings(src, 5, 24) : [],
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
