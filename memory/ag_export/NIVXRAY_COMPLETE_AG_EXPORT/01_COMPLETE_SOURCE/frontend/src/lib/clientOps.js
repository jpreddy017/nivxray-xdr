/**
 * clientOps.js — Lightweight JavaScript ports of the 12 most-used NivXRay
 * decode operations. Runs entirely in the browser for real-time recipe
 * preview. Falls back to the backend for ops not listed in CLIENT_OPS.
 *
 * Design goals:
 *   • Byte-preserving where possible (returns Uint8Array for binary output
 *     even when the input was text)
 *   • Zero dependencies except `pako` for gzip (already installed)
 *   • Errors are thrown — callers wrap in try/catch or use runClientRecipe
 */
import { inflate as pakoInflate, ungzip as pakoUngzip } from "pako";

// ---------- helpers ----------
const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: false });

function toBytes(x) {
  if (x instanceof Uint8Array) return x;
  if (typeof x === "string") return enc.encode(x);
  throw new TypeError("expected string or Uint8Array");
}
function toText(x) {
  if (typeof x === "string") return x;
  if (x instanceof Uint8Array) return dec.decode(x);
  throw new TypeError("expected string or Uint8Array");
}

// Latin-1 safe base64 encode (for arbitrary bytes)
function bytesToBase64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function base64ToBytes(b64) {
  const cleaned = b64.replace(/\s+/g, "");
  const bin = atob(cleaned);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---------- ops ----------
export const CLIENT_OPS = {
  "base64-decode": {
    label: "Base64 Decode",
    fn: (input) => {
      const bytes = base64ToBytes(toText(input));
      // Try UTF-8; if it decodes cleanly, return string. Else return raw bytes.
      try {
        const strict = new TextDecoder("utf-8", { fatal: true });
        return strict.decode(bytes);
      } catch {
        return bytes;
      }
    },
  },

  "base64-encode": {
    label: "Base64 Encode",
    fn: (input) => bytesToBase64(toBytes(input)),
  },

  "hex-decode": {
    label: "Hex Decode",
    fn: (input) => {
      const cleaned = toText(input).replace(/[^0-9a-fA-F]/g, "");
      if (cleaned.length % 2 !== 0) throw new Error("hex length not even");
      const out = new Uint8Array(cleaned.length / 2);
      for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(cleaned.substr(i * 2, 2), 16);
      }
      try {
        return new TextDecoder("utf-8", { fatal: true }).decode(out);
      } catch {
        return out;
      }
    },
  },

  "hex-encode": {
    label: "Hex Encode",
    fn: (input) => Array.from(toBytes(input))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(""),
  },

  "url-decode": {
    label: "URL Decode",
    fn: (input) => decodeURIComponent(toText(input).replace(/\+/g, " ")),
  },

  "url-encode": {
    label: "URL Encode",
    fn: (input) => encodeURIComponent(toText(input)),
  },

  "from-charcode": {
    label: "From Char Code",
    fn: (input) => {
      const text = toText(input);
      // Accept comma / space / semicolon separated
      const parts = text.split(/[,;\s]+/).filter(Boolean);
      return String.fromCharCode(...parts.map((p) => {
        const n = p.startsWith("0x") || p.startsWith("0X")
          ? parseInt(p.slice(2), 16)
          : parseInt(p, 10);
        if (Number.isNaN(n)) throw new Error(`invalid char code: ${p}`);
        return n;
      }));
    },
  },

  "xor": {
    label: "XOR",
    fn: (input, args = {}) => {
      const bytes = toBytes(input);
      const keyRaw = args.key ?? "0";
      const keyBytes =
        typeof keyRaw === "string" && keyRaw.startsWith("0x")
          ? new Uint8Array([parseInt(keyRaw.slice(2), 16) & 0xff])
          : typeof keyRaw === "string" && keyRaw.length > 1 && Number.isNaN(Number(keyRaw))
          ? enc.encode(keyRaw) // multi-char keys — repeating
          : new Uint8Array([parseInt(keyRaw, 10) & 0xff]);
      if (keyBytes.length === 0) throw new Error("XOR key required");
      const out = new Uint8Array(bytes.length);
      for (let i = 0; i < bytes.length; i++) {
        out[i] = bytes[i] ^ keyBytes[i % keyBytes.length];
      }
      try {
        return new TextDecoder("utf-8", { fatal: true }).decode(out);
      } catch {
        return out;
      }
    },
  },

  "gzip-decompress": {
    label: "Gzip Decompress",
    fn: (input) => {
      // Accept base64-wrapped or raw gzip bytes
      let bytes = toBytes(input);
      if (bytes.length > 4 && bytes[0] !== 0x1f) {
        // Not a gzip prefix — assume base64 wrapper and try to unwrap
        try {
          bytes = base64ToBytes(toText(input));
        } catch {
          /* keep original */
        }
      }
      const out = pakoUngzip(bytes);
      try {
        return new TextDecoder("utf-8", { fatal: true }).decode(out);
      } catch {
        return out;
      }
    },
  },

  "zlib-decompress": {
    label: "Zlib Decompress",
    fn: (input) => {
      let bytes = toBytes(input);
      if (bytes.length > 2 && bytes[0] !== 0x78) {
        try { bytes = base64ToBytes(toText(input)); } catch { /* keep */ }
      }
      const out = pakoInflate(bytes);
      try {
        return new TextDecoder("utf-8", { fatal: true }).decode(out);
      } catch {
        return out;
      }
    },
  },

  "base32-decode": {
    label: "Base32 Decode",
    fn: (input) => {
      const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
      const cleaned = toText(input).replace(/=+$/, "").toUpperCase().replace(/\s+/g, "");
      const bits = [];
      for (const ch of cleaned) {
        const v = alphabet.indexOf(ch);
        if (v < 0) throw new Error(`invalid base32 char: ${ch}`);
        for (let i = 4; i >= 0; i--) bits.push((v >> i) & 1);
      }
      const bytes = new Uint8Array(Math.floor(bits.length / 8));
      for (let i = 0; i < bytes.length; i++) {
        let b = 0;
        for (let j = 0; j < 8; j++) b = (b << 1) | bits[i * 8 + j];
        bytes[i] = b;
      }
      try {
        return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      } catch {
        return bytes;
      }
    },
  },

  "utf16le-decode": {
    label: "UTF-16LE Decode",
    fn: (input) => {
      const bytes = toBytes(input);
      // Every-other-byte pattern common in PowerShell -EncodedCommand payloads
      const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      const words = [];
      for (let i = 0; i + 1 < bytes.length; i += 2) {
        words.push(dv.getUint16(i, true));
      }
      return String.fromCharCode(...words);
    },
  },

  "from-decimal": {
    label: "From Decimal",
    fn: (input) => {
      const parts = toText(input).split(/[,\s;]+/).filter(Boolean);
      const bytes = new Uint8Array(parts.map((p) => {
        const n = parseInt(p, 10);
        if (Number.isNaN(n) || n < 0 || n > 255) throw new Error(`invalid byte: ${p}`);
        return n;
      }));
      try {
        return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      } catch {
        return bytes;
      }
    },
  },

  "from-binary": {
    label: "From Binary",
    fn: (input) => {
      const cleaned = toText(input).replace(/[^01]/g, "");
      if (cleaned.length % 8 !== 0) throw new Error("binary length not divisible by 8");
      const bytes = new Uint8Array(cleaned.length / 8);
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(cleaned.substr(i * 8, 8), 2);
      }
      try {
        return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      } catch {
        return bytes;
      }
    },
  },

  "rot13": {
    label: "ROT13",
    fn: (input) => toText(input).replace(/[a-zA-Z]/g, (c) => {
      const base = c <= "Z" ? 65 : 97;
      return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
    }),
  },
};

// ---------- pipeline runner ----------
/**
 * runClientRecipe(input, steps) → { output, ranSteps, unsupported, error }
 *
 * Executes as many steps as possible client-side, in order. If it hits an op
 * that's not in CLIENT_OPS, it stops and reports the remaining backend ops
 * (caller falls back to `POST /api/recipe/run`).
 */
export function runClientRecipe(input, steps) {
  let cur = input;
  const ranSteps = [];
  for (let i = 0; i < steps.length; i++) {
    const s = steps[i];
    const op = CLIENT_OPS[s.op];
    if (!op) {
      return {
        output: typeof cur === "string" ? cur : bytesToBase64(cur),
        outputBytes: cur instanceof Uint8Array ? cur : null,
        ranSteps,
        unsupported: steps.slice(i).map((x) => x.op),
        needsBackend: true,
      };
    }
    try {
      cur = op.fn(cur, s.args || {});
      ranSteps.push({ op: s.op, ok: true });
    } catch (e) {
      return {
        output: typeof cur === "string" ? cur : bytesToBase64(cur),
        outputBytes: cur instanceof Uint8Array ? cur : null,
        ranSteps: [...ranSteps, { op: s.op, ok: false, error: e.message }],
        error: `${s.op}: ${e.message}`,
      };
    }
  }
  return {
    output: typeof cur === "string" ? cur : bytesToBase64(cur),
    outputBytes: cur instanceof Uint8Array ? cur : null,
    ranSteps,
    unsupported: [],
    needsBackend: false,
  };
}

export const CLIENT_OP_IDS = Object.keys(CLIENT_OPS);
