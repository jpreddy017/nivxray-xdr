/**
 * magicLite.js — Client-side "Magic-lite" auto-detect on paste.
 *
 * Runs ALL 14 CLIENT_OPS in parallel against the input, scores each output
 * with the same heuristics the backend Magic decoder uses (printable ratio,
 * english word density, structure signatures), and returns the top-3
 * candidate chains. Purely client-side — zero network latency.
 *
 * Two-level scoring:
 *   1. Single-op candidates    — each op is applied once
 *   2. Recursive candidates    — best single-op output is recursively decoded
 *
 * Returns:
 *   {
 *     candidates: [{ op, args, output, score, breakdown, chain }],
 *     best: {...top candidate},
 *     elapsed_ms
 *   }
 */
import { CLIENT_OPS } from "./clientOps.js";

const COMMON_WORDS = new Set(
  "the be to of and a in that have i it for not on with he as you do at this but his by from they we say her she or an will my one all would there their what so up out if about who get which go me when make can like time no just him know take people into year your good some could them see other than then now look only come its over think also back after use two how our work first well way even new want because any these give day most us http https url domain ip mail email password user admin login exit exec eval file open close create delete run start stop server client key token secret cert cred config error debug info true false null void class function return value string object list array count size length name host port script command process malware attack exploit payload shellcode backdoor rootkit trojan phish encode decode encrypt decrypt base64 hex url html json xml powershell bash python microsoft windows linux system network".split(" ")
);

const PS_KWORDS = /\b(IEX|Invoke-Expression|Invoke-WebRequest|Net\.WebClient|DownloadString|DownloadFile|Add-MpPreference|New-Object|System\.Reflection|VirtualAlloc|CreateThread|FromBase64String)\b/i;
const URL_RE = /https?:\/\/[^\s"'<>]+/;
const PE_HEADER = /^\s*MZ.{50,120}This program (?:cannot|must)/s;

function _printableRatio(s) {
  if (!s) return 0;
  let p = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13) p++;
  }
  return p / s.length;
}

function _englishDensity(s) {
  const words = s.toLowerCase().match(/[a-z][a-z']{2,}/g) || [];
  if (words.length === 0) return 0;
  let hits = 0;
  for (const w of words) if (COMMON_WORDS.has(w)) hits++;
  return hits / words.length;
}

function _structureBonus(s) {
  const bonuses = [];
  let total = 0;
  if (/^\s*[[{]/.test(s) && (s.includes("{") || s.includes("["))) {
    total += 0.2;
    bonuses.push("json-shape");
  }
  if (URL_RE.test(s)) {
    total += 0.2;
    bonuses.push("url");
  }
  if (PS_KWORDS.test(s)) {
    total += 0.35;
    bonuses.push("ps-keywords");
  }
  if (PE_HEADER.test(s)) {
    total += 0.3;
    bonuses.push("pe-header");
  }
  return { total, bonuses };
}

/** Score any decoded output on a 0–~1.5 scale. */
export function scoreOutput(text) {
  if (!text || (typeof text !== "string" && !(text instanceof Uint8Array))) {
    return { score: 0, reasons: ["empty"] };
  }
  const s = typeof text === "string" ? text : new TextDecoder("utf-8", { fatal: false }).decode(text);
  if (!s) return { score: 0, reasons: ["empty"] };
  if (s.length > 200000) return { score: 0, reasons: ["output-too-large"] };
  const pr = _printableRatio(s);
  const ed = _englishDensity(s);
  const { total: sb, bonuses } = _structureBonus(s);
  const L = s.length;
  const sizeScore = L < 8 ? 0.1 : L > 20000 ? 0.5 : 1.0;
  const score = 0.3 * pr + 0.3 * ed + 0.15 * sizeScore + sb;
  const reasons = [];
  if (pr > 0.9) reasons.push(`printable=${pr.toFixed(2)}`);
  if (ed > 0.03) reasons.push(`english=${ed.toFixed(2)}`);
  reasons.push(...bonuses);
  return {
    score: Number(score.toFixed(4)),
    printable: Number(pr.toFixed(3)),
    english: Number(ed.toFixed(3)),
    size: L,
    reasons,
  };
}

// Detectors that decide whether a given op should even be tried on the input.
// Cheap gating so the "16 ops × recursion" search stays under 5ms for typical inputs.
function _isBase64Like(s) {
  const clean = s.replace(/\s+/g, "");
  return clean.length >= 8 && /^[A-Za-z0-9+/=_-]+$/.test(clean);
}
function _isHexLike(s) {
  const clean = s.replace(/\s+/g, "");
  return clean.length >= 8 && clean.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(clean);
}
function _hasCharCodes(s) {
  return s.includes("String.fromCharCode") || /^\s*(?:0x)?[0-9]+\s*[,;]/i.test(s);
}
function _hasHexEscapes(s) {
  return /\\x[0-9a-fA-F]{2}/.test(s);
}
function _hasUrlEnc(s) {
  return (s.match(/%[0-9A-Fa-f]{2}/g) || []).length >= 2;
}
function _hasHtmlEnt(s) {
  return /&(?:#x?[0-9a-fA-F]+|[a-zA-Z]+);/.test(s);
}
function _looksBase32(s) {
  const clean = s.replace(/\s+/g, "").replace(/=+$/, "");
  return clean.length >= 8 && /^[A-Z2-7]+$/i.test(clean);
}
function _looksUtf16le(s) {
  // half the bytes zero in alternating positions
  if (s.length < 8) return false;
  let zeros = 0;
  const cap = Math.min(s.length, 40);
  for (let i = 1; i < cap; i += 2) if (s.charCodeAt(i) === 0) zeros++;
  return zeros >= cap / 4;
}

/**
 * detectCandidates(input) → array of {op, applicable, why}.
 * Cheap heuristic filter — narrows 14 ops down to 3-6 that could plausibly apply.
 */
export function detectCandidates(input) {
  if (typeof input !== "string" || !input || input.length > 200_000) return [];
  const s = input.trim();
  const cands = [];
  if (_isBase64Like(s)) {
    cands.push({ op: "base64-decode", why: "base64-shaped input" });
    // gzip decompress speculates on base64 wrapper too
    cands.push({ op: "gzip-decompress", why: "possibly base64+gzip" });
    cands.push({ op: "zlib-decompress", why: "possibly base64+zlib" });
  }
  if (_isHexLike(s)) cands.push({ op: "hex-decode", why: "hex-shaped input" });
  if (_hasUrlEnc(s)) cands.push({ op: "url-decode", why: "URL % encoded chars" });
  if (_hasHtmlEnt(s)) cands.push({ op: "html-decode", why: "HTML entities detected" });
  if (_hasCharCodes(s) && s.includes("fromCharCode")) cands.push({ op: "from-charcode", why: "String.fromCharCode() call" });
  if (_hasHexEscapes(s)) cands.push({ op: "hex-decode", why: "\\xNN hex escapes" });
  if (_looksBase32(s) && !_isBase64Like(s)) cands.push({ op: "base32-decode", why: "base32-shaped input" });
  if (_looksUtf16le(s)) cands.push({ op: "utf16le-decode", why: "utf-16LE byte pattern" });
  if (/^[A-Za-z\s.,!?"'\-]{10,}$/.test(s) && !_isBase64Like(s)) {
    cands.push({ op: "rot13", why: "alphabetic — possible ROT13" });
  }
  // De-dupe by op id (preserve first occurrence)
  const seen = new Set();
  return cands.filter((c) => {
    if (seen.has(c.op)) return false;
    seen.add(c.op);
    return true;
  });
}

/**
 * magicLite(input, { maxDepth = 3, topN = 3 }) → { candidates, best, elapsedMs }
 *
 * Tries each detected candidate, scores the output, then recursively tries
 * further candidates on the best output. Returns top-N chains sorted by score.
 */
export function magicLite(input, { maxDepth = 3, topN = 3 } = {}) {
  const start = performance.now();
  const results = [];

  function walk(cur, chain, depth) {
    const cands = detectCandidates(typeof cur === "string" ? cur : "");
    for (const c of cands) {
      const op = CLIENT_OPS[c.op];
      if (!op) continue;
      let out;
      try {
        out = op.fn(cur, {});
      } catch {
        continue;
      }
      if (out == null) continue;
      const sb = scoreOutput(out);
      const newChain = [...chain, { op: c.op, args: {}, reason: c.why }];
      results.push({
        chain: newChain,
        output: typeof out === "string" ? out : new TextDecoder().decode(out),
        score: sb.score,
        breakdown: sb,
      });
      if (depth + 1 < maxDepth && sb.score > 0.2) {
        walk(out, newChain, depth + 1);
      }
    }
  }

  walk(input, [], 0);

  // De-dupe by output snippet and keep top-N
  const seen = new Set();
  const dedup = [];
  results
    .sort((a, b) => b.score - a.score)
    .forEach((r) => {
      const k = r.output.slice(0, 200) + "|" + r.chain.length;
      if (seen.has(k)) return;
      seen.add(k);
      dedup.push(r);
    });

  const topResults = dedup.slice(0, topN);
  return {
    candidates: topResults,
    best: topResults[0] || null,
    elapsedMs: Math.round(performance.now() - start),
  };
}
