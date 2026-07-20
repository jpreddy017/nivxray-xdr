"""NivX Forge · Evidence Extractor  ·  Feb-2026

Produces the SOC-grade **Verdict Card** block that ships alongside every
`/api/decode/smart` response. The card contains ONLY evidence-based
statements — never speculative labels.

    ✗  "Shellcode detected."
    ✓  "MZ signature found at offset 0; PE header missing (e_lfanew=0x0)."

Public entrypoints
------------------
- `build_verdict_card(input, output, chain, corrupted_container, is_shellcode)`
    Returns the top-level `verdict_card` object.

- `layer_metadata(op_id, before, after)`
    Returns the per-step evidence panel (encoding, length, ascii,
    hex_preview, integrity).

Design principles
-----------------
1. Every "indicator" cites a concrete artifact (bytes / offset / entropy).
2. Confidence downgrades to 0 for corrupted / undecodable inputs — we do
   NOT invent a verdict when the pipeline couldn't reach a terminal state.
3. Recommended actions are one-line SOC-runbook style ("Contain host …",
   "Escalate to IR", "Discard sample", "Enable Aggressive Recovery"), NOT
   marketing prose.
"""
from __future__ import annotations
import logging
import math
import re
from typing import Any, Dict, List, Optional

log = logging.getLogger("nivx.evidence_extractor")

# Analyst-facing message used when the automated verdict pipeline can't
# attribute a concrete verdict — either because evidence is insufficient
# or because an internal exception was caught. NEVER expose exception
# types / messages to the UI (they can leak internal paths & schema).
_FALLBACK_REASON = (
    "Automated verdict generation failed. Manual analyst review recommended."
)

# ── Byte-level constants used across indicators ─────────────────────────
_MZ    = b"MZ"
_PE_SIG = b"PE\x00\x00"
_ELF   = b"\x7fELF"
_GZIP  = b"\x1f\x8b\x08"
_ZLIB_PREFIXES = (b"\x78\x9c", b"\x78\xda", b"\x78\x01", b"\x78\x5e", b"\x78\x68")
_BZ2   = b"BZh"
_LZMA  = (b"\xfd7zXZ", b"\xfd7z\x58\x5a")

# Well-known x86/x64 shellcode prologues we recognise as EVIDENCE only
# (never as "definitive shellcode" — that's still an assumption).
_KNOWN_PROLOGUES: Dict[bytes, str] = {
    b"\xfc\xe8":       "MSFvenom x86 prologue (cld · call)",
    b"\xfc\x48":       "MSFvenom x64 prologue (cld · REX.W)",
    b"\xfc\xeb":       "Metasploit-family x86 prologue (cld · short-jmp)",
    b"\x48\x31\xc0":   "x64 zeroing prologue (xor rax, rax)",
    b"\x48\x31\xc9":   "x64 zeroing prologue (xor rcx, rcx)",
    b"\x48\x31\xd2":   "x64 zeroing prologue (xor rdx, rdx)",
    b"\x31\xc0":       "x86 zeroing prologue (xor eax, eax)",
    b"\x31\xc9":       "x86 zeroing prologue (xor ecx, ecx)",
    b"\x55\x48\x89\xe5": "x64 function frame (push rbp · mov rbp, rsp)",
}


def _to_bytes(s: str) -> bytes:
    if not s:
        return b""
    try:
        if all(ord(c) < 256 for c in s):
            return s.encode("latin-1")
        return s.encode("utf-8", errors="replace")
    except Exception:
        return s.encode("utf-8", errors="replace")


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    freq: Dict[int, int] = {}
    for x in b:
        freq[x] = freq.get(x, 0) + 1
    total = len(b)
    return round(-sum((c / total) * math.log2(c / total) for c in freq.values()), 3)


def _is_ascii(b: bytes) -> bool:
    if not b:
        return True
    printable = sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13))
    return printable / len(b) >= 0.95


def _hex_preview(b: bytes, n: int = 16) -> str:
    return " ".join(f"{x:02x}" for x in b[:n]) + (" …" if len(b) > n else "")


# ═══════════════════════════════════════════════════════════════════════
# Per-layer metadata — appended to `trace[]` entries
# ═══════════════════════════════════════════════════════════════════════
_ENCODING_LABELS: Dict[str, str] = {
    "extract-payload":   "Payload isolation (script wrapper strip)",
    "base64-decode":     "Base64 (RFC 4648)",
    "base32-decode":     "Base32 (RFC 4648)",
    "base85-decode":     "Base85 / ASCII85",
    "hex-decode":        "Hexadecimal ASCII",
    "url-decode":        "URL percent-encoding",
    "html-decode":       "HTML entity",
    "unicode-escape":    "Unicode escape (\\uNNNN)",
    "octal-ascii-decode": "Octal ASCII (\\NNN)",
    "js-charcode-decode": "JavaScript String.fromCharCode()",
    "js-hex-strings-decode": "JavaScript \\xNN hex escapes",
    "utf16le-decode":    "UTF-16 Little-Endian",
    "utf16-be-decode":   "UTF-16 Big-Endian",
    "utf32-le-decode":   "UTF-32 Little-Endian",
    "rot13":             "ROT-13 alphabetic shift",
    "reverse":           "String reversal",
    "gzip-decompress":   "GZIP (RFC 1952)",
    "zlib-decompress":   "ZLIB (RFC 1950)",
    "lzma-decompress":   "LZMA / XZ",
    "bzip2-decompress":  "BZIP2",
    "xor":               "Single-byte XOR",
    "xor-brute":         "Multi-byte XOR (brute-forced key)",
    "aes-cbc-decrypt":   "AES-CBC (analyst-provided key)",
    "rc4-decrypt":       "RC4 (hardcoded key)",
    "powershell-encoded": "PowerShell -EncodedCommand (UTF-16LE base64)",
    "powershell-deobfuscate": "PowerShell tick / [char[]] deobfuscation",
    "cmd-deobfuscate":   "CMD caret-escape deobfuscation",
    "env-expand":        "Environment-variable expansion (%TEMP%, $env:*)",
    "refang-iocs":       "IOC re-fanging (hxxp → http)",
    "extract-b64":       "Nested base64 span extraction",
    "extract-base64":    "Nested base64 span extraction",
    "ps-string-concat":  "PowerShell string concatenation",
    "ps-join-char-array": "PowerShell char-array join",
    "ps-format-op":      "PowerShell -f format-operator",
    "ps-binary-split-decode": "PowerShell binary-split / ToInt16",
    "batch-var-slice":   "Batch %var:~x,y% substring",
}


def layer_metadata(op_id: str, after: str, integrity_ok: bool = True,
                   integrity_reason: Optional[str] = None) -> Dict[str, Any]:
    """Evidence panel for a SINGLE peeled layer."""
    raw = _to_bytes(after or "")
    return {
        "encoding":   _ENCODING_LABELS.get(op_id, op_id),
        "op":         op_id,
        "length":     len(raw),
        "ascii":      _is_ascii(raw),
        "entropy":    _entropy(raw),
        "hex_preview": _hex_preview(raw),
        "integrity":  {"ok": bool(integrity_ok), "reason": integrity_reason},
    }


# ═══════════════════════════════════════════════════════════════════════
# Top-level Verdict Card
# ═══════════════════════════════════════════════════════════════════════
def _collect_indicators(input_text: str, output_text: str,
                        chain: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Cite concrete artifacts (bytes / entropy / encoding) as evidence."""
    ind: List[Dict[str, str]] = []
    out_b = _to_bytes(output_text)

    # ── Executable-format signatures ──
    if out_b.startswith(_MZ):
        # DOS header present — check e_lfanew and PE\0\0 for PE validity
        if len(out_b) >= 0x40:
            e_lfanew = int.from_bytes(out_b[0x3c:0x40], "little", signed=False)
            if 0 < e_lfanew < len(out_b) - 4 and out_b[e_lfanew:e_lfanew + 4] == _PE_SIG:
                ind.append({"label": f"PE header validated (e_lfanew=0x{e_lfanew:x}, PE\\0\\0 at offset {e_lfanew})", "kind": "positive"})
            else:
                ind.append({"label": f"MZ signature found at offset 0 — PE header missing or invalid (e_lfanew=0x{e_lfanew:x})", "kind": "negative"})
        else:
            ind.append({"label": f"MZ signature found — only {len(out_b)} bytes recovered (< 0x40 required for DOS header validation)", "kind": "negative"})
    if _ELF in out_b[:64]:
        ind.append({"label": "ELF magic (0x7f 45 4c 46) present within first 64 bytes", "kind": "positive"})

    # ── Container magic ──
    if out_b.startswith(_GZIP):
        ind.append({"label": "GZIP magic bytes preserved (1f 8b 08)", "kind": "positive"})
    for p in _ZLIB_PREFIXES:
        if out_b.startswith(p):
            ind.append({"label": f"ZLIB magic prefix detected ({p[0]:02x} {p[1]:02x})", "kind": "positive"})
            break
    if out_b.startswith(_BZ2):
        ind.append({"label": "BZIP2 magic (BZh) preserved", "kind": "positive"})
    if any(out_b.startswith(m) for m in _LZMA):
        ind.append({"label": "LZMA/XZ magic (fd 37 7a 58 5a) preserved", "kind": "positive"})

    # ── Shellcode prologues ──
    for prologue, desc in _KNOWN_PROLOGUES.items():
        if out_b.startswith(prologue):
            ind.append({"label": f"{desc} — first {len(prologue)} bytes: {' '.join(f'{b:02x}' for b in prologue)}",
                        "kind": "positive"})
            break

    # ── Entropy signal ──
    ent = _entropy(out_b)
    if len(out_b) >= 32:
        if ent >= 7.5:
            ind.append({"label": f"High entropy ({ent:.2f}) — indicates encrypted / packed / compressed data", "kind": "positive"})
        elif ent >= 6.0:
            ind.append({"label": f"Elevated entropy ({ent:.2f}) — moderate obfuscation", "kind": "neutral"})
        else:
            ind.append({"label": f"Low entropy ({ent:.2f}) — data is likely readable / ASCII text", "kind": "neutral"})

    # ── Encoding chain evidence ──
    chain_ops = [c.get("op") for c in chain or []]
    for op in chain_ops:
        label = _ENCODING_LABELS.get(op)
        if not label:
            continue
        # Only surface interesting encoding evidence (not extract-payload noise)
        if op in ("extract-payload", "refang-iocs", "extract-b64", "extract-base64"):
            continue
        ind.append({"label": f"{label} layer peeled", "kind": "neutral"})

    # ── XOR key recovery ──
    for step in chain or []:
        if step.get("op") in ("xor", "xor-brute"):
            key = (step.get("args") or {}).get("key")
            if key:
                ind.append({"label": f"XOR key recovered: {key}", "kind": "positive"})

    # ── UTF-16 flag ──
    if any(op in chain_ops for op in ("utf16le-decode", "utf16-be-decode", "powershell-encoded")):
        ind.append({"label": "UTF-16 alternating null-byte pattern detected", "kind": "positive"})

    # ── URL / IOC surfaces (lightweight — the deeper /analyze pass is authoritative) ──
    urls = re.findall(r"https?://[^\s'\"<>\\]+", output_text or "")
    for u in urls[:3]:
        ind.append({"label": f"URL surfaced in decoded output: {u}", "kind": "positive"})

    return ind


def _classify(indicators: List[Dict[str, str]],
              corrupted: Optional[Dict[str, Any]],
              chain: List[Dict[str, Any]],
              output_text: str) -> Dict[str, Any]:
    """Verdict + confidence — evidence-driven, never speculative."""
    # Corrupted container short-circuits.
    if corrupted:
        salvaged = corrupted.get("salvaged")
        if salvaged:
            preview = salvaged[:80] + ("…" if len(salvaged) > 80 else "")
            return {
                "label":      "Corrupted",
                "confidence": 20,
                "reason":     (f"Corrupted {corrupted.get('kind', '?')} container "
                               f"({corrupted.get('reason', 'integrity check failed')}), "
                               f"but raw deflate salvaged {len(salvaged)} bytes "
                               f"of UNVERIFIED plaintext: {preview!r}."),
                "recommended_action": (
                    "Compare salvaged plaintext against source before use — "
                    "CRC/trailer was invalid so integrity cannot be attested. "
                    "Do NOT ingest into automated pipelines without manual review."
                ),
            }
        return {
            "label":      "Corrupted",
            "confidence": 0,
            "reason":     (f"Corrupted {corrupted.get('kind', '?')} container: "
                           f"{corrupted.get('reason', 'integrity check failed')}. "
                           "Raw payload was also unrecoverable."),
            "recommended_action": (
                "Discard sample OR re-request the payload from the analyst. "
                "Do not attempt further deterministic recovery — enable "
                "Aggressive Recovery only if provenance is trusted."
            ),
        }

    positive = [i for i in indicators if i.get("kind") == "positive"]
    n_positive = len(positive)
    chain_len = len([c for c in (chain or []) if c.get("op") != "extract-payload"])

    # Undecoded — no chain and no indicators
    if chain_len == 0 and n_positive == 0:
        return {
            "label":      "Undecoded",
            "confidence": 0,
            "reason":     "No recognised encoding layer or executable signature found in the input.",
            "recommended_action": (
                "Manually inspect the raw bytes / hex dump. "
                "If provenance is untrusted, discard the sample."
            ),
        }

    # Malicious — hard evidence of exec-format / shellcode prologue / active
    # URL / malware family match / LOLBAS abuse.
    hard = [i for i in positive if any(k in i["label"] for k in (
        "PE header validated", "ELF magic", "prologue", "MSFvenom",
        "URL surfaced", "URL indicator", "Malware family match",
        "LOLBAS binary",
    ))]
    if hard:
        return {
            "label":      "Malicious",
            "confidence": min(95, 60 + 10 * len(hard)),
            "reason":     hard[0]["label"] + ".",
            "recommended_action": (
                "Contain source host, hunt for parent process, submit to "
                "sandbox / VirusTotal, and correlate URL / MITRE mapping."
            ),
        }

    # MITRE-heavy signals — even without a URL / LOLBIN we escalate to
    # Suspicious-High when ATT&CK techniques are present.
    mitre = [i for i in positive if "MITRE ATT&CK" in i["label"]]
    if len(mitre) >= 3:
        return {
            "label":      "Suspicious",
            "confidence": min(80, 40 + 5 * len(mitre)),
            "reason":     (f"{len(mitre)} MITRE ATT&CK techniques identified: "
                            + ", ".join(m["label"].split("—", 1)[0].strip()
                                        for m in mitre[:3]) + "."),
            "recommended_action": (
                "Escalate to IR — the technique mapping is broad enough to "
                "indicate active tradecraft. Cross-check against SIEM."
            ),
        }

    # Suspicious — obfuscation chain OR high entropy OR magic-preserved-only
    if chain_len >= 1 or n_positive >= 1:
        return {
            "label":      "Suspicious",
            "confidence": min(80, 30 + 15 * chain_len + 5 * n_positive),
            "reason":     (positive[0]["label"] + "."
                           if positive else
                           f"Peeled {chain_len} encoding layer(s) without an executable "
                           "signature — reviewer confirmation required."),
            "recommended_action": (
                "Escalate to IR for behavioural sandbox / dynamic analysis "
                "and confirm the terminal payload against threat-intel."
            ),
        }

    # Benign — text output, no encoding
    return {
        "label":      "Benign",
        "confidence": 40,
        "reason":     "No obfuscation layers peeled and no executable signatures detected.",
        "recommended_action": "No further deterministic analysis required.",
    }


def _fallback_card(reason: str) -> Dict[str, Any]:
    """Structured fallback when the evidence pipeline can't build a
    concrete verdict — NEVER return None. Downstream consumers (UI, SIEM
    push, batch aggregators) rely on this shape being present.
    """
    return {
        "label":              "Inconclusive",
        "verdict":            "Inconclusive",       # explicit alias for old clients
        "confidence":         0,
        "risk_score":         0,
        "reason":             reason or "Insufficient evidence to attribute a verdict.",
        "indicators":         [],
        "recommended_action": (
            "Manually review the payload — the automated pipeline did not "
            "gather enough concrete evidence to attribute a verdict."
        ),
    }


def build_verdict_card(input_text: str, output_text: str,
                       chain: List[Dict[str, Any]],
                       corrupted_container: Optional[Dict[str, Any]] = None,
                       findings: Optional[Dict[str, Any]] = None,
                       ) -> Dict[str, Any]:
    """Assemble the SOC Verdict Card — the top-of-workspace analyst brief.

    Feb-2026 hardening (P0.1):
      * Always returns a structured dict — never `None`. Any internal
        exception is caught and converted into an `Inconclusive` fallback
        card so downstream UI / SIEM never sees a null.
      * When `findings` are supplied (MITRE / LOLBIN / IOC / family), they
        are lifted into indicators and contribute to the verdict tier —
        previously the card was decided ONLY on byte-level artifacts and
        chain length, so payloads with 7 MITRE + LOLBIN + URL that had no
        MZ header or `http://` literal in the output ended up as bland
        Suspicious-30% (or slipped through with a None when the caller's
        step-dict was missing a key).
    """
    try:
        indicators = _collect_indicators(input_text or "", output_text or "", chain or [])

        # Lift intelligence-pipeline findings into indicators so `_classify`
        # can see them. Findings are OPTIONAL — callers that don't have
        # them yet (early legacy path) still get a working card.
        if findings:
            for tech in (findings.get("mitre_techniques") or findings.get("mitre") or [])[:8]:
                tid = tech.get("id") if isinstance(tech, dict) else str(tech)
                tname = tech.get("technique") or tech.get("name") if isinstance(tech, dict) else ""
                if tid:
                    indicators.append({
                        "kind":  "positive",
                        "label": f"MITRE ATT&CK {tid}" + (f" — {tname}" if tname else ""),
                    })
            for hit in (findings.get("lolbas") or [])[:5]:
                name = hit.get("binary") or hit.get("name") if isinstance(hit, dict) else str(hit)
                if name:
                    indicators.append({
                        "kind":  "positive",
                        "label": f"LOLBAS binary observed: {name}",
                    })
            iocs = findings.get("iocs") or {}
            if isinstance(iocs, dict):
                for u in (iocs.get("urls") or [])[:3]:
                    indicators.append({"kind": "positive",
                                        "label": f"URL indicator: {u}"})
                for h in (iocs.get("hosts") or iocs.get("domains") or [])[:3]:
                    indicators.append({"kind": "positive",
                                        "label": f"Host / domain indicator: {h}"})
                for i in (iocs.get("ips") or [])[:3]:
                    indicators.append({"kind": "positive",
                                        "label": f"IP indicator: {i}"})
            fam = findings.get("family") or {}
            if isinstance(fam, dict) and fam.get("name"):
                indicators.append({
                    "kind":  "positive",
                    "label": f"Malware family match: {fam.get('name')} "
                             f"(confidence {fam.get('confidence', 0)})",
                })

        # Surface salvaged plaintext as a POSITIVE indicator so analysts see it in
        # the Evidence list, not just buried in the Reason line.
        if corrupted_container and corrupted_container.get("salvaged"):
            salv = corrupted_container["salvaged"]
            preview = salv[:80] + ("…" if len(salv) > 80 else "")
            indicators.insert(0, {
                "kind":  "positive",
                "label": (f"Raw deflate salvaged {len(salv)} bytes (UNVERIFIED — "
                          f"CRC could not be validated): {preview!r}"),
            })
        verdict = _classify(indicators, corrupted_container, chain or [], output_text or "")
        return {
            "label":               verdict["label"],
            "verdict":             verdict["label"],      # alias — some clients read `verdict`
            "confidence":          verdict["confidence"],
            "risk_score":          verdict["confidence"], # alias — legacy field name
            "reason":              verdict["reason"],
            "indicators":          indicators,
            "recommended_action":  verdict["recommended_action"],
        }
    except Exception:
        log.exception("Verdict card generation failed")
        return _fallback_card(_FALLBACK_REASON)
