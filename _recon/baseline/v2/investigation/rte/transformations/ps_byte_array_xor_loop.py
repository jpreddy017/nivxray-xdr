"""ps_byte_array_xor_loop · fold the canonical Empire / Nishang /
Cobalt Strike terminal stager idiom:

    [Byte[]]$var_code = [System.Convert]::FromBase64String('<b64>')
    for ($x = 0; $x -lt $var_code.Count; $x++) {
        $var_code[$x] = $var_code[$x] -bxor <K>
    }

Base64-decodes the blob, applies ``b ^ K`` for each byte, and emits
a synthetic printable block that surfaces ASCII-embedded IOCs
(C2 IPs, User-Agents, function names, paths) hidden inside the
resulting shellcode.  100 % deterministic — no runtime execution.

Registered BEFORE ``ps_static_base64`` so the specific-idiom (blob +
loop referencing the same variable) wins over the bare
``FromBase64String(...)`` matcher.  Otherwise the base64 blob would
be folded away first and the XOR-loop context would be lost.
"""
from __future__ import annotations

import base64
import re
from typing import List, Optional, Tuple

from ...evidence import Evidence
from ..models import Artifact


# ── Canonical CS / Empire / Nishang idiom ─────────────────────────
_IDIOM_RE = re.compile(
    r"""
    \[\s*Byte\s*\[\s*\]\s*\]\s*
    \$(?P<var>[A-Za-z_][A-Za-z0-9_]*)
    \s*=\s*
    \[\s*(?:System\.)?Convert\s*\]\s*::\s*FromBase64String\s*\(
        \s*['"](?P<b64>[A-Za-z0-9+/=\s]{40,})['"]\s*
    \)\s*;?\s*
    for\s*\(
        \s*\$\w+\s*=\s*0\s*;\s*
        \$\w+\s*-lt\s*\$(?P=var)\.(?:Count|Length)\s*;\s*
        \$\w+\s*\+\+\s*
    \)\s*\{\s*
        \$(?P=var)\s*\[\s*\$\w+\s*\]\s*=\s*
        \$(?P=var)\s*\[\s*\$\w+\s*\]\s*
        -b?xor\s*(?P<key>0[xX][0-9a-fA-F]+|\d{1,3})
    \s*\}?
    """,
    re.IGNORECASE | re.DOTALL | re.VERBOSE,
)


def _scan_iocs(buf: bytes) -> List[str]:
    """Extract IPs / URLs / domains / User-Agents from a byte blob."""
    hits: List[str] = []
    ip = re.findall(rb"\b(\d{1,3}(?:\.\d{1,3}){3})\b", buf)
    for candidate in ip:
        octs = [int(o) for o in candidate.split(b".")]
        if all(0 <= o <= 255 for o in octs) and octs[0] not in (0, 127, 255):
            hits.append(f"ip:{candidate.decode()}")
    url = re.findall(rb"https?://[A-Za-z0-9.\-_/?%=&+~#:@]{6,300}", buf)
    for u in url:
        hits.append(f"url:{u.decode(errors='ignore')}")
    ua = re.search(rb"Mozilla/[0-9.]+ \([^\x00\n]{5,200}", buf)
    if ua:
        hits.append(f"ua:{ua.group().decode(errors='ignore')}")
    return hits


def _ascii_strings(buf: bytes, *, min_len: int = 5,
                    max_out: int = 24) -> List[str]:
    out, cur = [], []
    for b in buf:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                out.append("".join(cur))
                if len(out) >= max_out:
                    break
            cur = []
    if cur and len(cur) >= min_len and len(out) < max_out:
        out.append("".join(cur))
    return out


class PsByteArrayXorLoopTransformation:
    NAME = "ps_byte_array_xor_loop"

    def _try(self, artifact: Artifact) -> Optional[Tuple[str, int, int, int]]:
        m = _IDIOM_RE.search(artifact.content)
        if not m:
            return None
        b64 = re.sub(r"\s+", "", m.group("b64"))
        if len(b64) < 40:
            return None
        key_tok = m.group("key")
        try:
            key = (int(key_tok, 16) if key_tok.lower().startswith("0x")
                     else int(key_tok))
        except ValueError:
            return None
        if not (0 <= key <= 0xFF):
            return None
        try:
            raw = base64.b64decode(b64 + "=" * (-len(b64) % 4), validate=False)
        except Exception:
            return None
        if not raw:
            return None
        return b64, key, m.start(), m.end()

    def applicable(self, artifact: Artifact) -> Evidence | None:
        r = self._try(artifact)
        if r is None:
            return None
        _, key, _, _ = r
        return Evidence(
            source=f"rte.{self.NAME}",
            observation=(
                f"[Byte[]]$var = FromBase64String(...) + "
                f"for(){{-bxor 0x{key:02X}}} idiom detected"
            ),
            # Higher than ps_static_base64 (93) so we win when both
            # would fire — the XOR-loop idiom is strictly more
            # specific than a lone FromBase64String call.
            confidence=96,
            rationale=(
                "PowerShell script contains the canonical Empire / "
                "Nishang / Cobalt Strike terminal stager idiom: a "
                "byte-array bound to a static base64 blob followed by "
                "a `for` loop that XORs every byte with a constant "
                "key. This is deterministic — the recovered plaintext "
                "surfaces the shellcode's ASCII-embedded IOCs (C2 IPs, "
                "User-Agents, function names)."
            ),
            meta={"xor_key": key, "xor_key_hex": f"0x{key:02X}"},
        )

    def apply(self, artifact: Artifact) -> tuple[str, list[Evidence]]:
        r = self._try(artifact)
        assert r is not None
        b64, key, start, end = r
        raw = base64.b64decode(b64 + "=" * (-len(b64) % 4), validate=False)
        decoded = bytes(b ^ key for b in raw)
        iocs = _scan_iocs(decoded)
        strings = _ascii_strings(decoded)
        tag_lines = [
            f"[byte-array XOR loop decoded · key=0x{key:02X} · "
            f"{len(decoded)} bytes]",
        ]
        if iocs:
            tag_lines.append("  embedded_iocs: " + ", ".join(iocs))
        if strings:
            tag_lines.append("  extracted_strings:")
            for s in strings[:16]:
                tag_lines.append(f"    · {s}")
        tag = "\n".join(tag_lines)
        new_content = artifact.content[:start] + tag + artifact.content[end:]
        ev = Evidence(
            source=f"rte.{self.NAME}",
            observation=(
                f"XOR-decoded {len(decoded)} bytes with key 0x{key:02X}"
                + (f" · IOCs: {', '.join(iocs)}" if iocs else "")
            ),
            confidence=96,
            rationale=(
                "Base64-decoded the byte array and applied XOR with the "
                "extracted constant key.  Surfaced embedded ASCII "
                "strings + IOCs for downstream promotion into the "
                "canonical IOC set."
            ),
            meta={
                "xor_key":         key,
                "xor_key_hex":     f"0x{key:02X}",
                "bytes_in":        len(raw),
                "bytes_out":       len(decoded),
                "embedded_iocs":   iocs,
                "extracted_strings": strings[:16],
                "in_len":          len(artifact.content),
                "out_len":         len(new_content),
            },
        )
        return new_content, [ev]


TRANSFORMATION = PsByteArrayXorLoopTransformation()
