"""RC5 · Phase 9.5d · Obfuscation-only Benign family (GC-291 … GC-296).

Family of regression samples proving the generic invariant:
  Obfuscation is EVIDENCE, not GUILT.
  Multi-layer decoding that produces a benign plaintext must NEVER
  elevate the verdict above Benign — regardless of how many layers,
  which encodings, or which combinations were used.

Every sample here decodes to a harmless string with zero exec-graph
malicious evidence (no URLs, LOLBAS, persistence keys, process spawn,
credential access, network I/O). Expected outcome: verdict `Benign`,
`T1027` allowed as descriptive evidence but not verdict-driving.

Coverage matrix (encodings × chain-lengths):
  GC-291 · base64                              → benign
  GC-292 · base64(base64)                      → benign (2-layer)
  GC-293 · hex → base64                        → benign (mixed)
  GC-294 · gzip → base64                       → benign (compression)
  GC-295 · UTF-16LE PS `-EncodedCommand`       → benign PS Write-Host
  GC-296 · char-array → IEX                    → benign Write-Host
"""
from __future__ import annotations

import base64
import gzip
from typing import Any, Dict, Tuple


_BENIGN_PLAINTEXT_1 = "SOC Challenge: If you can read this, you decoded it correctly."
_BENIGN_PLAINTEXT_2 = "hello world"
_BENIGN_PLAINTEXT_3 = "training exercise · decode complete"
_BENIGN_PS = 'Write-Host "hello from benign decoded PowerShell"'


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _hex(s: str) -> str:
    return s.encode().hex()


def _utf16le_b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-16le")).decode()


def _b64_of_gzip(s: str) -> str:
    return base64.b64encode(gzip.compress(s.encode())).decode()


OBFUSCATION_BENIGN_FAMILY: Tuple[Dict[str, Any], ...] = (
    {
        # Single-layer base64 of a benign challenge string. Even one
        # decode should be Benign; nothing malicious in the plaintext.
        "id": "GC-291-b64-benign-challenge",
        "language": "cmd",
        "category": "packers_obfuscation",
        "input": f"echo {_b64(_BENIGN_PLAINTEXT_1)} | base64 -d",
        "expected": {"verdict": "Benign"},
    },
    {
        # Two nested base64 layers of a benign string. T1027 may fire
        # as a descriptive tag but must NOT lift verdict.
        "id": "GC-292-b64-b64-benign",
        "language": "cmd",
        "category": "packers_obfuscation",
        "input": f"echo {_b64(_b64(_BENIGN_PLAINTEXT_2))}",
        "expected": {"verdict": "Benign"},
    },
    {
        # Hex + base64 mixed chain, benign plaintext outcome.
        "id": "GC-293-hex-b64-benign",
        "language": "cmd",
        "category": "packers_obfuscation",
        "input": f"echo {_b64(_hex(_BENIGN_PLAINTEXT_3))}",
        "expected": {"verdict": "Benign"},
    },
    {
        # Gzip + base64 compression chain, benign plaintext.
        # Exercises the FromBase64+decompress path we added in 9.5c.
        "id": "GC-294-gzip-b64-benign",
        "language": "powershell",
        "category": "packers_obfuscation",
        "input": (
            f'$b = [System.Convert]::FromBase64String("{_b64_of_gzip(_BENIGN_PLAINTEXT_2)}"); '
            f'$s = [System.Text.Encoding]::UTF8.GetString($b); Write-Host $s'
        ),
        "expected": {"verdict": "Benign"},
    },
    {
        # PowerShell `-EncodedCommand` (UTF-16LE base64) with a
        # benign `Write-Host` inside. Deep -enc decoding correctly
        # reveals the harmless payload; verdict must stay Benign.
        "id": "GC-295-ps-enc-benign-writehost",
        "language": "powershell",
        "category": "packers_obfuscation",
        "input": f"powershell -nop -w hidden -enc {_utf16le_b64(_BENIGN_PS)}",
        "expected": {"verdict_min": "Benign"},
    },
    {
        # Char-array + concat + IEX construction that ultimately
        # invokes a benign Write-Host. Obfuscation everywhere; NO
        # malicious semantics. Must stay Benign.
        "id": "GC-296-char-array-iex-benign",
        "language": "powershell",
        "category": "packers_obfuscation",
        "input": (
            "$c = [char]87+[char]114+[char]105+[char]116+[char]101+"
            "[char]45+[char]72+[char]111+[char]115+[char]116; "
            "& $c 'benign decoded output'"
        ),
        "expected": {"verdict_min": "Benign"},
    },
)


__all__ = ["OBFUSCATION_BENIGN_FAMILY"]
