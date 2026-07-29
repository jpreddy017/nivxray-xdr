"""ADR-0004 · MITRE shape discriminator tests.

Locks the three-shape (A / B / C) classification against real-corpus
sample heads pulled from DIAGNOSTIC_RC4_SHELLCODE_2026-02-28.md.
"""

from nivxforge.attribution.mitre_shape import classify


CASE_0001_INPUT = (
    "powershell -NoProfile -NonInteractive \""
    "((97,68,95,66,83,27,126,89,69,66,22,17,126,83,90,90,89,22,97,89,68,"
    "90,82,23,17,22,27,112,89,68,83,81,68,89,67,88,82,117,89,90,89,68,22,"
    "113,68,83,83,88) | ForEach-Object {[Char]($_ -bxor '0x36')} ) -join '' | Invoke-Expression\""
)

# Six diagnostic-corpus heads — representative of the 187 mislabelled rows.
DIAGNOSTIC_HEADS = [
    "powershell -NonInter \"((97,68,95,66,83,27,126,89,69,66) | ForEach-Object {[Char]($_ -bxor '0x2A')} ) | iex\"",
    "powershell -nop -w hidden \"((88,84,73,49,57,120,102,99) | ForEach-Object {[char]($_ -bxor '0x5C')} ) -join '' | iex\"",
    "powershell -nop -w hidden \"((70,99,120,101,116,60,89,126) | ForEach-Object {[char]($_ -bxor '0x11')} ) -join '' | Invoke-Expression\"",
    "powershell -nop -w hidden \"((99,111,114,10,2,67,93,88) | ForEach-Object {[char]($_ -bxor '0x21')} ) -join '' | iex\"",
    "powershell -nop -w hidden \"((127,88,64,89,93,83,27,115) | ForEach-Object {[char]($_ -bxor '0x2A')} ) -join '' | iex\"",
    CASE_0001_INPUT,
]

TRUE_RC4_INPUT = "arbitrary bytes here — key scheduling and PRGA are in the chain"


# ── Shape A · PowerShell string-XOR ────────────────────────────────────
def test_case_0001_classifies_as_shape_a():
    r = classify(CASE_0001_INPUT)
    assert r.shape == "A_powershell_xor"
    assert "T1027.010" in r.mitre_ids
    assert "T1140" in r.mitre_ids  # key 0x36 recovered
    assert "T1027.013" not in r.mitre_ids
    assert r.recovered_xor_key == "0x36"


def test_all_diagnostic_heads_classify_as_shape_a():
    for head in DIAGNOSTIC_HEADS:
        r = classify(head)
        assert r.shape == "A_powershell_xor", f"failed on head: {head[:60]!r}"
        assert "T1027.010" in r.mitre_ids
        assert "T1027.013" not in r.mitre_ids, (
            "mislabelling regression — this head must NOT be tagged T1027.013"
        )


# ── Shape B · true RC4 ────────────────────────────────────────────────
def test_true_rc4_via_chain_op_classifies_as_shape_b():
    r = classify(TRUE_RC4_INPUT, chain_ops=["rc4-inline-decrypt"])
    assert r.shape == "B_true_rc4"
    assert "T1027.013" in r.mitre_ids
    assert "T1027.010" not in r.mitre_ids


def test_true_rc4_shortname_op_also_matches():
    r = classify(TRUE_RC4_INPUT, chain_ops=["some-other-op", "rc4"])
    assert r.shape == "B_true_rc4"
    assert "T1027.013" in r.mitre_ids


# ── Shape C · ambiguous ───────────────────────────────────────────────
def test_plain_text_classifies_as_shape_c():
    r = classify("Just a benign string with no obfuscation.")
    assert r.shape == "C_ambiguous"
    assert r.mitre_ids == []


def test_powershell_without_all_invariants_is_shape_c():
    # has PS head + int-array but no -bxor / [char] / IEX → not Shape A.
    r = classify("powershell -c \"(1,2,3,4,5,6,7)\"")
    assert r.shape == "C_ambiguous"
    assert "T1027.013" not in r.mitre_ids
    assert "T1027.010" not in r.mitre_ids
