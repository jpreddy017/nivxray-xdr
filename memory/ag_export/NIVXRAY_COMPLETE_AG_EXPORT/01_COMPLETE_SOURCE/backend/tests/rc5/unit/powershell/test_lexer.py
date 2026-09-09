"""Phase 3 · PowerShell tokenizer / normalizer tests (30 tests)."""
import pytest
from engine.parsers.powershell_parser import PowerShellParser, _normalize, _tokenize

P = PowerShellParser()


def _kinds(text):
    return [t.kind for t in _tokenize(_normalize(text)) if t.kind not in ("WS", "NL", "LINE_COMMENT", "BLOCK_COMMENT")]


# ── Backtick normalization ──────────────────────────────────────────
def test_backtick_removed_in_identifier():
    assert _normalize("W`r`i`t`e-Host") == "Write-Host"


def test_backtick_line_continuation_removed():
    assert _normalize("iex `\n$x") == "iex $x"


def test_backtick_not_stripped_in_dq_string():
    # Inside "" the ` is preserved so the atom parser can decode `n → \n
    src = 'Write-Host "hello`nworld"'
    out = _normalize(src)
    assert "`n" in out


# ── Comments ─────────────────────────────────────────────────────────
def test_line_comment_dropped():
    assert "IDENT" in _kinds("iex # this is a comment")


def test_block_comment_dropped():
    kinds = _kinds("<# skip #> iex")
    assert kinds == ["IDENT"]


# ── Strings ─────────────────────────────────────────────────────────
def test_single_quoted_string():
    kinds = _kinds("Write-Output 'hello world'")
    assert "STR_SQ" in kinds


def test_double_quoted_string():
    kinds = _kinds('Write-Output "hello $name"')
    assert "STR_DQ" in kinds


def test_here_string_double():
    src = '$s = @"\nline1\nline2\n"@'
    kinds = _kinds(src)
    assert "HERE_DQ" in kinds


def test_here_string_single():
    src = "$s = @'\nline1\n'@"
    kinds = _kinds(src)
    assert "HERE_SQ" in kinds


def test_sq_string_embedded_quote_via_doubling():
    kinds = _kinds("$x = 'it''s'")
    assert "STR_SQ" in kinds


# ── Variables ────────────────────────────────────────────────────────
def test_var_simple():
    assert "VAR" in _kinds("$foo")


def test_var_braced():
    assert "VAR_BRACE" in _kinds("${my var}")


def test_var_env_scope():
    assert "VAR_SCOPED" in _kinds("$env:USERPROFILE")


def test_var_script_scope():
    assert "VAR_SCOPED" in _kinds("$script:name")


# ── Numbers ─────────────────────────────────────────────────────────
def test_integer():
    assert "NUMBER" in _kinds("$x = 42")


def test_float():
    assert "NUMBER" in _kinds("$x = 3.14")


# ── Types ──────────────────────────────────────────────────────────
def test_type_char():
    assert "TYPE" in _kinds("[char]65")


def test_type_convert():
    assert "TYPE" in _kinds("[Convert]::FromBase64String('YQ==')")


def test_type_dotted():
    assert "TYPE" in _kinds("[System.Text.Encoding]::UTF8")


# ── Operators ───────────────────────────────────────────────────────
def test_op_join():
    kinds = _kinds("$a -join ','")
    assert "OP2" in kinds


def test_op_replace():
    kinds = _kinds("'ab' -replace 'a','x'")
    assert "OP2" in kinds


def test_op_format():
    kinds = _kinds("'{0}' -f 'x'")
    assert "OP2" in kinds


def test_op_static_call():
    kinds = _kinds("[Convert]::FromBase64String")
    assert "OP2" in kinds


# ── Parameter flags ────────────────────────────────────────────────
def test_param_flag():
    kinds = _kinds("powershell -Nop -w hidden")
    assert "PARAM" in kinds


def test_param_encodedcommand_flag():
    kinds = _kinds("powershell -EncodedCommand YQ==")
    assert "PARAM" in kinds


# ── Punctuation ─────────────────────────────────────────────────────
def test_pipe():
    assert "PIPE" in _kinds("Get-Process | Sort-Object")


def test_semicolon():
    assert "SEMI" in _kinds("$a=1; $b=2")


def test_parens():
    kinds = _kinds("(1 + 2)")
    assert "LPAREN" in kinds and "RPAREN" in kinds


def test_brackets():
    kinds = _kinds("$a[0]")
    assert "LBRACK" in kinds and "RBRACK" in kinds


def test_braces_for_scriptblock():
    kinds = _kinds("{ echo hi }")
    assert "LBRACE" in kinds and "RBRACE" in kinds
