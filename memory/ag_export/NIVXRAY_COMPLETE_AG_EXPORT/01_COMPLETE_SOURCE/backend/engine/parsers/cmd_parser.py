"""RC5 Phase 2 · CMD Parser.

Deterministic tokenizer + parser that converts normalized CMD text into an
`SIRTree`. NEVER executes anything. Emits `SIRKind.unresolved` for
fragments it cannot fully model.

Supported (Phase 2 baseline):
  * `SET NAME=value` and `SET /A` (arithmetic parsed as unresolved for now)
  * `%VAR%` expansion
  * `%VAR:old=new%` substring replacement (basic)
  * `!VAR!` delayed expansion (marker only — resolution is interpreter's job)
  * Command sequencing: `&`, `&&`, `||`
  * `CALL <cmd>` — parsed as CallExpr with attrs["second_pass"]=True
  * `ECHO <args>` and general command spawn
  * `IF <a> EQU|==|NEQ <b> <then>` (basic equality; else / elseif deferred)
  * Double-quoted strings with embedded variables
  * Escape `^` (line continuation + literal special-char escape)
  * Parenthesised blocks — parsed as Block with children
  * Redirection tokens (`>`, `>>`, `<`, `2>`) captured as attrs

Deferred to Phase 2.1 (emitted as SIRKind.unresolved with reason):
  * `FOR /F` / `FOR /L` / `FOR /R` loops
  * `IF DEFINED` / `IF EXIST` / `IF ERRORLEVEL`
  * `SET /A` arithmetic evaluator
  * `SETLOCAL EnableDelayedExpansion` scope tracking

See RC5 spec § 3 (SIR) and § 12.5 (plugin API stability).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple

from ..plugin_api import SemanticParser, register_parser
from ..semantic_ir import SIRKind, SIRNode, SIRTree


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------
_TOKEN_RE = re.compile(
    r"""
    (?P<SEP>       &&|\|\||&|\|          )   # && || & |
  | (?P<LPAREN>    \(                    )
  | (?P<RPAREN>    \)                    )
  | (?P<REDIR>     >>|>|<|2>|2>>         )
  | (?P<QUOTED>    "(?:\^.|[^"\\^])*"    )   # "..." tolerant of ^ escapes
  | (?P<DELAYED>   !(?P<DNAME>[A-Za-z_][A-Za-z0-9_]*)!  )
  | (?P<PVAR>      %(?P<PNAME>[A-Za-z_][A-Za-z0-9_]*)
                     (?::(?P<PMOD>[^%]*))?   # optional :old=new / :~offset,len
                    %                    )
  | (?P<WS>        [ \t]+                )
  | (?P<NL>        \r?\n                 )
  | (?P<WORD>      (?:\^.|[^\s&|()<>%!"^])+ ) # tolerant of ^X escapes
    """,
    re.VERBOSE,
)


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    start: int
    end: int
    extras: Tuple[Tuple[str, str], ...] = ()   # e.g. ('name', 'X'), ('mod', ':a=b')

    def attr(self, key: str) -> Optional[str]:
        for k, v in self.extras:
            if k == key:
                return v
        return None


def tokenize(text: str) -> List[Token]:
    tokens: List[Token] = []
    i = 0
    n = len(text)
    while i < n:
        m = _TOKEN_RE.match(text, i)
        if not m:
            # Unknown byte — emit as WORD of length 1 to keep tokenization total.
            tokens.append(Token("WORD", text[i], i, i + 1))
            i += 1
            continue
        kind = m.lastgroup or "WORD"
        val = m.group(kind)
        extras: List[Tuple[str, str]] = []
        if kind == "PVAR":
            extras.append(("name", m.group("PNAME") or ""))
            mod = m.group("PMOD")
            if mod:
                extras.append(("mod", mod))
        elif kind == "DELAYED":
            extras.append(("name", m.group("DNAME") or ""))
        tokens.append(Token(kind, val, m.start(), m.end(), tuple(extras)))
        i = m.end()
    return tokens


# ---------------------------------------------------------------------------
# Parser — token stream to SIR
# ---------------------------------------------------------------------------
class CmdParser(SemanticParser):
    name = "cmd"

    # ── entry point ────────────────────────────────────────────────────
    def parse(self, normalized_text: str) -> SIRTree:
        # 1. Line-continuation collapse (^ at EOL joins next line)
        text = re.sub(r"\^\r?\n", "", normalized_text)
        # 2. Tokenize
        toks = [t for t in tokenize(text) if t.kind != "WS"]
        # 3. Parse into program
        stmts, warnings = self._parse_program(toks, text)
        root = SIRNode(
            kind=SIRKind.program, children=tuple(stmts),
            parser=self.name, source_span=(0, len(text)),
        )
        return SIRTree(
            root=root, parser=self.name, original_length=len(text),
            warnings=tuple(warnings),
        )

    # ── recursive parser ───────────────────────────────────────────────
    def _parse_program(self, toks: List[Token], text: str) -> Tuple[List[SIRNode], List[str]]:
        stmts: List[SIRNode] = []
        warnings: List[str] = []
        i = 0
        n = len(toks)
        while i < n:
            # skip newlines
            if toks[i].kind == "NL":
                i += 1
                continue
            node, i, warns = self._parse_pipeline(toks, i, text)
            warnings.extend(warns)
            if node is not None:
                stmts.append(node)
        return stmts, warnings

    def _parse_pipeline(self, toks: List[Token], i: int, text: str
                        ) -> Tuple[Optional[SIRNode], int, List[str]]:
        """Parse a & / && / || sequence."""
        node, i, warns = self._parse_command(toks, i, text)
        while i < len(toks) and toks[i].kind == "SEP":
            op = toks[i].value
            i += 1
            right, i, w2 = self._parse_command(toks, i, text)
            warns.extend(w2)
            node = SIRNode(
                kind=SIRKind.binary_op, value=op,
                children=(node, right) if node and right else (),
                parser="cmd",
            )
        return node, i, warns

    def _parse_command(self, toks: List[Token], i: int, text: str
                       ) -> Tuple[Optional[SIRNode], int, List[str]]:
        """Parse one command: SET / CALL / IF / ECHO / parenthesised block / generic."""
        if i >= len(toks):
            return None, i, []
        t = toks[i]
        # Parenthesised block
        if t.kind == "LPAREN":
            return self._parse_paren_block(toks, i, text)
        # Newlines end a command
        if t.kind == "NL":
            return None, i, []
        # Recognise SET / CALL / IF / ECHO by first WORD token
        if t.kind == "WORD":
            head = t.value.upper()
            if head == "SET":
                return self._parse_set(toks, i, text)
            if head == "CALL":
                return self._parse_call(toks, i, text)
            if head == "IF":
                return self._parse_if(toks, i, text)
        # Generic command
        return self._parse_generic_command(toks, i, text)

    # ── SET NAME=value ────────────────────────────────────────────────
    def _parse_set(self, toks: List[Token], i: int, text: str
                   ) -> Tuple[SIRNode, int, List[str]]:
        start = toks[i].start
        i += 1  # consume SET
        # optional /A flag → mark unresolved for arithmetic phase-2.1
        arithmetic = False
        if i < len(toks) and toks[i].kind == "WORD" and toks[i].value.upper() in ("/A", "/P"):
            arithmetic = toks[i].value.upper() == "/A"
            i += 1
        # Collect the rest of the line up to NL / SEP as the assignment
        end_i = i
        parts: List[Token] = []
        while end_i < len(toks) and toks[end_i].kind not in ("NL", "SEP"):
            parts.append(toks[end_i])
            end_i += 1
        # Join back into raw text to split on the first '='
        raw = "".join(p.value for p in parts).strip()
        if "=" not in raw:
            # SET without = lists env vars — unresolved for interpreter phase
            node = SIRNode(
                kind=SIRKind.unresolved,
                attrs={"reason": "SET without '=': env var listing", "raw": raw},
                parser="cmd",
                source_span=(start, toks[end_i - 1].end if parts else start),
            )
            return node, end_i, []
        name, _, value = raw.partition("=")
        attrs = {"name": name.strip(), "arithmetic": arithmetic}
        value_child = self._value_to_sir(value)
        node = SIRNode(
            kind=SIRKind.assignment,
            attrs=attrs, children=(value_child,),
            parser="cmd",
            source_span=(start, toks[end_i - 1].end if parts else start),
        )
        return node, end_i, []

    # ── CALL <cmd …> ──────────────────────────────────────────────────
    def _parse_call(self, toks: List[Token], i: int, text: str
                    ) -> Tuple[SIRNode, int, List[str]]:
        start = toks[i].start
        i += 1  # consume CALL
        inner, i, warns = self._parse_command(toks, i, text)
        # Mark as second-pass so interpreter re-evaluates expansion.
        if inner is None:
            inner = SIRNode(kind=SIRKind.unresolved,
                            attrs={"reason": "empty CALL"}, parser="cmd")
        wrapper = SIRNode(
            kind=SIRKind.invocation_expr,
            attrs={"second_pass": True},
            children=(inner,),
            parser="cmd",
            source_span=(start, inner.source_span[1] if inner.source_span else start),
        )
        return wrapper, i, warns

    # ── IF <lhs> EQU|==|NEQ <rhs> <then> ──────────────────────────────
    def _parse_if(self, toks: List[Token], i: int, text: str
                  ) -> Tuple[SIRNode, int, List[str]]:
        start = toks[i].start
        i += 1  # consume IF
        # unresolved advanced forms
        if i < len(toks) and toks[i].kind == "WORD" and toks[i].value.upper() in (
            "DEFINED", "EXIST", "ERRORLEVEL", "NOT", "/I",
        ):
            return SIRNode(
                kind=SIRKind.unresolved,
                attrs={"reason": f"IF {toks[i].value.upper()} — deferred to Phase 2.1"},
                parser="cmd",
                source_span=(start, toks[i].end),
            ), i + 1, []
        # LHS — one value expr
        lhs, i = self._one_value_expr(toks, i)
        # operator
        if i >= len(toks) or toks[i].kind != "WORD" or toks[i].value.upper() not in (
            "EQU", "NEQ", "==", "!=", "GEQ", "LEQ", "GTR", "LSS",
        ):
            return SIRNode(
                kind=SIRKind.unresolved,
                attrs={"reason": "IF without recognised operator"},
                parser="cmd",
                source_span=(start, toks[i - 1].end if i else start),
            ), i, []
        op = toks[i].value.upper()
        i += 1
        rhs, i = self._one_value_expr(toks, i)
        # then-branch
        then_node, i, warns = self._parse_command(toks, i, text)
        if then_node is None:
            then_node = SIRNode(kind=SIRKind.unresolved, attrs={"reason": "empty IF then-branch"}, parser="cmd")
        node = SIRNode(
            kind=SIRKind.if_stmt,
            attrs={"op": op},
            children=(lhs, rhs, then_node),
            parser="cmd",
            source_span=(start, then_node.source_span[1] if then_node.source_span else start),
        )
        return node, i, warns

    # ── Parenthesised block ──────────────────────────────────────────
    def _parse_paren_block(self, toks: List[Token], i: int, text: str
                           ) -> Tuple[SIRNode, int, List[str]]:
        start = toks[i].start
        i += 1  # consume (
        stmts: List[SIRNode] = []
        warns: List[str] = []
        depth = 1
        # Slice out until matching )
        block_toks: List[Token] = []
        while i < len(toks) and depth > 0:
            if toks[i].kind == "LPAREN":
                depth += 1
            elif toks[i].kind == "RPAREN":
                depth -= 1
                if depth == 0:
                    break
            block_toks.append(toks[i])
            i += 1
        # Recursively parse inner
        inner_stmts, warns = self._parse_program(block_toks, text)
        end = toks[i].end if i < len(toks) else (block_toks[-1].end if block_toks else start)
        if i < len(toks) and toks[i].kind == "RPAREN":
            i += 1
        node = SIRNode(
            kind=SIRKind.block, children=tuple(inner_stmts),
            parser="cmd", source_span=(start, end),
        )
        return node, i, warns

    # ── Generic command (echo, dir, custom exe, …) ────────────────────
    def _parse_generic_command(self, toks: List[Token], i: int, text: str
                               ) -> Tuple[SIRNode, int, List[str]]:
        start_tok = toks[i]
        head_val = self._token_display(start_tok)
        head_children: List[SIRNode] = []
        head_children.append(self._token_to_sir(start_tok))
        last_end = start_tok.end
        i += 1
        args: List[SIRNode] = []
        redirects: List[Tuple[str, str]] = []
        while i < len(toks) and toks[i].kind not in ("SEP", "NL", "RPAREN"):
            t = toks[i]
            if t.kind == "REDIR":
                redir_op = t.value
                i += 1
                if i < len(toks) and toks[i].kind not in ("SEP", "NL", "RPAREN"):
                    redirects.append((redir_op, self._token_display(toks[i])))
                    last_end = toks[i].end
                    i += 1
                continue
            new_sir = self._token_to_sir(t)
            # Fuse into previous arg if adjacent (no whitespace gap) — so
            # `%X%.exe` or `!X!.exe` becomes a single concat argument.
            if args and t.start == last_end:
                prev = args[-1]
                fused = SIRNode(
                    kind=SIRKind.binary_op, value="+",
                    children=(prev.children if (prev.kind == SIRKind.binary_op and prev.value == "+") else (prev,))
                             + (new_sir,),
                    parser="cmd",
                    source_span=(prev.source_span[0] if prev.source_span else t.start, t.end),
                )
                args[-1] = fused
            else:
                args.append(new_sir)
            last_end = t.end
            i += 1
        node = SIRNode(
            kind=SIRKind.call_expr,
            value=head_val,
            attrs={"redirects": redirects} if redirects else {},
            children=tuple(head_children + args),
            parser="cmd",
            source_span=(start_tok.start, toks[i - 1].end if i > 0 else start_tok.end),
        )
        return node, i, []

    # ── Helpers ───────────────────────────────────────────────────────
    def _token_display(self, t: Token) -> str:
        if t.kind == "QUOTED":
            return t.value[1:-1]  # strip quotes
        return t.value

    def _token_to_sir(self, t: Token) -> SIRNode:
        if t.kind == "PVAR":
            name = t.attr("name") or ""
            mod = t.attr("mod")
            var_ref = SIRNode(
                kind=SIRKind.var_ref, value=name,
                attrs={"delayed": False},
                parser="cmd", source_span=(t.start, t.end),
            )
            if not mod:
                return var_ref
            # substring / replace modifiers
            # %VAR:old=new% — replace form
            if "=" in mod:
                old, _, new = mod.partition("=")
                return SIRNode(
                    kind=SIRKind.replace_op,
                    value=":=",
                    children=(
                        var_ref,
                        SIRNode(kind=SIRKind.string_literal, value=old, parser="cmd"),
                        SIRNode(kind=SIRKind.string_literal, value=new, parser="cmd"),
                    ),
                    parser="cmd", source_span=(t.start, t.end),
                )
            # %VAR:~offset,length% — substring form
            if mod.startswith("~"):
                return SIRNode(
                    kind=SIRKind.substring_op,
                    value="~",
                    attrs={"raw_mod": mod},
                    children=(var_ref,),
                    parser="cmd", source_span=(t.start, t.end),
                )
            # unknown modifier → unresolved child
            return SIRNode(
                kind=SIRKind.unresolved,
                attrs={"reason": f"unknown %VAR% modifier: {mod!r}"},
                parser="cmd", source_span=(t.start, t.end),
            )
        if t.kind == "DELAYED":
            return SIRNode(
                kind=SIRKind.delayed_ref, value=t.attr("name") or "",
                parser="cmd", source_span=(t.start, t.end),
            )
        if t.kind == "QUOTED":
            # Quoted strings may contain variables — parse recursively.
            inner = t.value[1:-1]
            # simple heuristic: if it contains no % or !, treat as literal
            if "%" not in inner and "!" not in inner:
                return SIRNode(
                    kind=SIRKind.string_literal, value=inner,
                    parser="cmd", source_span=(t.start, t.end),
                )
            # else parse the inner as concat of pieces
            return self._value_to_sir(inner)
        # WORD or leftover
        # Handle inline ^X escapes — collapse to X
        v = re.sub(r"\^(.)", r"\1", t.value)
        return SIRNode(
            kind=SIRKind.string_literal, value=v,
            parser="cmd", source_span=(t.start, t.end),
        )

    def _value_to_sir(self, raw: str) -> SIRNode:
        """Turn a raw value string (RHS of SET or inner of QUOTED) into an SIR
        node — a StringLiteral, VarRef, or a Concat of pieces if it contains
        variables interleaved with literal text."""
        # Tokenize just the value using the same tokenizer, but ignore SEP/PAREN etc.
        parts: List[SIRNode] = []
        j = 0
        while j < len(raw):
            m = _TOKEN_RE.match(raw, j)
            if not m:
                parts.append(SIRNode(kind=SIRKind.string_literal, value=raw[j], parser="cmd"))
                j += 1
                continue
            kind = m.lastgroup or "WORD"
            tok = Token(kind, m.group(kind), m.start(), m.end(),
                        tuple(
                            [("name", m.group("PNAME"))] + ([("mod", m.group("PMOD"))] if m.group("PMOD") else [])
                            if kind == "PVAR"
                            else [("name", m.group("DNAME"))] if kind == "DELAYED"
                            else []
                        ))
            if tok.kind in ("PVAR", "DELAYED"):
                parts.append(self._token_to_sir(tok))
            else:
                v = m.group(kind)
                if v:
                    parts.append(SIRNode(kind=SIRKind.string_literal, value=v, parser="cmd"))
            j = m.end()
        if not parts:
            return SIRNode(kind=SIRKind.string_literal, value="", parser="cmd")
        if len(parts) == 1:
            return parts[0]
        return SIRNode(
            kind=SIRKind.binary_op, value="+",   # concat
            children=tuple(parts), parser="cmd",
        )

    def _one_value_expr(self, toks: List[Token], i: int) -> Tuple[SIRNode, int]:
        if i >= len(toks):
            return SIRNode(kind=SIRKind.string_literal, value="", parser="cmd"), i
        n = self._token_to_sir(toks[i])
        return n, i + 1


# ---------------------------------------------------------------------------
# Register at import time — plugin API contract.
# ---------------------------------------------------------------------------
_INSTANCE = CmdParser()
register_parser(_INSTANCE)


def get_cmd_parser() -> CmdParser:
    return _INSTANCE
