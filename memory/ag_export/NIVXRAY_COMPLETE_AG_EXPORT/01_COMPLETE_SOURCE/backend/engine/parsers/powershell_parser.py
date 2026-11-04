"""RC5 Phase 3 · PowerShell Parser.

Deterministic tokenizer + parser converting normalized PowerShell text into
an ``SIRTree``. Deliberately conservative — it emits ``SIRKind.unresolved``
for anything it can't cleanly model. Never executes anything.

Phase-3 in-scope:
  * Backtick collapse (line continuation + literal char escape)
  * Whitespace / case normalization for cmdlets & aliases
  * Comments: ``# …`` (line) and ``<# … #>`` (block)
  * Single-quoted (literal) and double-quoted (expandable) strings
  * Variables: ``$var``, ``${braced var}``, ``$env:X``, ``$script:X``
  * Arrays, indexing, slicing, reverse-indexing
  * String ops: ``+``, ``-join``, ``-split``, ``-replace``, ``-f``
  * Method / static calls: ``.Method()``, ``::Static()``
  * ``[char]N``, ``[int]"n"``, ``[Convert]::FromBase64String``,
    ``[Text.Encoding]::UTF8.GetString``
  * Aliases (48 canonical) → resolved to cmdlets
  * Cmdlet call parsing with named/positional args
  * ScriptBlock literals ``{ … }`` — parsed, not evaluated (lazy)
  * ``-EncodedCommand <b64>`` → base64 → UTF-16LE decoded body inlined
    as child SIR statements
  * AMSI/ETW bypass fingerprint markers → tags SIR nodes for downstream
    (never a verdict source in isolation).

Phase-3.1 deferred (emitted as ``Unresolved`` with ``reason``):
  * ``param()`` blocks, function definitions
  * ``try/catch/finally`` control flow
  * ``-match`` / ``-notmatch`` regex operators
  * Multi-file dot-sourcing (``. .\\script.ps1``)
  * .NET reflection via ``Add-Type``, ``[Type]::InvokeMember``
  * ``Get-Variable`` / ``Get-Item`` runtime introspection
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from ..plugin_api import SemanticParser, register_parser
from ..semantic_ir import SIRKind, SIRNode, SIRTree
from ..normalizers_ps.alias_map import ALIAS_MAP, AMSI_BYPASS_MARKERS, ETW_BYPASS_MARKERS


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------
_TOKEN_RE = re.compile(
    r"""
    (?P<BLOCK_COMMENT>  <\#.*?\#>              )   # <# ... #>
  | (?P<LINE_COMMENT>   \#[^\n]*               )
  | (?P<HERE_DQ>        @"[\s\S]*?"@           )
  | (?P<HERE_SQ>        @'[\s\S]*?'@           )
  | (?P<STR_SQ>         '(?:[^']|'')*'         )   # 'literal'
  | (?P<STR_DQ>         "(?:\\.|`.|[^"`\\])*"  )   # "expandable"
  | (?P<URL>            https?://[^\s'"<>()\[\]|&;`]+ )   # bare URL as one token
  | (?P<VAR_BRACE>      \$\{[^}]+\}            )
  | (?P<VAR_SCOPED>     \$(?:env|script|global|local|private):[A-Za-z_][A-Za-z0-9_]* )
  | (?P<VAR>            \$[A-Za-z_][A-Za-z0-9_]* )
  | (?P<NUMBER>         -?\d+(?:\.\d+)?        )
  | (?P<TYPE>           \[[A-Za-z_][A-Za-z0-9_.]*\] )   # [Convert] / [char] / [Text.Encoding]
  | (?P<OP2>            ::|-eq|-ne|-gt|-lt|-ge|-le|-and|-or|-xor|-not
                       |-join|-split|-replace|-match|-notmatch|-like|-notlike|-f
                       |-band|-bor|-bxor|-shl|-shr|-in|-notin|-contains )
  | (?P<PIPE>           \|                     )
  | (?P<SEMI>           ;                      )
  | (?P<COMMA>          ,                      )
  | (?P<DOT>            \.                     )
  | (?P<LPAREN>         \(                     )
  | (?P<RPAREN>         \)                     )
  | (?P<LBRACK>         \[                     )
  | (?P<RBRACK>         \]                     )
  | (?P<LBRACE>         \{                     )
  | (?P<RBRACE>         \}                     )
  | (?P<AMP>            &                      )
  | (?P<EQ>             =                      )
  | (?P<PLUS>           \+                     )
  | (?P<WS>             [ \t]+                 )
  | (?P<NL>             \r?\n                  )
  | (?P<IDENT>          [A-Za-z_][A-Za-z0-9_\-]* )
  | (?P<PARAM>          -[A-Za-z][A-Za-z0-9]*  )   # -Nop / -EncodedCommand
  | (?P<OTHER>          .                      )
    """,
    re.VERBOSE | re.DOTALL,
)


@dataclass(frozen=True)
class Tok:
    kind: str
    value: str
    start: int
    end: int


def _tokenize(text: str) -> List[Tok]:
    out: List[Tok] = []
    i = 0
    n = len(text)
    while i < n:
        m = _TOKEN_RE.match(text, i)
        if not m:
            out.append(Tok("OTHER", text[i], i, i + 1))
            i += 1
            continue
        k = m.lastgroup or "OTHER"
        v = m.group(k)
        out.append(Tok(k, v, m.start(), m.end()))
        i = m.end()
    return out


# ---------------------------------------------------------------------------
# Normalizer — runs BEFORE tokenization
# ---------------------------------------------------------------------------
def _normalize(text: str) -> str:
    # 1. Backtick line-continuation: strip ` at EOL
    text = re.sub(r"`\r?\n", "", text)
    # 2. Backtick literal escapes inside identifiers (e.g. W`r`i`t`e-Host)
    #    ONLY outside quoted strings — inside "..." / '...' the ` is a
    #    real escape prefix and must survive until the atom parser sees it.
    out: List[str] = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        # Enter a quoted string — copy verbatim until matching quote
        if c in ("'", '"'):
            quote = c
            out.append(c)
            i += 1
            while i < n:
                # `X escape inside DQ string
                if quote == '"' and text[i] == "`" and i + 1 < n:
                    out.append(text[i]); out.append(text[i + 1])
                    i += 2
                    continue
                # doubled-quote escape inside SQ string
                if text[i] == quote:
                    if quote == "'" and i + 1 < n and text[i + 1] == "'":
                        out.append("''")
                        i += 2
                        continue
                    out.append(quote)
                    i += 1
                    break
                out.append(text[i])
                i += 1
            continue
        # Outside strings: strip `X where X is alphanumeric.
        if c == "`" and i + 1 < n and text[i + 1].isalnum():
            out.append(text[i + 1])
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
class PowerShellParser(SemanticParser):
    name = "powershell"

    def parse(self, normalized_text: str) -> SIRTree:
        text = _normalize(normalized_text)
        toks = [t for t in _tokenize(text) if t.kind not in ("WS", "LINE_COMMENT", "BLOCK_COMMENT")]
        warnings: List[str] = []
        stmts: List[SIRNode] = []
        i = 0
        while i < len(toks):
            if toks[i].kind in ("NL", "SEMI"):
                i += 1
                continue
            prev_i = i
            node, i = self._parse_statement(toks, i, warnings)
            if node is not None:
                stmts.append(node)
            # Anti-hang safeguard — if a downstream parser returns without
            # advancing `i`, we skip one token and record a warning rather
            # than looping forever. Prevents future coverage-gap regressions
            # from becoming infinite loops.
            if i == prev_i:
                warnings.append(
                    f"parser: no-advance at token {toks[i].kind}={toks[i].value!r} "
                    f"@ {toks[i].start}; skipping to avoid hang"
                )
                i += 1
        root = SIRNode(kind=SIRKind.program, children=tuple(stmts), parser=self.name,
                       source_span=(0, len(text)))
        return SIRTree(root=root, parser=self.name, original_length=len(text),
                       warnings=tuple(warnings))

    # ── statement dispatch ──────────────────────────────────────────
    def _parse_statement(self, toks, i, warnings):
        t = toks[i]
        # Assignment `$x = <expr>`
        if t.kind in ("VAR", "VAR_BRACE", "VAR_SCOPED"):
            if i + 1 < len(toks) and toks[i + 1].kind == "EQ":
                return self._parse_assignment(toks, i, warnings)
        # ScriptBlock literal (rare at top-level but valid)
        if t.kind == "LBRACE":
            return self._parse_scriptblock(toks, i, warnings)
        # Otherwise — pipeline (may just be a bare expression)
        return self._parse_pipeline(toks, i, warnings)

    # ── assignment ───────────────────────────────────────────────────
    def _parse_assignment(self, toks, i, warnings):
        var_tok = toks[i]
        i += 2  # skip var + =
        rhs, i = self._parse_pipeline(toks, i, warnings)
        node = SIRNode(
            kind=SIRKind.assignment,
            attrs={"name": var_tok.value},
            children=(rhs,) if rhs else (),
            parser="powershell",
            source_span=(var_tok.start, rhs.source_span[1] if rhs and rhs.source_span else var_tok.end),
        )
        return node, i

    # ── pipeline (`… | …`) ──────────────────────────────────────────
    def _parse_pipeline(self, toks, i, warnings):
        left, i = self._parse_command(toks, i, warnings)
        if left is None:
            return None, i
        stages = [left]
        while i < len(toks) and toks[i].kind == "PIPE":
            i += 1
            right, i = self._parse_command(toks, i, warnings)
            if right is not None:
                stages.append(right)
        if len(stages) == 1:
            return left, i
        return SIRNode(kind=SIRKind.pipeline, children=tuple(stages),
                       parser="powershell"), i

    # ── command / call / expression ─────────────────────────────────
    def _parse_command(self, toks, i, warnings):
        if i >= len(toks) or toks[i].kind in ("NL", "SEMI", "RPAREN", "RBRACE"):
            return None, i
        # `&` invocation of variable / scriptblock: `& $sb args...`
        if toks[i].kind == "AMP":
            i += 1
            target, i = self._parse_expression(toks, i, warnings)
            args, i = self._parse_args(toks, i, warnings)
            return SIRNode(
                kind=SIRKind.invocation_expr,
                attrs={"kind": "amp"},
                children=(target,) + tuple(args) if target else tuple(args),
                parser="powershell",
            ), i
        # IDENT / TYPE — a cmdlet name (with optional aliases)
        if toks[i].kind == "IDENT":
            head_tok = toks[i]
            head_val = head_tok.value
            i += 1
            # Fuse `.ext` segments into the head when they're NOT method
            # invocations (no LPAREN after). Handles `powershell.exe`,
            # `cmd.exe`, `wmic.exe`, etc.
            while (i + 1 < len(toks)
                   and toks[i].kind == "DOT"
                   and toks[i + 1].kind == "IDENT"
                   and (i + 2 >= len(toks) or toks[i + 2].kind != "LPAREN")):
                head_val = head_val + "." + toks[i + 1].value
                i += 2
            head_name = ALIAS_MAP.get(head_val.lower(), head_val)
            args, i = self._parse_args(toks, i, warnings)
            call = SIRNode(
                kind=SIRKind.call_expr,
                value=head_name,
                attrs=self._call_attrs(head_name, args),
                children=tuple(args),
                parser="powershell",
                source_span=(head_tok.start, args[-1].source_span[1] if args and args[-1].source_span else head_tok.end),
            )
            # Special: -EncodedCommand reconstruction (only for powershell.exe)
            if head_name.lower() in ("powershell", "powershell.exe", "pwsh", "pwsh.exe"):
                enc = self._extract_encoded_command(args)
                if enc is not None:
                    call = call.model_copy(update={
                        "attrs": {**call.attrs, "encoded_command_decoded": enc},
                    })
            return call, i
        # Otherwise treat as bare expression
        expr, i = self._parse_expression(toks, i, warnings)
        return expr, i

    def _extract_encoded_command(self, args: List[SIRNode]) -> Optional[str]:
        for idx, arg in enumerate(args):
            if arg.kind == SIRKind.string_literal and isinstance(arg.value, str):
                v = arg.value.lower()
                if v in ("-enc", "-ec", "-encodedcommand") and idx + 1 < len(args):
                    nxt = args[idx + 1]
                    if nxt.kind == SIRKind.string_literal and isinstance(nxt.value, str):
                        try:
                            raw = base64.b64decode(nxt.value, validate=False)
                            return raw.decode("utf-16le", errors="replace")
                        except Exception:
                            return None
        return None

    def _call_attrs(self, head_name: str, args: List[SIRNode]) -> dict:
        attrs: dict = {}
        # AMSI/ETW bypass marker tagging (semantic tag; NOT a verdict source)
        joined = " ".join(str(a.value) if isinstance(a.value, str) else "" for a in args)
        for m in AMSI_BYPASS_MARKERS:
            if m in joined:
                attrs["semantic_tag"] = "amsi_bypass"
                break
        if "semantic_tag" not in attrs:
            for m in ETW_BYPASS_MARKERS:
                if m in joined:
                    attrs["semantic_tag"] = "etw_bypass"
                    break
        return attrs

    # ── args (positional + named) ───────────────────────────────────
    def _parse_args(self, toks, i, warnings) -> Tuple[List[SIRNode], int]:
        args: List[SIRNode] = []
        while i < len(toks) and toks[i].kind not in ("NL", "SEMI", "PIPE", "RPAREN", "RBRACE"):
            t = toks[i]
            if t.kind == "PARAM":
                args.append(SIRNode(kind=SIRKind.string_literal, value=t.value,
                                    parser="powershell",
                                    source_span=(t.start, t.end)))
                i += 1
                # Special: -EncodedCommand / -enc / -ec take a raw
                # base64 payload that must be captured as ONE argument,
                # not split on `=` `+` `/`. Greedy-consume the next run
                # of adjacent tokens that form valid base64.
                if t.value.lower() in ("-encodedcommand", "-enc", "-ec"):
                    b64_pieces: List[str] = []
                    b64_start = None
                    last_end = None
                    while i < len(toks) and toks[i].kind not in (
                        "NL", "SEMI", "PIPE", "RPAREN", "RBRACE", "PARAM"
                    ):
                        tt = toks[i]
                        # Adjacency check — only join if no whitespace
                        # between previous piece and this one.
                        if last_end is not None and tt.start != last_end:
                            break
                        b64_pieces.append(tt.value)
                        if b64_start is None:
                            b64_start = tt.start
                        last_end = tt.end
                        i += 1
                    if b64_pieces:
                        args.append(SIRNode(
                            kind=SIRKind.string_literal,
                            value="".join(b64_pieces),
                            parser="powershell",
                            source_span=(b64_start, last_end),
                        ))
                continue
            expr, i = self._parse_expression(toks, i, warnings)
            if expr is None:
                break
            args.append(expr)
        return args, i

    # ── expression (with operators) ─────────────────────────────────
    def _parse_expression(self, toks, i, warnings) -> Tuple[Optional[SIRNode], int]:
        # Parse a base atom, then chain binary/unary ops.
        left, i = self._parse_atom(toks, i, warnings)
        while i < len(toks) and toks[i].kind in ("OP2", "PLUS", "COMMA"):
            op_tok = toks[i]
            op = op_tok.value
            # COMMA at expr level = array literal
            if op_tok.kind == "COMMA":
                items = [left]
                while i < len(toks) and toks[i].kind == "COMMA":
                    i += 1
                    nxt, i = self._parse_atom(toks, i, warnings)
                    if nxt is not None:
                        items.append(nxt)
                    else:
                        break
                left = SIRNode(kind=SIRKind.array_literal, children=tuple(items),
                               parser="powershell")
                continue
            i += 1
            # For -replace / -f / -split, RHS may be a comma-separated list.
            # Parse a comma-list at atom precedence so we get a proper
            # array_literal instead of consuming commas at expression level.
            if op in ("-replace", "-f", "-split"):
                rhs_items: List[SIRNode] = []
                first, i = self._parse_atom(toks, i, warnings)
                if first is not None:
                    rhs_items.append(first)
                    while i < len(toks) and toks[i].kind == "COMMA":
                        i += 1
                        nxt, i = self._parse_atom(toks, i, warnings)
                        if nxt is not None:
                            rhs_items.append(nxt)
                        else:
                            break
                if len(rhs_items) == 1:
                    right = rhs_items[0]
                elif rhs_items:
                    right = SIRNode(kind=SIRKind.array_literal,
                                    children=tuple(rhs_items),
                                    parser="powershell")
                else:
                    break
            else:
                right, i = self._parse_atom(toks, i, warnings)
                if right is None:
                    break
            kind = SIRKind.binary_op
            if op == "-join":
                kind = SIRKind.join_op
            elif op == "-split":
                kind = SIRKind.split_op
            elif op == "-replace":
                kind = SIRKind.replace_op
            elif op == "-f":
                kind = SIRKind.format_op
            left = SIRNode(kind=kind, value=op, children=(left, right),
                           parser="powershell")
        return left, i

    # ── atom (literals, variables, calls, member access) ───────────
    def _parse_atom(self, toks, i, warnings) -> Tuple[Optional[SIRNode], int]:
        if i >= len(toks):
            return None, i
        t = toks[i]
        node: Optional[SIRNode] = None
        # Prefix -join / unary constructs
        if t.kind == "OP2" and t.value in ("-join", "-not"):
            i += 1
            operand, i = self._parse_atom(toks, i, warnings)
            if operand is None:
                return None, i
            k = SIRKind.join_op if t.value == "-join" else SIRKind.unary_op
            node = SIRNode(kind=k, value=t.value, children=(operand,),
                           parser="powershell")
            return self._chain_postfix(node, toks, i, warnings)
        if t.kind == "STR_SQ":
            node = SIRNode(kind=SIRKind.string_literal, value=t.value[1:-1].replace("''", "'"),
                           parser="powershell", source_span=(t.start, t.end))
            i += 1
        elif t.kind == "STR_DQ":
            # Simple double-quoted — expansions handled by interpreter later
            inner = t.value[1:-1]
            # Decode ` escapes
            inner = re.sub(r"`([nrtb0'\"$` ])", lambda m: {"n": "\n", "r": "\r", "t": "\t",
                                                          "b": "\b", "0": "\0"}
                           .get(m.group(1), m.group(1)), inner)
            node = SIRNode(kind=SIRKind.string_literal, value=inner,
                           attrs={"expandable": True},
                           parser="powershell", source_span=(t.start, t.end))
            i += 1
        elif t.kind == "HERE_DQ":
            node = SIRNode(kind=SIRKind.string_literal, value=t.value[3:-3],
                           attrs={"expandable": True, "here": True},
                           parser="powershell")
            i += 1
        elif t.kind == "HERE_SQ":
            node = SIRNode(kind=SIRKind.string_literal, value=t.value[3:-3],
                           attrs={"here": True}, parser="powershell")
            i += 1
        elif t.kind == "NUMBER":
            node = SIRNode(kind=SIRKind.number_literal, value=t.value,
                           parser="powershell", source_span=(t.start, t.end))
            i += 1
        elif t.kind in ("VAR", "VAR_BRACE", "VAR_SCOPED"):
            name = t.value.lstrip("$")
            if name.startswith("{") and name.endswith("}"):
                name = name[1:-1]
            node = SIRNode(kind=(SIRKind.env_ref if name.lower().startswith("env:")
                                 else SIRKind.var_ref),
                           value=name.split(":")[-1] if ":" in name else name,
                           parser="powershell", source_span=(t.start, t.end))
            i += 1
        elif t.kind == "TYPE":
            # Type accelerator, e.g. [char] or [Convert]
            tname = t.value[1:-1]
            node = SIRNode(kind=SIRKind.member_expr, value=tname,
                           attrs={"is_type": True},
                           parser="powershell", source_span=(t.start, t.end))
            i += 1
        elif t.kind == "LPAREN":
            i += 1
            # Inside `( … )` we may have a full cmdlet call, not just an
            # expression. Delegate to _parse_command so `-Params 'x'` and
            # nested pipelines parse correctly.
            inner, i = self._parse_command(toks, i, warnings)
            # skip )
            if i < len(toks) and toks[i].kind == "RPAREN":
                i += 1
            node = inner
        elif t.kind == "LBRACK":
            # array/index/slice — very simple: parse tokens until ]
            i += 1
            items: List[SIRNode] = []
            while i < len(toks) and toks[i].kind != "RBRACK":
                e, i = self._parse_expression(toks, i, warnings)
                if e is None:
                    break
                items.append(e)
                if i < len(toks) and toks[i].kind == "COMMA":
                    i += 1
            if i < len(toks) and toks[i].kind == "RBRACK":
                i += 1
            node = SIRNode(kind=SIRKind.array_literal, children=tuple(items),
                           parser="powershell")
        elif t.kind == "LBRACE":
            node, i = self._parse_scriptblock(toks, i, warnings)
        elif t.kind == "IDENT":
            # bare word — treat as string literal (positional arg)
            node = SIRNode(kind=SIRKind.string_literal, value=t.value,
                           parser="powershell", source_span=(t.start, t.end))
            i += 1
        elif t.kind == "URL":
            node = SIRNode(kind=SIRKind.string_literal, value=t.value,
                           parser="powershell", source_span=(t.start, t.end))
            i += 1
        elif t.kind == "PARAM":
            node = SIRNode(kind=SIRKind.string_literal, value=t.value,
                           parser="powershell", source_span=(t.start, t.end))
            i += 1
        else:
            # Unknown — unresolved with reason
            node = SIRNode(kind=SIRKind.unresolved,
                           attrs={"reason": f"unhandled token: {t.kind}={t.value!r}"},
                           parser="powershell", source_span=(t.start, t.end))
            i += 1
        return self._chain_postfix(node, toks, i, warnings)

    def _chain_postfix(self, base, toks, i, warnings):
        # Handle .Method(), ::Static(), [index], AND [type] N casting
        while i < len(toks):
            t = toks[i]
            if t.kind == "DOT" and i + 1 < len(toks) and toks[i + 1].kind == "IDENT":
                # Only chain as method / property access if:
                #   (a) receiver is a variable / type / call-result / member, OR
                #   (b) next-next token is LPAREN (unambiguous method invocation)
                #
                # This prevents `notepad.exe` from being misparsed as
                # `notepad`.exe (method call with no args).
                receiver_kind = base.kind if base is not None else None
                is_method_call = (i + 2 < len(toks) and toks[i + 2].kind == "LPAREN")
                # Allow property/method chaining on these receivers only:
                chainable_receivers = {
                    SIRKind.var_ref, SIRKind.env_ref, SIRKind.member_expr,
                    SIRKind.call_expr, SIRKind.index_expr, SIRKind.invocation_expr,
                }
                if not is_method_call and receiver_kind not in chainable_receivers:
                    # Treat `.ext` as literal suffix (e.g. notepad.exe → one arg)
                    if base is not None and base.kind == SIRKind.string_literal:
                        fused = SIRNode(
                            kind=SIRKind.string_literal,
                            value=str(base.value or "") + "." + toks[i + 1].value,
                            parser="powershell",
                            source_span=(base.source_span[0] if base.source_span else t.start, toks[i + 1].end),
                        )
                        base = fused
                        i += 2
                        continue
                    # otherwise fall through and let it be property access
                name = toks[i + 1].value
                i += 2
                args: List[SIRNode] = []
                if i < len(toks) and toks[i].kind == "LPAREN":
                    i += 1
                    args, i = self._parse_call_args(toks, i, warnings)
                    if i < len(toks) and toks[i].kind == "RPAREN":
                        i += 1
                base = SIRNode(
                    kind=SIRKind.member_expr, value=name,
                    attrs={"kind": "method", "arity": len(args)},
                    children=(base,) + tuple(args),
                    parser="powershell",
                )
            elif t.kind == "OP2" and t.value == "::" and i + 1 < len(toks) and toks[i + 1].kind == "IDENT":
                name = toks[i + 1].value
                i += 2
                args: List[SIRNode] = []
                if i < len(toks) and toks[i].kind == "LPAREN":
                    i += 1
                    args, i = self._parse_call_args(toks, i, warnings)
                    if i < len(toks) and toks[i].kind == "RPAREN":
                        i += 1
                base = SIRNode(
                    kind=SIRKind.member_expr, value=name,
                    attrs={"kind": "static", "arity": len(args)},
                    children=(base,) + tuple(args),
                    parser="powershell",
                )
            elif t.kind == "LBRACK":
                # index / slice
                i += 1
                idx, i = self._parse_expression(toks, i, warnings)
                if i < len(toks) and toks[i].kind == "RBRACK":
                    i += 1
                if idx is not None:
                    base = SIRNode(
                        kind=SIRKind.index_expr, children=(base, idx),
                        parser="powershell",
                    )
            else:
                # `[type] value` cast — base is a type member_expr and next
                # token is a NUMBER / STR / VAR — treat as cast call.
                if (base is not None and base.kind == SIRKind.member_expr
                        and base.attrs.get("is_type")
                        and t.kind in ("NUMBER", "STR_SQ", "STR_DQ", "VAR", "VAR_BRACE", "VAR_SCOPED")):
                    operand, i = self._parse_atom(toks, i, warnings)
                    if operand is None:
                        break
                    base = SIRNode(
                        kind=SIRKind.member_expr, value=str(base.value or ""),
                        attrs={"kind": "static", "arity": 1, "is_type": True},
                        children=(base, operand),
                        parser="powershell",
                    )
                    continue
                break
        return base, i

    def _parse_call_args(self, toks, i, warnings):
        """Parse comma-separated arg list, stopping at RPAREN. This
        variant does NOT let bare commas promote to array_literal — each
        atom is a separate argument. Binary operators (`+`, `-eq`,
        `-join`, etc.) between atoms ARE consumed so expressions like
        ``$w.Foo($env:APPDATA + '\\x.dll')`` parse cleanly and do not
        leave a stray `+` token that would trigger a top-level parse
        loop hang (RC5 coverage-gap fix, Feb 2026)."""
        args: List[SIRNode] = []
        while i < len(toks) and toks[i].kind not in ("RPAREN", "NL", "SEMI"):
            atom, i = self._parse_atom(toks, i, warnings)
            if atom is None:
                break
            # Chain binary operators (except COMMA, which is the arg separator).
            while i < len(toks) and toks[i].kind in ("OP2", "PLUS"):
                op = toks[i].value
                i += 1
                rhs, i = self._parse_atom(toks, i, warnings)
                if rhs is None:
                    break
                kind = SIRKind.binary_op
                if op == "-join":
                    kind = SIRKind.join_op
                elif op == "-split":
                    kind = SIRKind.split_op
                elif op == "-replace":
                    kind = SIRKind.replace_op
                elif op == "-f":
                    kind = SIRKind.format_op
                atom = SIRNode(kind=kind, value=op, children=(atom, rhs),
                               parser="powershell")
            args.append(atom)
            if i < len(toks) and toks[i].kind == "COMMA":
                i += 1
            else:
                break
        return args, i

    # ── ScriptBlock literal ─────────────────────────────────────────
    def _parse_scriptblock(self, toks, i, warnings):
        start = toks[i].start
        i += 1  # consume {
        stmts: List[SIRNode] = []
        depth = 1
        block_toks: List[Tok] = []
        while i < len(toks) and depth > 0:
            if toks[i].kind == "LBRACE":
                depth += 1
                block_toks.append(toks[i])
            elif toks[i].kind == "RBRACE":
                depth -= 1
                if depth == 0:
                    break
                block_toks.append(toks[i])
            else:
                block_toks.append(toks[i])
            i += 1
        # Parse inner tokens recursively
        inner_i = 0
        while inner_i < len(block_toks):
            if block_toks[inner_i].kind in ("NL", "SEMI"):
                inner_i += 1
                continue
            node, inner_i = self._parse_statement(block_toks, inner_i, warnings)
            if node is not None:
                stmts.append(node)
        if i < len(toks) and toks[i].kind == "RBRACE":
            i += 1
        sb = SIRNode(
            kind=SIRKind.script_block_lit,
            children=tuple(stmts),
            parser="powershell",
            source_span=(start, toks[i - 1].end if i > 0 else start),
        )
        return sb, i


_INSTANCE = PowerShellParser()
register_parser(_INSTANCE)


def get_powershell_parser() -> PowerShellParser:
    return _INSTANCE
