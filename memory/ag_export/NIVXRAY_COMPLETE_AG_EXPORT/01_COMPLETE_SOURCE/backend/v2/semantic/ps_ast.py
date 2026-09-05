"""NivXRay PowerShell AST engine (Phase 9.4).

Hand-rolled, deterministic tokenizer + light AST for PowerShell scripts
recovered from EncodedCommand / obfuscated payloads.

Design goals:
    • Zero external dependencies (no pwsh, no antlr, no third-party libs)
    • Deterministic — same input always produces same tree
    • Analyst-observable focus — we don't need a semantically perfect
      compiler; we need enough structure to detect adversarial behavior
      (variable resolution, format-string reconstruction, char-array
      joins, method chains).
    • Extensible — the `Node` schema is stable; new behavior extractors
      slot in without touching the parser.
    • Pluggable — if a native pwsh AST parser is ever added, this module
      is the ONLY thing that changes; downstream extractors read Nodes.

Public API:
    tokenize(script) -> list[Token]
    parse(script)    -> Script
    resolve_strings(script) -> dict[str, str]   # variable-name → constant

Everything else (behavior extraction, IOC harvesting, verdict scoring)
lives in sibling modules and consumes the AST here.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable


# ── Token types ──────────────────────────────────────────────────
TOK_STRING     = "STRING"          # 'literal' or "literal"
TOK_NUMBER     = "NUMBER"
TOK_IDENT      = "IDENT"           # Verb-Noun, Method, bareword
TOK_VARIABLE   = "VARIABLE"        # $x, ${x}, $env:X
TOK_OPERATOR   = "OPERATOR"        # -f, -join, -replace, -eq, -match, -bxor, +, =, .
TOK_PIPE       = "PIPE"            # |
TOK_SEMI       = "SEMI"            # ;  \n  (statement terminator)
TOK_COMMA      = "COMMA"
TOK_LPAREN     = "LPAREN"
TOK_RPAREN     = "RPAREN"
TOK_LBRACE     = "LBRACE"
TOK_RBRACE     = "RBRACE"
TOK_LBRACK     = "LBRACK"
TOK_RBRACK     = "RBRACK"
TOK_DOLPAREN   = "DOLPAREN"        # $( - open subexpression
TOK_AT_ARRAY   = "AT_ARRAY"        # @(  - array literal
TOK_AT_HASH    = "AT_HASH"         # @{  - hashtable literal
TOK_TYPECAST   = "TYPECAST"        # [char[]], [byte], [Convert]
TOK_STATIC_ACC = "STATIC_ACC"      # ::
TOK_MEMBER_ACC = "MEMBER_ACC"      # .Method
TOK_ARG        = "ARG"             # unquoted argument token
TOK_EOF        = "EOF"


@dataclass
class Token:
    kind: str
    value: str
    start: int
    end: int
    quote: str = ""     # for strings: '  or  "


# ── Tokenizer ────────────────────────────────────────────────────
_WORD_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
_OPS_WORD = {
    "f", "join", "replace", "split", "match", "notmatch", "like", "notlike",
    "eq", "ne", "gt", "lt", "ge", "le", "and", "or", "not", "band", "bor",
    "bxor", "bnot", "shl", "shr", "as", "is", "isnot", "in", "notin", "contains",
    "notcontains",
}


def tokenize(src: str) -> list[Token]:
    """Return a flat token stream. Never raises — malformed input just
    stops the scan and returns whatever we managed to lex."""
    toks: list[Token] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]

        # Whitespace (non-newline) — skip
        if c in " \t":
            i += 1
            continue

        # Backtick line continuation — skip backtick + following whitespace/newline
        if c == "`" and i + 1 < n and src[i + 1] in " \t\r\n":
            i += 1
            while i < n and src[i] in " \t\r\n":
                i += 1
            continue

        # Backtick escape inside code (rare outside strings) — just drop it
        if c == "`" and i + 1 < n:
            i += 2
            continue

        # Newline / semicolon — statement terminator
        if c in ";\r\n":
            toks.append(Token(TOK_SEMI, c, i, i + 1))
            i += 1
            continue

        # Comment
        if c == "#":
            while i < n and src[i] not in "\r\n":
                i += 1
            continue

        # String literals — single or double quoted
        if c in "'\"":
            q, start = c, i
            i += 1
            buf = []
            while i < n:
                ch = src[i]
                if ch == q:
                    # PS supports doubled quote as escape
                    if i + 1 < n and src[i + 1] == q:
                        buf.append(q)
                        i += 2
                        continue
                    i += 1
                    break
                if ch == "`" and q == '"' and i + 1 < n:
                    esc = {"n": "\n", "r": "\r", "t": "\t", "0": "\0"}
                    buf.append(esc.get(src[i + 1], src[i + 1]))
                    i += 2
                    continue
                buf.append(ch)
                i += 1
            toks.append(Token(TOK_STRING, "".join(buf), start, i, quote=q))
            continue

        # Variable: $x, ${x}, $env:X, $script:x, $(...)
        if c == "$":
            start = i
            if i + 1 < n and src[i + 1] == "(":
                toks.append(Token(TOK_DOLPAREN, "$(", i, i + 2))
                i += 2
                continue
            i += 1
            if i < n and src[i] == "{":
                i += 1
                v = []
                while i < n and src[i] != "}":
                    v.append(src[i]); i += 1
                if i < n and src[i] == "}":
                    i += 1
                toks.append(Token(TOK_VARIABLE, "".join(v), start, i))
                continue
            # Scoped variable: $env:PATH, $script:x
            v = []
            while i < n and (src[i] in _WORD_CHARS or src[i] == ":"):
                v.append(src[i]); i += 1
            toks.append(Token(TOK_VARIABLE, "".join(v), start, i))
            continue

        # Array literal @(...) / hashtable @{...}
        if c == "@" and i + 1 < n and src[i + 1] == "(":
            toks.append(Token(TOK_AT_ARRAY, "@(", i, i + 2)); i += 2; continue
        if c == "@" and i + 1 < n and src[i + 1] == "{":
            toks.append(Token(TOK_AT_HASH, "@{", i, i + 2)); i += 2; continue

        # Type-cast / accelerator: [Convert], [char[]], [System.Text.Encoding]
        if c == "[":
            start = i; i += 1
            depth = 1; buf = []
            while i < n and depth > 0:
                if src[i] == "[":
                    depth += 1
                elif src[i] == "]":
                    depth -= 1
                    if depth == 0:
                        i += 1
                        break
                buf.append(src[i]); i += 1
            body = "".join(buf).strip()
            # If we consumed a full [Type] token, emit TYPECAST; else treat as LBRACK
            if body:
                toks.append(Token(TOK_TYPECAST, body, start, i))
            else:
                toks.append(Token(TOK_LBRACK, "[", start, start + 1))
            continue

        if c == "]":
            toks.append(Token(TOK_RBRACK, "]", i, i + 1)); i += 1; continue

        # Parentheses / braces
        if c == "(": toks.append(Token(TOK_LPAREN, "(", i, i + 1)); i += 1; continue
        if c == ")": toks.append(Token(TOK_RPAREN, ")", i, i + 1)); i += 1; continue
        if c == "{": toks.append(Token(TOK_LBRACE, "{", i, i + 1)); i += 1; continue
        if c == "}": toks.append(Token(TOK_RBRACE, "}", i, i + 1)); i += 1; continue

        if c == ",": toks.append(Token(TOK_COMMA, ",", i, i + 1)); i += 1; continue
        if c == "|":
            # `||` (short-circuit or) is still a pipe at the granularity we care about
            toks.append(Token(TOK_PIPE, "|", i, i + 1)); i += 1; continue

        # Static access ::
        if c == ":" and i + 1 < n and src[i + 1] == ":":
            toks.append(Token(TOK_STATIC_ACC, "::", i, i + 2)); i += 2; continue

        # Member access .Method or .Prop  (but NOT a bare dot in numeric)
        if c == ".":
            start = i; i += 1
            v = []
            while i < n and src[i] in _WORD_CHARS:
                v.append(src[i]); i += 1
            if v:
                toks.append(Token(TOK_MEMBER_ACC, "".join(v), start, i))
                continue
            toks.append(Token(TOK_OPERATOR, ".", start, i))
            continue

        # Numeric literal (int or hex)
        if c.isdigit() or (c == "-" and i + 1 < n and src[i + 1].isdigit()
                           and (not toks or toks[-1].kind in (
                               TOK_OPERATOR, TOK_COMMA, TOK_LPAREN, TOK_LBRACK,
                               TOK_PIPE, TOK_SEMI, TOK_AT_ARRAY))):
            start = i
            if c == "-":
                i += 1
            if i + 1 < n and src[i] == "0" and src[i + 1] in "xX":
                i += 2
                while i < n and src[i] in "0123456789abcdefABCDEF":
                    i += 1
            else:
                while i < n and (src[i].isdigit() or src[i] == "."):
                    i += 1
            toks.append(Token(TOK_NUMBER, src[start:i], start, i))
            continue

        # Word operator: -f, -join, -replace, -eq …
        if c == "-" and i + 1 < n and src[i + 1].isalpha():
            start = i; i += 1
            v = []
            while i < n and src[i] in _WORD_CHARS and src[i] != "-":
                v.append(src[i]); i += 1
            word = "".join(v).lower()
            if word in _OPS_WORD:
                toks.append(Token(TOK_OPERATOR, "-" + word, start, i))
                continue
            # Not a known word operator → treat as a CLI flag argument
            toks.append(Token(TOK_ARG, "-" + "".join(v), start, i))
            continue

        # Symbol operators
        if c in "+=*/%<>!&":
            toks.append(Token(TOK_OPERATOR, c, i, i + 1)); i += 1; continue

        # Identifier / bareword
        if c in _WORD_CHARS or c == "\\":
            start = i
            v = []
            while i < n and (src[i] in _WORD_CHARS or src[i] in ":\\/."):
                v.append(src[i]); i += 1
            toks.append(Token(TOK_IDENT, "".join(v), start, i))
            continue

        # Fallback — swallow the byte so the loop advances.
        i += 1
    toks.append(Token(TOK_EOF, "", n, n))
    return toks


# ── AST node schema ──────────────────────────────────────────────
@dataclass
class Node:
    kind: str
    text: str = ""
    start: int = 0
    end: int = 0
    children: list["Node"] = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind, "text": self.text,
            "start": self.start, "end": self.end,
            "children": [c.to_dict() for c in self.children],
            "meta": self.meta,
        }


@dataclass
class Script:
    src: str
    tokens: list[Token]
    statements: list[Node]
    variables: dict[str, str]           # resolved literal values
    def to_dict(self) -> dict:
        return {
            "statements": [s.to_dict() for s in self.statements],
            "variables":  dict(self.variables),
            "src_len":    len(self.src),
        }


# ── Statement parser ─────────────────────────────────────────────
class _Parser:
    def __init__(self, src: str):
        self.src = src
        self.toks = tokenize(src)
        self.pos = 0

    def _peek(self, off: int = 0) -> Token:
        return self.toks[min(self.pos + off, len(self.toks) - 1)]

    def _eat(self, kind: str | None = None) -> Token:
        t = self.toks[self.pos]
        if kind and t.kind != kind:
            return t
        self.pos += 1
        return t

    def parse(self) -> list[Node]:
        stmts: list[Node] = []
        # Skip leading statement terminators
        while self._peek().kind == TOK_SEMI:
            self._eat()
        while self._peek().kind != TOK_EOF:
            snap = self.pos
            stmt = self._parse_statement()
            if stmt is not None:
                stmts.append(stmt)
            # Safety: if we made no progress, advance one token to avoid infinite loop
            if self.pos == snap:
                self._eat()
            # Consume any terminators between statements
            while self._peek().kind == TOK_SEMI:
                self._eat()
        return stmts

    def _parse_statement(self) -> Node | None:
        start_tok = self._peek()
        # Peek for `$var = ...` assignment
        if (start_tok.kind == TOK_VARIABLE and
                self._peek(1).kind == TOK_OPERATOR and self._peek(1).value == "="):
            var = self._eat(TOK_VARIABLE)
            self._eat(TOK_OPERATOR)   # =
            rhs = self._parse_pipeline()
            n = Node("Assignment", start=var.start,
                     end=(rhs.end if rhs else var.end),
                     meta={"target": var.value})
            if rhs is not None:
                n.children.append(rhs)
            return n
        # Otherwise it's a pipeline (may be a single expression)
        return self._parse_pipeline()

    def _parse_pipeline(self) -> Node | None:
        first = self._parse_expression_or_call()
        if first is None:
            return None
        # Consume `| next | next`
        if self._peek().kind != TOK_PIPE:
            return first
        pipe = Node("Pipeline", start=first.start, end=first.end)
        pipe.children.append(first)
        while self._peek().kind == TOK_PIPE:
            self._eat(TOK_PIPE)
            nxt = self._parse_expression_or_call()
            if nxt is None:
                break
            pipe.children.append(nxt)
            pipe.end = nxt.end
        return pipe

    def _parse_expression_or_call(self) -> Node | None:
        """Match either `Verb-Noun ARG ARG` (command) or an expression."""
        t = self._peek()
        if t.kind == TOK_EOF or t.kind == TOK_SEMI or t.kind == TOK_PIPE:
            return None
        # `&` call-operator prefix
        if t.kind == TOK_OPERATOR and t.value == "&":
            self._eat()
            return self._parse_expression_or_call()

        # Bareword identifier that looks like a cmdlet → parse as Call
        if t.kind == TOK_IDENT and self._looks_like_command(t.value):
            return self._parse_call(t)

        # Otherwise parse as an expression (may still yield useful info)
        first = self._parse_expression()
        if first is None:
            return None
        # Consume trailing binary operators: -f, -join, -replace, +
        while self._peek().kind == TOK_OPERATOR and self._peek().value in (
                "+", "-f", "-join", "-replace", "-split"):
            op = self._eat(TOK_OPERATOR)
            rhs = self._parse_arg()
            if rhs is None:
                break
            wrapper = Node("Paren", start=first.start, end=rhs.end)
            wrapper.children.extend([
                first,
                Node("Op", text=op.value, start=op.start, end=op.end),
                rhs,
            ])
            first = wrapper
        return first

    @staticmethod
    def _looks_like_command(name: str) -> bool:
        low = name.lower()
        # PowerShell cmdlets are Verb-Noun; also allow common aliases / native binaries
        if "-" in name and name.split("-")[0].isalpha():
            return True
        return low in {
            "iex", "iwr", "irm", "curl", "wget", "start", "saps", "ii",
            "gc", "cat", "type", "gci", "ls", "dir", "cp", "copy", "mv",
            "move", "rm", "del", "ni", "md", "mkdir", "sc", "sal", "gps",
            "ps", "gsv", "sv", "ac", "echo", "write", "sleep", "kill",
            "powershell", "powershell.exe", "cmd", "cmd.exe", "certutil",
            "bitsadmin", "rundll32", "regsvr32", "mshta", "wscript",
            "cscript", "schtasks", "reg", "net", "netsh", "sc.exe",
            "wmic", "whoami", "hostname", "ipconfig", "invoke-expression",
            "invoke-webrequest", "invoke-restmethod", "start-process",
            "new-object", "add-type", "set-mppreference", "get-credential",
            "register-scheduledtask", "new-scheduledtask", "new-service",
        }

    def _parse_call(self, name_tok: Token) -> Node:
        self._eat()
        call = Node("Call", text=name_tok.value,
                    start=name_tok.start, end=name_tok.end,
                    meta={"cmdlet": name_tok.value})
        # Consume arguments until pipeline / statement break
        while True:
            t = self._peek()
            if t.kind in (TOK_EOF, TOK_SEMI, TOK_PIPE):
                break
            arg = self._parse_arg()
            if arg is None:
                break
            call.children.append(arg)
            call.end = arg.end
        return call

    def _parse_arg(self) -> Node | None:
        """One CLI-style argument (string, variable, parenthesised expr,
        bareword flag, number, subexpression)."""
        t = self._peek()
        if t.kind == TOK_STRING:
            self._eat()
            return Node("String", text=t.value, start=t.start, end=t.end,
                        meta={"quote": t.quote})
        if t.kind == TOK_NUMBER:
            self._eat()
            return Node("Number", text=t.value, start=t.start, end=t.end)
        if t.kind == TOK_VARIABLE:
            self._eat()
            return Node("Var", text=t.value, start=t.start, end=t.end)
        if t.kind == TOK_LPAREN:
            n = self._parse_paren_expr()
            return self._chain_member_access(n)
        if t.kind == TOK_DOLPAREN:
            n = self._parse_paren_expr(is_dol=True)
            return self._chain_member_access(n)
        if t.kind == TOK_AT_ARRAY:
            n = self._parse_array_literal()
            return self._chain_member_access(n)
        if t.kind == TOK_TYPECAST:
            self._eat()
            # Followed by static access :: or a value
            n = Node("TypeCast", text=t.value, start=t.start, end=t.end)
            if self._peek().kind == TOK_STATIC_ACC:
                self._eat()
                member = self._peek()
                if member.kind in (TOK_IDENT, TOK_VARIABLE):
                    self._eat()
                    n.kind = "StaticMember"
                    n.meta["member"] = member.value
                    n.end = member.end
                    # Optional call arguments
                    if self._peek().kind == TOK_LPAREN:
                        args = self._parse_paren_expr()
                        n.children.append(args)
                        n.end = args.end
                        n.kind = "StaticCall"
            return n
        if t.kind == TOK_IDENT:
            self._eat()
            # `.Method(...)` chain
            n = Node("Ident", text=t.value, start=t.start, end=t.end)
            while self._peek().kind == TOK_MEMBER_ACC:
                m = self._eat(TOK_MEMBER_ACC)
                node = Node("MemberAccess", text=m.value,
                            start=n.start, end=m.end,
                            meta={"member": m.value})
                node.children.append(n)
                if self._peek().kind == TOK_LPAREN:
                    args = self._parse_paren_expr()
                    node.children.append(args)
                    node.end = args.end
                    node.kind = "MethodCall"
                n = node
            return n
        if t.kind == TOK_ARG:
            self._eat()
            return Node("Flag", text=t.value, start=t.start, end=t.end)
        # Unrecognised — advance and skip
        return None

    def _chain_member_access(self, n: Node) -> Node:
        """Attach `.Method(...)` or `.Prop` chains to an existing node."""
        while self._peek().kind == TOK_MEMBER_ACC:
            m = self._eat(TOK_MEMBER_ACC)
            node = Node("MemberAccess", text=m.value,
                        start=n.start, end=m.end,
                        meta={"member": m.value})
            node.children.append(n)
            if self._peek().kind == TOK_LPAREN:
                args = self._parse_paren_expr()
                node.children.append(args)
                node.end = args.end
                node.kind = "MethodCall"
            n = node
        return n

    def _parse_paren_expr(self, is_dol: bool = False) -> Node:
        open_tok = self._eat()
        n = Node("SubExpr" if is_dol else "Paren",
                 start=open_tok.start, end=open_tok.end)
        depth = 1
        buf_children: list[Node] = []
        # Simple approach — collect nested arguments until matching RPAREN
        while depth > 0 and self._peek().kind != TOK_EOF:
            t = self._peek()
            if t.kind in (TOK_LPAREN, TOK_DOLPAREN):
                depth += 1
                buf_children.append(self._parse_paren_expr(is_dol=(t.kind == TOK_DOLPAREN)))
                continue
            if t.kind == TOK_RPAREN:
                self._eat()
                depth -= 1
                if depth == 0:
                    n.end = t.end
                    break
                continue
            arg = self._parse_arg()
            if arg is None:
                # If we can't parse it, still consume one token to make progress
                skipped = self._eat()
                if skipped.kind == TOK_EOF:
                    break
                continue
            buf_children.append(arg)
            # Consume any binary-op glue so we don't loop forever
            if self._peek().kind == TOK_OPERATOR:
                op = self._eat(TOK_OPERATOR)
                buf_children.append(Node("Op", text=op.value,
                                         start=op.start, end=op.end))
            elif self._peek().kind == TOK_COMMA:
                self._eat()
            elif self._peek().kind == TOK_MEMBER_ACC:
                m = self._eat(TOK_MEMBER_ACC)
                buf_children.append(Node("MemberAccess", text=m.value,
                                         start=m.start, end=m.end,
                                         meta={"member": m.value}))
                if self._peek().kind == TOK_LPAREN:
                    inner = self._parse_paren_expr()
                    buf_children.append(inner)
        n.children = buf_children
        return n

    def _parse_array_literal(self) -> Node:
        open_tok = self._eat()
        n = Node("Array", start=open_tok.start, end=open_tok.end)
        while self._peek().kind not in (TOK_RPAREN, TOK_EOF):
            arg = self._parse_arg()
            if arg is not None:
                n.children.append(arg)
            if self._peek().kind == TOK_COMMA:
                self._eat()
        if self._peek().kind == TOK_RPAREN:
            close = self._eat()
            n.end = close.end
        return n

    def _parse_expression(self) -> Node | None:
        """Bare expression — chains of args + operators."""
        return self._parse_arg()


# ── String resolver (constant folding) ───────────────────────────
def _all_children(n: Node) -> Iterable[Node]:
    yield n
    for c in n.children:
        yield from _all_children(c)


def _fold_string(n: Node, vars_: dict[str, str]) -> str | None:
    """Return the constant string value of `n` if it can be folded at
    compile time, else None."""
    if n.kind == "String":
        return n.text
    if n.kind == "Number":
        try:
            return str(int(n.text, 0))
        except Exception:
            return n.text
    if n.kind == "Var":
        return vars_.get(n.text.lower())
    if n.kind == "Ident":
        return n.text
    if n.kind == "Paren" or n.kind == "SubExpr":
        parts = [_fold_string(c, vars_) for c in n.children]
        # Detect `-f` format operator inside a paren
        ops = [c for c in n.children if c.kind == "Op"]
        f_ops = [c for c in ops if c.text.lower() == "-f"]
        j_ops = [c for c in ops if c.text.lower() == "-join"]
        r_ops = [c for c in ops if c.text.lower() == "-replace"]
        if f_ops:
            # Format string is the first operand; args are what follow.
            fmt_idx = next((i for i, c in enumerate(n.children) if c.kind == "Op" and c.text.lower() == "-f"), -1)
            if fmt_idx > 0:
                fmt_node = n.children[fmt_idx - 1]
                arg_nodes = [c for c in n.children[fmt_idx + 1:] if c.kind not in ("Op",)]
                fmt = _fold_string(fmt_node, vars_)
                args = [_fold_string(a, vars_) for a in arg_nodes]
                if fmt is not None and all(a is not None for a in args):
                    try:
                        # `.NET` style `{0}{1}` — cast args to str
                        return _pwsh_format(fmt, args)
                    except Exception:
                        return None
        if j_ops:
            # `-join` on an array literal: `('a','b','c') -join ''`
            arr_node = n.children[0]
            sep_node = n.children[-1] if n.children[-1].kind != "Op" else None
            sep = _fold_string(sep_node, vars_) if sep_node is not None else ""
            elems = _fold_array(arr_node, vars_)
            if elems is not None and sep is not None:
                return sep.join(elems)
        if r_ops:
            # Very shallow: only fold if there are exactly 3 operands ('haystack' -replace 'needle','sub')
            operands = [c for c in n.children if c.kind != "Op"]
            if len(operands) >= 3:
                hay = _fold_string(operands[0], vars_)
                pat = _fold_string(operands[1], vars_)
                sub = _fold_string(operands[2], vars_)
                if hay is not None and pat is not None and sub is not None:
                    try:
                        return re.sub(pat, sub, hay)
                    except Exception:
                        return None
        # Plain concatenation via `+` operators
        plus_ops = [c for c in ops if c.text == "+"]
        if plus_ops and parts and all(p is not None for p in parts if p is not None):
            # Walk children left→right, skipping Op nodes
            collected = []
            for c in n.children:
                if c.kind == "Op":
                    continue
                v = _fold_string(c, vars_)
                if v is None:
                    return None
                collected.append(v)
            return "".join(collected)
        # Single element parenthesised → forward
        if len(n.children) == 1:
            return _fold_string(n.children[0], vars_)
        return None
    if n.kind == "Array":
        elems = _fold_array(n, vars_)
        if elems is not None:
            return "".join(elems)
        return None
    if n.kind == "TypeCast":
        return None
    if n.kind == "StaticCall" or n.kind == "MethodCall":
        # e.g. [Convert]::FromBase64String('...') → we return the ARG as-is
        # since we can't safely execute it; behavior extractor handles it.
        return None
    return None


def _fold_array(n: Node, vars_: dict[str, str]) -> list[str] | None:
    """Return a list of folded string elements, or None if any element
    cannot be folded."""
    if n.kind not in ("Array", "Paren", "SubExpr"):
        return None
    elems: list[str] = []
    for c in n.children:
        if c.kind == "Op" and c.text == ",":
            continue
        v = _fold_string(c, vars_)
        if v is None:
            return None
        # `[char[]] (0x69, 0x65, 0x78)` — char-array reconstruction
        # If parent context is a `[char[]]` cast this would be a chr call.
        elems.append(v)
    return elems


def _pwsh_format(fmt: str, args: list[str]) -> str:
    """Reimplements PowerShell's `.NET string.Format` for `{n}` placeholders."""
    def repl(m):
        idx_s = m.group(1)
        try:
            idx = int(idx_s.split(",")[0].split(":")[0])
        except ValueError:
            return m.group(0)
        return args[idx] if 0 <= idx < len(args) else m.group(0)
    return re.sub(r"\{(\d+(?:,[^{}]*)?(?::[^{}]*)?)\}", repl, fmt)


def resolve_variables(stmts: list[Node]) -> dict[str, str]:
    """Walk assignment statements and pre-compute constant string values.
    Only Assignments whose RHS folds to a constant are recorded."""
    vars_: dict[str, str] = {}
    for s in stmts:
        if s.kind != "Assignment":
            continue
        target = (s.meta.get("target") or "").lower()
        if not target or not s.children:
            continue
        rhs = s.children[0]
        val = _fold_string(rhs, vars_)
        if val is not None:
            vars_[target] = val
    return vars_


# ── Public entry point ───────────────────────────────────────────
def parse(src: str) -> Script:
    parser = _Parser(src or "")
    stmts = parser.parse()
    vars_ = resolve_variables(stmts)
    return Script(src=src or "", tokens=parser.toks, statements=stmts, variables=vars_)


def resolve_strings(script: Script) -> dict[str, str]:
    """Return the flat variable-name → constant string mapping."""
    return dict(script.variables)


def walk(nodes: Iterable[Node]) -> Iterable[Node]:
    """Depth-first traversal helper for behavior extractors."""
    for n in nodes:
        yield from _all_children(n)
