"""RC5 Phase 3 · PowerShell Interpreter.

Consumes an `SIRTree` produced by `PowerShellParser` and emits an immutable
`ExecGraph`. Statically evaluates every deterministic operation PS would
perform. Never executes anything. On any fragment it can't fully model,
emits an `UnresolvedNode` — never a guess.

Key capabilities:
  * Variable propagation / constant folding
  * String materialization with `"$var"` expansion inside double-quoted strings
  * `-join` / `-split` / `-replace` / `-f` / `+` / method calls
  * `[Convert]::FromBase64String`, `[char]N`, `[int]"n"`,
    `[Text.Encoding]::UTF8.GetString`
  * Array literals, indexing, slicing (`[-1]`, `[0..3]`)
  * `IEX` / `Invoke-Expression` / `& $sb` fixed-point re-parse (cap = 6)
  * ScriptBlock deferred eval
  * -EncodedCommand body inlined + parsed
"""
from __future__ import annotations

import base64
from typing import Any, Dict, List, Optional, Tuple

from ..exec_graph import (
    ExecGraph,
    ExecNode,
    NodeKind,
    SideEffect,
    SideEffectVerb,
)
from ..plugin_api import SemanticInterpreter, get_parser, register_interpreter
from ..semantic_ir import SIRKind, SIRNode, SIRTree
from ..normalizers_ps.alias_map import AMSI_BYPASS_MARKERS, ETW_BYPASS_MARKERS


IEX_MAX_ROUNDS = 6


class PowerShellInterpreter(SemanticInterpreter):
    parser_name = "powershell"

    def interpret(self, sir: SIRTree) -> ExecGraph:
        graph = ExecGraph()
        env: Dict[str, Any] = {}
        iex_rounds = 0
        for stmt in sir.root.children:
            graph, env, _ = self._eval(stmt, graph, env, iex_rounds, parents=())
        return graph

    # ── Dispatcher ──────────────────────────────────────────────────
    def _eval(self, node, graph, env, iex_rounds, parents):
        k = node.kind
        if k == SIRKind.assignment:
            return self._eval_assignment(node, graph, env, iex_rounds, parents)
        if k == SIRKind.call_expr:
            return self._eval_call(node, graph, env, iex_rounds, parents)
        if k == SIRKind.pipeline:
            last_id = None
            for stage in node.children:
                graph, env, last_id = self._eval(stage, graph, env, iex_rounds, parents)
            return graph, env, last_id
        if k == SIRKind.invocation_expr:
            return self._eval_invocation(node, graph, env, iex_rounds, parents)
        if k == SIRKind.script_block_lit:
            # scriptblock literal at top level — record without evaluating
            n = ExecNode(kind=NodeKind.script_block,
                         args={"stmt_count": len(node.children)},
                         reconstructed="{ …scriptblock… }",
                         parser="powershell", inputs=parents)
            return graph.add_node(n), env, n.id
        # Bare expression — materialize, drop
        val, conf, graph = self._materialize(node, graph, env, parents)
        n = ExecNode(kind=NodeKind.string_op,
                     args={"op": "bare_expr", "value": val},
                     reconstructed=str(val),
                     confidence=conf, parser="powershell", inputs=parents)
        return graph.add_node(n), env, n.id

    # ── Assignment ──────────────────────────────────────────────────
    def _eval_assignment(self, node, graph, env, iex_rounds, parents):
        name = node.attrs.get("name", "").lstrip("$").split(":")[-1]
        if not node.children:
            return graph, env, None
        val, conf, graph = self._materialize(node.children[0], graph, env, parents)
        new_env = dict(env)
        new_env[name] = val
        bind = ExecNode(
            kind=NodeKind.var_bind,
            args={"name": name, "value": val, "scope": "current"},
            reconstructed=f"${name} = {val!r}",
            confidence=conf, parser="powershell", inputs=parents,
        )
        bind = bind.model_copy(update={
            "side_effects": (SideEffect(verb=SideEffectVerb.var_bind,
                                        node_id=bind.id,
                                        evidence=f"${name} = {val!r}"),),
        })
        return graph.add_node(bind), new_env, bind.id

    # ── Call ────────────────────────────────────────────────────────
    def _eval_call(self, node, graph, env, iex_rounds, parents):
        head = str(node.value or "")
        head_lower = head.lower()

        # Materialize args
        arg_vals: List[str] = []
        confs: List[int] = []
        for c in node.children:
            v, cc, graph = self._materialize(c, graph, env, parents)
            arg_vals.append(str(v))
            confs.append(cc)
        conf = min(confs) if confs else 100

        # IEX fixed-point re-parse
        if head_lower in ("invoke-expression", "iex") and arg_vals:
            # Read cap at call-time so tests can monkeypatch the module attr.
            import sys as _sys
            _mod = _sys.modules[__name__]
            _cap = getattr(_mod, "IEX_MAX_ROUNDS", IEX_MAX_ROUNDS)
            if iex_rounds >= _cap:
                n = ExecNode(kind=NodeKind.unresolved,
                             args={"reason": f"IEX exceeded fixed-point cap {_cap}"},
                             confidence=max(0, conf - 20), parser="powershell",
                             inputs=parents)
                return graph.add_node(n), env, n.id
            inner_src = arg_vals[0]
            parser = get_parser("powershell")
            sir = parser.parse(inner_src)
            # Evaluate inner statements in current env — full fixed-point
            for stmt in sir.root.children:
                graph, env, _ = self._eval(stmt, graph, env, iex_rounds + 1, parents)
            # Emit a marker
            marker = ExecNode(kind=NodeKind.var_expand,
                              args={"kind": "iex_expansion", "round": iex_rounds + 1,
                                    "source": inner_src[:120]},
                              reconstructed=inner_src,
                              confidence=max(0, conf - 5),
                              parser="powershell", inputs=parents)
            return graph.add_node(marker), env, marker.id

        # -EncodedCommand body already decoded at parse time
        enc_body = node.attrs.get("encoded_command_decoded")
        if enc_body:
            parser = get_parser("powershell")
            inner_sir = parser.parse(enc_body)
            for stmt in inner_sir.root.children:
                graph, env, _ = self._eval(stmt, graph, env, iex_rounds, parents)
            reconstructed = f"{head} " + " ".join(arg_vals)
            proc = ExecNode(
                kind=NodeKind.process,
                args={"image": head, "args": arg_vals,
                      "encoded_command": True,
                      "decoded_body": enc_body[:400]},
                reconstructed=reconstructed,
                confidence=conf,
                parser="powershell", inputs=parents,
            )
            proc = proc.model_copy(update={
                "side_effects": (SideEffect(verb=SideEffectVerb.create_process,
                                            node_id=proc.id,
                                            evidence=reconstructed),),
            })
            return graph.add_node(proc), env, proc.id

        # Default: process spawn (Start-Process / powershell / anything else)
        reconstructed = f"{head} " + " ".join(arg_vals) if arg_vals else head
        proc_kind = NodeKind.process
        if head_lower in ("write-output", "echo", "write-host"):
            proc_kind = NodeKind.string_op
        semantic_tag = node.attrs.get("semantic_tag")
        proc = ExecNode(
            kind=proc_kind,
            args={"image": head, "args": arg_vals,
                  **({"semantic_tag": semantic_tag} if semantic_tag else {})},
            reconstructed=reconstructed,
            confidence=conf, parser="powershell", inputs=parents,
        )
        if proc_kind == NodeKind.process:
            proc = proc.model_copy(update={
                "side_effects": (SideEffect(verb=SideEffectVerb.create_process,
                                            node_id=proc.id,
                                            evidence=reconstructed),),
            })
        return graph.add_node(proc), env, proc.id

    # ── & invocation ────────────────────────────────────────────────
    def _eval_invocation(self, node, graph, env, iex_rounds, parents):
        # First child is target expression
        if not node.children:
            n = ExecNode(kind=NodeKind.unresolved,
                         args={"reason": "empty & invocation"},
                         confidence=0, parser="powershell", inputs=parents)
            return graph.add_node(n), env, n.id
        target = node.children[0]
        val, conf, graph = self._materialize(target, graph, env, parents)
        # If target is a ScriptBlock literal, evaluate its statements
        if isinstance(target, SIRNode) and target.kind == SIRKind.script_block_lit:
            for stmt in target.children:
                graph, env, _ = self._eval(stmt, graph, env, iex_rounds + 1, parents)
            marker = ExecNode(kind=NodeKind.var_expand,
                              args={"kind": "scriptblock_invoke"},
                              reconstructed="& { …scriptblock… }",
                              confidence=conf,
                              parser="powershell", inputs=parents)
            return graph.add_node(marker), env, marker.id
        # Otherwise treat as external invocation
        proc = ExecNode(kind=NodeKind.process,
                        args={"image": str(val), "args": []},
                        reconstructed=f"& {val}",
                        confidence=conf, parser="powershell", inputs=parents)
        proc = proc.model_copy(update={
            "side_effects": (SideEffect(verb=SideEffectVerb.create_process,
                                        node_id=proc.id,
                                        evidence=f"& {val}"),),
        })
        return graph.add_node(proc), env, proc.id

    # ── Value materialization ───────────────────────────────────────
    def _materialize(self, node, graph, env, parents) -> Tuple[Any, int, ExecGraph]:
        if node is None:
            return "", 100, graph
        k = node.kind
        if k == SIRKind.string_literal:
            v = node.value
            if node.attrs.get("expandable"):
                v = self._expand_string(str(v or ""), env)
            return v, 100, graph
        if k == SIRKind.number_literal:
            try:
                return int(node.value), 100, graph
            except (TypeError, ValueError):
                try:
                    return float(node.value), 100, graph
                except Exception:
                    return node.value, 100, graph
        if k == SIRKind.var_ref:
            name = str(node.value or "")
            if name in env:
                return env[name], 95, graph
            return f"${name}", 40, graph
        if k == SIRKind.env_ref:
            name = str(node.value or "")
            return f"$env:{name}", 40, graph
        if k == SIRKind.array_literal:
            items: List[Any] = []
            confs: List[int] = []
            for c in node.children:
                v, cc, graph = self._materialize(c, graph, env, parents)
                items.append(v)
                confs.append(cc)
            return items, min(confs) if confs else 100, graph
        if k == SIRKind.index_expr and len(node.children) == 2:
            arr, ac, graph = self._materialize(node.children[0], graph, env, parents)
            idx, ic, graph = self._materialize(node.children[1], graph, env, parents)
            try:
                if isinstance(arr, str):
                    result = arr[int(idx)]
                elif isinstance(arr, list):
                    result = arr[int(idx)]
                else:
                    return "", 30, graph
                return result, min(ac, ic), graph
            except Exception:
                return "", 30, graph
        if k in (SIRKind.binary_op, SIRKind.join_op, SIRKind.split_op,
                 SIRKind.replace_op, SIRKind.format_op):
            return self._materialize_binop(node, graph, env, parents)
        if k == SIRKind.member_expr:
            return self._materialize_member(node, graph, env, parents)
        if k == SIRKind.script_block_lit:
            return "{ …scriptblock… }", 60, graph
        if k == SIRKind.unresolved:
            return "", 0, graph
        return "", 30, graph

    def _expand_string(self, s: str, env: Dict[str, Any]) -> str:
        import re as _re
        def repl(m):
            name = m.group(1) or m.group(2)
            if name in env:
                return str(env[name])
            return m.group(0)
        return _re.sub(r"\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)", repl, s)

    def _materialize_binop(self, node, graph, env, parents):
        if len(node.children) != 2:
            return "", 0, graph
        left, lc, graph = self._materialize(node.children[0], graph, env, parents)
        right, rc, graph = self._materialize(node.children[1], graph, env, parents)
        op = node.value
        result: Any
        if op == "+":
            if isinstance(left, list) or isinstance(right, list):
                l = left if isinstance(left, list) else [left]
                r = right if isinstance(right, list) else [right]
                result = l + r
            elif isinstance(left, (int, float)) and isinstance(right, (int, float)):
                result = left + right
            else:
                result = str(left) + str(right)
        elif op == "-join":
            if isinstance(left, list):
                sep = str(right) if right is not None else ""
                result = sep.join(str(x) for x in left)
            else:
                result = str(left)
        elif op == "-split":
            sep = str(right) if right is not None else " "
            result = str(left).split(sep)
        elif op == "-replace":
            if isinstance(right, list) and len(right) == 2:
                # -replace 'pat','sub' — right becomes an array literal
                result = str(left).replace(str(right[0]), str(right[1]))
            else:
                result = str(left).replace(str(right), "")
        elif op == "-f":
            # -f string formatting: `"{0}-{1}" -f "a","b"`
            fmt = str(left)
            if isinstance(right, list):
                try:
                    result = fmt.format(*right)
                except (IndexError, KeyError, ValueError):
                    return "", 30, graph
            else:
                try:
                    result = fmt.format(right)
                except Exception:
                    return "", 30, graph
        else:
            return "", 30, graph
        return result, min(lc, rc), graph

    def _materialize_member(self, node, graph, env, parents):
        name = str(node.value or "")
        kind = node.attrs.get("kind")
        # Static call: base is a TYPE
        if kind == "static" and node.children:
            base_type = node.children[0]
            base_name = str(base_type.value or "").lower()
            arg_vals: List[Any] = []
            for c in node.children[1:]:
                v, _, graph = self._materialize(c, graph, env, parents)
                arg_vals.append(v)
            # [Convert]::FromBase64String("...")
            if base_name in ("convert", "system.convert") and name.lower() == "frombase64string" and arg_vals:
                try:
                    return base64.b64decode(str(arg_vals[0])), 90, graph
                except Exception:
                    return "", 30, graph
            # [Text.Encoding]::UTF8.GetString(bytes)  — approximate handling
            if "encoding" in base_name and name.lower() == "getstring" and arg_vals:
                try:
                    b = arg_vals[0]
                    if isinstance(b, (bytes, bytearray)):
                        return b.decode("utf-8", errors="replace"), 85, graph
                    return str(b), 60, graph
                except Exception:
                    return "", 30, graph
            # [char]N as static-call-shape (Type accelerator)
            if base_name == "char" and arg_vals:
                try:
                    return chr(int(arg_vals[0])), 100, graph
                except Exception:
                    return "", 30, graph
            if base_name == "int" and arg_vals:
                try:
                    return int(arg_vals[0]), 100, graph
                except Exception:
                    return "", 30, graph
            # Fallback: preserve `[Type]::name(...)` syntax so downstream
            # (AMSI-bypass fingerprinting, provenance) sees the raw form.
            preserved_type = str(base_type.value or "")
            args_render = "(" + ", ".join(str(a) for a in arg_vals) + ")" if arg_vals else ""
            return f"[{preserved_type}]::{name}{args_render}", 60, graph
        # Instance method
        if kind == "method" and node.children:
            recv, rc, graph = self._materialize(node.children[0], graph, env, parents)
            arg_vals = []
            for c in node.children[1:]:
                v, _, graph = self._materialize(c, graph, env, parents)
                arg_vals.append(v)
            if isinstance(recv, str):
                mname = name.lower()
                try:
                    if mname == "substring":
                        if len(arg_vals) == 1:
                            return recv[int(arg_vals[0]):], rc, graph
                        if len(arg_vals) == 2:
                            start = int(arg_vals[0])
                            length = int(arg_vals[1])
                            return recv[start:start + length], rc, graph
                    if mname == "replace" and len(arg_vals) == 2:
                        return recv.replace(str(arg_vals[0]), str(arg_vals[1])), rc, graph
                    if mname == "toupper":
                        return recv.upper(), rc, graph
                    if mname == "tolower":
                        return recv.lower(), rc, graph
                    if mname == "trim":
                        return recv.strip(), rc, graph
                    if mname == "split":
                        return recv.split(str(arg_vals[0])) if arg_vals else recv.split(), rc, graph
                    if mname == "tochararray":
                        return list(recv), rc, graph
                    if mname == "reverse":
                        return recv[::-1], rc, graph
                except Exception:
                    return "", 30, graph
                # Property access with no args OR unknown method — preserve
                # chain form so downstream fingerprinting (AMSI etc.) sees it.
                if arg_vals:
                    args_render = "(" + ", ".join(repr(a) for a in arg_vals) + ")"
                    return f"{recv}.{name}{args_render}", max(0, rc - 10), graph
                return f"{recv}.{name}", max(0, rc - 10), graph
            return "", 30, graph
        # Static call without a matching implementation — preserve syntax for
        # provenance / AMSI-bypass fingerprinting downstream.
        if kind == "static" and node.children:
            base_type = node.children[0]
            base_name = str(base_type.value or "")
            rendered = f"[{base_name}]::{name}"
            return rendered, 60, graph
        # bare type reference — return its name
        return name, 60, graph


_INSTANCE = PowerShellInterpreter()
register_interpreter(_INSTANCE)


def get_powershell_interpreter() -> PowerShellInterpreter:
    return _INSTANCE
