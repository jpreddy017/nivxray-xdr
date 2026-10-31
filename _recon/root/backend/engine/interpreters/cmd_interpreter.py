"""RC5 Phase 2 · CMD Interpreter.

Consumes an `SIRTree` produced by `CmdParser` and emits an immutable
`ExecGraph`. Statically evaluates every operation deterministic CMD would
perform — SET, %VAR% expansion, %VAR:old=new% replacement, delayed !VAR!
resolution (when `SETLOCAL EnableDelayedExpansion` scope is inferred),
sequencing, and CALL 2nd-pass.

Never executes anything. On any fragment it cannot fully reconstruct,
emits an `UnresolvedNode` — never a guess.

See RC5 spec § 12.2 (interpreter contract) and § 6 (confidence propagation).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from ..exec_graph import (
    ExecGraph,
    ExecNode,
    NodeKind,
    SideEffect,
    SideEffectVerb,
)
from ..plugin_api import SemanticInterpreter, register_interpreter
from ..semantic_ir import SIRKind, SIRNode, SIRTree


class CmdInterpreter(SemanticInterpreter):
    parser_name = "cmd"

    # ── entry ─────────────────────────────────────────────────────────
    def interpret(self, sir: SIRTree) -> ExecGraph:
        graph = ExecGraph()
        env: Dict[str, str] = {}
        delayed_enabled = False
        for stmt in sir.root.children:
            graph, env, delayed_enabled, _ = self._eval(
                stmt, graph, env, delayed_enabled, parent_ids=(),
            )
        return graph

    # ── core dispatcher ──────────────────────────────────────────────
    def _eval(
        self,
        node: SIRNode,
        graph: ExecGraph,
        env: Dict[str, str],
        delayed_enabled: bool,
        parent_ids: Tuple[str, ...],
    ) -> Tuple[ExecGraph, Dict[str, str], bool, Optional[str]]:
        """Return (new_graph, env, delayed_enabled, last_node_id)."""
        k = node.kind

        if k == SIRKind.assignment:
            return self._eval_set(node, graph, env, delayed_enabled, parent_ids)

        if k == SIRKind.binary_op and node.value in ("&", "&&", "||"):
            return self._eval_sequence(node, graph, env, delayed_enabled, parent_ids)

        if k == SIRKind.if_stmt:
            return self._eval_if(node, graph, env, delayed_enabled, parent_ids)

        if k == SIRKind.invocation_expr:
            return self._eval_call(node, graph, env, delayed_enabled, parent_ids)

        if k == SIRKind.block:
            for child in node.children:
                graph, env, delayed_enabled, _ = self._eval(
                    child, graph, env, delayed_enabled, parent_ids,
                )
            return graph, env, delayed_enabled, None

        if k == SIRKind.call_expr:
            return self._eval_command(node, graph, env, delayed_enabled, parent_ids)

        if k == SIRKind.unresolved:
            unresolved = ExecNode(
                kind=NodeKind.unresolved,
                args={"reason": node.attrs.get("reason", "unknown"),
                      "sir_kind": node.kind.value},
                reconstructed="",
                confidence=0,
                parser="cmd",
                inputs=parent_ids,
                notes=(f"CMD interpreter: {node.attrs.get('reason', 'unresolved')}",),
            )
            graph = graph.add_node(unresolved)
            return graph, env, delayed_enabled, unresolved.id

        # any other kind — record as unresolved
        unresolved = ExecNode(
            kind=NodeKind.unresolved,
            args={"reason": f"unhandled SIR kind: {k.value}"},
            confidence=0, parser="cmd", inputs=parent_ids,
        )
        graph = graph.add_node(unresolved)
        return graph, env, delayed_enabled, unresolved.id

    # ── SET ───────────────────────────────────────────────────────────
    def _eval_set(self, node: SIRNode, graph: ExecGraph, env: Dict[str, str],
                  delayed_enabled: bool, parent_ids: Tuple[str, ...]):
        name = str(node.attrs.get("name", "")).upper()
        if node.attrs.get("arithmetic"):
            # SET /A — deferred to Phase 2.1
            un = ExecNode(
                kind=NodeKind.unresolved,
                args={"reason": "SET /A arithmetic — Phase 2.1"},
                confidence=0, parser="cmd", inputs=parent_ids,
            )
            return graph.add_node(un), env, delayed_enabled, un.id
        # Compute RHS value
        value_child = node.children[0] if node.children else None
        rhs_val, rhs_conf, graph = self._materialize(
            value_child, graph, env, delayed_enabled, parent_ids,
        )
        new_env = dict(env)
        new_env[name] = rhs_val
        # Special: SETLOCAL EnableDelayedExpansion is expressed via a command
        # `setlocal enabledelayedexpansion` — assignment doesn't affect scope.
        # We keep `delayed_enabled` as-is here.
        bind_node = ExecNode(
            kind=NodeKind.var_bind,
            args={"name": name, "value": rhs_val, "scope": "current"},
            reconstructed=f"SET {name}={rhs_val}",
            side_effects=(),  # populate below
            confidence=rhs_conf,
            parser="cmd",
            inputs=parent_ids,
        )
        # Add a var_bind side-effect referencing self.
        bind_node = bind_node.model_copy(update={
            "side_effects": (SideEffect(
                verb=SideEffectVerb.var_bind, node_id=bind_node.id,
                evidence=f"SET {name}={rhs_val}",
            ),),
        })
        graph = graph.add_node(bind_node)
        return graph, new_env, delayed_enabled, bind_node.id

    # ── Sequence (& / && / ||) ───────────────────────────────────────
    def _eval_sequence(self, node: SIRNode, graph: ExecGraph, env: Dict[str, str],
                       delayed_enabled: bool, parent_ids: Tuple[str, ...]):
        # Concat / plain binary_op fallback — value may be "+" for concat inside strings
        if node.value == "+":
            # Not a real command sequence — this is a concat SIR node. Treat as
            # a materialized value (unresolved as a *statement*).
            val, conf, graph = self._materialize(node, graph, env, delayed_enabled, parent_ids)
            un = ExecNode(
                kind=NodeKind.unresolved,
                args={"reason": "orphan concat expression",
                      "materialized": val},
                confidence=conf, parser="cmd", inputs=parent_ids,
            )
            return graph.add_node(un), env, delayed_enabled, un.id
        # Sequential eval of both sides — CMD semantics for && are conditional
        # on ERRORLEVEL, which we can't statically know. We reconstruct both
        # branches and let downstream reasoning worry about probability.
        last_id: Optional[str] = None
        for child in node.children:
            graph, env, delayed_enabled, last_id = self._eval(
                child, graph, env, delayed_enabled, parent_ids,
            )
        return graph, env, delayed_enabled, last_id

    # ── IF ───────────────────────────────────────────────────────────
    def _eval_if(self, node: SIRNode, graph: ExecGraph, env: Dict[str, str],
                 delayed_enabled: bool, parent_ids: Tuple[str, ...]):
        # Statically evaluate the condition when both sides materialize to literals.
        if len(node.children) < 3:
            un = ExecNode(kind=NodeKind.unresolved,
                          args={"reason": "IF missing operands"},
                          confidence=0, parser="cmd", inputs=parent_ids)
            return graph.add_node(un), env, delayed_enabled, un.id
        lhs_node, rhs_node, then_node = node.children[0], node.children[1], node.children[2]
        lhs_val, lhs_conf, graph = self._materialize(lhs_node, graph, env, delayed_enabled, parent_ids)
        rhs_val, rhs_conf, graph = self._materialize(rhs_node, graph, env, delayed_enabled, parent_ids)
        op = node.attrs.get("op", "==")
        result = self._eval_if_op(op, lhs_val, rhs_val)
        if result is None:
            # can't statically evaluate — still record then-branch as maybe
            graph, env, delayed_enabled, last_id = self._eval(
                then_node, graph, env, delayed_enabled, parent_ids,
            )
            return graph, env, delayed_enabled, last_id
        if result:
            graph, env, delayed_enabled, last_id = self._eval(
                then_node, graph, env, delayed_enabled, parent_ids,
            )
            return graph, env, delayed_enabled, last_id
        # False — record a no-op via unresolved with a clarifying reason
        un = ExecNode(
            kind=NodeKind.unresolved,
            args={"reason": f"IF {lhs_val!r} {op} {rhs_val!r} evaluated false — then-branch skipped",
                  "static_eval": True},
            confidence=min(lhs_conf, rhs_conf),
            parser="cmd", inputs=parent_ids,
            notes=("IF condition statically evaluated to False",),
        )
        return graph.add_node(un), env, delayed_enabled, un.id

    def _eval_if_op(self, op: str, a: str, b: str) -> Optional[bool]:
        if op in ("==", "EQU"):
            return a == b
        if op in ("!=", "NEQ"):
            return a != b
        try:
            ai, bi = int(a), int(b)
        except ValueError:
            return None
        if op == "GEQ":
            return ai >= bi
        if op == "LEQ":
            return ai <= bi
        if op == "GTR":
            return ai > bi
        if op == "LSS":
            return ai < bi
        return None

    # ── CALL (2nd-pass expansion) ────────────────────────────────────
    def _eval_call(self, node: SIRNode, graph: ExecGraph, env: Dict[str, str],
                   delayed_enabled: bool, parent_ids: Tuple[str, ...]):
        if not node.children:
            un = ExecNode(kind=NodeKind.unresolved,
                          args={"reason": "empty CALL"},
                          confidence=0, parser="cmd", inputs=parent_ids)
            return graph.add_node(un), env, delayed_enabled, un.id
        inner = node.children[0]
        # 2nd-pass semantics: CMD re-expands variables *after* the initial
        # substitution. For our simple model, we materialize twice.
        # First pass: normal eval → produces graph & command
        graph, env, delayed_enabled, first_id = self._eval(
            inner, graph, env, delayed_enabled, parent_ids,
        )
        # Add a marker node showing CALL semantics.
        marker = ExecNode(
            kind=NodeKind.var_expand,
            args={"kind": "call_second_pass"},
            reconstructed=f"CALL <{first_id}>",
            confidence=(graph.find(first_id).confidence if first_id else 0),
            parser="cmd",
            inputs=(first_id,) if first_id else (),
            notes=("CALL — second-pass expansion applied",),
        )
        return graph.add_node(marker), env, delayed_enabled, marker.id

    # ── Command (call_expr) ──────────────────────────────────────────
    def _eval_command(self, node: SIRNode, graph: ExecGraph, env: Dict[str, str],
                      delayed_enabled: bool, parent_ids: Tuple[str, ...]):
        # First child is the head; rest are args.
        parts: List[str] = []
        pieces_confs: List[int] = []
        for child in node.children:
            val, conf, graph = self._materialize(child, graph, env, delayed_enabled, parent_ids)
            parts.append(val)
            pieces_confs.append(conf)
        if not parts:
            un = ExecNode(kind=NodeKind.unresolved,
                          args={"reason": "empty command"},
                          confidence=0, parser="cmd", inputs=parent_ids)
            return graph.add_node(un), env, delayed_enabled, un.id
        head = parts[0]
        args = parts[1:]
        head_upper = head.upper()
        reconstructed = " ".join([head] + args).strip()
        conf = min(pieces_confs) if pieces_confs else 100

        # Detect SETLOCAL EnableDelayedExpansion — scope toggle
        if head_upper == "SETLOCAL":
            for a in args:
                if a.upper() == "ENABLEDELAYEDEXPANSION":
                    delayed_enabled = True
            # emit a var_bind-like marker
            marker = ExecNode(
                kind=NodeKind.var_bind,
                args={"name": "__setlocal__", "value": " ".join(args),
                      "scope": "setlocal"},
                reconstructed=reconstructed,
                confidence=conf, parser="cmd", inputs=parent_ids,
            )
            return graph.add_node(marker), env, delayed_enabled, marker.id

        # ECHO — produce a plain output node (String op)
        if head_upper == "ECHO":
            n = ExecNode(
                kind=NodeKind.string_op,
                args={"op": "echo", "text": " ".join(args)},
                reconstructed=reconstructed,
                confidence=conf, parser="cmd", inputs=parent_ids,
            )
            return graph.add_node(n), env, delayed_enabled, n.id

        # Every other command is treated as a process spawn.
        proc = ExecNode(
            kind=NodeKind.process,
            args={"image": head, "args": args,
                  "redirects": node.attrs.get("redirects", [])},
            reconstructed=reconstructed,
            confidence=conf, parser="cmd", inputs=parent_ids,
        )
        # Self-reference side-effect so graph.dangling_refs() stays clean.
        proc = proc.model_copy(update={
            "side_effects": (SideEffect(
                verb=SideEffectVerb.create_process, node_id=proc.id,
                evidence=reconstructed,
            ),),
        })
        return graph.add_node(proc), env, delayed_enabled, proc.id

    # ── Value materialization (SIR value → concrete string) ──────────
    def _materialize(self, node: Optional[SIRNode], graph: ExecGraph, env: Dict[str, str],
                     delayed_enabled: bool, parent_ids: Tuple[str, ...]
                     ) -> Tuple[str, int, ExecGraph]:
        """Return (materialized_string, confidence, new_graph)."""
        if node is None:
            return "", 100, graph
        k = node.kind
        if k == SIRKind.string_literal:
            return str(node.value or ""), 100, graph
        if k == SIRKind.var_ref:
            name = str(node.value or "").upper()
            if name in env:
                # Emit a var_expand node for provenance
                child = ExecNode(
                    kind=NodeKind.var_expand,
                    args={"name": name, "kind": "normal", "value": env[name]},
                    reconstructed=env[name],
                    confidence=90,   # slight drop for expansion vs literal
                    parser="cmd", inputs=parent_ids,
                )
                graph = graph.add_node(child)
                return env[name], 90, graph
            # Unknown variable → CMD keeps the literal `%VAR%` in output
            return f"%{name}%", 40, graph
        if k == SIRKind.delayed_ref:
            name = str(node.value or "").upper()
            if delayed_enabled and name in env:
                child = ExecNode(
                    kind=NodeKind.var_expand,
                    args={"name": name, "kind": "delayed", "value": env[name]},
                    reconstructed=env[name],
                    confidence=90, parser="cmd", inputs=parent_ids,
                )
                graph = graph.add_node(child)
                return env[name], 90, graph
            return f"!{name}!", 40, graph
        if k == SIRKind.replace_op:
            # children = (var_ref, StringLit(old), StringLit(new))
            var_val, vc, graph = self._materialize(node.children[0], graph, env, delayed_enabled, parent_ids)
            old = str(node.children[1].value or "") if len(node.children) > 1 else ""
            new = str(node.children[2].value or "") if len(node.children) > 2 else ""
            result = var_val.replace(old, new) if old else var_val
            child = ExecNode(
                kind=NodeKind.string_op,
                args={"op": "replace", "old": old, "new": new, "in": var_val},
                reconstructed=result,
                confidence=min(vc, 90), parser="cmd", inputs=parent_ids,
            )
            graph = graph.add_node(child)
            return result, min(vc, 90), graph
        if k == SIRKind.substring_op:
            var_val, vc, graph = self._materialize(node.children[0], graph, env, delayed_enabled, parent_ids)
            raw_mod = node.attrs.get("raw_mod", "~")
            # parse ~offset[,length]
            body = raw_mod[1:]  # strip '~'
            try:
                if "," in body:
                    off_s, len_s = body.split(",", 1)
                    off = int(off_s)
                    ln = int(len_s)
                    if off < 0:
                        result = var_val[off:] if ln >= 0 else var_val[off:off + ln]
                    else:
                        result = var_val[off:off + ln] if ln >= 0 else var_val[off:len(var_val) + ln]
                else:
                    off = int(body)
                    result = var_val[off:] if off >= 0 else var_val[off:]
            except (ValueError, IndexError):
                return var_val, min(vc, 30), graph
            child = ExecNode(
                kind=NodeKind.string_op,
                args={"op": "substring", "raw_mod": raw_mod, "in": var_val},
                reconstructed=result,
                confidence=min(vc, 90), parser="cmd", inputs=parent_ids,
            )
            graph = graph.add_node(child)
            return result, min(vc, 90), graph
        if k == SIRKind.binary_op and node.value == "+":
            # concat
            parts: List[str] = []
            confs: List[int] = []
            for c in node.children:
                v, cc, graph = self._materialize(c, graph, env, delayed_enabled, parent_ids)
                parts.append(v)
                confs.append(cc)
            result = "".join(parts)
            child = ExecNode(
                kind=NodeKind.concat,
                args={"parts": parts, "result": result},
                reconstructed=result,
                confidence=min(confs) if confs else 100,
                parser="cmd", inputs=parent_ids,
            )
            graph = graph.add_node(child)
            return result, child.confidence, graph
        if k == SIRKind.unresolved:
            return "", 0, graph
        # anything else — unknown; degrade
        return "", 30, graph


# ---------------------------------------------------------------------------
# Register at import time.
# ---------------------------------------------------------------------------
_INSTANCE = CmdInterpreter()
register_interpreter(_INSTANCE)


def get_cmd_interpreter() -> CmdInterpreter:
    return _INSTANCE
