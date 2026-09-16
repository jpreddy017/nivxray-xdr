"""
Phase 3.5 · Behavior-linked Workspace Dependency Graph.

We do NOT emit a static import dump. Per PRD.md §Phase 3.5, the graph must
answer "which imported module actually changed THIS sample's output?" not
"what is imported."

Method:
  1. Load the Phase 3 A/B matrix (evidence).
  2. For every ❌ row, identify the FIRST op that appears in the current
     decoder chain but not in the baseline chain (the divergent op).
  3. Locate the file in the CURRENT tree that owns that op (grep for the
     op string on a fixed set of source dirs).
  4. From that owning file, walk its import chain UP toward
     `backend/routers/ops.py` via a reverse-import search.
  5. Classify every file in the chain:
        - Workspace-owned : imported directly by routers/ops.py OR living
          under backend/workspace/
        - Shared Utility  : lives under a utility path (base64, hex, gzip,
          crypto, encoding, generic helpers) and does NOT define
          interpreter/decoder/normalizer/parser behavior
        - External Dep    : 3rd-party (installed via pip)
        - Unused/Dead     : not touched by any corpus sample

Output:
    artifacts/phase3_5_dep_graph.json
    phase3_5_dep_graph.md
"""
import ast
import json
import re
import subprocess
import sys
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parent
ART = ROOT / "artifacts"
ART.mkdir(exist_ok=True)

CURRENT_BE = Path("/app/backend")
BASELINE_BE = Path("/tmp/workspace-v1.5.6/backend")

# Behavioral roots — imports from these trees are treated as behavioral
# (owned by Workspace after isolation, or to-be-forked). Everything else
# imported from stdlib / site-packages is treated as external.
BEHAVIORAL_ROOTS = {
    "routers", "operations", "ops_extended", "decoders", "engine",
    "v2", "timeline", "nivxforge", "analysis_core", "smart_decoder",
    "magic_decoder", "reasoning", "ps_semantic_mini", "ps_normalizer",
    "ps_alias_normalizer", "ps_backtick_normalizer", "ps_reverse_swap",
    "cmd_runtime_reconstruct", "rc4_inline_decrypt", "crypto_api_annotator",
    "ps_inline_eval", "batch_envvar_substitute", "ops_base_family",
    "rc40_orchestrator_plugins", "ps_encodedcommand_multilayer",
    "workspace",
}

UTILITY_HINTS = {
    "base64", "hex", "gzip", "zlib", "crypto", "encoding", "utils",
    "helpers", "compression", "logging_utils", "text_utils",
}


def _load_matrix() -> list:
    path = ART / "phase3_ab_matrix.json"
    if not path.exists():
        print(f"ERR: {path} missing — run runner.py first", file=sys.stderr)
        sys.exit(2)
    return json.loads(path.read_text())


def _first_divergent_op(m: dict) -> str | None:
    b = m.get("baseline_ops") or []
    c = m.get("current_ops") or []
    i = 0
    while i < min(len(b), len(c)) and b[i] == c[i]:
        i += 1
    if i < len(c):
        return c[i]
    if i < len(b):
        return f"MISSING_IN_CURRENT::{b[i]}"
    return None


def _grep_op_owner(op_name: str, tree: Path) -> list[str]:
    """Find files in `tree` that register / mention this op string."""
    if not op_name or op_name.startswith("MISSING_IN_CURRENT::"):
        return []
    # We grep for the literal op name in .py files under common behavioral dirs.
    cmd = [
        "grep", "-rln", "--include=*.py",
        f'"{op_name}"',
        str(tree / "routers"),
        str(tree / "operations.py"),
        str(tree / "ops_extended.py"),
        str(tree / "decoders"),
        str(tree / "engine"),
        str(tree / "v2"),
        str(tree / "timeline"),
        str(tree / "nivxforge"),
        str(tree / "analysis_core.py"),
        str(tree / "smart_decoder.py"),
        str(tree / "magic_decoder.py"),
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        files = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
        # Prefer files under decoders/ or engine/ that DEFINE (register) the op
        # rather than files that just log it.
        return files
    except Exception:
        return []


def _module_path_to_key(p: Path, tree: Path) -> str:
    """Convert /tmp/.../backend/decoders/ps_alias_normalizer.py → decoders.ps_alias_normalizer"""
    try:
        rel = p.resolve().relative_to(tree.resolve())
    except ValueError:
        return str(p)
    parts = list(rel.parts)
    if parts and parts[-1].endswith(".py"):
        parts[-1] = parts[-1][:-3]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _direct_imports_of(module_key: str, tree: Path) -> set[str]:
    """Return the set of files under `tree` that directly import module_key.
    Excludes test files — tests import production modules but are NOT on the
    production call chain, so they must not appear in behavior-linked chains.
    """
    # module_key may be dotted; grep first component alone is too broad, so
    # match import lines precisely.
    top = module_key.split(".")[0]
    tail = module_key.split(".")[-1]
    patterns = [
        rf"from\s+{re.escape(module_key)}\s+import",
        rf"import\s+{re.escape(module_key)}\b",
        rf"from\s+{re.escape(top)}\s+import\s+.*\b{re.escape(tail)}\b",
    ]
    hits: set[str] = set()
    for pat in patterns:
        try:
            r = subprocess.run(
                ["grep", "-rlnE", "--include=*.py", pat, str(tree)],
                capture_output=True, text=True, timeout=15,
            )
            for ln in r.stdout.splitlines():
                p = ln.strip()
                if not p:
                    continue
                # exclude tests, benchmarks, and the workspace_recovery harness
                if ("/tests/" in p or p.endswith("/tests.py")
                        or "/workspace_recovery/" in p
                        or "/.pytest_cache/" in p):
                    continue
                hits.add(p)
        except Exception:
            continue
    return hits


def _walk_up_to_ops(owner_files: list[str], tree: Path, max_depth: int = 6) -> list[list[str]]:
    """
    From a set of owner files, walk up the import graph until we hit
    routers/ops.py. Returns a list of chains (each chain is a list of module
    keys ordered leaf → root).
    """
    target = str((tree / "routers" / "ops.py").resolve())
    chains: list[list[str]] = []
    for owner in owner_files:
        cur = Path(owner).resolve()
        chain = [_module_path_to_key(cur, tree)]
        seen = {str(cur)}
        for _ in range(max_depth):
            if str(cur) == target:
                break
            module_key = _module_path_to_key(cur, tree)
            importers = _direct_imports_of(module_key, tree)
            # Prefer routers/ops.py if it directly imports us
            if target in importers:
                chain.append(_module_path_to_key(Path(target), tree))
                break
            # else pick any importer that we haven't visited
            step = None
            for imp in importers:
                if imp not in seen:
                    step = imp
                    break
            if not step:
                break
            seen.add(step)
            cur = Path(step)
            chain.append(_module_path_to_key(cur, tree))
        chains.append(chain)
    return chains


def _classify(module_key: str, tree: Path) -> str:
    if not module_key:
        return "unknown"
    top = module_key.split(".")[0]
    if top == "workspace":
        return "Workspace-owned (already isolated)"
    if top == "routers":
        return "Workspace-owned (entry point)"
    if top in BEHAVIORAL_ROOTS:
        return "Behavioral (candidate for restore / isolation)"
    for hint in UTILITY_HINTS:
        if hint in module_key:
            return "Shared Utility (may remain shared)"
    p = tree / module_key.replace(".", "/")
    if p.with_suffix(".py").exists() or (p / "__init__.py").exists():
        return "Behavioral (candidate for restore / isolation)"
    return "External Dep (leave unchanged)"


def _static_ops_imports(tree: Path) -> dict:
    """Return the direct import list of routers/ops.py in `tree`."""
    p = tree / "routers" / "ops.py"
    try:
        src = p.read_text()
    except FileNotFoundError:
        return {"error": f"missing {p}"}
    try:
        mod = ast.parse(src)
    except SyntaxError as e:
        return {"error": f"syntax {e}"}
    imports = []
    for node in ast.walk(mod):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append({"kind": "import", "module": alias.name})
        elif isinstance(node, ast.ImportFrom):
            imports.append({"kind": "from", "module": node.module, "names": [n.name for n in node.names]})
    return {"imports": imports}


def main() -> int:
    matrix = _load_matrix()
    static = {
        "current": _static_ops_imports(CURRENT_BE),
        "baseline": _static_ops_imports(BASELINE_BE),
    }

    graphs = []
    module_bucket = defaultdict(list)  # module_key → list of sample ids that touched it
    for m in matrix:
        if m["identical"]:
            continue
        div_op = _first_divergent_op(m)
        entry = {
            "sample_id": m["id"],
            "family": m["family"],
            "first_divergence_stage": m["first_divergence_stage"],
            "first_divergent_op": div_op,
            "baseline_ops": m["baseline_ops"],
            "current_ops": m["current_ops"],
        }
        if div_op and not div_op.startswith("MISSING_IN_CURRENT::"):
            owners = _grep_op_owner(div_op, CURRENT_BE)
            entry["owning_files_current"] = owners
            chains = _walk_up_to_ops(owners, CURRENT_BE)
            entry["behavior_chains"] = [
                [{"module": k, "classification": _classify(k, CURRENT_BE)} for k in chain]
                for chain in chains
            ]
            for chain in chains:
                for k in chain:
                    module_bucket[k].append(m["id"])
        else:
            # Divergent op is missing in current (regression removed a behavior)
            missing = (div_op or "").replace("MISSING_IN_CURRENT::", "")
            owners = _grep_op_owner(missing, BASELINE_BE)
            entry["owning_files_baseline_only"] = owners
        graphs.append(entry)

    # Classification roll-up
    rollup = []
    for module_key, samples in sorted(module_bucket.items(), key=lambda x: -len(x[1])):
        rollup.append({
            "module": module_key,
            "classification": _classify(module_key, CURRENT_BE),
            "samples_touched": sorted(set(samples)),
            "sample_count": len(set(samples)),
        })

    payload = {
        "corpus_matrix_path": str(ART / "phase3_ab_matrix.json"),
        "current_ops_direct_imports": static["current"],
        "baseline_ops_direct_imports": static["baseline"],
        "per_sample_behavior_chains": graphs,
        "module_rollup": rollup,
    }
    (ART / "phase3_5_dep_graph.json").write_text(json.dumps(payload, indent=2, default=str))
    _emit_markdown(payload)
    return 0


def _emit_markdown(payload: dict) -> None:
    lines = []
    lines.append("# Phase 3.5 · Behavior-linked Workspace Dependency Graph")
    lines.append("")
    lines.append("This graph is derived from **runtime evidence** (Phase 3 A/B matrix),")
    lines.append("not static-import inference. For every ❌ sample we identify the")
    lines.append("current-tree op that is not in the baseline chain, locate its owning")
    lines.append("source file, and walk the import graph upward toward `routers/ops.py`.")
    lines.append("Test files, `.pytest_cache`, and the `workspace_recovery/` harness are")
    lines.append("excluded from the walk so tests do not pollute the production chain.")
    lines.append("")
    # ---- Evidence Summary ---------------------------------------------
    lines.append("## Evidence Summary — Modules Ranked by Behavioral Blast Radius")
    lines.append("")
    lines.append("The following modules are the **candidate root causes of decoder")
    lines.append("drift** between the v1.5.6 baseline and current HEAD. Ranking is by")
    lines.append("how many divergent corpus samples touch them (higher = higher risk).")
    lines.append("These become the working set for Phase 4 (root cause) and the")
    lines.append("minimal-fork target list for Phase 6 (isolation).")
    lines.append("")
    lines.append("| Rank | Module | Classification | Samples Affected |")
    lines.append("|-----:|--------|----------------|-----------------:|")
    ranked = [r for r in payload["module_rollup"] if r["module"] not in ("routers.ops",)]
    for i, r in enumerate(ranked[:20], 1):
        lines.append(f"| {i} | `{r['module']}` | {r['classification']} | {r['sample_count']} |")
    lines.append("")
    lines.append("## Per-Sample Behavior-linked Chain")
    lines.append("")
    for e in payload["per_sample_behavior_chains"]:
        lines.append(f"### `{e['sample_id']}` — {e['family']}")
        lines.append("")
        lines.append(f"- First divergence stage: `{e['first_divergence_stage']}`")
        lines.append(f"- First divergent op (current only): `{e.get('first_divergent_op')}`")
        owners = e.get("owning_files_current") or e.get("owning_files_baseline_only") or []
        lines.append(f"- Owning files: {json.dumps(owners)}")
        for chain in e.get("behavior_chains", []) or []:
            lines.append("")
            lines.append("Behavior-linked chain (leaf → root):")
            lines.append("")
            lines.append("```")
            for step in chain:
                lines.append(f"  {step['module']}     [{step['classification']}]")
            lines.append("```")
        lines.append("")
    lines.append("## Module Rollup — modules exercised by divergent samples")
    lines.append("")
    lines.append("| Module | Classification | Samples | Count |")
    lines.append("|--------|----------------|---------|-------|")
    for r in payload["module_rollup"]:
        lines.append(f"| `{r['module']}` | {r['classification']} | {', '.join(r['samples_touched'])} | {r['sample_count']} |")
    lines.append("")
    lines.append("## Static Import Roots (for cross-reference)")
    lines.append("")
    lines.append("**Current `routers/ops.py` direct imports** (first 25):")
    lines.append("```")
    for imp in (payload["current_ops_direct_imports"].get("imports") or [])[:25]:
        lines.append(f"  {imp}")
    lines.append("```")
    lines.append("")
    lines.append("**Baseline `routers/ops.py` direct imports** (first 25):")
    lines.append("```")
    for imp in (payload["baseline_ops_direct_imports"].get("imports") or [])[:25]:
        lines.append(f"  {imp}")
    lines.append("```")
    (ROOT / "phase3_5_dep_graph.md").write_text("\n".join(lines))
    print(f"[phase3.5] wrote {ROOT / 'phase3_5_dep_graph.md'}")


if __name__ == "__main__":
    sys.exit(main())
