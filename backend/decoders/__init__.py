"""NivXRay — Decoder plugin registry (v1.6.0 · modular refactor).

Every atomic codec lives in its own file:
    decoders/base64.py, base58.py, base85.py, hex.py, xor.py,
    gzip.py, zlib.py, lzma.py, brotli.py, utf16.py, reverse.py, ...

Each plugin exposes:
    ID          - str      canonical op id (e.g. "base64-decode")
    NAME        - str      human-readable name
    CATEGORY    - str      "encoding" / "compression" / "cipher" / …
    detect(text) -> float  0..1 confidence this codec applies
    decode(text) -> str    the actual transform (may raise)

The registry auto-discovers plugins via directory scan on import.
"""
from __future__ import annotations
import importlib
import pkgutil
from typing import Callable, Dict, List

_REGISTRY: Dict[str, dict] = {}


def register(plugin_id: str, name: str, category: str,
             detect: Callable[[str], float],
             decode: Callable[[str], str]) -> None:
    _REGISTRY[plugin_id] = {
        "id": plugin_id, "name": name, "category": category,
        "detect": detect, "decode": decode,
    }


def all_plugins() -> List[dict]:
    return list(_REGISTRY.values())


def get(plugin_id: str) -> dict | None:
    return _REGISTRY.get(plugin_id)


def auto_discover() -> None:
    """Import every module in this package so their register() calls fire."""
    for _, name, _ in pkgutil.iter_modules(__path__):
        if name.startswith("_"):
            continue
        importlib.import_module(f"{__name__}.{name}")


auto_discover()
