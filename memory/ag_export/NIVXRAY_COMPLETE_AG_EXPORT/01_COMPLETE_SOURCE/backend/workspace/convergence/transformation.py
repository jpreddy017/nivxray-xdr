"""
Transformation metadata — declared shape of every deterministic pass
operation in the Convergence Engine.

Every transformation in ``structural.py`` / ``content.py`` /
``decoder.py`` / ``semantic.py`` registers a :class:`Transformation`
descriptor here. This gives the engine three properties beyond the
raw callable:

1. **Introspection** — the Convergence Certificate can list every
   transformation the engine is *capable* of running, not just the
   subset that fired on the current artifact.
2. **Provenance** — pass records reference transformations by name,
   and the descriptor tells you what it consumes / produces.
3. **Future-proofing** — a plugin registry (post-M8) can register
   external transformations against the same descriptor without
   changing any engine code.

Contract
--------
Every transformation MUST be:

* **Deterministic** — identical input yields identical output.
* **Pure** — no I/O, no clocks, no randomness, no hidden state.
* **Idempotent when re-applied** — running it on its own output
  never changes anything further (may hold trivially, e.g. numeric
  folding on ``105`` is a no-op).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Literal

Category = Literal["structural", "content", "decoder", "semantic"]


@dataclass(frozen=True)
class Transformation:
    """Descriptor for a single deterministic transformation."""

    name: str
    category: Category
    consumes: str  # short type/shape descriptor, e.g. "powershell-text"
    produces: str  # short type/shape descriptor, e.g. "powershell-text"
    preconditions: tuple[str, ...]
    postconditions: tuple[str, ...]
    # Higher priority runs first within a pass. Reserved for future
    # scheduler use; passes today apply in module-declared order and
    # can ignore this field.
    priority: int = 100
    deterministic: bool = True
    reversible: bool = False
    # Runs the transformation on ``content`` and returns
    # ``(new_content, times_it_fired)``. ``times_it_fired == 0`` means
    # the transformation produced no changes.
    apply: Callable[[str], tuple[str, int]] | None = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "consumes": self.consumes,
            "produces": self.produces,
            "preconditions": list(self.preconditions),
            "postconditions": list(self.postconditions),
            "priority": self.priority,
            "deterministic": self.deterministic,
            "reversible": self.reversible,
        }


__all__ = ["Category", "Transformation"]
