"""Load versioned rule packs from JSON content (no Python-coded rules)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from .rules import RuleRegistry, SequenceRule, parse_rule

STARTER_PACK = Path(__file__).with_name("content") / "starter_rules.json"
MAX_PACK_BYTES = 1_000_000


def load_pack(path: Path = STARTER_PACK) -> List[SequenceRule]:
    raw = path.read_bytes()
    if len(raw) > MAX_PACK_BYTES:
        raise ValueError("rule pack too large")
    doc = json.loads(raw)
    if not isinstance(doc, dict) or doc.get("pack_version") != 1 or not isinstance(doc.get("rules"), list):
        raise ValueError("rule pack must be {pack_version: 1, rules: [...]}")
    return [parse_rule(r) for r in doc["rules"]]


def registry_from_pack(path: Path = STARTER_PACK, registry: Optional[RuleRegistry] = None) -> RuleRegistry:
    reg = registry or RuleRegistry()
    for r in load_pack(path):
        reg.register(r)
    return reg
