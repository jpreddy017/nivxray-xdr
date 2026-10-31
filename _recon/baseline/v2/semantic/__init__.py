"""v2/semantic · Command semantic parser (Phase 3f).

Single source of truth for turning a raw command line into structured
Evidence Objects (Entity → Action → Target with confidence).

Consumers: trajectory, MITRE mapper, reports, future graph pipeline.
No duplication of parsing logic anywhere else.
"""
from v2.semantic.rules import RULES, Rule                    # noqa: F401
from v2.semantic.parser import (                              # noqa: F401
    Evidence,
    parse_command,
)
