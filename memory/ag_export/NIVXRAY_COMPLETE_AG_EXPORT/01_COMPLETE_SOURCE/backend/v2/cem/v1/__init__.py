"""CEM v1 · frozen schema. Never mutate — add a new version instead."""
from v2.cem.v1.schema import (  # noqa: F401
    VERSION,
    Provenance,
    Entity,
    Relationship,
    CanonicalEvent,
    ENTITY_KINDS,
    EVENT_KINDS,
    RELATIONSHIP_KINDS,
)
