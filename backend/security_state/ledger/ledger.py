"""Security State Ledger: cryptographically chained, tamper-evident audit ledger."""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from ..contracts import (
    canonical_json,
    sha256_digest,
)


@dataclass
class LedgerBlock:
    """An individual block in the tamper-evident security state ledger."""
    block_index: int
    block_id: str
    tenant_id: str
    case_id: str
    timestamp: str
    event_type: str  # 'EVIDENCE_INGESTED', 'STATE_TRANSITION', 'CAUSAL_INFERRED', 'IMPACT_EVALUATED', 'ACTION_APPROVED', 'ACTION_EXECUTED', 'CONTAINMENT_VERIFIED'
    entity_id: str
    payload: Dict[str, Any]
    previous_block_hash: str
    block_hash: str = ""

    def __post_init__(self) -> None:
        if not self.block_hash:
            self.block_hash = self.compute_hash()

    def compute_hash(self) -> str:
        body = {
            "block_index": self.block_index,
            "block_id": self.block_id,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "entity_id": self.entity_id,
            "payload": self.payload,
            "previous_block_hash": self.previous_block_hash,
        }
        return sha256_digest(canonical_json(body))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SecurityStateLedger:
    """Immutable, append-only security state ledger with cryptographic verification."""
    GENESIS_HASH = "0" * 64

    def __init__(self, tenant_id: str, case_id: str) -> None:
        self.tenant_id = tenant_id
        self.case_id = case_id
        self.blocks: List[LedgerBlock] = []

    def append(
        self,
        event_type: str,
        entity_id: str,
        payload: Dict[str, Any],
        timestamp: str = "2026-09-04T00:00:00Z",
    ) -> LedgerBlock:
        """Append a new verified entry to the cryptographic ledger."""
        prev_hash = self.blocks[-1].block_hash if self.blocks else self.GENESIS_HASH
        idx = len(self.blocks)
        block = LedgerBlock(
            block_index=idx,
            block_id=f"block-{uuid.uuid4().hex[:12]}",
            tenant_id=self.tenant_id,
            case_id=self.case_id,
            timestamp=timestamp,
            event_type=event_type,
            entity_id=entity_id,
            payload=payload,
            previous_block_hash=prev_hash,
        )
        self.blocks.append(block)
        return block

    def verify_integrity(self) -> bool:
        """Validate that all blocks in the ledger are cryptographically sound and unbroken."""
        if not self.blocks:
            return True

        for i, block in enumerate(self.blocks):
            # Check recomputed hash
            if block.compute_hash() != block.block_hash:
                return False
            # Check link to previous block
            if i == 0:
                if block.previous_block_hash != self.GENESIS_HASH:
                    return False
            else:
                if block.previous_block_hash != self.blocks[i - 1].block_hash:
                    return False
        return True

    def to_list(self) -> List[Dict[str, Any]]:
        return [b.to_dict() for b in self.blocks]
