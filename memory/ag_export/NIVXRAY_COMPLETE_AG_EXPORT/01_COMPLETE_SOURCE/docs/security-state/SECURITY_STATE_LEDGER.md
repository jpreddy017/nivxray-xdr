# NivXRay Security State Ledger Specification

> **Document Type:** Audit Ledger Specification  
> **Status:** Authoritative  
> **Package:** `backend/security_state/ledger/`  

---

## 1. Cryptographically Chained Append-Only Audit

The Security State Ledger provides an immutable audit trail of the entire investigation lifecycle:

$$
H_0 = 0^{64}
$$
$$
H_i = \text{SHA-256}\left( \text{canonical\_json}( \text{Block}_i \parallel H_{i-1} ) \right)
$$

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│     Block 0     │      │     Block 1     │      │     Block 2     │
│ Evidence Ingest │───→  │ State Transition│───→  │ Action Verified │
│ Hash: 7b3a...   │      │ Prev: 7b3a...   │      │ Prev: c912...   │
│                 │      │ Hash: c912...   │      │ Hash: f4e8...   │
└─────────────────┘      └─────────────────┘      └─────────────────┘
```

---

## 2. Integrity Verification

The `verify_integrity()` algorithm walks the ledger from block 0 to $N$:
1. Verifies that `block_hash == compute_hash(block)`.
2. Verifies that `previous_block_hash == prior_block.block_hash`.
Any modification to an event payload breaks the SHA-256 chain and triggers immediate invalidation.
