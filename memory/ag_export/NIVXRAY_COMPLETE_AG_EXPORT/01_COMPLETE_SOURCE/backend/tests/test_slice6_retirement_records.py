"""Phase A · Slice 6 · RTE-consumes-UAIE cleanup + retirement audit.

The RTE ``ps_byte_array_xor_loop`` transformation was proven
byte-equivalent to the UAIE ``transformer.byte_array_xor_loop``
capability in Slice 3.  This slice writes the machine-readable
retirement record that MUST exist BEFORE the RTE duplicate is
physically deleted.

Per user directive (2026-02-04):

    Before deleting any duplicate transformation, generate a
    machine-readable retirement record.  That gives a durable
    audit trail explaining why the legacy path was removed.

The physical deletion of the duplicate RTE transformation itself is
performed in a follow-up commit (the "Slice-6 execution" phase) —
this file locks the record in place so an accidental revert cannot
erase the justification.
"""
from __future__ import annotations

import os

from services.uaie.retirement_ledger import (
    write_retirement_record, list_retirement_records,
)


# Every retirement record we plan to write during Slice 6.  Filling
# these in progressively — each entry that has ``equivalence_source``
# set means the record is safe to emit right now.
_PENDING_RETIREMENTS = [
    {
        "legacy":         "v2.investigation.rte.transformations.ps_byte_array_xor_loop",
        "replacement":    "services.uaie.plugins.transformer_byte_array_xor_loop",
        "capability_id":  "ps.byte_array_xor_loop",
        "retired_in":     "PhaseA.Slice6",
        "equivalence": {
            "topology":       "waived",   # RTE has no ProvenanceGraph
            "evidence":       "pass",     # XOR key + C2 IP identical
            "recipe":         "pass",     # deep-peel-byte_array_xor_loop
            "verdict_inputs": "pass",     # reached_shellcode + IOCs match
        },
        "equivalence_source": (
            "tests/test_slice3_byte_array_xor.py · "
            "test_slice3_all_three_engines_agree_on_xor_key_and_c2 · "
            "test_slice3_retirement_gates_are_met"),
        "notes": (
            "All three current implementations (recursive_decoder peel, "
            "RTE transformation, UAIE plugin) produce XOR key 0x23 and "
            "surface C2 IP 149.28.81.19 on the Golden Vertical Chain "
            "payload.  The UAIE plugin is now the canonical owner; the "
            "recursive_decoder legacy peel remains until Phase-C "
            "engine-consolidation."),
    },
]


def test_slice6_retirement_records_are_emitted():
    """Emit every ready retirement record.  Re-runnable — records
    are idempotent (overwrite by legacy identifier).  This is the
    audit trail that survives even if the legacy code is later
    deleted from the tree."""
    for pending in _PENDING_RETIREMENTS:
        path = write_retirement_record(
            legacy        = pending["legacy"],
            replacement   = pending["replacement"],
            capability_id = pending["capability_id"],
            retired_in    = pending["retired_in"],
            equivalence   = pending["equivalence"],
            notes         = pending["notes"] + "\nEquivalence source: "
                                + pending["equivalence_source"],
        )
        assert os.path.isfile(path)


def test_slice6_ledger_reads_back_records():
    records = list_retirement_records()
    # Every entry has the schema-version + minimum fields.
    for r in records:
        for k in ("schema_version", "legacy", "replacement",
                    "capability_id", "retired_in", "retired_at",
                    "equivalence"):
            assert k in r, f"retirement record missing key {k}: {r}"
        assert r["schema_version"] == 1
        # The equivalence dict is a status map per dimension.
        assert isinstance(r["equivalence"], dict)


def test_slice6_ps_byte_array_xor_loop_retirement_is_recorded():
    """The Slice-3 flagship duplicate is retirement-audited."""
    records = list_retirement_records()
    hit = [r for r in records
             if r["capability_id"] == "ps.byte_array_xor_loop"]
    assert hit, "ps.byte_array_xor_loop retirement record MISSING"
    r = hit[0]
    assert r["retired_in"] == "PhaseA.Slice6"
    # Every 4 gate dimensions accounted for (pass / waived / fail).
    for dim in ("topology", "evidence", "recipe", "verdict_inputs"):
        assert dim in r["equivalence"]
        assert r["equivalence"][dim] in ("pass", "waived", "fail")
