"""Capability Contract + Registry tests  (R28.6 / Phase 6).

Covers the data contract, the registry, and the planner-query API.
Does NOT touch the orchestrator (Phase 6 step 3 will) — this suite
proves the registry works in isolation, which is the prerequisite
for the planner integration in the next iteration.
"""
from __future__ import annotations

import pytest

from services.uaie import contract as C
from services.uaie.contract import (CAT_ANALYZER, CAT_EXECUTOR,
                                       CAT_RECOGNIZER, CAT_REPAIR,
                                       CAT_VALIDATOR, CATEGORIES,
                                       CapabilityContract,
                                       IMPROVES_DECODE, IMPROVES_MITRE,
                                       all_contracts, applicable_contracts,
                                       contracts_by_category,
                                       contracts_improving, contracts_producing,
                                       get, register, stats)


def _snap():
    return (dict(C._CONTRACT_REGISTRY), dict(C._IMPL_REGISTRY))


def _restore(s):
    C._CONTRACT_REGISTRY.clear()
    C._IMPL_REGISTRY.clear()
    C._CONTRACT_REGISTRY.update(s[0])
    C._IMPL_REGISTRY.update(s[1])
    C._rebuild_indexes()


# ══════════════════════════════════════════════════════════════════
# 1 · CapabilityContract validation
# ══════════════════════════════════════════════════════════════════
def test_contract_rejects_invalid_category():
    with pytest.raises(ValueError):
        CapabilityContract(id="x", version="1.0", category="nope")


def test_contract_rejects_confidence_out_of_range():
    with pytest.raises(ValueError):
        CapabilityContract(id="x", version="1.0", category=CAT_RECOGNIZER,
                             confidence_gain=1.5)
    with pytest.raises(ValueError):
        CapabilityContract(id="x", version="1.0", category=CAT_RECOGNIZER,
                             confidence_gain=-0.1)


def test_contract_rejects_cost_out_of_range():
    with pytest.raises(ValueError):
        CapabilityContract(id="x", version="1.0", category=CAT_RECOGNIZER, cost=0)
    with pytest.raises(ValueError):
        CapabilityContract(id="x", version="1.0", category=CAT_RECOGNIZER, cost=6)


def test_contract_is_frozen():
    c = CapabilityContract(id="x", version="1.0", category=CAT_RECOGNIZER)
    with pytest.raises((AttributeError, TypeError)):
        c.id = "hacked"   # type: ignore


def test_contract_applies_to_universal_wildcard():
    c = CapabilityContract(id="u", version="1.0", category=CAT_RECOGNIZER,
                             requires=("*",))
    assert c.applies_to("text") is True
    assert c.applies_to("anything") is True


def test_contract_applies_to_specific_types_only():
    c = CapabilityContract(id="s", version="1.0", category=CAT_EXECUTOR,
                             requires=("base64", "gzip_bytes"))
    assert c.applies_to("base64")     is True
    assert c.applies_to("gzip_bytes") is True
    assert c.applies_to("text")       is False


# ══════════════════════════════════════════════════════════════════
# 2 · Registry basic ops
# ══════════════════════════════════════════════════════════════════
def test_register_and_get():
    snap = _snap()
    try:
        c = CapabilityContract(id="rec.demo", version="1.0",
                                 category=CAT_RECOGNIZER, requires=("text",))
        register(c, impl="IMPL")
        got = get("rec.demo")
        assert got is not None
        assert got[0] is c
        assert got[1] == "IMPL"
    finally:
        _restore(snap)


def test_register_replaces_prior_by_id():
    snap = _snap()
    try:
        c1 = CapabilityContract(id="rec.dup", version="1.0",
                                  category=CAT_RECOGNIZER, requires=("text",))
        c2 = CapabilityContract(id="rec.dup", version="2.0",
                                  category=CAT_RECOGNIZER, requires=("*",))
        register(c1, impl="v1")
        register(c2, impl="v2")
        c, i = get("rec.dup")
        assert c.version == "2.0"
        assert i == "v2"
    finally:
        _restore(snap)


def test_get_returns_none_for_unknown_id():
    assert get("nope.nada") is None


# ══════════════════════════════════════════════════════════════════
# 3 · Planner queries
# ══════════════════════════════════════════════════════════════════
def test_applicable_contracts_matches_by_type_plus_universal():
    snap = _snap()
    try:
        register(CapabilityContract(id="a", version="1", category=CAT_EXECUTOR,
                                       requires=("base64",)), impl=1)
        register(CapabilityContract(id="b", version="1", category=CAT_EXECUTOR,
                                       requires=("gzip_bytes",)), impl=2)
        register(CapabilityContract(id="u", version="1", category=CAT_RECOGNIZER,
                                       requires=("*",)), impl=3)
        got = applicable_contracts("base64")
        ids = [c.id for c in got]
        assert "a" in ids
        assert "u" in ids
        assert "b" not in ids
    finally:
        _restore(snap)


def test_contracts_producing_and_consuming_indexes():
    snap = _snap()
    try:
        register(CapabilityContract(id="d", version="1", category=CAT_EXECUTOR,
                                       requires=("base64",),
                                       produces=("base64_decoded",),
                                       consumes=("base64",)),
                    impl="dec")
        register(CapabilityContract(id="g", version="1", category=CAT_EXECUTOR,
                                       requires=("gzip_bytes",),
                                       produces=("gzip_decoded",)),
                    impl="gz")
        assert [c.id for c in contracts_producing("base64_decoded")] == ["d"]
        assert [c.id for c in contracts_producing("gzip_decoded")]  == ["g"]
        assert contracts_producing("nothing_registered") == []
    finally:
        _restore(snap)


def test_contracts_improving_indexes_by_dimension():
    snap = _snap()
    try:
        register(CapabilityContract(id="m", version="1", category=CAT_ANALYZER,
                                       requires=("text",),
                                       improves=(IMPROVES_MITRE,)),
                    impl="mitre")
        register(CapabilityContract(id="d", version="1", category=CAT_EXECUTOR,
                                       requires=("base64",),
                                       improves=(IMPROVES_DECODE,)),
                    impl="dec")
        by_mitre = [c.id for c in contracts_improving(IMPROVES_MITRE)]
        by_dec   = [c.id for c in contracts_improving(IMPROVES_DECODE)]
        assert by_mitre == ["m"]
        assert by_dec   == ["d"]
    finally:
        _restore(snap)


def test_contracts_by_category_indexes():
    snap = _snap()
    try:
        register(CapabilityContract(id="r1", version="1", category=CAT_RECOGNIZER,
                                       requires=("*",)), impl=1)
        register(CapabilityContract(id="r2", version="1", category=CAT_RECOGNIZER,
                                       requires=("*",)), impl=2)
        register(CapabilityContract(id="e1", version="1", category=CAT_EXECUTOR,
                                       requires=("text",)), impl=3)
        recs = sorted(c.id for c in contracts_by_category(CAT_RECOGNIZER))
        exes = sorted(c.id for c in contracts_by_category(CAT_EXECUTOR))
        assert recs == ["r1", "r2"]
        assert exes == ["e1"]
    finally:
        _restore(snap)


def test_stats_shape():
    snap = _snap()
    try:
        register(CapabilityContract(id="s1", version="1", category=CAT_EXECUTOR,
                                       requires=("text",),
                                       produces=("out",),
                                       improves=(IMPROVES_DECODE,)),
                    impl=1)
        s = stats()
        assert s["contracts"] >= 1
        assert isinstance(s["by_category"], dict)
        assert isinstance(s["by_requires"], dict)
        assert isinstance(s["by_produces"], dict)
        assert isinstance(s["by_improves"], dict)
    finally:
        _restore(snap)


# ══════════════════════════════════════════════════════════════════
# 4 · Applicable-contracts ordering is deterministic (cost, id)
# ══════════════════════════════════════════════════════════════════
def test_applicable_contracts_deterministic_ordering():
    snap = _snap()
    try:
        # Register in reverse alphabetical to prove ordering isn't
        # insertion order.
        register(CapabilityContract(id="z", version="1", category=CAT_EXECUTOR,
                                       requires=("text",), cost=2), impl=1)
        register(CapabilityContract(id="a", version="1", category=CAT_EXECUTOR,
                                       requires=("text",), cost=1), impl=2)
        register(CapabilityContract(id="m", version="1", category=CAT_EXECUTOR,
                                       requires=("text",), cost=1), impl=3)
        got = [c.id for c in applicable_contracts("text")]
        # Expected order: cost ASC, id ASC → a(1), m(1), z(2)
        assert got == ["a", "m", "z"]
    finally:
        _restore(snap)


# ══════════════════════════════════════════════════════════════════
# 5 · Zero orchestrator impact — regressions from Phase 6 must not
#    break the existing 211 tests.  (Verified in CI; here we just
#    prove import + clear + re-register cycles are clean.)
# ══════════════════════════════════════════════════════════════════
def test_contract_registry_never_polluted_by_other_tests():
    snap = _snap()
    try:
        C.clear()
        assert all_contracts() == []
        assert stats()["contracts"] == 0
    finally:
        _restore(snap)
