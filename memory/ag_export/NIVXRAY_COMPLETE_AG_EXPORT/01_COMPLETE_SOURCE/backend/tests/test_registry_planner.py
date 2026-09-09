"""Registry-Driven Planner tests  (R28.7 / Phase 6 · Step 3).

Verifies the architectural boundary:
    · The planner NEVER inspects the plugin implementation.
    · The planner is deterministic given a fixed registry state.
    · Recognizers precede executors precede analyzers precede family.
    · cost / priority_hint / expected_gain break ties in that order.
    · An artifact whose type nothing supports returns an empty plan.
"""
from __future__ import annotations

from services.uaie import contract as C
from services.uaie.artifact import make_artifact
from services.uaie.contract import (CAT_ANALYZER, CAT_EXECUTOR, CAT_FAMILY,
                                       CAT_MITRE_MAPPER, CAT_RECOGNIZER,
                                       CAT_VALIDATOR, CapabilityContract,
                                       IMPROVES_DECODE, IMPROVES_MITRE,
                                       register)
from services.uaie.planner_v2 import plan_for, plan_stats


def _snap():
    return (dict(C._CONTRACT_REGISTRY), dict(C._IMPL_REGISTRY))


def _restore(s):
    C._CONTRACT_REGISTRY.clear()
    C._IMPL_REGISTRY.clear()
    C._CONTRACT_REGISTRY.update(s[0])
    C._IMPL_REGISTRY.update(s[1])
    C._rebuild_indexes()


# ══════════════════════════════════════════════════════════════════
# 1 · Category ordering — recognizers precede executors precede analyzers
# ══════════════════════════════════════════════════════════════════
def test_category_ordering_recognizer_executor_analyzer_family():
    snap = _snap()
    try:
        C.clear()
        register(CapabilityContract(id="a.family", version="1",
                                        category=CAT_FAMILY, requires=("text",)),
                    impl="family")
        register(CapabilityContract(id="b.exec",   version="1",
                                        category=CAT_EXECUTOR, requires=("text",)),
                    impl="exec")
        register(CapabilityContract(id="c.analyze", version="1",
                                        category=CAT_ANALYZER, requires=("text",)),
                    impl="an")
        register(CapabilityContract(id="d.rec", version="1",
                                        category=CAT_RECOGNIZER, requires=("*",)),
                    impl="rec")
        register(CapabilityContract(id="e.mitre", version="1",
                                        category=CAT_MITRE_MAPPER, requires=("text",)),
                    impl="mitre")
        register(CapabilityContract(id="f.val", version="1",
                                        category=CAT_VALIDATOR, requires=("text",)),
                    impl="val")
        art = make_artifact(b"hello", "text", discovered_by="t")
        plan = plan_for(art)
        cats = [c.category for c, _ in plan]
        expected_order = [CAT_RECOGNIZER, CAT_VALIDATOR, CAT_EXECUTOR,
                            CAT_ANALYZER, CAT_MITRE_MAPPER, CAT_FAMILY]
        assert cats == expected_order
    finally:
        _restore(snap)


# ══════════════════════════════════════════════════════════════════
# 2 · Cost breaks ties within the same category
# ══════════════════════════════════════════════════════════════════
def test_cost_breaks_ties_within_category():
    snap = _snap()
    try:
        C.clear()
        register(CapabilityContract(id="z.exec", version="1",
                                        category=CAT_EXECUTOR, requires=("text",),
                                        cost=5), impl=1)
        register(CapabilityContract(id="a.exec", version="1",
                                        category=CAT_EXECUTOR, requires=("text",),
                                        cost=1), impl=2)
        register(CapabilityContract(id="m.exec", version="1",
                                        category=CAT_EXECUTOR, requires=("text",),
                                        cost=3), impl=3)
        art = make_artifact(b"hello", "text", discovered_by="t")
        plan = plan_for(art)
        ids = [c.id for c, _ in plan]
        assert ids == ["a.exec", "m.exec", "z.exec"]   # cheap → dear
    finally:
        _restore(snap)


# ══════════════════════════════════════════════════════════════════
# 3 · priority_hint breaks ties when cost equal (higher wins)
# ══════════════════════════════════════════════════════════════════
def test_priority_hint_breaks_ties_when_cost_equal():
    snap = _snap()
    try:
        C.clear()
        register(CapabilityContract(id="a", version="1",
                                        category=CAT_EXECUTOR, requires=("text",),
                                        cost=2, priority_hint=1),  impl=1)
        register(CapabilityContract(id="b", version="1",
                                        category=CAT_EXECUTOR, requires=("text",),
                                        cost=2, priority_hint=5),  impl=2)
        register(CapabilityContract(id="c", version="1",
                                        category=CAT_EXECUTOR, requires=("text",),
                                        cost=2, priority_hint=3),  impl=3)
        art = make_artifact(b"hello", "text", discovered_by="t")
        ids = [c.id for c, _ in plan_for(art)]
        assert ids == ["b", "c", "a"]   # higher priority_hint first
    finally:
        _restore(snap)


# ══════════════════════════════════════════════════════════════════
# 4 · total_expected_gain breaks ties when cost+priority equal
# ══════════════════════════════════════════════════════════════════
def test_expected_gain_breaks_ties_when_cost_and_priority_equal():
    snap = _snap()
    try:
        C.clear()
        register(CapabilityContract(id="small", version="1",
                                        category=CAT_EXECUTOR, requires=("text",),
                                        cost=1, priority_hint=0,
                                        improves=(IMPROVES_DECODE,),
                                        confidence_gain=0.1), impl=1)
        register(CapabilityContract(id="big",   version="1",
                                        category=CAT_EXECUTOR, requires=("text",),
                                        cost=1, priority_hint=0,
                                        improves=(IMPROVES_DECODE,),
                                        confidence_gain=0.8), impl=2)
        art = make_artifact(b"hello", "text", discovered_by="t")
        ids = [c.id for c, _ in plan_for(art)]
        assert ids == ["big", "small"]   # bigger gain first
    finally:
        _restore(snap)


# ══════════════════════════════════════════════════════════════════
# 5 · id ASC is the final tie-break — plan is bit-deterministic
# ══════════════════════════════════════════════════════════════════
def test_id_asc_is_final_deterministic_tie_break():
    snap = _snap()
    try:
        C.clear()
        for name in ["z", "b", "q", "a", "m"]:
            register(CapabilityContract(id=name, version="1",
                                            category=CAT_EXECUTOR,
                                            requires=("text",),
                                            cost=1, priority_hint=0,
                                            improves=(IMPROVES_DECODE,),
                                            confidence_gain=0.5),
                        impl=name)
        art = make_artifact(b"hello", "text", discovered_by="t")
        ids = [c.id for c, _ in plan_for(art)]
        assert ids == sorted(ids)
    finally:
        _restore(snap)


# ══════════════════════════════════════════════════════════════════
# 6 · Empty plan for unsupported artifact type (no false starts)
# ══════════════════════════════════════════════════════════════════
def test_empty_plan_for_unsupported_type():
    snap = _snap()
    try:
        C.clear()
        register(CapabilityContract(id="a.exec", version="1",
                                        category=CAT_EXECUTOR,
                                        requires=("text",),
                                        cost=1), impl=1)
        art = make_artifact(b"", "totally_unknown_type", discovered_by="t")
        plan = plan_for(art)
        assert plan == []
    finally:
        _restore(snap)


# ══════════════════════════════════════════════════════════════════
# 7 · Universal wildcard "*" matches ANY artifact type
# ══════════════════════════════════════════════════════════════════
def test_universal_wildcard_matches_all_types():
    snap = _snap()
    try:
        C.clear()
        register(CapabilityContract(id="u.exec", version="1",
                                        category=CAT_EXECUTOR,
                                        requires=("*",),
                                        cost=1), impl=1)
        for artifact_type in ("text", "gzip_bytes", "arbitrary_new_type"):
            art = make_artifact(b"x", artifact_type, discovered_by="t")
            assert [c.id for c, _ in plan_for(art)] == ["u.exec"]
    finally:
        _restore(snap)


# ══════════════════════════════════════════════════════════════════
# 8 · produces_confidence · gain_for + total_expected_gain
# ══════════════════════════════════════════════════════════════════
def test_produces_confidence_per_dimension_lookup():
    c = CapabilityContract(
        id="multi", version="1", category=CAT_ANALYZER,
        requires=("text",),
        improves=("analysis", "mitre", "ioc"),
        produces_confidence=(("analysis", 0.20),
                                ("mitre", 0.15),
                                ("ioc", 0.10)),
    )
    assert c.gain_for("analysis")    == 0.20
    assert c.gain_for("mitre")        == 0.15
    assert c.gain_for("ioc")          == 0.10
    assert c.gain_for("nonexistent") == 0.0
    assert abs(c.total_expected_gain() - 0.45) < 1e-9


def test_gain_for_falls_back_to_confidence_gain_when_no_per_dim_map():
    c = CapabilityContract(
        id="simple", version="1", category=CAT_EXECUTOR,
        requires=("text",),
        improves=(IMPROVES_DECODE,),
        confidence_gain=0.30,
    )
    assert c.gain_for(IMPROVES_DECODE) == 0.30
    assert c.gain_for(IMPROVES_MITRE)   == 0.0
    assert c.total_expected_gain() == 0.30


# ══════════════════════════════════════════════════════════════════
# 9 · Plan-stats helper for the audit layer
# ══════════════════════════════════════════════════════════════════
def test_plan_stats_shape_and_totals():
    snap = _snap()
    try:
        C.clear()
        register(CapabilityContract(id="a", version="1",
                                        category=CAT_RECOGNIZER,
                                        requires=("*",)), impl=1)
        register(CapabilityContract(id="b", version="1",
                                        category=CAT_EXECUTOR,
                                        requires=("text",),
                                        improves=(IMPROVES_DECODE,),
                                        confidence_gain=0.20), impl=2)
        register(CapabilityContract(id="c", version="1",
                                        category=CAT_ANALYZER,
                                        requires=("text",),
                                        produces_confidence=(("analysis", 0.30),
                                                                ("ioc", 0.15))),
                    impl=3)
        art = make_artifact(b"hello", "text", discovered_by="t")
        stats = plan_stats(art)
        assert stats["applicable_count"] == 3
        assert stats["by_category"] == {
            CAT_RECOGNIZER: 1, CAT_EXECUTOR: 1, CAT_ANALYZER: 1,
        }
        # 0.0 (a) + 0.20 (b) + 0.30 + 0.15 (c) = 0.65
        assert abs(stats["total_expected_gain"] - 0.65) < 1e-9
    finally:
        _restore(snap)


# ══════════════════════════════════════════════════════════════════
# 10 · Planner NEVER inspects the impl — it only passes it through
# ══════════════════════════════════════════════════════════════════
def test_planner_treats_impl_as_opaque():
    snap = _snap()
    try:
        C.clear()

        class _Weird:
            """An impl the planner MUST NOT interrogate.  It has no
            recognisable protocol members, and attempting to use it
            would raise."""
            def __getattribute__(self, name):
                if name in ("__class__", "__dict__"):
                    return object.__getattribute__(self, name)
                raise RuntimeError(
                    f"planner touched impl attribute {name!r} — "
                    "architectural rule violated")

        register(CapabilityContract(id="opaque", version="1",
                                        category=CAT_EXECUTOR,
                                        requires=("text",)),
                    impl=_Weird())
        art = make_artifact(b"x", "text", discovered_by="t")
        plan = plan_for(art)
        # If the planner touched the impl, _Weird would have raised.
        assert len(plan) == 1
        assert plan[0][0].id == "opaque"
    finally:
        _restore(snap)
