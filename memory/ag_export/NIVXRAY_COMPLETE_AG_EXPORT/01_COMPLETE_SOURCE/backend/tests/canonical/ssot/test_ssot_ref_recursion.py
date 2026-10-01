"""T2.5 · ssot_ref roundtrip + recursive artefact references (D6-r)."""
import pytest
from canonical.ssot import (
    AuthoritativeSSOT, Provenance, InMemorySSOTStore, GraphNode, Artifact,
    make_ssot_ref, validate_ref,
)


PROV = Provenance(engine="test", version="1.0.0", at="phase2")


def test_make_ssot_ref_valid_hash_produces_valid_ref():
    fp = "a" * 64
    ref = make_ssot_ref(fp)
    assert validate_ref(ref)
    assert ref == f"cssot:sha256:{fp}"


def test_make_ssot_ref_rejects_bad_hash():
    with pytest.raises(ValueError):
        make_ssot_ref("not a hash")
    with pytest.raises(ValueError):
        make_ssot_ref("abc123")


def test_validate_ref_rejects_bad_prefix():
    assert not validate_ref("ssot:sha256:" + "a" * 64)
    assert not validate_ref("cssot:md5:" + "a" * 32)
    assert not validate_ref("")


def test_store_put_get_roundtrip_byte_identical():
    store = InMemorySSOTStore()
    s = AuthoritativeSSOT(id="fixed", created_at="t", updated_at="t")
    s.append("evidence_graph.nodes",
             GraphNode(id="n1", kind="input", label="root"), PROV)
    s.freeze()

    ref = store.put(s)
    reloaded = store.get(ref)
    assert reloaded is not None
    assert reloaded.fingerprint() == s.fingerprint()
    assert reloaded.to_canonical_json() == s.to_canonical_json()


def test_store_put_is_idempotent_by_fingerprint():
    """Same content stored twice yields the same ref and does not
    create a second copy (immutable-store invariant)."""
    store = InMemorySSOTStore()
    s = AuthoritativeSSOT(id="fixed", created_at="t", updated_at="t")
    s.append("evidence_graph.nodes",
             GraphNode(id="n", kind="input", label="x"), PROV)

    ref1 = store.put(s)
    ref2 = store.put(s)
    assert ref1 == ref2
    assert store.count() == 1


def test_recursive_artefact_references_child_ssot():
    """D6-r · child SSOT stored by ref; parent's artifact carries the ref."""
    store = InMemorySSOTStore()

    # Build a child SSOT (e.g. decoded PowerShell inside a base64 blob).
    child = AuthoritativeSSOT(id="child", created_at="t", updated_at="t")
    child.append("evidence_graph.nodes",
                 GraphNode(id="cn1", kind="decoded",
                           label="decoded powershell"), PROV)
    child.freeze()
    child_ref = store.put(child)

    # Parent SSOT carries an artifact whose investigation_ref points at
    # the child.
    parent = AuthoritativeSSOT(id="parent", created_at="t", updated_at="t")
    parent.append("artifacts",
                  Artifact(id="a1", kind="base64_blob",
                           label="embedded powershell",
                           investigation_ref=child_ref),
                  PROV)
    parent.freeze()
    parent_ref = store.put(parent)

    # Dereference: parent → artifact.investigation_ref → child
    reloaded_parent = store.get(parent_ref)
    assert reloaded_parent is not None
    assert len(reloaded_parent.artifacts) == 1
    ref_in_artifact = reloaded_parent.artifacts[0].investigation_ref
    assert validate_ref(ref_in_artifact)
    assert ref_in_artifact == child_ref

    reloaded_child = store.get(ref_in_artifact)
    assert reloaded_child is not None
    assert reloaded_child.fingerprint() == child.fingerprint()


def test_deep_recursion_two_levels_deep():
    """SSOT A -> artefact -> SSOT B -> artefact -> SSOT C. All addressable."""
    store = InMemorySSOTStore()

    c = AuthoritativeSSOT(id="c", created_at="t", updated_at="t")
    c.append("evidence_graph.nodes",
             GraphNode(id="cn", kind="terminal", label="terminal fragment"), PROV)
    c_ref = store.put(c)

    b = AuthoritativeSSOT(id="b", created_at="t", updated_at="t")
    b.append("artifacts",
             Artifact(id="ba", kind="decoded", label="middle layer",
                      investigation_ref=c_ref), PROV)
    b_ref = store.put(b)

    a = AuthoritativeSSOT(id="a", created_at="t", updated_at="t")
    a.append("artifacts",
             Artifact(id="aa", kind="base64_blob", label="top layer",
                      investigation_ref=b_ref), PROV)
    a_ref = store.put(a)

    # Traverse the chain.
    ra = store.get(a_ref)
    rb = store.get(ra.artifacts[0].investigation_ref)
    rc = store.get(rb.artifacts[0].investigation_ref)
    assert rc.fingerprint() == c.fingerprint()


def test_store_get_returns_none_for_unknown_ref():
    store = InMemorySSOTStore()
    unknown_ref = f"cssot:sha256:{'f'*64}"
    assert store.get(unknown_ref) is None
    assert not store.exists(unknown_ref)
