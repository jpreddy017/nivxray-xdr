"""T2.4 · Deterministic canonical JSON + sha256 fingerprint."""
from canonical.ssot import AuthoritativeSSOT, Provenance, GraphNode, Source


PROV = Provenance(engine="test", version="1.0.0", at="phase2")


def _build(n_nodes: int = 3, src: str = "workspace") -> AuthoritativeSSOT:
    s = AuthoritativeSSOT(
        id="fixed-id-0001",
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
        source=Source(surface=src, endpoint="/test",
                      correlation_id="c1", channel="test"),
    )
    for i in range(n_nodes):
        s.append("evidence_graph.nodes",
                 GraphNode(id=f"n{i}", kind="input", label=f"lbl{i}",
                           attrs={"idx": i}),
                 PROV)
    return s


def test_canonical_json_stable_across_replays():
    j0 = _build().to_canonical_json()
    for _ in range(50):
        assert _build().to_canonical_json() == j0


def test_fingerprint_deterministic_same_content_same_hash():
    fp0 = _build().fingerprint()
    for _ in range(50):
        assert _build().fingerprint() == fp0
    # 64-hex sha256
    assert len(fp0) == 64
    assert all(c in "0123456789abcdef" for c in fp0)


def test_different_content_different_fingerprint():
    a = _build(n_nodes=3).fingerprint()
    b = _build(n_nodes=4).fingerprint()
    c = _build(n_nodes=3, src="api").fingerprint()
    assert a != b
    assert a != c
    assert b != c


def test_key_order_does_not_affect_fingerprint():
    """Attrs assigned in different insert orders must still fingerprint
    identically because canonical JSON is sort_keys."""
    s1 = AuthoritativeSSOT(id="fixed", created_at="t", updated_at="t")
    s1.append("evidence_graph.nodes",
              GraphNode(id="n", kind="input", label="x",
                        attrs={"b": 1, "a": 2}),
              PROV)
    s2 = AuthoritativeSSOT(id="fixed", created_at="t", updated_at="t")
    s2.append("evidence_graph.nodes",
              GraphNode(id="n", kind="input", label="x",
                        attrs={"a": 2, "b": 1}),
              PROV)
    assert s1.fingerprint() == s2.fingerprint()


def test_to_ssot_ref_matches_fingerprint():
    s = _build()
    ref = s.to_ssot_ref()
    assert ref.startswith("cssot:sha256:")
    assert ref.endswith(s.fingerprint())
