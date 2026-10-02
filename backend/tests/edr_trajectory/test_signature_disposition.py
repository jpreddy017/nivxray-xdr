from edr_trajectory.disposition import signature_assessment


def test_signature_hit_is_malicious_with_provenance():
    a = signature_assessment({"kind": "SIGNATURE", "name": "EICAR-Test-Signature", "engine": "nivxforge-av", "at": "2026-10-02T08:35:04Z", "observation_id": "o"})
    assert a["state"] == "MALICIOUS" and a["evidence"][0]["basis"] == "nivxforge-av signature EICAR-Test-Signature, 2026-10-02T08:35:04Z"
    assert signature_assessment({"kind": "HASH_REPUTATION", "name": "known-bad", "engine": "rep", "at": "t"})["state"] == "MALICIOUS"


def test_match_ml_ioc_mitre_never_malicious():
    for k in ("BEHAVIORAL_MATCH", "ML_TESTING", "IOC_CORRELATION", "MITRE_MAPPING", None):
        assert signature_assessment({"kind": k, "name": "x", "engine": "e", "at": "t"}) is None
    assert signature_assessment({"kind": "SIGNATURE", "name": "x"}) is None  # no time -> no provenance -> no verdict
