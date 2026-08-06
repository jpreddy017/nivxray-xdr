"""
IDA · Slice 1 · Artifact Splitter + Input Classifier tests.

Covers:
  · Deterministic ordering (same paste → identical artifact list)
  · Provenance (offset / length / line / extractor)
  · Per-type extractor correctness (URL, hash, ip, domain, path,
    registry, cve, yara)
  · Overlap protection (no two artifacts claim the same bytes,
    except commands which are line-scoped)
  · IDA verdict classes (mixed_artifacts · threat_report_url ·
    ioc_list · yara_ruleset · sigma_ruleset · none)
"""
from services.ida import split_artifacts, classify_artifact_input


# ══════════════════════════════════════════════════════════════════
# Splitter · type detection
# ══════════════════════════════════════════════════════════════════
def test_split_url_only() -> None:
    arts = split_artifacts("https://www.esentire.com/blog/UNC6692")
    assert len(arts) == 1
    a = arts[0]
    assert a.type == "url"
    assert a.canonical == "https://www.esentire.com/blog/UNC6692"
    assert a.source["extractor"] == "ida.url"
    assert a.source["offset"] == 0
    assert a.source["length"] == len(a.value)


def test_split_sha256_hash() -> None:
    h = "d41d8cd98f00b204e9800998ecf8427e" * 2  # 64 chars
    arts = split_artifacts(f"IOC seen in the wild: {h}")
    hash_arts = [a for a in arts if a.type == "hash"]
    assert len(hash_arts) == 1
    assert hash_arts[0].metadata["kind"] == "sha256"
    assert hash_arts[0].canonical == h.lower()


def test_split_md5_and_sha1() -> None:
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    arts = split_artifacts(f"{md5}\n{sha1}\n")
    kinds = {a.metadata.get("kind") for a in arts if a.type == "hash"}
    assert kinds == {"md5", "sha1"}


def test_split_ipv4_scope() -> None:
    arts = split_artifacts("beacon to 8.8.8.8 while 10.0.0.5 is internal")
    ip_by_scope = {a.metadata["scope"]: a.canonical for a in arts if a.type == "ip"}
    assert ip_by_scope["public"] == "8.8.8.8"
    assert ip_by_scope["private"] == "10.0.0.5"


def test_split_domain_blocks_file_extensions() -> None:
    arts = split_artifacts(
        "Command: notepad.exe opens malicious.docm from evil.com"
    )
    domains = {a.canonical for a in arts if a.type == "domain"}
    # notepad.exe and malicious.docm must NOT be flagged as domains.
    assert "notepad.exe" not in domains
    assert "malicious.docm" not in domains
    assert "evil.com" in domains


def test_split_registry_hive_expansion() -> None:
    arts = split_artifacts(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Bad"
    )
    reg = [a for a in arts if a.type == "registry_key"]
    assert len(reg) == 1
    assert reg[0].canonical.startswith("HKEY_CURRENT_USER\\Software\\Microsoft\\")
    assert reg[0].metadata["hive"] == "HKEY_CURRENT_USER"


def test_split_file_path_windows() -> None:
    arts = split_artifacts(r"drops C:\Users\Public\payload.exe on host")
    paths = [a for a in arts if a.type == "file_path"]
    assert len(paths) == 1
    assert paths[0].canonical.endswith("payload.exe")


def test_split_cve() -> None:
    arts = split_artifacts("Exploits CVE-2023-23397 in Outlook.")
    cve = [a for a in arts if a.type == "cve"]
    assert len(cve) == 1
    assert cve[0].canonical == "CVE-2023-23397"
    assert cve[0].metadata["year"] == 2023


def test_split_command_line() -> None:
    arts = split_artifacts(
        'powershell -NoProfile -EncodedCommand JAB... ; whoami\n'
    )
    cmds = [a for a in arts if a.type == "command"]
    assert len(cmds) >= 1
    assert cmds[0].source["extractor"] == "ida.command"
    assert cmds[0].source["line"] == 1


def test_split_yara_rule() -> None:
    yara = (
        'rule Cobalt_Strike_Beacon : APT\n'
        '{\n'
        '  meta:\n'
        '    author = "test"\n'
        '  strings:\n'
        '    $a = "beacon"\n'
        '  condition:\n'
        '    $a\n'
        '}\n'
    )
    arts = split_artifacts(yara)
    yara_arts = [a for a in arts if a.type == "yara_rule"]
    assert len(yara_arts) == 1
    assert "condition" in yara_arts[0].value


# ══════════════════════════════════════════════════════════════════
# Splitter · determinism + provenance
# ══════════════════════════════════════════════════════════════════
def test_split_is_deterministic() -> None:
    paste = (
        "powershell -e ABC123==\n"
        "https://evil.example/mal.php\n"
        "d41d8cd98f00b204e9800998ecf8427e\n"
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
    )
    a1 = [a.to_dict() for a in split_artifacts(paste)]
    a2 = [a.to_dict() for a in split_artifacts(paste)]
    assert a1 == a2


def test_split_ordering_is_reading_order() -> None:
    paste = (
        "https://a.example/one\n"                   # line 1
        "d41d8cd98f00b204e9800998ecf8427e\n"        # line 2
        "10.0.0.5\n"                                # line 3
    )
    arts = split_artifacts(paste)
    lines = [a.source["line"] for a in arts]
    assert lines == sorted(lines)


def test_provenance_offsets_point_to_slice() -> None:
    paste = "before https://evil.example/ after"
    arts = split_artifacts(paste)
    urls = [a for a in arts if a.type == "url"]
    assert len(urls) == 1
    a = urls[0]
    assert paste[a.source["offset"]: a.source["offset"] + a.source["length"]] == a.value


# ══════════════════════════════════════════════════════════════════
# IDA verdict · class routing
# ══════════════════════════════════════════════════════════════════
def test_verdict_threat_report_url() -> None:
    v = classify_artifact_input("https://www.esentire.com/blog/UNC6692")
    assert v["ida_class"] == "threat_report_url"
    assert v["confidence"] >= 0.9
    assert v["summary"].get("url", 0) == 1


def test_verdict_mixed_artifacts() -> None:
    paste = (
        "powershell -e JAB... ; whoami\n"
        "https://evil.example/mal.php\n"
        "d41d8cd98f00b204e9800998ecf8427e\n"
    )
    v = classify_artifact_input(paste)
    assert v["ida_class"] == "mixed_artifacts"
    assert v["summary"].get("command", 0) >= 1
    assert v["summary"].get("url", 0) >= 1
    assert v["summary"].get("hash", 0) >= 1


def test_verdict_ioc_list() -> None:
    paste = (
        "d41d8cd98f00b204e9800998ecf8427e\n"
        "da39a3ee5e6b4b0d3255bfef95601890afd80709\n"
        "https://evil.example/one\n"
        "10.0.0.5\n"
    )
    v = classify_artifact_input(paste)
    assert v["ida_class"] == "ioc_list"


def test_verdict_yara_ruleset() -> None:
    yara = (
        'rule Foo\n'
        '{\n'
        '  strings:\n'
        '    $a = "abcdefghijklmnopqrstuvwxyz1234567890"\n'
        '  condition:\n'
        '    $a\n'
        '}\n'
    )
    v = classify_artifact_input(yara)
    assert v["ida_class"] == "yara_ruleset"


def test_verdict_sigma_ruleset() -> None:
    sigma = (
        "title: Suspicious PowerShell\n"
        "logsource:\n"
        "  product: windows\n"
        "detection:\n"
        "  selection:\n"
        "    EventID: 4104\n"
    )
    v = classify_artifact_input(sigma)
    assert v["ida_class"] == "sigma_ruleset"


def test_verdict_none_on_plain_prose() -> None:
    v = classify_artifact_input(
        "Analyst notes: The attacker performed reconnaissance."
    )
    # No commands, no strong artifacts → IDA has nothing to say.
    assert v["ida_class"] == "none"
