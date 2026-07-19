"""RC2.1a — Malware Family Intelligence plugin regression suite.

Every family plugin has:
    1. A positive vector that triggers confidence >= 0.60
    2. A negative vector (english text) that must NOT fire
    3. Correct MITRE technique attachment
    4. YARA rule stub generation
    5. Atomic-Red-Team hint (when set)

Plus end-to-end orchestrator tests confirming the intelligence pass fires
correctly and the aggregator lifts the winning family into `findings.family`.
"""
from __future__ import annotations

import pytest

from engine.orchestrator import Orchestrator
from engine.registry import DecoderRegistry
from engine.models import AnalysisContext, Budget
from engine.fingerprint_util import compute as fingerprint_compute


# ---------------------------------------------------------------------------
# Positive vectors — hand-crafted samples derived from open-source signatures.
# NONE are runnable payloads; they are enough text to trigger our sig scan.
# ---------------------------------------------------------------------------
POSITIVES = {
    "family-meterpreter": (
        b"\xfc\xe8\x89\x00\x00\x00" +  # x86 stager prologue
        b"\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30" +
        b"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28" +
        b"metsrv.dll\x00stdapi\x00reverse_tcp\x00ws2_32\x00"
    ).decode("latin-1"),

    "family-asyncrat": (
        "AsyncClient.Settings V=1.0 AsyncMutex_ABCDEF12 "
        "<AsyncRAT.Config Ports_Settings='6606' Base_Settings='ok' "
        "InstallStartup=true SendPassword=true Aes256='yes'"
    ),

    "family-lumma": (
        "GET /api/steal HTTP/1.1\nHost: lumma-shop.top\n"
        "User-Agent: TeslaBrowser/5.5\n"
        "build_id=xJ7hd0\n"
        '{"crypto":[{"name":"MetaMask"}],"browsers":[{"name":"Chrome"}],'
        '"wallets":[{"name":"Exodus"}]}'
    ),

    "family-darkgate": (
        "AutoIt3ExecuteLine %STAT% %B64% Piece_1|Piece_2|Piece_3 "
        "DGSNM NIM53 cQHNb /cdn/index.php"
    ),

    "family-remcos": (
        "Remcos-RAT v3.4.2 BreakingSecurity "
        "Remcos_MUTEX_ABCD1234 \x1c\x00\x02SETTINGS OFFLINEKEYLOG "
        "KEYL_STATE|CAMS|SCRN| /panel/login.php?url= Screenshot=1"
    ),

    "family-agenttesla": (
        "AgentTesla v3 OriginLogger "
        "SMTPServer=smtp.gmail.com SMTPPort=587 SMTPUsername=x@y.z "
        "Screen Resolution: 1920x1080\nTime: 12:00\n"
        "IsKeylogEnabled=true IsScreenshotEnabled=true "
        "pw_string_chrome=abc /Panel/login.php"
    ),

    "family-quasarrat": (
        "Quasar.Common Quasar.Client SETTINGS \x01\x02\x03HOSTS "
        "BSF3lLtvGT3+dSagRhTG CN=Quasar Server CA "
        "SubDirectory=SubDir InstallName=client.exe "
        "GetProcesses GetSystemInfo DoDownloadFile"
    ),

    "family-cobaltstrike": (
        b"\xfc\xe8\x8f\x00\x00\x00" +   # beacon shellcode prologue
        b"beacon.dll\x00i_am_key_statement\x00Malleable-C2 " +
        b"/updates.rss /submit.php?id=X __cfduid=Y\x00" +
        b"\x00\x01\x00\x01\x00\x02\xbe\xef\xbe\xef"
    ).decode("latin-1"),

    "family-snake-keylogger": (
        "Snake Keylogger v3.6 Snake.Client "
        "Snake Passwords\nSnake Keystrokes\n"
        "SMTPServer=smtp.mail.com SMTPPass=pw123 "
        "PW-Chrome KEYLOG-Notepad IsScreenshot=true "
        "/Snake/Panel/login.php "
        "https://api.telegram.org/bot123456:AAABBBCCCDDDEEEFFFGGGHHHIII/sendMessage"
    ),
}

NEGATIVE = (
    "The quick brown fox jumps over the lazy dog. "
    "This is an unremarkable README file with nothing malicious in it. "
    "Copyright (c) 2026 Widgets Inc. All rights reserved."
)


@pytest.fixture(scope="module", autouse=True)
def _ensure_registry():
    """Ensure family plugins are discovered once for the module.
    We do NOT reset between tests: family plugin modules only call
    ``DecoderRegistry.register()`` at import time, so wiping the registry
    mid-run would leave subsequent tests with an empty registry (Python
    caches the loaded modules and won't re-execute the module bodies).
    """
    # Warm the registry once
    _ = DecoderRegistry.all()
    yield


class TestFamilyPluginRegistration:
    def test_nine_family_plugins_registered(self):
        # Filter to family-* plugins specifically (other intelligence plugins
        # like ioc-extractor share the "intelligence" category by design).
        ids = {p.id for p in DecoderRegistry.all()
               if getattr(p, "category", None) == "intelligence"
               and p.id.startswith("family-")}
        assert ids == {
            "family-meterpreter", "family-asyncrat", "family-lumma",
            "family-darkgate", "family-remcos", "family-agenttesla",
            "family-quasarrat", "family-cobaltstrike", "family-snake-keylogger",
        }

    def test_total_plugin_count(self):
        # Baseline: 12 base decoders + 9 family plugins = 21.
        # RC2.2 additions: utf16, ps-reconstruct, data-uri, ioc-extractor,
        # base58, jwt, reverse-string = +7 → 28.
        assert len(DecoderRegistry.all()) >= 21


class TestFamilyPluginPositiveDetection:
    @pytest.mark.parametrize("plugin_id,payload", list(POSITIVES.items()))
    def test_positive_vector_fires(self, plugin_id, payload):
        plugin = DecoderRegistry.get(plugin_id)
        ctx = AnalysisContext(budget=Budget())
        fp = fingerprint_compute(payload)
        det = plugin.detect(payload, fp, ctx)
        assert det.confidence >= 0.10, (
            f"{plugin_id} did not detect positive vector: {det.why}"
        )
        res = plugin.decode(payload, det.args, ctx)
        assert res.family_hints, f"{plugin_id} produced no family_hints"
        hint = res.family_hints[0]
        assert hint.confidence >= 0.60, (
            f"{plugin_id} confidence too low: {hint.confidence:.2f}"
        )
        assert hint.evidence_items, f"{plugin_id} produced no evidence items"
        assert hint.mitre_techniques, f"{plugin_id} produced no MITRE hints"
        assert hint.yara_suggestion, f"{plugin_id} produced no YARA suggestion"


class TestFamilyPluginNegatives:
    @pytest.mark.parametrize("plugin_id", list(POSITIVES.keys()))
    def test_english_prose_does_not_fire(self, plugin_id):
        plugin = DecoderRegistry.get(plugin_id)
        ctx = AnalysisContext(budget=Budget())
        fp = fingerprint_compute(NEGATIVE)
        det = plugin.detect(NEGATIVE, fp, ctx)
        assert det.confidence == 0.0, (
            f"{plugin_id} false-positive on english text (conf={det.confidence:.2f})"
        )


class TestFamilyPluginContent:
    def test_meterpreter_mitre_includes_t1055_012(self):
        plugin = DecoderRegistry.get("family-meterpreter")
        ids = {m.id for m in plugin.mitre}
        assert "T1055.012" in ids
        assert "T1027" in ids
        assert "T1059.001" in ids

    def test_cobaltstrike_mitre_includes_t1071(self):
        plugin = DecoderRegistry.get("family-cobaltstrike")
        ids = {m.id for m in plugin.mitre}
        assert "T1071.001" in ids
        assert "T1055" in ids

    def test_lumma_mitre_includes_credential_theft(self):
        plugin = DecoderRegistry.get("family-lumma")
        ids = {m.id for m in plugin.mitre}
        assert "T1555.003" in ids  # browser-cred theft
        assert "T1041" in ids       # exfil over C2

    def test_agenttesla_smtp_exfil_mapped(self):
        plugin = DecoderRegistry.get("family-agenttesla")
        ids = {m.id for m in plugin.mitre}
        assert "T1048.003" in ids   # unencrypted-protocol exfil
        assert "T1056.001" in ids   # keylogging

    def test_yara_seed_name_conventions(self):
        cs = DecoderRegistry.get("family-cobaltstrike")
        meterp = DecoderRegistry.get("family-meterpreter")
        assert cs.yara_seed_name.startswith("APT_")
        assert meterp.yara_seed_name.startswith("APT_")
        for pid in ("family-asyncrat", "family-remcos", "family-lumma",
                    "family-agenttesla", "family-quasarrat",
                    "family-darkgate", "family-snake-keylogger"):
            p = DecoderRegistry.get(pid)
            assert p.yara_seed_name.startswith("MAL_"), (
                f"{pid} should use MAL_ prefix for commodity family"
            )

    def test_all_families_have_atomic_red_hints(self):
        for pid in POSITIVES:
            p = DecoderRegistry.get(pid)
            assert p.atomic_red, f"{pid} missing atomic_red hint"


class TestOrchestratorIntelligencePass:
    """Family plugins must fire via the post-decode intelligence pass."""

    @pytest.mark.parametrize("plugin_id,payload", list(POSITIVES.items()))
    def test_orchestrator_lifts_family_into_findings(self, plugin_id, payload):
        report = Orchestrator().run(payload)
        assert report.findings.family.family != "unknown", (
            f"{plugin_id}: family aggregator returned 'unknown'"
        )
        assert report.findings.family.confidence >= 0.60, (
            f"{plugin_id}: aggregated confidence too low "
            f"({report.findings.family.confidence:.2f})"
        )
        # YARA + evidence_items + MITRE propagated from FamilyHint into
        # FamilyMatch by the RC2.1a aggregator patch
        assert report.findings.family.yara_suggestion is not None
        assert report.findings.family.evidence_items
        assert report.findings.family.mitre_techniques

    def test_negative_no_family(self):
        r = Orchestrator().run(NEGATIVE)
        assert r.findings.family.family == "unknown"

    def test_intelligence_pass_appends_step(self):
        # AsyncRAT positive → intelligence pass should append the confirming step
        r = Orchestrator().run(POSITIVES["family-asyncrat"])
        ids = [s.decoder for s in r.trace]
        assert "family-asyncrat" in ids


class TestFamilyPluginContract:
    """Contract tests — every family plugin must satisfy the plugin API."""

    @pytest.mark.parametrize("plugin_id", list(POSITIVES.keys()))
    def test_plugin_has_required_attributes(self, plugin_id):
        p = DecoderRegistry.get(plugin_id)
        assert p.family_name and p.family_name != "unknown"
        assert p.category == "intelligence"
        assert p.signatures                    # non-empty
        assert p.calibration > 0
        assert p.mitre                         # at least one MITRE hint
        assert p.yara_seed_name
