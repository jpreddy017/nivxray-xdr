"""Plugin · Cobalt Strike Beacon Config Parser (Cap Pack 1 · #3) · WRAPPER.

Wraps the existing 240-line ``decoders.cobaltstrike_beacon_config
.CobaltStrikeBeaconConfigExtractor`` into a UAIE Capability that
consumes ``cs_config_raw`` (emitted by ``shellcode.analyzer`` when
it finds the CS XOR magic) OR any ``shellcode_bytes`` / raw byte
payload — the underlying extractor already handles both.

Structured fields extracted (deterministic, no LLM):
    · beacon_type (HTTP / HTTPS / TCP / SMB / DNS / …)
    · port · sleep_time · jitter · maxdns
    · c2_server (parsed into c2_hosts + c2_uris)
    · user_agent · http_post_uri · watermark
    · spawnto_x86 · spawnto_x64 · process_inject_start

R26 compliance
──────────────
Pure wrapper.  No reimplementation.  No queue access.  No LLM.
"""
from __future__ import annotations

from time    import perf_counter
from typing  import List

from ...artifact   import Artifact
from ...recognizer import Recognition, Reason, HIGH, CERTAIN
from ...capability import CapabilityResult, register
from ...evidence   import make_evidence
from .. import register_plugin

# The existing production extractor — DO NOT REIMPLEMENT.
from decoders.cobaltstrike_beacon_config import (
    CobaltStrikeBeaconConfigExtractor as _CS,
    _MAGIC_SIGS as _CS_SIGS,
)
try:
    from engine.models import AnalysisContext, Fingerprint
    _HAS_ENGINE_MODELS = True
except Exception:
    _HAS_ENGINE_MODELS = False


NAME    = "family.cobalt_strike.beacon_config"
VERSION = "1.0.0"


def _bytes_from_artifact(artifact: Artifact) -> bytes:
    from services.die.preprocessor.recursive_decoder import _extract_rawbytes
    text = artifact.payload.decode("utf-8", errors="replace")
    hit = _extract_rawbytes(text)
    return hit[0] if hit else artifact.payload


class _Recognizer:
    name = NAME

    def recognize(self, artifact: Artifact) -> List[Recognition]:
        raw = _bytes_from_artifact(artifact)
        if not raw or len(raw) < 32:
            return []
        # Look for CS v3 (0x69) or v4 (0x2E) XOR magic, or plaintext magic
        # (in case a prior decoder already unwrapped the config).
        for key, sig in _CS_SIGS.items():
            if sig in raw:
                return [Recognition(
                    artifact_type="cs_config_raw",
                    confidence=CERTAIN,
                    reasons=[Reason("cs_beacon_magic", 0.90,
                                    f"CS-XOR-0x{key:02X} magic present")],
                    recognizer=NAME,
                )]
        if b"\x00\x01\x00\x01\x00\x02\x00" in raw:
            return [Recognition(
                artifact_type="cs_config_raw",
                confidence=HIGH,
                reasons=[Reason("cs_plaintext_magic", 0.80,
                                "plaintext CS TLV magic present")],
                recognizer=NAME,
            )]
        return []


class _Capability:
    name = NAME
    requires_artifact_type = ["cs_config_raw", "shellcode_bytes",
                               "pe_bytes", "gzip_decoded"]
    requires_evidence      = []

    def __init__(self):
        # Fresh extractor per plugin — the extractor itself is stateless.
        self._extractor = _CS()

    def execute(self, artifact: Artifact) -> CapabilityResult:
        t0 = perf_counter()
        raw = _bytes_from_artifact(artifact)
        payload_str = raw.decode("latin-1", errors="ignore")

        # Detect first — extractor emits the xor_key to use.
        ctx = None
        fp  = None
        if _HAS_ENGINE_MODELS:
            try:
                ctx = AnalysisContext()
                fp  = Fingerprint()
            except Exception:
                ctx, fp = None, None

        try:
            detect = self._extractor.detect(payload_str, fp, ctx)
        except Exception:
            return CapabilityResult(elapsed_ms=(perf_counter() - t0) * 1000.0)
        if not detect or float(getattr(detect, "confidence", 0) or 0) < 0.5:
            return CapabilityResult(elapsed_ms=(perf_counter() - t0) * 1000.0)

        try:
            result = self._extractor.decode(
                payload_str, dict(getattr(detect, "args", {}) or {}), ctx,
            )
        except Exception:
            return CapabilityResult(elapsed_ms=(perf_counter() - t0) * 1000.0)

        # Parse the extractor's structured output.
        # PluginResult exposes:
        #   .iocs         → {urls, domains, ips, ...}
        #   .family_hints → List[FamilyHint(family, confidence, mitre_techniques)]
        #   .mitre_hints  → List[MitreHint(id, technique, tactic, evidence)]
        #   .tradecraft   → List[TradecraftFlag(flag, severity, metadata)]
        # The structured beacon config lives in tradecraft[0].metadata.
        iocs = dict(getattr(result, "iocs", None) or {})
        family_hints  = list(getattr(result, "family_hints", None) or [])
        mitre_hints   = list(getattr(result, "mitre_hints",  None) or [])
        tradecraft    = list(getattr(result, "tradecraft",   None) or [])
        beacon_meta   = {}
        for tc in tradecraft:
            md = getattr(tc, "metadata", None) or {}
            if md:
                beacon_meta = md
                break

        evidence = []
        # Family evidence — CS beacon config is a "critical" verdict driver.
        fam_technique_ids = []
        for fh in family_hints:
            fam_technique_ids.extend(list(getattr(fh, "mitre_techniques", []) or []))
        fam_technique_ids.extend([str(mh.id) for mh in mitre_hints if getattr(mh, "id", None)])
        fam_technique_ids = list(dict.fromkeys(fam_technique_ids)) or ["T1071.001", "T1105", "T1055"]

        evidence.append(make_evidence(
            artifact_uri=artifact.uri, kind="family",
            value="cobalt_strike_beacon_config",
            source_capability=NAME, confidence=0.95, severity="critical",
            mitre_techniques=fam_technique_ids,
            kill_chain=["command-and-control"],
            reasons=[Reason("cs_beacon_config_extracted", 0.95,
                             getattr(detect, "why", "cs config extracted"))],
            location=f"xor_key={detect.args.get('xor_key', 0) if getattr(detect, 'args', None) else 0}",
            meta={"extractor": "CobaltStrikeBeaconConfigExtractor",
                    "notes": list(getattr(result, "notes", []) or [])},
        ))

        # Emit each parsed beacon config field as structured evidence.
        for key, value in (beacon_meta or {}).items():
            if value is None or value == [] or value == "":
                continue
            evidence.append(make_evidence(
                artifact_uri=artifact.uri,
                kind=f"cs_config.{key}",
                value=value,
                source_capability=NAME, confidence=0.90, severity="high",
                location="cs.beacon.tlv",
            ))

        # IOCs → normalise to canonical singular kinds with MITRE mapping.
        _NORM = {"urls": "url", "ips": "ipv4", "domains": "domain",
                 "user_agents": "user_agent"}
        for raw_kind, values in (iocs or {}).items():
            kind = _NORM.get(raw_kind, raw_kind)
            for v in (values or []):
                mitre = (["T1071.001"] if kind in ("url", "domain")
                          else ["T1105"] if kind == "ipv4"
                          else [])
                evidence.append(make_evidence(
                    artifact_uri=artifact.uri, kind=kind, value=v,
                    source_capability=NAME, confidence=0.90, severity="high",
                    mitre_techniques=mitre,
                    kill_chain=(["command-and-control"] if mitre else []),
                    location="cs.beacon.config",
                ))

        # Emit all MITRE hints from the extractor as first-class evidence.
        for mh in mitre_hints:
            evidence.append(make_evidence(
                artifact_uri=artifact.uri, kind="mitre_hint",
                value=str(getattr(mh, "id", "") or ""),
                source_capability=NAME, confidence=0.90, severity="medium",
                mitre_techniques=[str(getattr(mh, "id", "") or "")] if getattr(mh, "id", None) else [],
                location=str(getattr(mh, "source", "") or ""),
                meta={"evidence": str(getattr(mh, "evidence", "") or "")},
            ))

        return CapabilityResult(
            evidence=evidence,
            notes={
                "cs_config_output":   getattr(result, "output", "")[:2048],
                "cs_config_metadata": beacon_meta,
                "cs_detect_why":      getattr(detect, "why", ""),
            },
            elapsed_ms=(perf_counter() - t0) * 1000.0,
        )


recognizer = _Recognizer()
capability = _Capability()

register(capability)
register_plugin(NAME, VERSION, recognizer, capability,
                wraps_legacy="decoders.cobaltstrike_beacon_config.CobaltStrikeBeaconConfigExtractor")
