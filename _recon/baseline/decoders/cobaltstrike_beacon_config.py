"""Cobalt Strike Beacon config extractor (RC3.5 · Feb-2026).

Cobalt Strike beacons ship with an embedded, XOR-encrypted config block
containing analyst-critical IOCs (C2 URLs, ports, sleep/jitter, watermark,
spawnto, PE injection targets, etc.). Historically NivXRay only had a
rule-based CS family detector — this plugin promotes CS handling from
"we spotted a beacon" to "we extracted the C2 URL, watermark and dwell
time so IR can start hunting immediately".

Deterministic extraction algorithm:
    1. Locate a candidate config block via CS's XOR-encrypted TLV magic.
       CS-v3 XORs the config with 0x69, CS-v4 with 0x2E. The first two
       TLV entries in the plaintext config are always the tags 0x0001
       ("beacon-type") and 0x0002 ("port"), yielding the encrypted magic
       ``00 01 00 01 00 02 00 XX`` → after XOR = ``69 68 69 68 69 6B ...``
       (v3) or ``2E 2F 2E 2F 2E 2D ...`` (v4).
    2. Extract ~4096 bytes forward from the magic and XOR-decrypt.
    3. Parse the TLV stream and emit each field as a structured IOC /
       tradecraft flag.

References:
    * Sentinel-One "Cobalt Strike Beacon Config Extractor"
    * Fox-IT / NCC-Group `dissect.cobaltstrike` corpus
    * Malpedia cobalt_strike entry + Sekoia watermark table
"""
from __future__ import annotations

import re
import struct
from typing import Any, Dict, List, Optional

from engine.decoder_base import BaseDecoder
from engine.models import (
    AnalysisContext,
    DetectResult,
    FamilyHint,
    Fingerprint,
    MitreHint,
    PluginResult,
    TradecraftFlag,
)
from engine.registry import DecoderRegistry

# CS v3 XORs config with 0x69; CS v4 with 0x2E.
_XOR_KEYS = (0x2E, 0x69)

# The first four bytes of a plaintext CS config are always 00 01 00 01
# (tag=0x0001, type=0x0001 SHORT). XORing that with each key yields the
# signature we search for in the raw bytes.
_MAGIC_SIGS = {
    key: bytes(b ^ key for b in b"\x00\x01\x00\x01\x00\x02")
    for key in _XOR_KEYS
}

_TAG_NAMES = {
    0x0001: "beacon_type",   0x0002: "port",         0x0003: "sleep_time",
    0x0004: "jitter",        0x0005: "maxdns",       0x0007: "publickey",
    0x0008: "c2_server",     0x0009: "user_agent",   0x000a: "http_post_uri",
    0x000d: "c2_recover",    0x000e: "spawnto_x86",  0x001d: "spawnto_x64",
    0x0025: "watermark",     0x0032: "process_inject_start",
}

_BEACON_TYPES = {
    0: "HTTP", 1: "Hybrid HTTP DNS", 2: "SMB",
    4: "TCP",  8: "HTTPS",           16: "Bind TCP",
}


class CobaltStrikeBeaconConfigExtractor(BaseDecoder):
    id = "cobaltstrike-beacon-config"
    name = "Cobalt Strike Beacon Config Extractor"
    category = "intelligence"
    cost = 4
    tags = ("cobalt-strike", "beacon", "config-extract", "family")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not payload or len(payload) < 32:
            return DetectResult(confidence=0.0, why="Payload too small (<32 bytes)")
        try:
            raw = payload.encode("latin-1", errors="ignore")
        except Exception:
            return DetectResult(confidence=0.0, why="Non-latin1 payload")
        for key, sig in _MAGIC_SIGS.items():
            if sig in raw:
                return DetectResult(
                    confidence=0.85,
                    why=f"CS-XOR-{key:#x} config magic found "
                        f"(TLV tags 0x0001+0x0002 present after XOR)",
                    args={"xor_key": key},
                )
        # Also fire on the DECRYPTED magic — if a prior xor-brute step
        # already unwrapped the config, plaintext magic is visible.
        if b"\x00\x01\x00\x01\x00\x02\x00" in raw:
            return DetectResult(
                confidence=0.75,
                why="Plaintext CS config TLV magic 00 01 00 01 00 02 present",
                args={"xor_key": 0},
            )
        return DetectResult(confidence=0.0, why="No CS config magic")

    def _decrypt(self, raw: bytes, key: int, start: int, size: int = 4096) -> bytes:
        chunk = raw[start:start + size]
        if key == 0:
            return chunk
        return bytes(b ^ key for b in chunk)

    def _parse_tlv(self, cfg: bytes) -> Dict[str, Any]:
        """Walk the TLV stream, tolerating unknown tags."""
        out: Dict[str, Any] = {}
        i = 0
        while i + 6 <= len(cfg):
            tag, ttype, tlen = struct.unpack(">HHH", cfg[i:i + 6])
            i += 6
            if tag == 0 or tlen > len(cfg) - i:
                break
            val_bytes = cfg[i:i + tlen]
            i += tlen
            key = _TAG_NAMES.get(tag, f"tag_{tag:#06x}")
            if ttype == 1 and tlen == 2:          # SHORT
                (val,) = struct.unpack(">H", val_bytes)
                out[key] = val
            elif ttype == 2 and tlen == 4:        # INT
                (val,) = struct.unpack(">I", val_bytes)
                out[key] = val
            else:                                  # STRING / BLOB
                try:
                    s = val_bytes.decode("utf-8", errors="ignore").rstrip("\x00")
                    out[key] = s if s.isprintable() or s else val_bytes.hex()[:64]
                except Exception:
                    out[key] = val_bytes.hex()[:64]
            if len(out) > 50:                      # sanity fuse
                break
        return out

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        raw = payload.encode("latin-1", errors="ignore")
        xor_key = int(args.get("xor_key", 0))
        cfg_bytes = b""
        used_key = 0
        # Try requested key first, then fall back to the alternate.
        keys = [xor_key] + [k for k in (0, 0x2E, 0x69) if k != xor_key]
        for k in keys:
            sig = _MAGIC_SIGS.get(k) if k else b"\x00\x01\x00\x01\x00\x02\x00"
            if not sig:
                continue
            idx = raw.find(sig)
            if idx < 0:
                continue
            cfg_bytes = self._decrypt(raw, k, idx)
            used_key = k
            break

        if not cfg_bytes:
            return PluginResult(output="", notes=["No CS config block found"])

        parsed = self._parse_tlv(cfg_bytes)
        if not parsed:
            return PluginResult(output="", notes=["CS config magic found but TLV parse failed"])

        # ---- Extract analyst-relevant fields into structured surfaces ----
        c2_server = str(parsed.get("c2_server", ""))
        c2_hosts, c2_uris = [], []
        if c2_server:
            # CS packs "host1,uri1,host2,uri2,..." into a single string
            parts = [p for p in re.split(r"[,\x00]", c2_server) if p]
            for p in parts:
                if p.startswith("/"):
                    c2_uris.append(p)
                elif re.match(r"[a-zA-Z0-9.-]+$", p) and "." in p:
                    c2_hosts.append(p)
        port = parsed.get("port")
        sleep = parsed.get("sleep_time")
        jitter = parsed.get("jitter")
        watermark = parsed.get("watermark")
        beacon_type = _BEACON_TYPES.get(parsed.get("beacon_type", -1), "unknown")

        # ---- Build URLs from host+port for the IOC surface ----
        # PluginResult wants iocs as Dict[str, List[str]], not IOCBundle
        iocs: Dict[str, List[str]] = {"urls": [], "domains": [], "ips": []}
        scheme = "https" if beacon_type in ("HTTPS",) else "http"
        for host in c2_hosts:
            iocs["domains"].append(host)
            if port:
                base = f"{scheme}://{host}:{port}"
            else:
                base = f"{scheme}://{host}"
            for uri in (c2_uris or ["/"]):
                iocs["urls"].append(base + uri)

        summary = (
            f"Cobalt Strike Beacon config extracted\n"
            f"  · beacon_type : {beacon_type}\n"
            f"  · port        : {port}\n"
            f"  · sleep / jit : {sleep} ms / {jitter}%\n"
            f"  · watermark   : {watermark}\n"
            f"  · c2_hosts    : {c2_hosts}\n"
            f"  · c2_uris     : {c2_uris}\n"
            f"  · xor_key     : {used_key:#x}\n"
        )

        return PluginResult(
            output=summary,
            notes=[f"Extracted {len(parsed)} TLV field(s) via XOR key {used_key:#x}"],
            iocs=iocs,
            family_hints=[FamilyHint(
                family="Cobalt Strike Beacon",
                confidence=0.95,
                evidence=f"CS config extracted (beacon_type={beacon_type}, "
                         f"watermark={watermark}, {len(c2_hosts)} C2 host(s))",
            )],
            mitre_hints=[
                MitreHint(id="T1071.001", name="Application Layer Protocol",
                          source="cs-config", evidence="CS Beacon HTTP(S) C2"),
                MitreHint(id="T1573.002", name="Asymmetric Cryptography",
                          source="cs-config", evidence="CS Beacon RSA-encrypted metadata"),
                MitreHint(id="T1027", name="Obfuscated Files or Information",
                          source="cs-config",
                          evidence=f"XOR-{used_key:#x} encrypted beacon config"),
            ],
            tradecraft=[TradecraftFlag(
                flag="cobaltstrike-config-extracted",
                severity="critical",
                evidence=summary.strip(),
                metadata={
                    "beacon_type":   beacon_type,
                    "port":          port,
                    "sleep_ms":      sleep,
                    "jitter_pct":    jitter,
                    "watermark":     watermark,
                    "c2_hosts":      c2_hosts,
                    "c2_uris":       c2_uris,
                    "xor_key":       used_key,
                    "tlv_field_count": len(parsed),
                },
            )],
        )


DecoderRegistry.register(CobaltStrikeBeaconConfigExtractor())
