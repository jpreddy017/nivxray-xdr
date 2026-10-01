"""JSON adapter — parses structured JSON input, walks every leaf,
and emits typed artifacts for the security-interesting values
(URLs, IPs, hashes, base64 blobs > 40 chars, embedded scripts)."""
from __future__ import annotations
import json, re
from typing import Any, Optional
from ..artifact import make_artifact
from ._base import Adapter, AdapterResult, register_adapter


_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32,64}$")
_URL_RE  = re.compile(r"^https?://[A-Za-z0-9.\-_/?%=&+~#:@]{4,2048}$")


class _JsonAdapter:
    name = "adapter.json"
    priority = 65

    def sniff(self, payload: bytes, *, filename=None, declared_mime=None) -> int:
        head = payload[:4096].lstrip()
        if not head:
            return 0
        if head[:1] not in (b"{", b"["):
            return 0
        # Only claim if it actually parses.
        try:
            json.loads(payload.decode("utf-8", errors="replace"))
            return 88
        except Exception:
            return 0

    def _walk(self, obj: Any, out_urls, out_ips, out_hashes, out_scripts, path=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                self._walk(v, out_urls, out_ips, out_hashes, out_scripts,
                             f"{path}.{k}" if path else k)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                self._walk(v, out_urls, out_ips, out_hashes, out_scripts,
                             f"{path}[{i}]")
        elif isinstance(obj, str):
            s = obj.strip()
            if not s: return
            if _URL_RE.match(s):
                out_urls.add((s, path))
            elif _IPV4_RE.match(s):
                out_ips.add((s, path))
            elif _HASH_RE.match(s):
                out_hashes.add((s, path))
            elif len(s) > 200 and re.match(r"^[A-Za-z0-9+/=]+$", s):
                out_scripts.add((s, path, "base64_blob"))
            elif "$" in s and "(" in s and any(
                kw in s.lower() for kw in ("iex", "invoke-expression", "frombase64string", "downloadstring")
            ):
                out_scripts.add((s, path, "powershell"))

    def extract(self, payload: bytes, *, filename: Optional[str] = None) -> AdapterResult:
        artifacts, diagnostics = [], []
        meta = {"format": "application/json"}
        try:
            obj = json.loads(payload.decode("utf-8", errors="replace"))
        except Exception as e:
            diagnostics.append({"code": "DX_JSON_PARSE",
                                    "severity": "warn", "reason": str(e)})
            artifacts.append(make_artifact(
                payload, "text",
                discovered_by=self.name,
                meta={"source": "json_fallback_text"}))
            return AdapterResult(artifacts=artifacts,
                                    diagnostics=diagnostics, meta=meta)
        # Keep the full JSON as a text artifact so string-based
        # capabilities can scan it.
        artifacts.append(make_artifact(
            json.dumps(obj, indent=2).encode(), "text",
            discovered_by=self.name,
            meta={"source": "json_document"}))
        urls, ips, hashes, scripts = set(), set(), set(), set()
        self._walk(obj, urls, ips, hashes, scripts)
        for u, path in urls:
            artifacts.append(make_artifact(
                u.encode(), "url",
                discovered_by=self.name,
                meta={"source": "json_leaf", "json_path": path}))
        for ip, path in ips:
            artifacts.append(make_artifact(
                ip.encode(), "ip",
                discovered_by=self.name,
                meta={"source": "json_leaf", "json_path": path}))
        for h, path in hashes:
            artifacts.append(make_artifact(
                h.encode(), "hash",
                discovered_by=self.name,
                meta={"source": "json_leaf", "json_path": path,
                        "length": len(h)}))
        for s, path, kind in scripts:
            typ = "base64_bare" if kind == "base64_blob" else "powershell"
            artifacts.append(make_artifact(
                s.encode(), typ,
                discovered_by=self.name,
                meta={"source": "json_leaf", "json_path": path}))
        return AdapterResult(artifacts=artifacts,
                                diagnostics=diagnostics, meta=meta)


register_adapter(_JsonAdapter())
