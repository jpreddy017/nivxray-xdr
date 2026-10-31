"""URL adapter — treats the payload as a URL string (or a whole
input that STARTS with a URL) and emits typed artifacts BUT does
NOT actually fetch the URL by default.  Fetching is a downstream
Capability decision so the adapter stays deterministic and
side-effect-free per RADE invariants.

Emits:
  · ``url``        artifact — the raw URL string (always)
  · ``domain``     artifact — the hostname
  · ``ip``         artifact — when the hostname is a bare IP
"""
from __future__ import annotations
import re
from typing import Optional
from urllib.parse import urlparse
from ..artifact import make_artifact
from ._base import Adapter, AdapterResult, register_adapter


_URL_LINE_RE = re.compile(
    r"^\s*(?P<u>https?://[A-Za-z0-9.\-_/?%=&+~#:@]{4,2048})\s*$",
    re.MULTILINE,
)
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


class _UrlAdapter:
    name = "adapter.url"
    priority = 82

    def sniff(self, payload: bytes, *, filename=None, declared_mime=None) -> int:
        try:
            head = payload[:2048].decode("utf-8", errors="ignore").strip()
        except Exception:
            return 0
        if not head:
            return 0
        # Bare URL as the entire payload
        if _URL_LINE_RE.match(head) and len(head) < 2048:
            return 95
        # URL on the first line with more content below
        first_line = head.split("\n", 1)[0].strip()
        if first_line.startswith(("http://", "https://")) and len(first_line) < 2048:
            return 60
        return 0

    def extract(self, payload: bytes, *, filename: Optional[str] = None) -> AdapterResult:
        try:
            text = payload.decode("utf-8", errors="replace").strip()
        except Exception:
            text = ""
        # Prefer the exact URL if the whole payload IS the URL.
        m = _URL_LINE_RE.match(text)
        url = m.group("u") if m else text.split("\n", 1)[0].strip()
        artifacts = []
        artifacts.append(make_artifact(
            url.encode(), "url",
            discovered_by=self.name,
            meta={"source": "url_adapter"}))
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
        except Exception:
            host = ""
        if host:
            typ = "ip" if _IPV4_RE.match(host) else "domain"
            artifacts.append(make_artifact(
                host.encode(), typ,
                discovered_by=self.name,
                meta={"source": "url_hostname", "url": url}))
        return AdapterResult(artifacts=artifacts,
                                meta={"format": "text/uri",
                                       "url": url,
                                       "hostname": host})


register_adapter(_UrlAdapter())
