"""HTML adapter — parses the body with BeautifulSoup, emits the
extracted text as a ``text`` artifact and every ``href``/``src`` URL
as a ``url`` child so the UAIE loop investigates them further."""
from __future__ import annotations
import re
from typing import Optional
from ..artifact import make_artifact
from ._base import Adapter, AdapterResult, register_adapter


_HTML_MARKERS = (b"<html", b"<!doctype html", b"<HTML", b"<!DOCTYPE HTML")
_HTML_TAG_RE = re.compile(rb"<[a-zA-Z!][a-zA-Z0-9\-]{0,20}[\s/>]")


class _HtmlAdapter:
    name = "adapter.html"
    priority = 70

    def sniff(self, payload: bytes, *, filename=None, declared_mime=None) -> int:
        head = payload[:2048]
        if any(m in head for m in _HTML_MARKERS):
            return 90
        # No explicit doctype but plenty of tags?
        if len(_HTML_TAG_RE.findall(head)) >= 4:
            return 55
        if (declared_mime or "").startswith("text/html"):
            return 60
        return 0

    def extract(self, payload: bytes, *, filename: Optional[str] = None) -> AdapterResult:
        artifacts, diagnostics = [], []
        meta = {"format": "text/html"}
        text = ""
        urls = set()
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(payload, "html.parser")
            text = soup.get_text("\n", strip=True)
            for tag in soup.find_all(["a", "link", "script", "img", "iframe", "form"]):
                for attr in ("href", "src", "action"):
                    val = tag.get(attr)
                    if isinstance(val, str) and val.startswith(("http://", "https://")):
                        urls.add(val)
        except Exception as e:
            diagnostics.append({"code": "DX_HTML_PARSE",
                                    "severity": "warn", "reason": str(e)})
            # Best-effort text via tag-stripping.
            text = re.sub(rb"<[^>]+>", b" ", payload).decode("utf-8", errors="replace")
        # URLs by regex — catches URLs in JS strings and text.
        for u in re.findall(
            rb"https?://[A-Za-z0-9.\-_/?%=&+~#:@]{4,300}", payload
        ):
            urls.add(u.decode(errors="ignore"))
        if text.strip():
            artifacts.append(make_artifact(
                text.encode("utf-8"), "text",
                discovered_by=self.name,
                meta={"source": "html_text"}))
        for u in sorted(urls):
            artifacts.append(make_artifact(
                u.encode(), "url",
                discovered_by=self.name,
                meta={"source": "html_href"}))
        if not artifacts:
            artifacts.append(make_artifact(
                payload, "raw_bytes",
                discovered_by=self.name,
                meta={"reason": "html_no_content"}))
        return AdapterResult(artifacts=artifacts,
                                diagnostics=diagnostics, meta=meta)


register_adapter(_HtmlAdapter())
