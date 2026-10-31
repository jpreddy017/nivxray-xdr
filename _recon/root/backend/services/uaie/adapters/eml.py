"""EML / MSG / RFC-822 e-mail adapter — parses the message envelope
into typed artifacts: headers, sender, recipients, subject, body
(text + HTML variants), URLs, and every attachment as a child
artifact so nested files get investigated by the UAIE loop."""
from __future__ import annotations
import email, email.policy, re
from email.message import EmailMessage
from typing import Optional
from ..artifact import make_artifact
from ._base import Adapter, AdapterResult, register_adapter


class _EmlAdapter:
    name = "adapter.eml"
    priority = 80

    def sniff(self, payload: bytes, *, filename=None, declared_mime=None) -> int:
        head = payload[:2048].lower()
        # Classic RFC-822 headers appear near the top.
        markers = (b"received:", b"from:", b"to:", b"subject:",
                    b"message-id:", b"return-path:", b"mime-version:")
        hits = sum(1 for m in markers if m in head)
        if hits >= 3:
            return 90
        if hits >= 1 and (filename or "").lower().endswith((".eml", ".msg")):
            return 70
        return 0

    def extract(self, payload: bytes, *, filename: Optional[str] = None) -> AdapterResult:
        artifacts, diagnostics = [], []
        meta = {"format": "message/rfc822"}
        try:
            msg = email.message_from_bytes(
                payload, policy=email.policy.default)
        except Exception as e:
            diagnostics.append({"code": "DX_EML_PARSE",
                                    "severity": "warn", "reason": str(e)})
            artifacts.append(make_artifact(
                payload, "raw_bytes",
                discovered_by=self.name,
                meta={"reason": "eml_parse_failed"}))
            return AdapterResult(artifacts=artifacts,
                                    diagnostics=diagnostics, meta=meta)
        # Envelope metadata → single artifact
        envelope = {
            "from":     str(msg.get("From") or ""),
            "to":       str(msg.get("To") or ""),
            "cc":       str(msg.get("Cc") or ""),
            "subject":  str(msg.get("Subject") or ""),
            "date":     str(msg.get("Date") or ""),
            "message_id":  str(msg.get("Message-ID") or ""),
            "reply_to":    str(msg.get("Reply-To") or ""),
            "return_path": str(msg.get("Return-Path") or ""),
        }
        import json
        artifacts.append(make_artifact(
            json.dumps(envelope, indent=2).encode(),
            "email_envelope",
            discovered_by=self.name,
            meta={"source": "eml_headers"}))
        # Body parts (text + html) → typed text artifacts
        for part in msg.walk():
            ctype = part.get_content_type()
            disp  = str(part.get("Content-Disposition") or "").lower()
            if part.is_multipart():
                continue
            if "attachment" in disp:
                try:
                    payload_bytes = part.get_payload(decode=True) or b""
                except Exception:
                    payload_bytes = b""
                if payload_bytes:
                    artifacts.append(make_artifact(
                        payload_bytes, "email_attachment",
                        discovered_by=self.name,
                        meta={"source": "eml_attachment",
                                "content_type": ctype,
                                "filename": part.get_filename() or ""}))
                continue
            try:
                body = part.get_content()
            except Exception:
                try:
                    b = part.get_payload(decode=True) or b""
                    body = b.decode("utf-8", errors="replace")
                except Exception:
                    body = ""
            if not isinstance(body, str):
                continue
            if not body.strip():
                continue
            if ctype == "text/html":
                artifacts.append(make_artifact(
                    body.encode(), "html",
                    discovered_by=self.name,
                    meta={"source": "eml_body_html"}))
            else:
                artifacts.append(make_artifact(
                    body.encode(), "text",
                    discovered_by=self.name,
                    meta={"source": "eml_body_text"}))
        # Extract URLs from the whole message so orphan URLs in
        # headers or malformed HTML get seen.
        for u in set(re.findall(
            rb"https?://[A-Za-z0-9.\-_/?%=&+~#:@]{4,300}", payload)
        ):
            artifacts.append(make_artifact(
                u, "url",
                discovered_by=self.name,
                meta={"source": "eml_embedded_url"}))
        return AdapterResult(artifacts=artifacts,
                                diagnostics=diagnostics, meta=meta)


register_adapter(_EmlAdapter())
