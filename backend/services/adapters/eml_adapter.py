"""EML Evidence Adapter — Phase 3B (Flagship).

Turns a raw RFC-822 email into an IEP organised into five evidence
categories per the frozen architecture doc:

  · Identity   — sender / recipients / reply-to / return-path / display-name / message-id
  · Transport  — Received chain / SPF / DKIM / DMARC / ARC / Authentication-Results
  · Content    — plain text / HTML / URLs
  · Attachments — each attachment surfaces as a child-IEP candidate
  · Metadata   — priority / importance / date / client / encoding / language

MIME hierarchy is preserved via ``CONTAINS`` relationships so an
analyst can later see why a malicious URL only appeared in the HTML
part and not the plain-text alternative.
"""
from __future__ import annotations

import email
import email.policy
import hashlib
import re
from email.message import EmailMessage
from typing import Any, Dict, List, Optional

from models.iep import (
    IEPArtifact,
    IEPContent,
    IEPRelationship,
    IEPSource,
    IEPWarning,
    RelationshipType,
)
from services.ida.artifact_splitter import split_artifacts

from .base import EvidenceAdapter


class EMLAdapter(EvidenceAdapter):
    name         = "adapter.eml"
    version      = "1.0"
    capabilities = [
        # Identity
        "sender", "recipients", "reply_to", "return_path", "display_name", "message_id",
        # Transport
        "received_chain", "spf", "dkim", "dmarc", "arc", "authentication_results",
        # Content
        "text_plain", "text_html", "urls", "mime_hierarchy",
        # Attachments
        "attachments", "child_iep_candidates",
        # Metadata
        "priority", "importance", "date", "x_mailer", "encoding", "language",
    ]

    # ── Detection ────────────────────────────────────────────────────
    def can_handle(self, raw: Any) -> bool:
        if isinstance(raw, (bytes, bytearray)):
            head = bytes(raw[:2048]).decode("utf-8", errors="ignore")
        elif isinstance(raw, str):
            head = raw[:2048]
        else:
            return False
        # RFC-822 signal: at least Message-ID / Received / From on
        # separate lines, or MIME-Version.
        signals = 0
        if re.search(r"(?im)^from:\s", head):        signals += 1
        if re.search(r"(?im)^to:\s", head):          signals += 1
        if re.search(r"(?im)^subject:\s", head):     signals += 1
        if re.search(r"(?im)^message-id:\s", head):  signals += 1
        if re.search(r"(?im)^received:\s", head):    signals += 1
        if re.search(r"(?im)^mime-version:\s", head): signals += 1
        return signals >= 2

    # ── Extraction ───────────────────────────────────────────────────
    def extract(self, raw: Any) -> IEPContent:
        data = raw if isinstance(raw, (bytes, bytearray)) else str(raw).encode()
        msg: EmailMessage = email.message_from_bytes(
            bytes(data), policy=email.policy.default,
        )  # type: ignore
        info: Dict[str, Any] = {
            "identity":   self._extract_identity(msg),
            "transport":  self._extract_transport(msg),
            "content":    {"plain": "", "html": "", "urls": []},
            "attachments": [],
            "metadata":   self._extract_metadata(msg),
            "mime_tree":  [],
            "warnings":   [],
        }

        # Walk MIME tree — build hierarchy + content + attachments.
        blocks: List[Dict[str, Any]] = []
        text_parts: List[str] = []
        for i, part in enumerate(msg.walk(), start=1):
            ctype = part.get_content_type()
            fname = part.get_filename()
            cid   = part.get("Content-ID")
            disp  = part.get_content_disposition()
            node = {
                "index": i,
                "content_type": ctype,
                "filename": fname,
                "content_id": cid,
                "disposition": disp,
                "is_multipart": part.is_multipart(),
            }
            info["mime_tree"].append(node)
            if part.is_multipart():
                continue
            try:
                payload = part.get_content()
            except Exception:
                payload = None
            if fname or disp == "attachment":
                # Attachment — capture provenance + hash the bytes.
                try:
                    body = part.get_payload(decode=True) or b""
                except Exception:
                    body = b""
                sha = hashlib.sha256(body).hexdigest() if body else None
                info["attachments"].append({
                    "filename":     fname or f"attachment_{i}",
                    "mime_type":    ctype,
                    "content_id":   cid,
                    "disposition":  disp or "attachment",
                    "source_ref":   f"mime.part.{i}",
                    "sha256":       sha,
                    "size":         len(body),
                })
                continue
            if ctype == "text/plain" and isinstance(payload, str):
                info["content"]["plain"] += payload + "\n"
                text_parts.append(payload)
                blocks.append({"kind": "mime_text_plain",
                                "part": i, "text": payload})
            elif ctype == "text/html" and isinstance(payload, str):
                info["content"]["html"] += payload + "\n"
                blocks.append({"kind": "mime_text_html",
                                "part": i, "text": payload})
                # Cheap URL harvest from HTML anchors / src attributes.
                for m in re.finditer(r'''(?i)(?:href|src)=["']([^"']+)["']''', payload):
                    u = m.group(1).strip()
                    if u.startswith(("http://", "https://")):
                        info["content"]["urls"].append({"url": u, "part": i})
                text_parts.append(re.sub(r"<[^>]+>", " ", payload))

        content = IEPContent(text="\n".join(text_parts), blocks=blocks)
        content.__dict__["_eml"] = info
        return content

    # ── Identity ────────────────────────────────────────────────────
    def _extract_identity(self, msg) -> Dict[str, Any]:
        return {
            "from":         msg.get("From"),
            "to":           self._addrs(msg.get_all("To") or []),
            "cc":           self._addrs(msg.get_all("Cc") or []),
            "bcc":          self._addrs(msg.get_all("Bcc") or []),
            "reply_to":     msg.get("Reply-To"),
            "return_path":  msg.get("Return-Path"),
            "sender":       msg.get("Sender"),
            "message_id":   msg.get("Message-ID"),
            "subject":      msg.get("Subject"),
        }

    def _addrs(self, headers):
        return [str(h) for h in (headers or [])]

    # ── Transport ───────────────────────────────────────────────────
    def _extract_transport(self, msg) -> Dict[str, Any]:
        received = msg.get_all("Received") or []
        auth_res = msg.get_all("Authentication-Results") or []
        arc_seal = msg.get_all("ARC-Seal") or []
        arc_msg  = msg.get_all("ARC-Message-Signature") or []
        arc_auth = msg.get_all("ARC-Authentication-Results") or []
        # Very light SPF / DKIM / DMARC parsing — the Evidence Validator
        # (Phase 5) will do the strict validation.  Adapter only reports
        # what the headers already claim (R8).
        def _first(pat: str, corpus: str) -> Optional[str]:
            m = re.search(pat, corpus, re.I)
            return m.group(1) if m else None
        joined = " \n ".join(auth_res)
        return {
            "received":    [str(r) for r in received],
            "auth_results": [str(a) for a in auth_res],
            "arc_seal":    [str(a) for a in arc_seal],
            "arc_msg_sig": [str(a) for a in arc_msg],
            "arc_auth":    [str(a) for a in arc_auth],
            "spf":         _first(r"spf=([a-z]+)", joined),
            "dkim":        _first(r"dkim=([a-z]+)", joined),
            "dmarc":       _first(r"dmarc=([a-z]+)", joined),
        }

    # ── Metadata ────────────────────────────────────────────────────
    def _extract_metadata(self, msg) -> Dict[str, Any]:
        return {
            "date":        msg.get("Date"),
            "x_mailer":    msg.get("X-Mailer"),
            "priority":    msg.get("X-Priority"),
            "importance":  msg.get("Importance"),
            "language":    msg.get("Content-Language"),
            "encoding":    msg.get_content_charset(failobj=None),
        }

    # ── Normalization ────────────────────────────────────────────────
    def normalize(self, content: IEPContent) -> List[IEPArtifact]:
        eml = getattr(content, "_eml", {}) or {}
        out: List[IEPArtifact] = []
        ident = eml.get("identity") or {}

        # Identity — email_address artifacts
        def _push_email(kind: str, header_val, ref: str):
            if not header_val:
                return
            for a in re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", str(header_val)):
                out.append(IEPArtifact(
                    type="email_address", value=a,
                    source_ref=ref, tags=[f"eml_{kind}"],
                ))
        _push_email("from",        ident.get("from"),        "eml.header.from")
        for t in ident.get("to") or []:    _push_email("to",   t, "eml.header.to")
        for c in ident.get("cc") or []:    _push_email("cc",   c, "eml.header.cc")
        _push_email("reply_to",    ident.get("reply_to"),    "eml.header.reply_to")
        _push_email("return_path", ident.get("return_path"), "eml.header.return_path")

        if ident.get("message_id"):
            out.append(IEPArtifact(
                type="unknown", value=str(ident["message_id"]),
                source_ref="eml.header.message_id",
                tags=["eml_message_id"],
            ))

        # Content URLs
        for u in eml.get("content", {}).get("urls") or []:
            out.append(IEPArtifact(
                type="url", value=u["url"],
                source_ref=f"mime.part.{u.get('part')}",
                tags=["eml_html_url"],
            ))
        # Deterministic splitter on plain-text body
        plain = eml.get("content", {}).get("plain") or ""
        for a in (split_artifacts(plain) or []):
            t = self._map_type(getattr(a, "type", None))
            v = getattr(a, "value", None)
            if not (t and v):
                continue
            out.append(IEPArtifact(
                type=t, value=v,
                canonical=getattr(a, "canonical", None) or None,
                confidence=getattr(a, "confidence", 1.0) or 1.0,
                source_ref="mime.text_plain",
            ))

        # Attachments
        for att in eml.get("attachments") or []:
            out.append(IEPArtifact(
                type="file_path",
                value=att["filename"],
                source_ref=att["source_ref"],
                tags=["eml_attachment"],
                confidence=1.0,
                attributes={
                    "mime_type":   att.get("mime_type"),
                    "content_id":  att.get("content_id"),
                    "disposition": att.get("disposition"),
                    "sha256":      att.get("sha256"),
                    "size":        att.get("size"),
                },
            ))
            if att.get("sha256"):
                out.append(IEPArtifact(
                    type="hash", value=att["sha256"],
                    source_ref=att["source_ref"],
                    tags=["eml_attachment_sha256"],
                ))
        return out

    # ── Relationships (R8 · MIME hierarchy + attachments) ────────────
    def discover_relationships(self, content, artifacts):
        eml = getattr(content, "_eml", {}) or {}
        rels: List[IEPRelationship] = []
        email_ref = "eml.email"
        # Walk mime tree — parent contains child per structural nesting.
        # Since walk() returns preorder, we approximate hierarchy by
        # container / part types.
        prev_container = None
        for node in eml.get("mime_tree") or []:
            ref = f"mime.part.{node['index']}"
            if node["is_multipart"]:
                rels.append(IEPRelationship(
                    from_ref=email_ref if prev_container is None else prev_container,
                    to_ref=ref,
                    verb=RelationshipType.CONTAINS,
                    source_ref=ref,
                ))
                prev_container = ref
            else:
                rels.append(IEPRelationship(
                    from_ref=prev_container or email_ref,
                    to_ref=ref, verb=RelationshipType.CONTAINS,
                    source_ref=ref,
                ))
        # Email → attaches → each attachment
        for att in eml.get("attachments") or []:
            rels.append(IEPRelationship(
                from_ref=email_ref, to_ref=att["filename"],
                verb=RelationshipType.ATTACHES,
                source_ref=att["source_ref"],
            ))
        return rels

    # ── Warnings ─────────────────────────────────────────────────────
    def validate(self, iep) -> List[IEPWarning]:
        eml = getattr(iep.content, "_eml", {}) or {}
        w: List[IEPWarning] = [IEPWarning(**x) for x in eml.get("warnings") or []]
        ident = eml.get("identity") or {}
        trans = eml.get("transport") or {}
        # Reply-To mismatch heuristic (structural fact, not reasoning)
        rt   = ident.get("reply_to") or ""
        from_ = ident.get("from") or ""
        if rt and from_ and rt.strip() != from_.strip():
            w.append(IEPWarning(
                severity="info", code="eml_reply_to_differs_from_from",
                message="Reply-To header differs from From header.",
            ))
        if trans.get("spf")   == "fail": w.append(IEPWarning(severity="warn", code="eml_spf_fail",   message="SPF failed."))
        if trans.get("dkim")  == "fail": w.append(IEPWarning(severity="warn", code="eml_dkim_fail",  message="DKIM failed."))
        if trans.get("dmarc") == "fail": w.append(IEPWarning(severity="warn", code="eml_dmarc_fail", message="DMARC failed."))
        if eml.get("attachments"):
            w.append(IEPWarning(
                severity="info", code="eml_has_attachments",
                message=f"Email carries {len(eml['attachments'])} attachment(s).",
            ))
        if not ident.get("message_id"):
            w.append(IEPWarning(
                severity="warn", code="eml_missing_message_id",
                message="Email is missing a Message-ID header.",
            ))
        if not ident.get("subject"):
            w.append(IEPWarning(
                severity="info", code="eml_missing_subject",
                message="Email is missing a Subject header.",
            ))
        return w

    # ── Recursion — every attachment becomes a child IEP candidate ───
    def recurse(self, iep) -> List[IEPArtifact]:
        return [a for a in iep.artifacts if "eml_attachment" in (a.tags or [])]

    # ── Source ───────────────────────────────────────────────────────
    def _infer_source(self, raw: Any) -> IEPSource:
        data = raw if isinstance(raw, (bytes, bytearray)) else str(raw).encode()
        return IEPSource(
            kind="eml", size_bytes=len(data),
            sha256=hashlib.sha256(bytes(data)).hexdigest(),
            mime_type="message/rfc822",
        )

    # ── Type map ─────────────────────────────────────────────────────
    _TYPE_MAP = {
        "command": "command", "url": "url", "ip": "ip", "domain": "domain",
        "hash": "hash", "file_path": "file_path",
        "registry_key": "registry_key", "email": "email_address",
        "cve": "cve",
    }
    def _map_type(self, t):
        if not t:
            return "unknown"
        return self._TYPE_MAP.get(t, t)
