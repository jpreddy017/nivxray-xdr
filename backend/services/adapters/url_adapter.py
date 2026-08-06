"""URL Adapter — deterministic acquisition of remote pages.

Leverages the existing `services.ida.acquisition.acquire_url` cascade
(Trafilatura → readability-lxml → BeautifulSoup → Playwright fallback)
to fetch the article body, then reuses IDA-4's `extract_from_report`
to pull commands / IOCs / registry keys / actors / malware / CVEs /
timeline / hash-context.

Every extracted artifact carries a source_ref pointing back to the
line-or-block index inside the acquired document so R6 (provenance)
is satisfied.
"""
from __future__ import annotations

from typing import Any, Dict, List

from models.iep import IEPArtifact, IEPContent, IEPSource, IEPWarning

from .base import EvidenceAdapter


class URLAdapter(EvidenceAdapter):
    name    = "adapter.url"
    version = "1.0"

    # ── Detection ────────────────────────────────────────────────────
    def can_handle(self, raw: Any) -> bool:
        if not isinstance(raw, str):
            return False
        s = raw.strip()
        return s.startswith(("http://", "https://"))

    # ── Extraction (deterministic acquisition cascade) ───────────────
    def extract(self, raw: Any) -> IEPContent:
        # Import lazily so unit tests can mock the acquisition layer.
        from services.ida.acquisition import acquire_url  # type: ignore

        url = (raw or "").strip()
        res = acquire_url(url)
        # `acquire_url` returns an AcquiredResource dataclass, but tests
        # may patch it to return a dict — accept both shapes.
        if hasattr(res, "to_dict"):
            acq: Dict[str, Any] = res.to_dict()
        elif isinstance(res, dict):
            acq = res
        else:
            acq = {}
        text   = (acq.get("article_text") or acq.get("text") or "")
        blocks = self._blocks_from_acquisition(acq)
        content = IEPContent(text=text, blocks=blocks)
        # Stash the raw acquisition dict in metadata (statistics, vendor
        # profile, acquisition strategy used, cache stamp, …).
        content.__dict__["_acquisition"] = acq
        return content

    def _blocks_from_acquisition(self, acq: Dict[str, Any]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for i, b in enumerate(acq.get("structured_blocks") or [], start=1):
            out.append({"kind": "block", "index": i, "text": b})
        return out

    # ── Normalization ────────────────────────────────────────────────
    def normalize(self, content: IEPContent) -> List[IEPArtifact]:
        from services.ida.report_extractors import extract_all  # type: ignore

        text   = content.text or ""
        blocks = [b.get("text", "") for b in (content.blocks or [])]
        rep = extract_all(text, blocks) or {}

        out: List[IEPArtifact] = []
        # 1. Body artifacts (URLs / hashes / IPs / domains / paths / regs / CVEs)
        for a in rep.get("body_artifacts") or []:
            t = a.get("type"); v = a.get("value")
            if not (t and v):
                continue
            out.append(IEPArtifact(
                type=self._map_type(t),
                value=v,
                canonical=a.get("canonical") or None,
                confidence=a.get("confidence", 1.0),
                source_ref=f"body.{a.get('section') or 'article'}",
            ))
        # 2. Commands
        for c in rep.get("commands") or []:
            cmd = c.get("command"); ln = c.get("line")
            if not cmd:
                continue
            out.append(IEPArtifact(
                type="command",
                value=cmd,
                confidence=1.0,
                source_ref=f"body.line.{ln}" if ln else "body",
                attributes={
                    "executable": c.get("executable"),
                    "arguments":  c.get("arguments") or [],
                    "purpose":    c.get("purpose"),
                    "embedded_artifacts": c.get("embedded_artifacts") or {},
                },
            ))
        # 3. MITRE
        for m in rep.get("mitre_techniques") or []:
            out.append(IEPArtifact(type="mitre_technique", value=m.get("id") or "",
                                     tags=[m.get("name") or ""],
                                     source_ref="body"))
        # 4. Threat actors + malware + cves + yara + sigma
        for a in rep.get("threat_actors") or []:
            out.append(IEPArtifact(type="threat_actor", value=a.get("name") or "",
                                     source_ref="body"))
        for m in rep.get("malware_families") or []:
            out.append(IEPArtifact(type="malware_family", value=m.get("name") or "",
                                     source_ref="body"))
        for c in rep.get("cves") or []:
            out.append(IEPArtifact(type="cve", value=c.get("id") or "",
                                     source_ref="body"))
        for y in rep.get("yara_rules") or []:
            out.append(IEPArtifact(type="yara_rule", value=y.get("name") or "",
                                     source_ref="body"))
        for s in rep.get("sigma_rules") or []:
            out.append(IEPArtifact(type="sigma_rule", value=s.get("name") or "",
                                     source_ref="body"))
        return [a for a in out if a.value]

    # ── Adapter-level warnings ───────────────────────────────────────
    def validate(self, iep) -> List[IEPWarning]:
        warns: List[IEPWarning] = []
        acq = (iep.metadata.data or {}).get("acquisition") or {}
        if not (iep.content.text or "").strip():
            warns.append(IEPWarning(
                severity="warn",
                code="url_empty_body",
                message="URL acquired but no readable text extracted.",
            ))
        if acq.get("strategy") == "playwright_fallback":
            warns.append(IEPWarning(
                severity="info",
                code="url_playwright_fallback",
                message="Primary readability failed; Playwright headless "
                        "render was used to acquire the page.",
            ))
        return warns

    # ── Source detection ─────────────────────────────────────────────
    def _infer_source(self, raw: Any) -> IEPSource:
        url = (raw or "").strip()
        return IEPSource(kind="url", url=url,
                           raw_preview=url[:256])

    # ── Splitter type → canonical IEP artifact type ──────────────────
    _TYPE_MAP = {
        "command":       "command",
        "url":           "url",
        "ip":            "ip",
        "domain":        "domain",
        "hash":          "hash",
        "file_path":     "file_path",
        "registry_key":  "registry_key",
        "email":         "email_address",
        "cve":           "cve",
    }
    def _map_type(self, splitter_type: Any) -> str:
        if not splitter_type:
            return "unknown"
        return self._TYPE_MAP.get(splitter_type, splitter_type)

    # ── Override make_iep to lift acquisition metadata ───────────────
    def make_iep(self, raw, *, source=None, parent_iep_id=None,
                   pipeline_depth=0, metadata=None):
        content   = self.extract(raw)
        artifacts = self.normalize(content)
        src       = source or self._infer_source(raw)
        # Merge acquisition metadata harvested during extract().
        acq_meta = getattr(content, "_acquisition", {}) or {}
        md = dict(metadata or {})
        if acq_meta:
            md["acquisition"] = {
                "strategy":       acq_meta.get("strategy") or acq_meta.get("engine"),
                "sitename":       acq_meta.get("sitename"),
                "title":          acq_meta.get("title"),
                "vendor":         acq_meta.get("vendor") or acq_meta.get("sitename"),
                "final_url":      acq_meta.get("final_url"),
                "status_code":    acq_meta.get("status_code"),
                "block_count":    len(acq_meta.get("structured_blocks") or []),
            }
        from models.iep import make_iep as _mk
        iep = _mk(
            source=src, content=content, artifacts=artifacts, metadata=md,
            adapter=self.name, adapter_version=self.version,
            parent_iep_id=parent_iep_id, pipeline_depth=pipeline_depth,
        )
        iep.warnings.extend(self.validate(iep))
        return iep
