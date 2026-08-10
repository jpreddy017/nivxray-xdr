"""Auto-register built-in capability plug-ins."""
from ...iue.models import Capability
from ...ssot import (
    Artifact, GraphNode, GraphEdge, Provenance, ReasoningStep,
    make_ssot_ref,
)
from ..registry import register_capability, CapabilityRole


PROV_BUILTIN = Provenance(engine="canonical.executor.builtin",
                          version="1.0.0-phase3",
                          at="phase3")


# ── INPUT_HEALTH · Health role ───────────────────────────────────────────
def _cap_input_health(ssot, raw, ctx):
    """Records the IUE-emitted health signal as an evidence-graph node."""
    ssot.append("evidence_graph.nodes",
                GraphNode(id="ev.health.root",
                          kind="input_health",
                          label="pre-IUE health signal",
                          attrs=dict(ssot.input_health)),
                PROV_BUILTIN)


register_capability(Capability.INPUT_HEALTH, CapabilityRole.HEALTH,
                    _cap_input_health)


# ── IOC_EXTRACTOR · Analyzer role (regex-based; deterministic) ──────────
import re as _re

_URL_RE  = _re.compile(r"\bhttps?://[^\s\"'<>]+", _re.IGNORECASE)
_IP_RE   = _re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_RE = _re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_MD5_RE  = _re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = _re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = _re.compile(r"\b[a-fA-F0-9]{64}\b")


def _cap_ioc_extractor(ssot, raw, ctx):
    text = raw.as_text()
    findings = [
        ("url", sorted(set(_URL_RE.findall(text)))),
        ("ip",  sorted(set(_IP_RE.findall(text)))),
        ("email", sorted(set(_EMAIL_RE.findall(text)))),
        ("sha256", sorted(set(_SHA256_RE.findall(text)))),
        ("sha1", sorted(set(_SHA1_RE.findall(text)))),
        ("md5",  sorted(set(_MD5_RE.findall(text)))),
    ]
    for kind, values in findings:
        for i, v in enumerate(values):
            ssot.append("evidence_graph.nodes",
                        GraphNode(id=f"ev.ioc.{kind}.{i:04d}",
                                  kind="ioc",
                                  label=v,
                                  attrs={"ioc_kind": kind}),
                        PROV_BUILTIN)


register_capability(Capability.IOC_EXTRACTOR, CapabilityRole.ANALYZER,
                    _cap_ioc_extractor)


# ── COMMAND_DETECT · Analyzer role ──────────────────────────────────────
def _cap_command_detect(ssot, raw, ctx):
    """Deterministic naive command detection (fallback if MDR parser
    isn't reachable). Emits evidence-graph nodes only — NOT projections."""
    text = raw.as_text()
    lines = text.split("\n")
    keywords = ("powershell", "cmd", "wmic", "bash", "curl", "wget",
                "certutil", "regsvr32", "rundll32", "mshta")
    hits = []
    for ln in lines:
        ll = ln.lower()
        for kw in keywords:
            if kw in ll:
                hits.append((kw, ln.strip()[:200]))
                break
    for i, (kw, snippet) in enumerate(hits):
        ssot.append("evidence_graph.nodes",
                    GraphNode(id=f"ev.cmd.{i:04d}",
                              kind="command",
                              label=snippet,
                              attrs={"tool": kw}),
                    PROV_BUILTIN)


register_capability(Capability.COMMAND_DETECT, CapabilityRole.ANALYZER,
                    _cap_command_detect)


# ── ARCHIVE_EXTRACT · Analyzer role (DOCX/ZIP → artefacts[]) ────────────
def _cap_archive_extract(ssot, raw, ctx):
    """Extract archive members as artefacts. Deterministic ordering."""
    import zipfile
    import io
    payload = raw.as_bytes()
    if len(payload) < 4 or payload[:2] != b"PK":
        return
    try:
        z = zipfile.ZipFile(io.BytesIO(payload))
    except zipfile.BadZipFile:
        return
    for i, name in enumerate(sorted(z.namelist())):
        try:
            data = z.read(name)
        except Exception:                                           # noqa: BLE001
            continue
        ssot.append("artifacts",
                    Artifact(id=f"ev.archive.{i:04d}",
                             kind="archive_member",
                             label=name,
                             attrs={"size_bytes": len(data)}),
                    PROV_BUILTIN)


register_capability(Capability.ARCHIVE_EXTRACT, CapabilityRole.ANALYZER,
                    _cap_archive_extract)


# ── MITRE_MAP · Analyzer role ───────────────────────────────────────────
_MITRE_PATTERNS = {
    "T1059.001": ("PowerShell", ["powershell", "-encodedcommand", "-e "]),
    "T1059.003": ("Windows Command Shell", ["cmd /c", "cmd.exe"]),
    "T1218.010": ("Regsvr32", ["regsvr32"]),
    "T1218.011": ("Rundll32", ["rundll32"]),
    "T1105":     ("Ingress Tool Transfer", ["certutil -urlcache", "curl ", "wget "]),
}


def _cap_mitre_map(ssot, raw, ctx):
    text = raw.as_text().lower()
    for tid, (name, needles) in _MITRE_PATTERNS.items():
        matched = [n for n in needles if n in text]
        if matched:
            ssot.append("evidence_graph.nodes",
                        GraphNode(id=f"ev.mitre.{tid}",
                                  kind="mitre_technique",
                                  label=f"{tid}: {name}",
                                  attrs={"technique_id": tid,
                                         "matched": matched}),
                        PROV_BUILTIN)
            ssot.append("reasoning_steps",
                        ReasoningStep(id=f"rs.mitre.{tid}",
                                      rule="mitre.deterministic_needle_match",
                                      rationale=f"{tid} matched: {matched}"),
                        PROV_BUILTIN)


register_capability(Capability.MITRE_MAP, CapabilityRole.ANALYZER,
                    _cap_mitre_map)


# ── THREAT_INTEL_ENRICH · Enricher role (INV-2 isolated) ────────────────
def _cap_threat_intel(ssot, raw, ctx):
    """Isolated Enricher. Deterministic no-op unless a per-run TI oracle
    is provided via `ctx["ti_oracle"]`. INV-2: the deterministic
    conclusion of the investigation must be computable without this
    plug-in running. Phase 3 default: no network, no external lookup."""
    oracle = ctx.get("ti_oracle") if isinstance(ctx, dict) else None
    if not callable(oracle):
        return
    text = raw.as_text()
    for i, hit in enumerate(oracle(text) or []):
        ssot.append("evidence_graph.nodes",
                    GraphNode(id=f"ev.ti.{i:04d}",
                              kind="ti_hit",
                              label=str(hit.get("indicator", ""))[:200],
                              attrs=dict(hit)),
                    PROV_BUILTIN)


register_capability(Capability.THREAT_INTEL_ENRICH, CapabilityRole.ENRICHER,
                    _cap_threat_intel)


# ── RECURSIVE_DISCOVERY · Analyzer role (D6-r) ──────────────────────────
def _cap_recursive_discovery(ssot, raw, ctx):
    """For every artefact discovered so far, if it's investigable and
    depth budget allows, queue a child-SSOT ref. The executor picks up
    the queue after the plan finishes (see executor.py)."""
    depth = ctx.get("depth", 0) if isinstance(ctx, dict) else 0
    budget = ctx.get("budget") if isinstance(ctx, dict) else None
    max_depth = getattr(budget, "max_depth", 3)
    if depth >= max_depth:
        return

    # Phase 3 default: for each archive_member artifact, create a
    # placeholder child SSOT reference (empty, provenance-only). Full
    # child pipeline runs in Phase 5 EntryAdapter — Phase 3 only proves
    # the recursion contract.
    from ...ssot import AuthoritativeSSOT as _SSOT
    queue = []
    for i, art in enumerate(ssot.artifacts):
        if art.kind != "archive_member":
            continue
        child = _SSOT(
            id=f"child.{art.id}",
            source=ssot.source,
            input_raw=b"",  # placeholder — real payload wired in Phase 5
            provenance=PROV_BUILTIN,
        )
        # Record the parent link and the artefact origin.
        child.append("evidence_graph.nodes",
                     GraphNode(id="ev.recursion.parent_link",
                               kind="parent_link",
                               label=f"parent artefact: {art.label}",
                               attrs={"parent_artifact_id": art.id}),
                     PROV_BUILTIN)
        child.freeze()
        # Store into the shared store via the run-time-passed store ref.
        store = ctx.get("store") if isinstance(ctx, dict) else None
        if store is None:
            # Fall back: register the fingerprint but no store — the
            # executor will re-store the ssot after the plan finishes.
            continue
        child_ref = store.put(child)
        queue.append(child_ref)
        # Update parent artefact with the ref (append-only via a fresh
        # artefact carrying the parent link).
        ssot.append("artifacts",
                    Artifact(id=f"{art.id}.child_ref",
                             kind="child_ssot_ref",
                             label=child_ref,
                             parent_evidence_id=art.id,
                             investigation_ref=child_ref),
                    PROV_BUILTIN)
    if queue:
        ssot.metadata["_recursive_queue"] = queue


register_capability(Capability.RECURSIVE_DISCOVERY, CapabilityRole.ANALYZER,
                    _cap_recursive_discovery)
