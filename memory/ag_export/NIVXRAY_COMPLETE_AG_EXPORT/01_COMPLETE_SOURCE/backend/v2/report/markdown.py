"""v2/report/markdown.py · Deterministic Markdown rendering.

Same envelope → same Markdown bytes. Pure function, no side effects.
"""
from __future__ import annotations
from .schema import ReportEnvelope


def _section(title: str, order: int) -> str:
    return f"## {order}. {title}\n\n"


def _bullet(items: list[str]) -> str:
    return "\n".join(f"- {i}" for i in items) + ("\n\n" if items else "\n")


def render_markdown(env: ReportEnvelope) -> str:
    out: list[str] = []
    out.append(f"# NivXRay · Deterministic Investigation Report\n\n")
    out.append(f"**Case**: `{env.case_id}`  \n")
    out.append(f"**Generated at (derived from observations)**: `{env.generated_at}`  \n")
    out.append(f"**Schema**: `{env.schema_version}`  \n")
    out.append(f"**Signature (SHA-256)**: `{env.signature.get('sha256','—')}`  \n\n")
    out.append("---\n\n")

    for sec in env.sections:
        out.append(_section(sec.title, sec.order))
        if sec.narrative:
            out.append(sec.narrative.strip() + "\n\n")

        b = sec.body

        if sec.id == "executive_summary":
            vc = b.get("verdict_counts", {})
            out.append(f"| Malicious | Suspicious | Observation | Total |\n")
            out.append(f"|-----------|------------|-------------|-------|\n")
            out.append(f"| {vc.get('malicious',0)} "
                       f"| {vc.get('suspicious',0)} "
                       f"| {vc.get('benign',0)} "
                       f"| {b.get('event_total',0)} |\n\n")
            tactics = b.get("tactics") or []
            if tactics:
                out.append(f"**MITRE tactics observed**: {', '.join(tactics)}\n\n")

        elif sec.id == "case_metadata":
            for k in ("case_id", "name", "description", "status",
                      "created_at", "first_observed", "last_observed",
                      "observation_count"):
                v = b.get(k)
                if v is not None:
                    out.append(f"- **{k}**: `{v}`\n")
            tags = b.get("tags") or []
            if tags:
                out.append(f"- **tags**: {', '.join(tags)}\n")
            out.append("\n")

        elif sec.id == "verdict_rollup":
            counts = b.get("counts", {})
            pct = b.get("percentages", {})
            out.append("| Verdict | Count | Percentage |\n|---------|-------|-----------|\n")
            for k in ("malicious", "suspicious", "benign"):
                out.append(f"| {k} | {counts.get(k,0)} | {pct.get(k,0)}% |\n")
            out.append("\n")

        elif sec.id == "mitre_coverage":
            tacts = b.get("tactics", [])
            techs = b.get("techniques", [])
            if tacts:
                out.append("**Tactics**\n\n")
                out.append("| Tactic | Count |\n|--------|-------|\n")
                for t in tacts:
                    out.append(f"| {t['id']} | {t['count']} |\n")
                out.append("\n")
            if techs:
                out.append("**Techniques**\n\n")
                out.append("| Technique | Count |\n|-----------|-------|\n")
                for t in techs:
                    out.append(f"| {t['id']} | {t['count']} |\n")
                out.append("\n")

        elif sec.id == "process_ancestry":
            for p in b.get("top_processes", []):
                out.append(f"- `{p['process']}` — {p['event_count']} events\n")
            edges = b.get("spawn_edges", [])
            if edges:
                out.append("\n**Spawn edges**\n\n")
                for e in edges:
                    out.append(f"- `{e['parent']}` → {', '.join('`'+c+'`' for c in e['children'])}\n")
            out.append("\n")

        elif sec.id == "top_entities":
            for kind in ("file", "network", "registry", "user", "device"):
                items = b.get(kind, [])
                if not items: continue
                out.append(f"**{kind.title()}**\n\n")
                for it in items:
                    out.append(f"- `{it['iid']}` — {it['count']}\n")
                out.append("\n")

        elif sec.id == "chronological_timeline":
            rows = b.get("rows", [])
            out.append(f"| # | ts | lane | action | process | verdict | MITRE |\n")
            out.append(f"|---|----|------|--------|---------|---------|-------|\n")
            for i, r in enumerate(rows, 1):
                m = ",".join(r.get("mitre") or [])
                out.append(
                    f"| {i} | `{r.get('ts','')}` | {r.get('lane','')} "
                    f"| `{r.get('action','')}` | `{r.get('process','')}` "
                    f"| **{r.get('verdict','')}** | {m} |\n"
                )
            out.append("\n")

        elif sec.id == "commandline_decoding":
            for d in b.get("decoded_events", []):
                out.append(f"- **{d.get('ts','')}** `{d.get('frame_iid','')}`\n")
                out.append(f"    - raw: `{d.get('raw','')}`\n")
                if d.get("decoded"):
                    out.append(f"    - decoded: `{d['decoded']}`\n")
            out.append("\n")

        elif sec.id == "enrichment":
            out.append(f"_Status: {b.get('status','—')} · Enrichment kit lands in R3._\n\n")

        elif sec.id == "signature":
            sig = env.signature
            out.append(f"- **algorithm**: `{sig.get('algorithm','sha256')}`\n")
            out.append(f"- **sha256**: `{sig.get('sha256','—')}`\n")
            out.append(f"- **canonical_json_bytes**: `{sig.get('canonical_json_bytes','—')}`\n\n")

    return "".join(out)
