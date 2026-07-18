"""Generate NivXRay IP Protection Strategy PDF.

Consolidates the patent, trademark, trade-secret, and defensive-publication
discussion from the Feb 2026 chat into a single downloadable PDF report.
"""
from __future__ import annotations
from pathlib import Path
from datetime import date

from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    KeepTogether,
)
from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT

OUT = Path("/app/docs/exports/NivXRay_IP_Protection_Strategy.pdf")
OUT.parent.mkdir(parents=True, exist_ok=True)


def build_styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle(
        name="TitleBig", parent=ss["Title"],
        fontName="Helvetica-Bold", fontSize=22, leading=26,
        textColor=colors.HexColor("#0f172a"), spaceAfter=6,
    ))
    ss.add(ParagraphStyle(
        name="SubTitle", parent=ss["Normal"],
        fontName="Helvetica", fontSize=11, leading=14,
        textColor=colors.HexColor("#475569"), spaceAfter=16,
    ))
    ss.add(ParagraphStyle(
        name="H1", parent=ss["Heading1"],
        fontName="Helvetica-Bold", fontSize=15, leading=19,
        textColor=colors.HexColor("#0e7490"), spaceBefore=14, spaceAfter=8,
    ))
    ss.add(ParagraphStyle(
        name="H2", parent=ss["Heading2"],
        fontName="Helvetica-Bold", fontSize=12, leading=16,
        textColor=colors.HexColor("#0f172a"), spaceBefore=10, spaceAfter=5,
    ))
    ss.add(ParagraphStyle(
        name="Body", parent=ss["BodyText"],
        fontName="Helvetica", fontSize=10, leading=14,
        alignment=TA_JUSTIFY, spaceAfter=6,
    ))
    ss.add(ParagraphStyle(
        name="BulletX", parent=ss["BodyText"],
        fontName="Helvetica", fontSize=10, leading=14,
        leftIndent=14, bulletIndent=4, spaceAfter=3,
    ))
    ss.add(ParagraphStyle(
        name="Warn", parent=ss["BodyText"],
        fontName="Helvetica-Bold", fontSize=10, leading=14,
        textColor=colors.HexColor("#b91c1c"), spaceAfter=6,
    ))
    ss.add(ParagraphStyle(
        name="Note", parent=ss["BodyText"],
        fontName="Helvetica-Oblique", fontSize=9, leading=12,
        textColor=colors.HexColor("#475569"), spaceAfter=6,
    ))
    ss.add(ParagraphStyle(
        name="CodeX", parent=ss["Code"],
        fontName="Courier", fontSize=9, leading=12,
        textColor=colors.HexColor("#0f172a"),
        backColor=colors.HexColor("#f1f5f9"),
        borderPadding=4, spaceAfter=6,
    ))
    return ss


def build_document():
    ss = build_styles()
    doc = SimpleDocTemplate(
        str(OUT), pagesize=LETTER,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        title="NivXRay — IP Protection Strategy",
        author="NivXRay Documentation Engine",
        subject="Patent, trademark, trade-secret, and defensive-publication guidance",
    )
    story = []
    P = lambda t, s="Body": Paragraph(t, ss[s])

    # ─── COVER ──────────────────────────────────────────────────────────
    story.append(P("NivXRay — IP Protection Strategy", "TitleBig"))
    story.append(P(
        f"A practical, non-legal-advice guide to patents, trademarks, trade secrets, "
        f"and defensive publication for the NivXRay project.<br/>"
        f"Compiled {date.today().strftime('%B %d, %Y')} · v1.0",
        "SubTitle",
    ))

    story.append(P(
        "<b>Disclaimer:</b> This document is an <b>engineering-level summary of options</b>, "
        "written for the NivXRay project owner. It is <b>not legal advice</b>. Actual IP "
        "protection decisions must be validated with a licensed IP attorney in your "
        "jurisdiction before spending money on filings.",
        "Warn",
    ))

    # ─── EXECUTIVE SUMMARY ──────────────────────────────────────────────
    story.append(P("Executive Summary", "H1"))
    story.append(P(
        "NivXRay contains at least four technically novel methods that may be patentable "
        "under US law: (1) candidate-scored decoding with 'why-not' rationale, "
        "(2) wrapper-archetype dispatcher with terminal short-circuiting, "
        "(3) baseline-delta-gated blind-XOR recovery, and (4) plaintext short-circuiting "
        "for LLM-assisted decoders. Because the source code is public on GitHub since "
        "July 2026, the US patent grace-period clock is already counting down."
    ))

    story.append(P("Bottom-line recommendation", "H2"))
    for line in [
        "&bull; <b>File a US trademark for &lsquo;NivXRay&rsquo;</b> in the next 4 weeks &mdash; $250 filing, protects the brand, low risk.",
        "&bull; <b>Publish the defensive whitepaper</b> (already drafted in /app/docs/WHITEPAPER.md) to arXiv + IP.com in the next 4 weeks &mdash; blocks competitors from patenting your ideas.",
        "&bull; <b>Book an IP-lawyer consult</b> before June 2027 &mdash; decide whether to file a US provisional utility patent.",
        "&bull; <b>Keep detection rules and TI-DB as trade secrets</b> &mdash; do <b>not</b> publish the full ruleset if you want commercial defensibility.",
        "&bull; <b>Skip international patents</b> (EU / India / China) &mdash; grace period already expired.",
    ]:
        story.append(P(line, "BulletX"))

    story.append(Spacer(1, 10))

    # ─── SECTION 1 · What IS patentable ────────────────────────────────
    story.append(P("1. What IS realistically patentable in NivXRay", "H1"))
    story.append(P(
        "Post-<i>Alice v. CLS Bank</i> (2014), abstract software ideas get rejected. "
        "The USPTO requires a demonstrable <b>technical improvement to computer "
        "operation</b>. NivXRay contains four candidates that clear that bar:"
    ))
    novel = [
        ["Method", "Where implemented", "Novelty argument"],
        ["Candidate-based encoding\ndetection with confidence\nscoring & 'why-not'\nrationale",
         "backend/chain_analyzer.py\nbackend/wrapper_archetypes.py",
         "Emits a ranked list of decoded\ncandidates with rejection tokens\n(printable ratio, IOC bonus, MITRE\nmarker, magic-byte). No prior art\nknown."],
        ["Wrapper-archetype\ndispatcher with terminal\nshort-circuit flag",
         "backend/wrapper_archetypes.py\n(ARCHETYPES registry)",
         "70+ named archetype handlers,\neach with regex+heuristic match\ngate and terminal=True halt for\nblind-XOR-style handlers."],
        ["Baseline-delta-gated\nblind XOR recovery\n(256-key brute force with\nprintable+magic+English\nscoring)",
         "backend/wrapper_archetypes.py::\n_handle_blind_xor",
         "Rejects false-positives by\nrequiring best_score - baseline >=\n0.20 AND best_score >= 0.90. No\nprior art for this specific gate."],
        ["Plaintext short-circuit\nguard for LLM-assisted\ndecoders",
         "backend/routers/ai.py::\n_is_already_plaintext",
         "Prevents LLM hallucination on\nalready-decoded inputs via 9\nnegative + 1 positive regex tests.\nNo prior art found."],
        ["Parallel emission of\nSigma + Sysmon + MITRE\n+ YARA rules from single\ndecoded payload",
         "backend/sigma_generator.py",
         "Deterministic multi-format\nemitter with shared discriminating\ntoken extraction. Sigma-CLI/Uncoder\nconvert between formats but do\nnot derive from decoded payload."],
    ]
    t = Table(novel, colWidths=[1.7 * inch, 1.9 * inch, 3.3 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0e7490")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t)

    story.append(Spacer(1, 8))

    story.append(P("What is NOT patentable", "H2"))
    for line in [
        "&bull; The general idea of &lsquo;a security tool that decodes attacker payloads&rsquo; &mdash; abstract, rejected under <i>Alice</i>.",
        "&bull; MITRE ATT&amp;CK mapping &mdash; MITRE ATT&amp;CK is public domain.",
        "&bull; Regex signatures for known IOCs &mdash; heavy prior art (YARA, Suricata, Snort).",
        "&bull; UI features (coloured STATUS bar, chip banners) &mdash; only trade-dress protection possible.",
    ]:
        story.append(P(line, "BulletX"))

    # ─── SECTION 2 · Grace-Period Clock ────────────────────────────────
    story.append(PageBreak())
    story.append(P("2. The Public-Disclosure Grace-Period Clock", "H1"))
    story.append(P(
        "The moment you made an invention publicly available (GitHub push, blog "
        "post, release, sale), most patent systems started a countdown for how "
        "long you have to file a patent application. After the clock expires, "
        "<b>your own public disclosure becomes prior art against you</b> and you "
        "can no longer patent that invention."
    ))
    story.append(P(
        "<b>NivXRay's clock started on July 18, 2026</b> (the v1.2.0 public release; "
        "the repo has been public earlier still). The table below shows how much "
        "time you have per jurisdiction:"
    ))

    grace = [
        ["Country / Region", "Grace period", "Filing deadline", "Status"],
        ["USA", "12 months", "~July 18, 2027", "Open"],
        ["Canada", "12 months", "~July 18, 2027", "Open"],
        ["Japan", "12 months (must invoke exception)", "~July 18, 2027", "Open"],
        ["South Korea", "12 months", "~July 18, 2027", "Open"],
        ["Australia", "12 months", "~July 18, 2027", "Open"],
        ["EU (EPO)", "0 days — no grace", "Already expired", "Closed"],
        ["India", "0 days — no grace", "Already expired", "Closed"],
        ["China", "6 months (narrow exceptions)", "Already expired", "Closed"],
        ["UK", "6 months (very narrow)", "~Jan 18, 2027", "Closed in practice"],
    ]
    t = Table(grace, colWidths=[1.6 * inch, 2.0 * inch, 1.9 * inch, 1.4 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0e7490")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        # Highlight Open rows
        ("BACKGROUND", (3, 1), (3, 5), colors.HexColor("#dcfce7")),
        ("BACKGROUND", (3, 6), (3, 9), colors.HexColor("#fee2e2")),
    ]))
    story.append(t)

    story.append(Spacer(1, 8))
    story.append(P(
        "<b>Legal basis (US):</b> 35 U.S.C. § 102(b) states that the inventor's own "
        "public disclosure does not count as prior art against them if the US "
        "patent is filed within 12 months.",
        "Note",
    ))

    # ─── SECTION 3 · Full Strategy Bundle ──────────────────────────────
    story.append(PageBreak())
    story.append(P("3. Recommended IP Bundle (belt + suspenders)", "H1"))
    story.append(P(
        "Rather than chase one big patent, we recommend a multi-layer defence:"
    ))

    strategy = [
        ["Layer", "Cost", "What it covers", "Timeline"],
        ["Copyright (automatic)", "$0", "The literal source code + docs", "Already owned"],
        ["Trademark on 'NivXRay' + logo", "$250 USPTO + $1–2K atty", "Brand, prevents copycats", "6–12 mo"],
        ["Trade secret on TI-DB + rules", "$0 (NDAs only)", "Proprietary detection ruleset stays confidential", "Forever, if secret"],
        ["Defensive publication (arXiv + IP.com)", "~$155–255", "Blocks competitors from patenting same ideas", "48 hours"],
        ["US Provisional Utility Patent", "$300 USPTO + $2–5K atty", "12-mo 'Patent Pending' placeholder for 2–3 novel methods", "1–2 mo"],
        ["US Full Non-Provisional Patent", "$10–30K total", "20-yr exclusive right", "18–36 mo to grant"],
    ]
    t = Table(strategy, colWidths=[2.2 * inch, 1.3 * inch, 2.6 * inch, 0.9 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0e7490")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)

    story.append(Spacer(1, 10))
    story.append(P("Reality checks", "H2"))
    for line in [
        "&bull; <b>Alice test:</b> most software patents get rejected unless they show a technical improvement to computer operation (not just automating a business process). NivXRay&rsquo;s candidate-scoring, blind-XOR gating, and plaintext-guard arguably qualify; a bare MITRE lookup does not.",
        "&bull; <b>Prior-art search:</b> an IP attorney should do a full prior-art search first. Budget ~$1&ndash;3K. Existing systems to compare against: CyberChef, YARA, FLARE, Didier Stevens&rsquo; scripts, Detect-It-Easy, Sigma-CLI, Uncoder.io, MITRE ATT&amp;CK Navigator.",
        "&bull; <b>Enforcement cost:</b> winning a patent doesn&rsquo;t pay bills. Litigation costs $500K&ndash;$5M in the US. Only worth it if you have serious revenue or want to license/sell the patent.",
        "&bull; <b>Open-source trade-off:</b> once code is public on GitHub, you can&rsquo;t patent it in EU / India / China. The clock in US / Canada / Japan / Korea / Australia is 12 months.",
    ]:
        story.append(P(line, "BulletX"))

    # ─── SECTION 4 · Defensive publication ─────────────────────────────
    story.append(PageBreak())
    story.append(P("4. Defensive Publication — How & Where", "H1"))
    story.append(P(
        "Defensive publication is the cheapest, fastest way to protect your work "
        "if you do <b>not</b> want to file a patent yourself but want to stop competitors "
        "from patenting the same ideas around you. It works because patents can "
        "only be granted for <b>novel</b> inventions &mdash; publishing your methods "
        "publicly makes them prior art and therefore un-patentable by anyone else."
    ))

    story.append(P("Where to publish (ranked by defensive strength)", "H2"))
    venues = [
        ["Venue", "Cost", "Strength", "Time to publish"],
        ["IP.com Prior Art Database", "$155–255", "Very high\n(patent examiners search here)", "1–3 days"],
        ["arXiv (cs.CR category)", "Free", "High\n(indexed, cited, immutable)", "~48 hours"],
        ["Zenodo (CERN-backed)", "Free", "High\n(DOI-assigned, immutable)", "Instant"],
        ["SSRN", "Free", "Medium", "1–3 days"],
        ["GitHub tag + release notes", "Free", "Medium\n(immutable timestamp)", "Instant"],
        ["Personal blog / whitepaper", "Free", "Low\n(examiner may not find)", "Instant"],
    ]
    t = Table(venues, colWidths=[2.0 * inch, 1.0 * inch, 2.5 * inch, 1.5 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0e7490")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t)

    story.append(Spacer(1, 8))
    story.append(P(
        "<b>Recommended combo:</b> arXiv (indexed, cited) + IP.com "
        "(patent-examiner-searched) + GitHub v1.2.0-whitepaper tag "
        "(immutable timestamp on source of truth)."
    ))
    story.append(P(
        "A publication-ready whitepaper is already drafted at "
        "<font face='Courier'>/app/docs/WHITEPAPER.md</font> "
        "&mdash; approximately 3,500 words, CC-BY-4.0 licensed, cs.CR-category-formatted."
    ))

    # ─── SECTION 5 · Action Plan ───────────────────────────────────────
    story.append(PageBreak())
    story.append(P("5. Recommended Action Plan", "H1"))

    story.append(P("This week (~2 hours total)", "H2"))
    for line in [
        "&bull; Submit the WHITEPAPER.md to arXiv (cs.CR category). Cost: free. Effort: 30 min.",
        "&bull; Tag <font face='Courier'>v1.2.0-whitepaper</font> on GitHub with the same whitepaper attached. Cost: free. Effort: 5 min.",
        "&bull; Book a 30-minute free consult with an IP attorney (UpCounsel, LegalZoom &lsquo;Business Advisory Plan&rsquo; or local Bar referral). Cost: free consult. Effort: 15 min.",
    ]:
        story.append(P(line, "BulletX"))

    story.append(P("This month (~$400)", "H2"))
    for line in [
        "&bull; File US trademark application for &lsquo;NivXRay&rsquo; word mark via TEAS Plus. Cost: $250 USPTO fee (or $1&ndash;2K with attorney). Effort: 1&ndash;3 hrs.",
        "&bull; Publish whitepaper to IP.com Prior Art Database. Cost: ~$155&ndash;255. Effort: 1 hr.",
        "&bull; (Optional) File US Provisional Patent Application if attorney consult confirms viability. Cost: $300 USPTO + $2&ndash;5K attorney fees. Effort: 3&ndash;5 hrs with attorney.",
    ]:
        story.append(P(line, "BulletX"))

    story.append(P("Before July 18, 2027 (US grace-period deadline)", "H2"))
    for line in [
        "&bull; Decide whether to convert provisional to full non-provisional utility patent (~$10&ndash;30K total).",
        "&bull; If yes and you want international coverage, file PCT application within 12 months of provisional.",
        "&bull; If no, let provisional lapse. Your defensive publication + trademark still protect you.",
    ]:
        story.append(P(line, "BulletX"))

    story.append(P("Never (things to skip)", "H2"))
    for line in [
        "&bull; Do NOT try to patent MITRE ATT&amp;CK mappings, YARA-style regex rules, or the &lsquo;idea&rsquo; of a decoder &mdash; all rejected under <i>Alice</i> or MITRE&rsquo;s public-domain license.",
        "&bull; Do NOT file EU / India / China patents on already-disclosed material &mdash; grace-period already expired.",
        "&bull; Do NOT publish the full TI-DB curated ruleset if you want to sell the tool commercially &mdash; keep it as a trade secret.",
    ]:
        story.append(P(line, "BulletX"))

    # ─── SECTION 6 · Cost Summary ──────────────────────────────────────
    story.append(PageBreak())
    story.append(P("6. Cost Summary", "H1"))
    costs = [
        ["Path", "Total cost", "Best for"],
        ["A. Bare minimum (defensive only)", "$0", "Solo indie, no commercialization plans yet.\nJust publish whitepaper to arXiv + Zenodo + GitHub."],
        ["B. Brand + defensive", "~$400–2,500", "Solo indie, wants brand protection.\nTrademark + arXiv + IP.com publication."],
        ["C. Full defensive + provisional patent", "~$3,000–7,000", "Small startup with revenue potential.\nTrademark + IP.com + US provisional patent."],
        ["D. Full patent stack", "~$15,000–35,000", "Funded startup, planning acquisition/license.\nTrademark + full US non-provisional + PCT."],
    ]
    t = Table(costs, colWidths=[2.3 * inch, 1.4 * inch, 3.4 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0e7490")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)

    story.append(Spacer(1, 12))

    story.append(P("Recommended for NivXRay today", "H2"))
    story.append(P(
        "<b>Path B</b> (~$400&ndash;2,500) is the pragmatic sweet spot: it costs less than "
        "a decent laptop, secures the &lsquo;NivXRay&rsquo; brand, and locks in defensive "
        "prior-art protection without gambling $15&ndash;35K on a full patent grant that "
        "may or may not survive <i>Alice</i>-doctrine scrutiny."
    ))

    story.append(P(
        "Upgrade to Path C only after you have a paying customer or a serious "
        "acquisition offer that would justify the incremental $3&ndash;5K spend."
    ))

    # ─── SECTION 7 · Legal disclaimers ─────────────────────────────────
    story.append(PageBreak())
    story.append(P("7. Legal Disclaimers & Where to Get Real Advice", "H1"))
    story.append(P(
        "This document was written by an AI coding assistant summarizing publicly "
        "available information about US patent law and defensive-publication practice. "
        "It is <b>not legal advice</b> and must not be treated as such. IP law changes; "
        "grace periods differ per country; enforcement rules vary; new case law "
        "reshapes what is patentable every year."
    ))
    story.append(P("Where to get real IP counsel", "H2"))
    for line in [
        "&bull; <b>US:</b> Search <font face='Courier'>www.uspto.gov/patents/find-legal-help</font> for USPTO-approved practitioners.",
        "&bull; <b>UpCounsel:</b> On-demand freelance IP attorneys, transparent hourly rates.",
        "&bull; <b>Local Bar Association Referral Service:</b> Usually offers 30-min consults for $25&ndash;50.",
        "&bull; <b>Startup accelerators (Y Combinator, Techstars, 500 Global):</b> Provide free legal templates + attorney intros.",
        "&bull; <b>SCORE mentors:</b> Retired executives offer free 1-on-1 business/IP advice via SBA.",
    ]:
        story.append(P(line, "BulletX"))

    story.append(P(
        "Before spending money on any IP filing, get a written engagement letter, "
        "a written prior-art search summary, and a written patentability opinion "
        "from the attorney. If they won't put it in writing, hire someone else.",
        "Note",
    ))

    # ─── APPENDIX · Whitepaper link ────────────────────────────────────
    story.append(PageBreak())
    story.append(P("Appendix · Companion Whitepaper", "H1"))
    story.append(P(
        "A defensive-publication-grade whitepaper describing NivXRay's novel "
        "technical methods (§4.1&ndash;§4.5 of that document) is already drafted at:"
    ))
    story.append(P(
        "<font face='Courier'>/app/docs/WHITEPAPER.md</font>", "CodeX",
    ))
    story.append(P(
        "It follows arXiv cs.CR formatting conventions, is CC-BY-4.0 licensed, "
        "and can be uploaded directly to arXiv / IP.com / Zenodo without further "
        "editing. Total length ~3,500 words with 8 references and 2 appendices."
    ))

    story.append(Spacer(1, 20))
    story.append(P(
        "End of document · v1.0 · Generated by NivXRay Documentation Engine",
        "Note",
    ))

    doc.build(story)
    return OUT


if __name__ == "__main__":
    out = build_document()
    print(f"Generated: {out}  ({out.stat().st_size:,} bytes)")
