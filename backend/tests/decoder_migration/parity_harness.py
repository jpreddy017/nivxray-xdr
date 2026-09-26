"""Reusable parity harness for Gate 2D-B3 codec migration.

Compares a *reference* implementation against a *candidate*
implementation on identical fixture inputs and produces a
machine-readable, deterministic report.

Design invariants (owner-locked, Gate 2D-B3):
    - byte-identical decoded output where applicable
    - identical logical layer sequence (stage names, in order)
    - identical malformed/partial behaviour (both accept OR both reject)
    - provenance parity: static_only=True, execution=False,
      attck_promotion=False, network_access=False must be preserved
    - latency reporting (per-fixture pre vs post, aggregate p50/p95/p99)
    - never fabricates a decode; never accepts new inputs to
      inflate metrics

The harness is INTENTIONALLY dumb about which side is "correct" —
its only job is to detect *any* observable divergence.  Human review
adjudicates whether a divergence is a bug or an authorised
improvement (which must be explicitly documented per the B3 rules).
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

# ── Fixture root (canonical) ─────────────────────────────────────
FIXTURES_ROOT = Path(__file__).resolve().parents[1] / "fixtures"

# ── Codec capability taxonomy (7 codecs + 2 analyzers) ───────────
CODEC_CAPABILITIES = (
    "gzip",
    "zlib_deflate",
    "xor",
    "repeating_key_xor",
    "rc4",
    "aes_cbc",
    "utf16le",
)
ANALYZER_CAPABILITIES = (
    "pe",
    "shellcode",
)


# ── Data models ──────────────────────────────────────────────────
@dataclass(frozen=True)
class FixtureRecord:
    """Fully-hashed record of a fixture input."""

    fixture_id: str
    path: str
    size_bytes: int
    input_sha256: str
    codec_hints: tuple[str, ...]      # from filename heuristic
    expected_present: bool
    expected_sha256: Optional[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "fixture_id": self.fixture_id,
            "path": self.path,
            "size_bytes": self.size_bytes,
            "input_sha256": self.input_sha256,
            "codec_hints": list(self.codec_hints),
            "expected_present": self.expected_present,
            "expected_sha256": self.expected_sha256,
        }


@dataclass(frozen=True)
class DecodeSnapshot:
    """One end-to-end decode result under a specific implementation."""

    fixture_id: str
    implementation: str               # "reference" | "candidate"
    ok: bool                          # False iff exception raised
    exception: Optional[str]          # exception class name, if any
    final_text: Optional[str]         # None on exception
    final_sha256: Optional[str]
    final_bytes_len: Optional[int]
    layer_sequence: tuple[str, ...]   # stage names in order
    layer_count: int
    layers_detail: tuple[dict[str, Any], ...]
    latency_ms: float
    provenance: dict[str, Any]        # static_only / execution / etc.
    peeled_any: bool                  # final != input

    def to_dict(self) -> dict[str, Any]:
        return {
            "fixture_id": self.fixture_id,
            "implementation": self.implementation,
            "ok": self.ok,
            "exception": self.exception,
            "final_text": self.final_text,
            "final_sha256": self.final_sha256,
            "final_bytes_len": self.final_bytes_len,
            "layer_sequence": list(self.layer_sequence),
            "layer_count": self.layer_count,
            "layers_detail": list(self.layers_detail),
            "latency_ms": self.latency_ms,
            "provenance": self.provenance,
            "peeled_any": self.peeled_any,
        }


@dataclass
class ParityMismatch:
    fixture_id: str
    kind: str                         # output | layer_sequence | provenance | exception | length
    reference: Any
    candidate: Any
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ParityReport:
    total_fixtures: int
    applicable_fixtures: int
    matched: int
    mismatched: int
    mismatches: list[ParityMismatch] = field(default_factory=list)
    latency_reference_ms: dict[str, float] = field(default_factory=dict)
    latency_candidate_ms: dict[str, float] = field(default_factory=dict)
    per_codec_counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_fixtures": self.total_fixtures,
            "applicable_fixtures": self.applicable_fixtures,
            "matched": self.matched,
            "mismatched": self.mismatched,
            "mismatches": [m.to_dict() for m in self.mismatches],
            "latency_reference_ms": self.latency_reference_ms,
            "latency_candidate_ms": self.latency_candidate_ms,
            "per_codec_counts": self.per_codec_counts,
        }


# ── Codec hint inference (filename heuristic, deterministic) ─────
def infer_codec_hints(name: str) -> tuple[str, ...]:
    """Return codec-capability hints suggested by the fixture name.

    The heuristic is intentionally conservative: it labels a fixture
    with a codec ONLY when the filename mentions the codec's
    canonical short-form (gzip, zlib, deflate, xor, rc4, aes,
    utf16le, encodedcommand, shellcode, pe).  It never claims a
    fixture as "applicable" to a codec purely from content sniffing —
    that is the reference-implementation's job.
    """
    n = name.lower()
    hints: list[str] = []
    if "gzip" in n:
        hints.append("gzip")
    if "zlib" in n or "deflate" in n:
        hints.append("zlib_deflate")
    if "xor" in n:
        # Distinguish repeating-key XOR (multi-byte key) shape names.
        if "multi" in n or "multiline" in n or "repeating" in n:
            hints.append("repeating_key_xor")
        else:
            hints.append("xor")
    if "rc4" in n:
        hints.append("rc4")
    if "aes" in n:
        hints.append("aes_cbc")
    if "utf16le" in n or "encodedcommand" in n:
        hints.append("utf16le")
    if "shellcode" in n:
        hints.append("shellcode")
    if "_pe_" in n or n.startswith("pe_") or "pe_dotnet" in n or "reflection_assembly" in n:
        hints.append("pe")
    # de-dup, preserve order
    seen: set[str] = set()
    ordered: list[str] = []
    for h in hints:
        if h not in seen:
            seen.add(h)
            ordered.append(h)
    return tuple(ordered)


def _sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", errors="surrogatepass")
    return hashlib.sha256(data).hexdigest()


def enumerate_fixtures() -> list[FixtureRecord]:
    """Enumerate all .txt fixtures under FIXTURES_ROOT.

    Excludes .expected.txt sidecars and non-.txt (jsonl / evtx /
    plugin_regression / regression_baseline / mixed_investigation_input).
    """
    records: list[FixtureRecord] = []
    for p in sorted(FIXTURES_ROOT.iterdir()):
        if not p.is_file():
            continue
        if not p.name.endswith(".txt"):
            continue
        if p.name.endswith(".expected.txt"):
            continue
        raw = p.read_bytes()
        # Reference txt fixtures should be UTF-8; if not, we still
        # capture the byte-level hash for parity.
        exp_path = p.with_suffix(".expected.txt")
        exp_sha: Optional[str] = None
        if exp_path.exists():
            exp_sha = _sha256_hex(exp_path.read_bytes())
        records.append(FixtureRecord(
            fixture_id=p.stem,
            path=str(p.relative_to(FIXTURES_ROOT)),
            size_bytes=len(raw),
            input_sha256=_sha256_hex(raw),
            codec_hints=infer_codec_hints(p.name),
            expected_present=exp_path.exists(),
            expected_sha256=exp_sha,
        ))
    return records


# ── Snapshot capture ─────────────────────────────────────────────
def _static_provenance() -> dict[str, Any]:
    """Baseline provenance envelope every decode layer MUST satisfy."""
    return {
        "static_only": True,
        "execution": False,
        "network_access": False,
        "attck_promotion": False,
    }


def snapshot_reference(
    fixture: FixtureRecord,
    text: str,
    peel_fn: Callable[..., tuple[str, list[dict[str, Any]]]],
) -> DecodeSnapshot:
    """Invoke the reference decoder (recursive_decoder.peel_recursively)
    and produce a deterministic snapshot."""
    t0 = time.perf_counter()
    exception: Optional[str] = None
    final_text: Optional[str] = None
    layers: list[dict[str, Any]] = []
    try:
        final_text, layers = peel_fn(text)
    except Exception as exc:  # never crash the harness
        exception = type(exc).__name__
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    layer_seq = tuple(str(lyr.get("stage") or "") for lyr in layers)
    # Reduce layers_detail to serialisable + stable form.
    reduced: list[dict[str, Any]] = []
    for lyr in layers:
        stage = str(lyr.get("stage") or "")
        reduced.append({
            "stage": stage,
            "layer": lyr.get("layer"),
            "bytes_in": lyr.get("bytes_in"),
            "bytes_out": lyr.get("bytes_out"),
            # elapsed_ms omitted from the stable snapshot on purpose —
            # timing is machine-dependent and would create false
            # diffs.  It is captured separately in latency_*_ms.
            "meta_keys": sorted(list((lyr.get("meta") or {}).keys())),
        })

    return DecodeSnapshot(
        fixture_id=fixture.fixture_id,
        implementation="reference",
        ok=exception is None,
        exception=exception,
        final_text=final_text,
        final_sha256=(_sha256_hex(final_text) if final_text is not None else None),
        final_bytes_len=(len(final_text.encode("utf-8", errors="surrogatepass"))
                         if final_text is not None else None),
        layer_sequence=layer_seq,
        layer_count=len(layers),
        layers_detail=tuple(reduced),
        latency_ms=elapsed_ms,
        provenance=_static_provenance(),
        peeled_any=(final_text is not None and final_text != text),
    )


# ── Parity comparison ────────────────────────────────────────────
def compare(
    reference: DecodeSnapshot,
    candidate: DecodeSnapshot,
) -> list[ParityMismatch]:
    """Emit one mismatch per observable divergence.  Empty list == parity."""
    out: list[ParityMismatch] = []
    fid = reference.fixture_id
    if reference.ok != candidate.ok:
        out.append(ParityMismatch(
            fixture_id=fid, kind="exception",
            reference=reference.exception, candidate=candidate.exception,
            detail="one side raised while the other did not"))
        return out  # can't compare payloads if one side crashed
    if reference.exception != candidate.exception:
        out.append(ParityMismatch(
            fixture_id=fid, kind="exception",
            reference=reference.exception, candidate=candidate.exception))
    if reference.final_sha256 != candidate.final_sha256:
        out.append(ParityMismatch(
            fixture_id=fid, kind="output",
            reference=reference.final_sha256, candidate=candidate.final_sha256,
            detail=f"len ref={reference.final_bytes_len} cand={candidate.final_bytes_len}"))
    if reference.layer_sequence != candidate.layer_sequence:
        out.append(ParityMismatch(
            fixture_id=fid, kind="layer_sequence",
            reference=list(reference.layer_sequence),
            candidate=list(candidate.layer_sequence)))
    # provenance parity (must never regress)
    for key in ("static_only", "execution", "network_access", "attck_promotion"):
        r = reference.provenance.get(key)
        c = candidate.provenance.get(key)
        if r != c:
            out.append(ParityMismatch(
                fixture_id=fid, kind="provenance",
                reference={key: r}, candidate={key: c}))
    return out


# ── Report I/O ───────────────────────────────────────────────────
def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False))
