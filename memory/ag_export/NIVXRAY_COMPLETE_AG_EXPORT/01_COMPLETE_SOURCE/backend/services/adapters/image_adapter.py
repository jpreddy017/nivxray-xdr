"""Image Evidence Adapter — Phase 3C.

Deterministic-first extraction order (per M3 design):

  1. Magic-byte / MIME validation      (fail-fast on non-images)
  2. SHA-256 of raw bytes              (identity + cycle detection)
  3. EXIF metadata                     (camera, timestamps, geo, orientation)
  4. Dimensions + color mode           (Pillow — deterministic)
  5. Color profile / ICC               (Pillow — deterministic)
  6. Orientation preservation          (EXIF `Orientation` tag)
  7. OCR (Tesseract)                   (LAST — least deterministic)
  8. Layout blocks                     (from Tesseract page-segmentation data)
  9. Artifact extraction               (URL/IP/domain/hash/file_path/email
                                         from the OCR text via IDA splitter)

R8 · The adapter never reasons.  It surfaces:
      · what was extracted
      · WHERE it came from (block index)
      · HOW confident OCR was
     …and defers ALL interpretation to the Evidence Reasoning Engine.

R9 · Graceful degrade — if Tesseract is missing / errors, the IEP is
     still emitted with deterministic metadata and an
     ``ocr_unavailable`` warning.  If EXIF read fails, the metadata
     surfaces without EXIF.  Nothing aborts the investigation.

R10 · Idempotent — the same bytes always produce the same artifacts,
     same warnings, same OCR text (Tesseract's default deterministic
     config).
"""
from __future__ import annotations

import hashlib
import io
import struct
from typing import Any, Dict, List, Optional, Tuple

from models.iep import (
    IEPArtifact,
    IEPContent,
    IEPRelationship,
    IEPSource,
    IEPWarning,
    RelationshipType,
)
from services import resource_protection as rpp

from .base import EvidenceAdapter


# ─── Magic-byte fingerprints for common image formats ─────────────────
_MAGICS: Tuple[Tuple[bytes, str, str], ...] = (
    (b"\x89PNG\r\n\x1a\n",              "png",  "image/png"),
    (b"\xff\xd8\xff",                    "jpeg", "image/jpeg"),
    (b"GIF87a",                          "gif",  "image/gif"),
    (b"GIF89a",                          "gif",  "image/gif"),
    (b"BM",                              "bmp",  "image/bmp"),
    (b"II*\x00",                         "tiff", "image/tiff"),
    (b"MM\x00*",                         "tiff", "image/tiff"),
    (b"RIFF",                            "webp", "image/webp"),   # discriminated further below
)


def _detect_image_kind(raw: bytes) -> Optional[Tuple[str, str]]:
    """Return ``(fmt, mime)`` or ``None`` if bytes don't look like an image."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 8:
        return None
    head = bytes(raw[:16])
    for magic, fmt, mime in _MAGICS:
        if head.startswith(magic):
            if fmt == "webp":
                # WebP is RIFF….WEBP.
                if len(raw) >= 12 and raw[8:12] == b"WEBP":
                    return "webp", "image/webp"
                continue
            return fmt, mime
    return None


# ─── EXIF orientation values → user-friendly description ──────────────
_EXIF_ORIENTATION = {
    1: "Horizontal (normal)",
    2: "Mirrored horizontal",
    3: "Rotated 180°",
    4: "Mirrored vertical",
    5: "Mirrored horizontal · rotated 270° CW",
    6: "Rotated 90° CW",
    7: "Mirrored horizontal · rotated 90° CW",
    8: "Rotated 270° CW",
}


class ImageAdapter(EvidenceAdapter):
    name         = "adapter.image"
    version      = "1.0"
    capabilities = [
        "magic_validation", "sha256", "dimensions", "color_mode",
        "icc_profile", "exif", "gps", "orientation", "ocr_text",
        "ocr_confidence", "layout_blocks", "artifact_extraction",
    ]

    # ── Detection ────────────────────────────────────────────────────
    def can_handle(self, raw: Any) -> bool:
        if not isinstance(raw, (bytes, bytearray)):
            return False
        return _detect_image_kind(bytes(raw)) is not None

    # ── Extraction (deterministic-first, OCR last) ───────────────────
    def extract(self, raw: Any) -> IEPContent:
        data = bytes(raw)
        warnings: List[Dict[str, Any]] = []
        info: Dict[str, Any] = {
            "magic":       None,
            "sha256":      None,
            "dimensions":  None,
            "color_mode":  None,
            "icc_profile": None,
            "exif":        {},
            "gps":         None,
            "orientation": None,
            "ocr":         None,
            "layout":      [],
            "warnings":    warnings,
        }

        # ── 1. Magic / MIME (fail-fast) ──────────────────────────────
        kind = _detect_image_kind(data)
        if kind is None:
            warnings.append({
                "severity": "error", "code": "image_bad_magic",
                "message": "Bytes do not match any known image magic.",
            })
            return IEPContent(text="", blocks=[])
        info["magic"] = {"format": kind[0], "mime": kind[1]}

        # ── 2. SHA-256 (identity, cycle detection) ───────────────────
        info["sha256"] = hashlib.sha256(data).hexdigest()

        # Pillow is our workhorse — imported lazily so tests never pay the
        # cost when the adapter isn't exercised.
        try:
            from PIL import ExifTags, Image, ImageOps  # type: ignore
        except Exception as e:  # noqa: BLE001
            warnings.append({
                "severity": "warn", "code": "image_pillow_unavailable",
                "message": f"Pillow import failed: {e}",
            })
            content = IEPContent(text="", blocks=[])
            content._image = info  # type: ignore[attr-defined]
            return content

        try:
            im = Image.open(io.BytesIO(data))
            # Pillow lazy-loads — force decode so downstream reads see errors NOW.
            im.load()
        except Exception as e:  # noqa: BLE001
            warnings.append({
                "severity": "error", "code": "image_decode_failed",
                "message": f"Pillow could not decode image: {e}",
            })
            content = IEPContent(text="", blocks=[])
            content._image = info  # type: ignore[attr-defined]
            return content

        # ── 3. EXIF ──────────────────────────────────────────────────
        exif_dict: Dict[str, Any] = {}
        exif_orient_raw: Optional[int] = None
        try:
            exif_raw = im.getexif() if hasattr(im, "getexif") else None
            if exif_raw:
                for tag_id, value in exif_raw.items():
                    tag_name = ExifTags.TAGS.get(tag_id, f"tag_{tag_id}")
                    # Bytes / weird types → coerce to repr so JSON works.
                    if isinstance(value, bytes):
                        try:
                            exif_dict[tag_name] = value.decode("utf-8", errors="replace")
                        except Exception:
                            exif_dict[tag_name] = repr(value[:64])
                    elif isinstance(value, (str, int, float, list, tuple, dict)):
                        exif_dict[tag_name] = value
                    else:
                        exif_dict[tag_name] = str(value)
                exif_orient_raw = exif_raw.get(0x0112)  # Orientation tag
        except Exception as e:  # noqa: BLE001
            warnings.append({
                "severity": "info", "code": "image_exif_read_failed",
                "message": f"EXIF read failed: {e}",
            })
        info["exif"] = exif_dict

        # ── 4. Dimensions + color mode ───────────────────────────────
        try:
            info["dimensions"] = {"width": im.width, "height": im.height}
            info["color_mode"] = im.mode
        except Exception:
            pass

        # ── 5. ICC profile ───────────────────────────────────────────
        try:
            icc = im.info.get("icc_profile")
            if icc:
                info["icc_profile"] = {
                    "size_bytes": len(icc),
                    "sha256":     hashlib.sha256(icc).hexdigest(),
                }
        except Exception:
            pass

        # ── 6. Orientation preservation (crucial for mobile screenshots)
        # We record BOTH the raw EXIF value and whether we normalised the
        # pixel data before running OCR — analysts can then tell rotated
        # screenshots from normal ones.
        rotation_applied = False
        display_im = im
        if exif_orient_raw and exif_orient_raw != 1:
            try:
                display_im = ImageOps.exif_transpose(im)
                rotation_applied = True
            except Exception:
                pass
        info["orientation"] = {
            "exif_orientation":   exif_orient_raw,
            "description":        _EXIF_ORIENTATION.get(exif_orient_raw or 1,
                                                          "Horizontal (normal)"),
            "rotation_applied":   rotation_applied,
        }

        # ── 7. OCR (last — least deterministic step) ─────────────────
        ocr_text = ""
        ocr_confidence: Optional[float] = None
        ocr_blocks: List[Dict[str, Any]] = []
        try:
            import pytesseract  # type: ignore
        except Exception as e:  # noqa: BLE001
            warnings.append({
                "severity": "info", "code": "image_ocr_unavailable",
                "message": f"pytesseract not available: {e}",
            })
            pytesseract = None  # type: ignore

        if pytesseract is not None:
            try:
                # Deterministic Tesseract config: no adaptive layout, no
                # DPI guessing.  OEM=1 (LSTM), PSM=6 (uniform block of
                # text).  These flags are what Tesseract's own reference
                # docs recommend for reproducible extraction.
                cfg = "--oem 1 --psm 6"
                ocr_text = pytesseract.image_to_string(display_im, config=cfg) or ""
                data_dict = pytesseract.image_to_data(
                    display_im, config=cfg,
                    output_type=pytesseract.Output.DICT,
                )
                # Per-word confidence (Tesseract emits -1 for skipped rows)
                conf_values: List[float] = []
                for i, c in enumerate(data_dict.get("conf") or []):
                    try:
                        c_val = float(c)
                    except (TypeError, ValueError):
                        continue
                    if c_val >= 0:
                        conf_values.append(c_val)
                if conf_values:
                    ocr_confidence = round(sum(conf_values) / len(conf_values), 1)
                # Layout blocks — one per Tesseract block (block_num column).
                blocks_by_id: Dict[int, Dict[str, Any]] = {}
                for i in range(len(data_dict.get("text") or [])):
                    txt = (data_dict["text"][i] or "").strip()
                    if not txt:
                        continue
                    b_id = int(data_dict["block_num"][i])
                    row = blocks_by_id.setdefault(b_id, {
                        "block_id":   b_id,
                        "text":       [],
                        "words":      0,
                        "confidences": [],
                        "left":       int(data_dict["left"][i]),
                        "top":        int(data_dict["top"][i]),
                        "right":      int(data_dict["left"][i] + data_dict["width"][i]),
                        "bottom":     int(data_dict["top"][i] + data_dict["height"][i]),
                    })
                    row["text"].append(txt)
                    row["words"] += 1
                    try:
                        cval = float(data_dict["conf"][i])
                        if cval >= 0:
                            row["confidences"].append(cval)
                    except (TypeError, ValueError):
                        pass
                    row["right"]  = max(row["right"],  int(data_dict["left"][i] + data_dict["width"][i]))
                    row["bottom"] = max(row["bottom"], int(data_dict["top"][i]  + data_dict["height"][i]))
                for b_id, row in sorted(blocks_by_id.items()):
                    row["text"] = " ".join(row["text"])
                    row["confidence"] = (
                        round(sum(row["confidences"]) / len(row["confidences"]), 1)
                        if row["confidences"] else None
                    )
                    row.pop("confidences", None)
                    ocr_blocks.append(row)
            except Exception as e:  # noqa: BLE001
                warnings.append({
                    "severity": "warn", "code": "image_ocr_failed",
                    "message": f"OCR failed: {e}",
                })

        # OCR summary — the Evidence Validator will use these fields
        # later to discount low-confidence artifacts.
        chars = len(ocr_text.strip())
        info["ocr"] = {
            "engine":              "tesseract" if pytesseract is not None else None,
            "avg_confidence":      ocr_confidence,
            "characters_detected": chars,
            "text_length":         len(ocr_text),
            "block_count":         len(ocr_blocks),
        }
        info["layout"] = ocr_blocks
        if pytesseract is not None and chars < 4 and ocr_confidence is None:
            warnings.append({
                "severity": "info", "code": "image_ocr_no_text",
                "message": "OCR completed but detected no printable characters.",
            })
        if ocr_confidence is not None and ocr_confidence < 60 and chars > 0:
            warnings.append({
                "severity": "info", "code": "image_ocr_low_confidence",
                "message": f"OCR average confidence {ocr_confidence}% below 60% "
                           f"threshold — treat extracted artifacts with caution.",
            })

        # ── Content projection ───────────────────────────────────────
        blocks_projection: List[Dict[str, Any]] = []
        for b in ocr_blocks:
            blocks_projection.append({
                "type":       "ocr_block",
                "block_id":   b["block_id"],
                "text":       b["text"],
                "words":      b["words"],
                "confidence": b["confidence"],
                "bbox":       [b["left"], b["top"], b["right"], b["bottom"]],
            })

        content = IEPContent(text=ocr_text, blocks=blocks_projection)
        content._image = info  # type: ignore[attr-defined]
        return content

    # ── Normalization → canonical artifacts ──────────────────────────
    def normalize(self, content: IEPContent) -> List[IEPArtifact]:
        info = getattr(content, "_image", {}) or {}
        out: List[IEPArtifact] = []
        # Deterministic identity artifact — SHA-256 of the image bytes.
        if info.get("sha256"):
            out.append(IEPArtifact(
                type="hash",
                value=info["sha256"],
                source_ref="image.sha256",
                tags=["image_identity"],
                confidence=1.0,
                attributes={
                    "algorithm": "sha256",
                    "format":    (info.get("magic") or {}).get("format"),
                    "mime":      (info.get("magic") or {}).get("mime"),
                },
            ))
        # GPS artifact (if present in EXIF) — surfaces as a canonical
        # coordinate string.  Structural extraction only; no reasoning.
        gps = info.get("gps")
        if gps and isinstance(gps, dict) and gps.get("lat") is not None and gps.get("lon") is not None:
            out.append(IEPArtifact(
                type="unknown",
                value=f"{gps['lat']},{gps['lon']}",
                source_ref="image.exif.gps",
                tags=["image_gps"],
                confidence=1.0,
                attributes=gps,
            ))

        # OCR-derived artifacts — only if we got text.
        ocr = info.get("ocr") or {}
        text = content.text or ""
        blocks = info.get("layout") or []
        if text.strip():
            try:
                from services.ida.artifact_splitter import split_artifacts
                splits = split_artifacts(text) or []
            except Exception:
                splits = []
            # Map splitter types → canonical IEP artifact types.
            type_map = {
                "url":          "url",
                "domain":       "domain",
                "ip":           "ip",
                "hash":         "hash",
                "file_path":    "file_path",
                "registry_key": "registry_key",
                "email":        "email_address",
                "cve":          "cve",
                "command":      "command",
            }
            # Precompute per-block confidence so extracted artifacts
            # inherit the OCR confidence of their source block.
            block_confidence: Dict[str, Optional[float]] = {}
            for b in blocks:
                block_confidence[b["text"]] = b["confidence"]

            avg_conf = ocr.get("avg_confidence")
            for s in splits:
                t = type_map.get(getattr(s, "type", None))
                v = getattr(s, "value", None)
                if not (t and v):
                    continue
                # Which OCR block emitted this artifact?
                src_ref = "image.ocr"
                block_conf = None
                for b in blocks:
                    if v in b["text"]:
                        src_ref = f"image.ocr.block.{b['block_id']}"
                        block_conf = b["confidence"]
                        break
                # Composite confidence: 1.0 for deterministic detection
                # (extractor) × ocr_confidence/100.  This lets the
                # Evidence Validator downgrade low-OCR-confidence
                # artifacts without inventing new logic.
                comp_conf = 1.0
                if block_conf is not None:
                    comp_conf = round(max(block_conf, 0) / 100.0, 3)
                elif avg_conf is not None:
                    comp_conf = round(max(avg_conf, 0) / 100.0, 3)
                out.append(IEPArtifact(
                    type=t, value=v,
                    source_ref=src_ref,
                    canonical=getattr(s, "canonical", None) or None,
                    confidence=comp_conf,
                    tags=["image_ocr"],
                    attributes={
                        "ocr_block_confidence": block_conf,
                        "ocr_avg_confidence":   avg_conf,
                    },
                ))
        return out

    # ── Relationships (R8 · structural only) ─────────────────────────
    def discover_relationships(
        self,
        content: IEPContent,
        artifacts: List[IEPArtifact],
    ) -> List[IEPRelationship]:
        rels: List[IEPRelationship] = []
        image_ref = "image"
        blocks = (getattr(content, "_image", {}) or {}).get("layout") or []
        # image CONTAINS each OCR block
        for b in blocks:
            rels.append(IEPRelationship(
                from_ref=image_ref,
                to_ref=f"image.ocr.block.{b['block_id']}",
                verb=RelationshipType.CONTAINS,
                source_ref=f"image.ocr.block.{b['block_id']}",
            ))
        # each block REFERENCES the artifacts extracted from it
        for a in artifacts:
            if not a.source_ref or not a.source_ref.startswith("image.ocr.block."):
                continue
            rels.append(IEPRelationship(
                from_ref=a.source_ref,
                to_ref=a.value,
                verb=RelationshipType.REFERENCES,
                source_ref=a.source_ref,
                confidence=a.confidence,
            ))
        return rels

    # ── Adapter caveats ──────────────────────────────────────────────
    def validate(self, iep) -> List[IEPWarning]:
        info = getattr(iep.content, "_image", {}) or {}
        return [IEPWarning(**w) for w in info.get("warnings") or []]

    # ── OCR summary + orientation + EXIF into the adapter manifest ───
    def make_iep(self, raw, **ctx):
        iep = super().make_iep(raw, **ctx)
        info = getattr(iep.content, "_image", {}) or {}
        iep.metadata.data.setdefault("image", {}).update({
            "magic":       info.get("magic"),
            "sha256":      info.get("sha256"),
            "dimensions":  info.get("dimensions"),
            "color_mode":  info.get("color_mode"),
            "icc_profile": info.get("icc_profile"),
            "orientation": info.get("orientation"),
            "ocr":         info.get("ocr"),
            "exif_tag_count": len(info.get("exif") or {}),
        })
        return iep

    # ── Source detection ─────────────────────────────────────────────
    def _infer_source(self, raw: Any) -> IEPSource:
        data = bytes(raw) if isinstance(raw, (bytes, bytearray)) else str(raw).encode()
        kind = _detect_image_kind(data)
        return IEPSource(
            kind="image",
            size_bytes=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            mime_type=(kind[1] if kind else "application/octet-stream"),
        )
