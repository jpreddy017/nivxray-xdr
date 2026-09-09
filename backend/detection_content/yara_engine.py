"""
NivXRay XDR — First-Class YARA Execution & Static Artifact Analysis Engine.
Provides native parsing, byte-pattern scanning, PE/ELF artifact inspection,
and condition evaluation for YARA rules without generic text search flattening.

Feeds: Evidence -> SSOT -> IKG -> Security State -> Verdict pipeline.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import re
import struct
from typing import Any, Dict, List, Optional, Tuple, Set


@dataclass
class YaraStringDefinition:
    identifier: str       # e.g. "$s1", "$hex_prologue"
    str_type: str         # "text", "hex", "regex"
    pattern: bytes        # raw byte pattern
    wildcard_mask: Optional[bytes] = None  # for hex masks with ??
    is_wide: bool = False
    is_nocase: bool = False
    is_ascii: bool = True


@dataclass
class YaraMatchOccurrence:
    identifier: str
    offset: int
    length: int
    matched_data: str


@dataclass
class YaraRuleMatch:
    rule_name: str
    tags: List[str]
    meta: Dict[str, Any]
    matched_strings: List[YaraMatchOccurrence]
    matched_count: int
    threat_family: str
    confidence: float
    mitre_attack: List[str]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_evidence(self, artifact_bytes: bytes, filename: str = "artifact.bin") -> Dict[str, Any]:
        """Convert YARA match into NivXRay Canonical Evidence format."""
        sha256 = hashlib.sha256(artifact_bytes).hexdigest()
        md5 = hashlib.md5(artifact_bytes).hexdigest()
        return {
            "evidence_type": "artifact_yara_detection",
            "artifact": {
                "filename": filename,
                "size": len(artifact_bytes),
                "sha256": sha256,
                "md5": md5,
            },
            "yara_match": {
                "rule_name": self.rule_name,
                "threat_family": self.threat_family,
                "confidence": self.confidence,
                "tags": self.tags,
                "meta": self.meta,
                "matched_strings": [asdict(m) for m in self.matched_strings],
                "mitre_attack": self.mitre_attack,
            },
            "security_state_impact": {
                "proven_capability": "malware_artifact_delivery",
                "family": self.threat_family,
                "confidence_score": self.confidence,
            },
            "timestamp": self.timestamp,
        }


class YaraRule:
    """Represents a compiled, deterministic YARA detection rule."""

    def __init__(
        self,
        name: str,
        meta: Optional[Dict[str, Any]] = None,
        strings: Optional[List[YaraStringDefinition]] = None,
        condition_str: str = "any of them",
        tags: Optional[List[str]] = None,
        raw_text: str = "",
    ):
        self.name = name
        self.meta = meta or {}
        self.strings = strings or []
        self.condition_str = condition_str.strip()
        self.tags = tags or []
        self.raw_text = raw_text

    def evaluate(self, data: bytes) -> Optional[YaraRuleMatch]:
        if not isinstance(data, (bytes, bytearray)):
            return None
        data = bytes(data)
        data_len = len(data)

        matched_occurrences: List[YaraMatchOccurrence] = []
        string_matches: Dict[str, List[YaraMatchOccurrence]] = {}

        for sdef in self.strings:
            hits = self._search_string(data, sdef)
            if hits:
                string_matches[sdef.identifier] = hits
                matched_occurrences.extend(hits)

        # Condition Evaluation
        cond_lower = self.condition_str.lower()
        is_matched = False

        if "filesize" in cond_lower:
            # Check basic filesize heuristic
            m = re.search(r'filesize\s*(<|>|<=|>=|==)\s*(\d+)', cond_lower)
            if m:
                op, val = m.group(1), int(m.group(2))
                if op == "<" and not (data_len < val): return None
                if op == ">" and not (data_len > val): return None
                if op == "<=" and not (data_len <= val): return None
                if op == ">=" and not (data_len >= val): return None
                if op == "==" and not (data_len == val): return None

        if "uint16(0)" in cond_lower:
            # Check PE Magic MZ
            if data_len < 2 or data[:2] != b"MZ":
                return None

        if "uint32(0)" in cond_lower:
            # Check ELF Magic \x7fELF
            if data_len < 4 or data[:4] != b"\x7fELF":
                return None

        if cond_lower in ("any of them", "any of them and filesize < 10mb"):
            is_matched = len(string_matches) > 0
        elif cond_lower.startswith("all of them"):
            is_matched = len(string_matches) == len(self.strings) and len(self.strings) > 0
        elif " of them" in cond_lower:
            m = re.search(r'(\d+)\s+of\s+them', cond_lower)
            if m:
                needed = int(m.group(1))
                is_matched = len(string_matches) >= needed
            else:
                is_matched = len(string_matches) > 0
        elif cond_lower in ("true", "1"):
            is_matched = True
        else:
            # Identifier-based condition: e.g. "$s1 and ($s2 or $s3)"
            eval_ctx = {s.identifier: (s.identifier in string_matches) for s in self.strings}
            is_matched = self._eval_boolean_expr(self.condition_str, eval_ctx)

        if not is_matched:
            return None

        # Extract meta intelligence
        threat_fam = str(self.meta.get("threat_family", self.meta.get("family", self.meta.get("malware", "UnknownMalware"))))
        conf = float(self.meta.get("confidence", 0.90))
        mitre = self.meta.get("mitre_attack", [])
        if isinstance(mitre, str):
            mitre = [mitre]

        return YaraRuleMatch(
            rule_name=self.name,
            tags=self.tags,
            meta=self.meta,
            matched_strings=matched_occurrences,
            matched_count=len(matched_occurrences),
            threat_family=threat_fam,
            confidence=conf,
            mitre_attack=mitre,
        )

    def _search_string(self, data: bytes, sdef: YaraStringDefinition) -> List[YaraMatchOccurrence]:
        hits: List[YaraMatchOccurrence] = []
        if sdef.str_type == "hex" and sdef.wildcard_mask:
            # Wildcard mask search
            pattern = sdef.pattern
            mask = sdef.wildcard_mask
            pat_len = len(pattern)
            for i in range(0, len(data) - pat_len + 1):
                chunk = data[i:i + pat_len]
                match = True
                for b_c, b_p, m in zip(chunk, pattern, mask):
                    if m and b_c != b_p:
                        match = False
                        break
                if match:
                    hits.append(YaraMatchOccurrence(
                        identifier=sdef.identifier,
                        offset=i,
                        length=pat_len,
                        matched_data=chunk.hex().upper(),
                    ))
                    if len(hits) >= 10: break
            return hits

        # Text search (ASCII and/or Wide)
        patterns_to_test: List[bytes] = []
        if sdef.is_ascii:
            patterns_to_test.append(sdef.pattern)
        if sdef.is_wide:
            # UTF-16LE encoding
            try:
                patterns_to_test.append(sdef.pattern.decode('latin-1').encode('utf-16le'))
            except Exception:
                pass

        for pat in patterns_to_test:
            if sdef.is_nocase:
                haystack = data.lower()
                needle = pat.lower()
            else:
                haystack = data
                needle = pat

            start = 0
            while True:
                idx = haystack.find(needle, start)
                if idx == -1:
                    break
                raw_match = data[idx:idx + len(pat)]
                hits.append(YaraMatchOccurrence(
                    identifier=sdef.identifier,
                    offset=idx,
                    length=len(pat),
                    matched_data=raw_match.decode('latin-1', errors='replace'),
                ))
                start = idx + 1
                if len(hits) >= 10:
                    break

        return hits

    @staticmethod
    def _eval_boolean_expr(expr: str, ctx: Dict[str, bool]) -> bool:
        # Safe deterministic boolean expression evaluation
        tokens = expr.replace("(", " ( ").replace(")", " ) ").split()
        for i, tok in enumerate(tokens):
            if tok.startswith("$"):
                tokens[i] = "True" if ctx.get(tok, False) else "False"
            elif tok.lower() in ("and", "or", "not"):
                tokens[i] = tok.lower()
        subst = " ".join(tokens)
        try:
            # Only allow True, False, and, or, not, (, )
            if re.match(r'^[TrueFalseandornot\(\)\s]+$', subst):
                return bool(eval(subst))  # nosec: safe guarded boolean expression
        except Exception:
            pass
        return any(ctx.values())


class YaraParser:
    """Parses standard YARA text (.yar) into structured YaraRule instances."""

    @classmethod
    def parse_rule_text(cls, text: str) -> YaraRule:
        rule_name_match = re.search(r'rule\s+([A-Za-z0-9_]+)(?:\s*:\s*([^\{]+))?\s*\{', text)
        if not rule_name_match:
            raise ValueError("Invalid YARA rule format: missing 'rule <name>' declaration")

        name = rule_name_match.group(1)
        tags_raw = rule_name_match.group(2) or ""
        tags = [t.strip() for t in tags_raw.split() if t.strip()]

        # Meta section
        meta: Dict[str, Any] = {}
        meta_match = re.search(r'meta:\s*(.*?)(?=\bstrings\s*:|\bcondition\s*:|\s*\}\s*$)', text, re.DOTALL)
        if meta_match:
            for line in meta_match.group(1).splitlines():
                line = line.strip()
                if "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip('"').strip("'")
                    meta[k] = v

        # Strings section
        strings: List[YaraStringDefinition] = []
        strings_match = re.search(r'strings:\s*(.*?)(?=\bcondition\s*:|\s*\}\s*$)', text, re.DOTALL)
        if strings_match:
            for line in strings_match.group(1).splitlines():
                line = line.strip()
                if not line or not line.startswith("$"):
                    continue
                m = re.match(r'(\$[A-Za-z0-9_]+)\s*=\s*(.*?)$', line)
                if not m:
                    continue
                var_name = m.group(1)
                val_part = m.group(2).strip()

                if val_part.startswith("{") and val_part.endswith("}"):
                    # Hex bytes: e.g. { 4D 5A 90 00 ?? 03 }
                    hex_str = val_part[1:-1].strip()
                    pat_bytes = bytearray()
                    mask_bytes = bytearray()
                    for token in hex_str.split():
                        if token == "??" or token == "?":
                            pat_bytes.append(0x00)
                            mask_bytes.append(0)  # wildcard (ignore mismatch)
                        else:
                            try:
                                pat_bytes.append(int(token, 16))
                                mask_bytes.append(1)  # exact match
                            except ValueError:
                                pass
                    strings.append(YaraStringDefinition(
                        identifier=var_name,
                        str_type="hex",
                        pattern=bytes(pat_bytes),
                        wildcard_mask=bytes(mask_bytes),
                    ))
                elif val_part.startswith('"'):
                    # Text string literal: e.g. "CreateRemoteThread" ascii wide nocase
                    str_content_match = re.match(r'"(.*?)"(.*)$', val_part)
                    if str_content_match:
                        content = str_content_match.group(1)
                        modifiers = str_content_match.group(2).lower()
                        is_wide = "wide" in modifiers
                        is_nocase = "nocase" in modifiers
                        is_ascii = "ascii" in modifiers or not is_wide
                        strings.append(YaraStringDefinition(
                            identifier=var_name,
                            str_type="text",
                            pattern=content.encode("latin-1"),
                            is_wide=is_wide,
                            is_nocase=is_nocase,
                            is_ascii=is_ascii,
                        ))

        # Condition section
        cond = "any of them"
        cond_match = re.search(r'condition:\s*(.*?)(?=\s*\}\s*$)', text, re.DOTALL)
        if cond_match:
            cond = cond_match.group(1).strip()

        return YaraRule(
            name=name,
            meta=meta,
            strings=strings,
            condition_str=cond,
            tags=tags,
            raw_text=text,
        )


class YaraExecutionEngine:
    """Runtime engine that registers and executes YARA rules against file artifacts."""

    def __init__(self):
        self._rules: Dict[str, YaraRule] = {}

    def register_rule(self, rule: YaraRule):
        self._rules[rule.name] = rule

    def register_yara_source(self, yara_text: str) -> YaraRule:
        rule = YaraParser.parse_rule_text(yara_text)
        self.register_rule(rule)
        return rule

    def scan_artifact(self, data: bytes, filename: str = "artifact.bin") -> List[YaraRuleMatch]:
        matches: List[YaraRuleMatch] = []
        for r in self._rules.values():
            m = r.evaluate(data)
            if m:
                matches.append(m)
        return matches

    def count(self) -> int:
        return len(self._rules)


YARA_ENGINE = YaraExecutionEngine()
