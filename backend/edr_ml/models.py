"""Model contract, registry, deterministic explainable scorers and the fit boundary."""
from __future__ import annotations

import copy
import json
import re
import statistics
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from edr_behavior.contracts import sha
from edr_behavior.rules import LIFECYCLE, TRANSITIONS

from .safe import clamp01, finite, r6
from .schema import COLD, KNOWN, FeatureSchema, FeatureVector, SchemaError, SchemaRegistry

SCORED, OUT_COLD, OUT_UNKNOWN, SCHEMA_MISMATCH = "SCORED", COLD, "UNKNOWN", "SCHEMA_MISMATCH"
MODEL_KEYS = {"model_id", "model_version", "feature_schema_version", "model_type", "parameters",
              "lifecycle", "threshold", "description", "created_at", "updated_at", "provenance"}
_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")
DEFAULT_MODELS = Path(__file__).parent / "content" / "starter_models.json"
TOP_K = 5


class ModelError(ValueError):
    pass


def _req(cond: bool, msg: str) -> None:
    if not cond:
        raise ModelError(msg)


@dataclass(frozen=True)
class ModelSpec:
    model_id: str
    model_version: str
    feature_schema_version: str
    model_type: str
    parameters: Dict[str, Any] = field(compare=False)
    lifecycle: str
    threshold: float
    description: str
    content_hash: str
    terms: Tuple[Tuple[str, float, Dict[str, float]], ...]  # (feature, weight, transform params)
    min_coverage: float

    def features(self) -> Tuple[str, ...]:
        return tuple(t[0] for t in self.terms)


@dataclass(frozen=True)
class ScoreResult:
    outcome: str
    score: Optional[float]
    confidence: int
    coverage: float
    contributions: Tuple[Dict[str, Any], ...] = ()
    unknown: Tuple[str, ...] = ()
    cold: Tuple[str, ...] = ()
    reasons: Tuple[str, ...] = ()


def model_hash(doc: Dict[str, Any]) -> str:
    body = {k: v for k, v in doc.items() if k not in ("lifecycle", "created_at", "updated_at")}
    return "mc_" + sha(json.dumps(body, sort_keys=True, separators=(",", ":")))[:32]


def _num(v: Any, lo: float, hi: float, name: str) -> float:
    f = finite(v)
    _req(f is not None and lo <= f <= hi, f"{name} must be a finite number in [{lo}, {hi}]")
    return f


def _feat(schema: FeatureSchema, name: Any, types: Sequence[str]) -> str:
    _req(isinstance(name, str), "feature name must be a string")
    try:
        spec = schema.spec(name)
    except SchemaError as e:
        raise ModelError(str(e)) from None
    _req(spec.type in types, f"feature {name} type {spec.type} not allowed for this model type")
    return name


def _terms_rarity(p: Dict[str, Any], schema: FeatureSchema):
    _req(set(p) <= {"features", "min_coverage"}, "RARITY parameters")
    fs = p.get("features")
    _req(isinstance(fs, list) and 1 <= len(fs) <= 32 and len(set(fs)) == len(fs), "RARITY features")
    return tuple((_feat(schema, n, ("RATIO", "BOOL")), 1.0, {"lo": 0.0, "hi": 1.0}) for n in fs)


def _terms_weighted(p: Dict[str, Any], schema: FeatureSchema):
    _req(set(p) <= {"features", "min_coverage"}, "WEIGHTED parameters")
    fs = p.get("features")
    _req(isinstance(fs, dict) and 1 <= len(fs) <= 32, "WEIGHTED features")
    out = []
    for n in sorted(fs):
        d = fs[n]
        _req(isinstance(d, dict) and set(d) <= {"weight", "range"}, f"{n}: weight/range")
        _feat(schema, n, ("RATIO", "BOOL", "COUNT", "NUMBER"))
        rng = d.get("range", [0, 1])
        _req(isinstance(rng, list) and len(rng) == 2, f"{n}: range")
        lo, hi = _num(rng[0], -1e9, 1e9, f"{n}.range"), _num(rng[1], -1e9, 1e9, f"{n}.range")
        _req(lo < hi, f"{n}: range lo < hi")
        out.append((n, _num(d.get("weight"), 1e-6, 100, f"{n}.weight"), {"lo": lo, "hi": hi}))
    return tuple(out)


def _terms_robust_z(p: Dict[str, Any], schema: FeatureSchema):
    _req(set(p) <= {"features", "z_cap", "min_coverage"}, "ROBUST_Z parameters")
    fs = p.get("features")
    _req(isinstance(fs, dict) and 1 <= len(fs) <= 32, "ROBUST_Z features")
    cap = _num(p.get("z_cap", 6.0), 0.5, 100, "z_cap")
    out = []
    for n in sorted(fs):
        d = fs[n]
        _req(isinstance(d, dict) and set(d) == {"median", "mad"}, f"{n}: median/mad")
        _feat(schema, n, ("COUNT", "NUMBER", "RATIO"))
        out.append((n, 1.0, {"median": _num(d["median"], -1e12, 1e12, f"{n}.median"),
                             "mad": _num(d["mad"], 0, 1e12, f"{n}.mad"), "z_cap": cap}))
    return tuple(out)


def _norm_linear(value: float, t: Dict[str, float]) -> Tuple[float, Dict[str, Any]]:
    return clamp01((value - t["lo"]) / (t["hi"] - t["lo"])), {"range": [t["lo"], t["hi"]]}


def _norm_robust_z(value: float, t: Dict[str, float]) -> Tuple[float, Dict[str, Any]]:
    med, mad, cap = t["median"], t["mad"], t["z_cap"]
    if mad > 0:
        z = 0.6745 * (value - med) / mad
    else:
        z = 0.0 if value == med else (cap if value > med else -cap)
    return clamp01(max(0.0, z) / cap), {"median": med, "mad": mad, "z": r6(z)}


_SCORERS: Dict[str, Tuple[Callable, Callable]] = {
    "RARITY": (_terms_rarity, _norm_linear),
    "WEIGHTED": (_terms_weighted, _norm_linear),
    "ROBUST_Z": (_terms_robust_z, _norm_robust_z),
}


def register_scorer(model_type: str, terms: Callable, norm: Callable) -> None:
    """Code-level seam for optional scorers (e.g. an sklearn adapter). Data files cannot add code."""
    if model_type in _SCORERS or not _ID.fullmatch(model_type):
        raise ModelError(f"scorer {model_type!r} already registered or invalid")
    _SCORERS[model_type] = (terms, norm)


def parse_model(doc: Dict[str, Any], schemas: SchemaRegistry) -> ModelSpec:
    _req(isinstance(doc, dict) and set(doc) <= MODEL_KEYS, "unknown model keys")
    mid, ver = doc.get("model_id"), doc.get("model_version")
    _req(isinstance(mid, str) and bool(_ID.fullmatch(mid)), f"bad model_id {mid!r}")
    _req(isinstance(ver, str) and bool(_ID.fullmatch(ver)), f"bad model_version {ver!r}")
    _req(doc.get("model_type") in _SCORERS, f"unknown model_type {doc.get('model_type')!r}")
    try:
        schema = schemas.get(doc.get("feature_schema_version"))
    except SchemaError as e:
        raise ModelError(str(e)) from None
    params = doc.get("parameters")
    _req(isinstance(params, dict), "parameters must be an object")
    terms = _SCORERS[doc["model_type"]][0](params, schema)
    lc = doc.get("lifecycle", "DRAFT")
    _req(lc in LIFECYCLE, "lifecycle")
    return ModelSpec(model_id=mid, model_version=ver, feature_schema_version=schema.version,
                     model_type=doc["model_type"], parameters=copy.deepcopy(params), lifecycle=lc,
                     threshold=_num(doc.get("threshold"), 0.0, 1.0, "threshold"),
                     description=str(doc.get("description", ""))[:1024], content_hash=model_hash(doc),
                     terms=terms, min_coverage=_num(params.get("min_coverage", 0.5), 0.0, 1.0, "min_coverage"))


def score(model: ModelSpec, vector: FeatureVector) -> ScoreResult:
    if vector.schema_version != model.feature_schema_version:
        return ScoreResult(SCHEMA_MISMATCH, None, 0, 0.0, reasons=(
            f"vector schema {vector.schema_version} != model schema {model.feature_schema_version}",))
    norm = _SCORERS[model.model_type][1]
    total_w = sum(w for _, w, _ in model.terms)
    known_w = acc = cold_w = unk_w = 0.0
    parts, unknown, cold = [], [], []
    for name, w, t in model.terms:
        fv = vector.get(name)
        if fv.state == KNOWN:
            n, detail = norm(fv.value, t)
            acc += w * n
            known_w += w
            parts.append((name, w, n, fv, detail))
        elif fv.state == COLD:
            cold.append(name)
            cold_w += w
        else:
            unknown.append(name)
            unk_w += w
    coverage = r6(known_w / total_w)
    if known_w == 0 or coverage < model.min_coverage:
        outcome = OUT_COLD if cold_w > 0 and cold_w >= unk_w else OUT_UNKNOWN
        return ScoreResult(outcome, None, 0, coverage, (), tuple(unknown), tuple(cold),
                           (f"feature coverage {coverage} < min_coverage {model.min_coverage}",))
    s = r6(acc / known_w)
    if finite(s) is None:
        raise ArithmeticError("non-finite score")
    contribs = sorted(({"feature": name, "value": fv.value, "weight": r6(w), "normalized": r6(n),
                        "share": r6(w * n / known_w), "transform": detail, "baseline": dict(fv.baseline),
                        "evidence_keys": [r.stable_key() for r in fv.evidence_refs]}
                       for name, w, n, fv, detail in parts), key=lambda c: (-c["share"], c["feature"]))
    return ScoreResult(SCORED, s, int(round(100 * coverage)), coverage, tuple(contribs),
                       tuple(unknown), tuple(cold))


class ModelRegistry:
    """(model_id, model_version) is immutable; lifecycle follows the rule lifecycle."""

    def __init__(self, schemas: SchemaRegistry) -> None:
        self.schemas = schemas
        self._m: Dict[Tuple[str, str], ModelSpec] = {}

    def register(self, doc: Dict[str, Any]) -> ModelSpec:
        m = parse_model(doc, self.schemas)
        key = (m.model_id, m.model_version)
        prev = self._m.get(key)
        if prev is not None and prev.content_hash != m.content_hash:
            raise ModelError(f"{m.model_id}@{m.model_version} already registered with different content")
        self._m.setdefault(key, m)
        return self._m[key]

    def get(self, model_id: str, version: str) -> ModelSpec:
        return self._m[(model_id, version)]

    def set_lifecycle(self, model_id: str, version: str, state: str) -> ModelSpec:
        cur = self.get(model_id, version)
        if state not in TRANSITIONS[cur.lifecycle]:
            raise ModelError(f"illegal transition {cur.lifecycle} -> {state}")
        if state == "ACTIVE":
            for (mid, v), m in list(self._m.items()):
                if mid == model_id and v != version and m.lifecycle == "ACTIVE":
                    self._m[(mid, v)] = replace(m, lifecycle="DEPRECATED")
        self._m[(model_id, version)] = replace(cur, lifecycle=state)
        return self._m[(model_id, version)]

    def live(self) -> List[ModelSpec]:
        return sorted((m for m in self._m.values() if m.lifecycle in ("ACTIVE", "TESTING")),
                      key=lambda m: (m.model_id, m.model_version))


def load_models(registry: ModelRegistry, path: Path = DEFAULT_MODELS) -> List[ModelSpec]:
    docs = json.loads(Path(path).read_text(encoding="utf-8"), parse_constant=_reject_constant)
    _req(isinstance(docs, list), "model pack must be a list")
    return [registry.register(d) for d in docs]


def _reject_constant(name: str) -> Any:
    raise ModelError(f"non-finite constant {name} not allowed")


def fit_robust_z(template: Dict[str, Any], vectors: Sequence[FeatureVector], *, model_version: str,
                 data_label: str, min_samples: int = 20) -> Dict[str, Any]:
    """Deterministic median/MAD fit. Returns a NEW DRAFT model doc; never activates anything."""
    _req(data_label == "SYNTHETIC", "model fitting is restricted to SYNTHETIC data in this phase")
    names = template.get("parameters", {}).get("features")
    _req(isinstance(names, list) and names, "template parameters.features must list feature names")
    fitted = {}
    for name in sorted(set(names)):
        xs = sorted(fv.value for v in vectors for fv in [v.get(name)] if fv.state == KNOWN)
        _req(len(xs) >= min_samples, f"{name}: {len(xs)} known samples < min_samples {min_samples}")
        med = statistics.median(xs)
        fitted[name] = {"median": r6(med), "mad": r6(statistics.median(abs(x - med) for x in xs))}
    doc = {k: copy.deepcopy(v) for k, v in template.items() if k in MODEL_KEYS}
    params = {k: v for k, v in template["parameters"].items() if k != "features"}
    params["features"] = fitted
    doc.update(model_version=model_version, model_type="ROBUST_Z", lifecycle="DRAFT", parameters=params,
               provenance={"fit": "fit_robust_z", "data_label": data_label,
                           "samples": len(vectors), "min_samples": min_samples})
    return doc
