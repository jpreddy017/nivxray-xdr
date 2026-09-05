"""Dataset exporters — emit training rows in multiple formats.

Formats produced:
  • JSONL (canonical NivXRay format — `TrainingRecord` per line)
  • OpenAI fine-tuning chat format (`{"messages": [system,user,assistant]}`)
  • Anthropic conversational format (`{"conversations": [{"role": ..., "content": ...}]}`)
  • CSV flattened (tabular subset — id, platform, category, raw, decoded, ascii_tree)

All formats include the same underlying tree data — only the framing differs.
"""
from __future__ import annotations
import csv
import io
import json
from typing import Iterable, List

from training.schema import TrainingRecord
from training.system_prompt import NIVXRAY_PROCESS_TREE_SYSTEM
from training.tree_formats import to_ascii_tree, to_edge_list


# --- 1. Canonical JSONL ------------------------------------------------- #
def to_jsonl(records: Iterable[TrainingRecord]) -> str:
    lines: List[str] = []
    for r in records:
        lines.append(json.dumps(r.model_dump(), ensure_ascii=False, separators=(",", ":")))
    return "\n".join(lines)


# --- 2. OpenAI fine-tuning (chat.completion) --------------------------- #
def to_openai_chat_jsonl(records: Iterable[TrainingRecord]) -> str:
    """One-record-per-line JSON. Each record: {"messages":[system,user,assistant]}."""
    lines: List[str] = []
    for r in records:
        assistant_json = json.dumps(
            r.predicted_process_tree.model_dump(),
            ensure_ascii=False, separators=(",", ":"),
        )
        payload = {
            "messages": [
                {"role": "system", "content": NIVXRAY_PROCESS_TREE_SYSTEM.strip()},
                {"role": "user", "content":
                    f"RAW_INPUT:\n{r.input_raw_command}\n\n"
                    f"DECODED_OUTPUT:\n{r.decoded_script_analysis}\n\n"
                    "Emit strict JSON per the schema. Cite every node."},
                {"role": "assistant", "content": assistant_json},
            ],
            "metadata": {
                "training_id": r.training_id,
                "platform": r.platform,
                "category": r.category,
                "difficulty": r.difficulty,
                "tags": r.tags,
            },
        }
        lines.append(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    return "\n".join(lines)


# --- 3. Anthropic conversational format --------------------------------- #
def to_anthropic_jsonl(records: Iterable[TrainingRecord]) -> str:
    """Anthropic-style: {"system": ..., "conversations": [{"role":"user"/"assistant", "content": ...}]}."""
    lines: List[str] = []
    for r in records:
        assistant_json = json.dumps(
            r.predicted_process_tree.model_dump(),
            ensure_ascii=False, separators=(",", ":"),
        )
        payload = {
            "system": NIVXRAY_PROCESS_TREE_SYSTEM.strip(),
            "conversations": [
                {"role": "user", "content":
                    f"RAW_INPUT:\n{r.input_raw_command}\n\n"
                    f"DECODED_OUTPUT:\n{r.decoded_script_analysis}\n\n"
                    "Emit strict JSON per the schema. Cite every node."},
                {"role": "assistant", "content": assistant_json},
            ],
            "metadata": {
                "training_id": r.training_id, "platform": r.platform,
                "category": r.category, "difficulty": r.difficulty,
                "tags": r.tags,
            },
        }
        lines.append(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    return "\n".join(lines)


# --- 4. Flattened CSV --------------------------------------------------- #
def to_csv(records: Iterable[TrainingRecord]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([
        "training_id", "platform", "category", "difficulty", "tags",
        "input_raw_command", "decoded_script_analysis",
        "verdict", "severity", "mitre_ids", "tactics", "lolbins",
        "ascii_tree",
    ])
    for r in records:
        t = r.predicted_process_tree
        w.writerow([
            r.training_id, r.platform, r.category, r.difficulty, "|".join(r.tags),
            r.input_raw_command, r.decoded_script_analysis,
            t.rationale.verdict, t.rationale.severity,
            "|".join(t.rationale.mitre_ids), "|".join(t.rationale.tactics),
            "|".join(t.rationale.lolbins),
            to_ascii_tree(t),
        ])
    return buf.getvalue()


# --- 5. Edge-list JSONL (for graph-based fine-tuning) ------------------- #
def to_edge_list_jsonl(records: Iterable[TrainingRecord]) -> str:
    lines: List[str] = []
    for r in records:
        el = to_edge_list(r.predicted_process_tree)
        el["training_id"] = r.training_id
        el["platform"] = r.platform
        el["category"] = r.category
        el["input_raw_command"] = r.input_raw_command
        el["decoded_script_analysis"] = r.decoded_script_analysis
        lines.append(json.dumps(el, ensure_ascii=False, separators=(",", ":")))
    return "\n".join(lines)


FORMATS = {
    "jsonl":       ("application/x-ndjson",         to_jsonl),
    "openai":      ("application/x-ndjson",         to_openai_chat_jsonl),
    "anthropic":   ("application/x-ndjson",         to_anthropic_jsonl),
    "csv":         ("text/csv",                     to_csv),
    "edge-list":   ("application/x-ndjson",         to_edge_list_jsonl),
}
