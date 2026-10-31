"""E3 · DETECTION COVERAGE MATRIX — measured from code + data.

Owner rule: this is not documentation theatre. Every cell is derived
mechanically from the rule registry, the canonical schema, the rules'
own fixtures and the REAL Windows corpus. Nothing is asserted.

    python3 scripts/e3_coverage_matrix.py            # markdown + json
    python3 scripts/e3_coverage_matrix.py --tenant T  # a different corpus

A technique is NOT reported as a percentage of ATT&CK. A technique may
require telemetry we do not collect or an engine we do not have, and
that is reported as such:

    SUPPORTED    the rule fires on CANONICAL evidence, and that evidence
                 is actually collected on the real endpoint
    PARTIAL      it fires on canonical evidence, but the evidence is not
                 collected (or only partly) on the real endpoint
    UNSUPPORTED  it cannot fire on canonical evidence at all — a dead
                 rule, regardless of what its own fixture says
    NOT_TESTED   no fixture, so no control could be run
"""
from __future__ import annotations

import argparse
import asyncio
import collections
import json
import os
import sys
from typing import Any, Dict, List

sys.path.insert(0, "/app/backend")

from dotenv import load_dotenv                              # noqa: E402

load_dotenv("/app/backend/.env")

REAL_TENANT = "ten_f1a5479243e901cf159e230fa0"
CANONICAL = "xdr_canonical_evidence"

#: The VOCABULARY BRIDGE. A rule declares its needs in Sigma's logsource
#: dialect (`process_creation`); canonical evidence speaks NivXForge's
#: (`event_type: process_create`). Both are legitimate and neither is
#: renamed — the bridge is made explicit here so nobody later writes a
#: comparison against the wrong one, and so "does the sensor supply what
#: this rule needs?" becomes an answerable question.
TELEMETRY_BRIDGE: Dict[str, Dict[str, Any]] = {
    "process_creation": {"event_types": ["process_create"],
                         "fields": ["process.name",
                                    "process.executable_path"],
                         "channels": ["Microsoft-Windows-Sysmon/Operational",
                                      "Security"]},
    "command_line": {"event_types": ["process_create"],
                     "fields": ["process.command_line"],
                     "channels": ["Microsoft-Windows-Sysmon/Operational",
                                  "Security"]},
    "process.command_line": {"event_types": ["process_create"],
                             "fields": ["process.command_line"],
                             "channels": [
                                 "Microsoft-Windows-Sysmon/Operational"]},
    "process.executable_path": {"event_types": ["process_create"],
                                "fields": ["process.executable_path"],
                                "channels": [
                                    "Microsoft-Windows-Sysmon/Operational"]},
    "parent_process": {"event_types": ["process_create"],
                       "fields": ["process.parent_name",
                                  "process.parent_process_guid"],
                       "channels": [
                           "Microsoft-Windows-Sysmon/Operational"]},
    "registry_event": {"event_types": ["registry_event", "registry_set"],
                       "fields": ["registry.key_path"],
                       "channels": [
                           "Microsoft-Windows-Sysmon/Operational"]},
    "file_activity": {"event_types": ["file_create", "file_event"],
                      "fields": ["file.path"],
                      "channels": ["Microsoft-Windows-Sysmon/Operational"]},
    "dns_query": {"event_types": ["dns_query"],
                  "fields": ["network.dns_query"],
                  "channels": ["Microsoft-Windows-Sysmon/Operational"]},
    "network_traffic": {"event_types": ["network_connect"],
                        "fields": ["network.dest_ip"],
                        "channels": [
                            "Microsoft-Windows-Sysmon/Operational"]},
    # A service-creation rule can ALSO fire on the installing process's
    # command line, so both event types are listed; the missing
    # service-name field is what makes such a rule PARTIAL rather than
    # supported, and that is the honest answer.
    "service_creation": {"event_types": ["service_installed",
                                         "process_create"],
                         "fields": ["registry.service_name"],
                         "channels": ["System", "Security",
                                      "Microsoft-Windows-Sysmon/Operational"]},
    "script_block_logging": {
        "event_types": ["powershell_script_block"],
        "fields": ["process.command_line"],
        "channels": ["Microsoft-Windows-PowerShell/Operational"]},
    "security_event_4768": {"event_types": ["kerberos_tgt_request"],
                            "fields": ["identity.username"],
                            "channels": ["Security"]},
    "security_event_4769": {"event_types": ["kerberos_service_ticket"],
                            "fields": ["identity.username"],
                            "channels": ["Security"]},
    "kerberos": {"event_types": ["kerberos_tgt_request",
                                 "kerberos_service_ticket"],
                 "fields": ["identity.username"], "channels": ["Security"]},
    "active_directory_audit": {"event_types": ["directory_change"],
                               "fields": ["identity.username"],
                               "channels": ["Security",
                                            "Directory Service"]},
    "endpoint": {"event_types": ["process_create"],
                 "fields": ["process.name"],
                 "channels": ["Microsoft-Windows-Sysmon/Operational"]},
    "identity": {"event_types": ["logon_success"],
                 "fields": ["identity.username"], "channels": ["Security"]},
    "auditd": {"event_types": ["process_create"], "fields": [],
               "channels": [], "note": "Linux auditd — not a Windows source"},
}

#: Sources this Windows sensor cannot observe at all. Stated so a gap is
#: never mistaken for a detection failure.
NOT_A_WINDOWS_ENDPOINT_SOURCE = {
    "cloud_audit", "m365_exchange", "entra_id", "iam", "ad_cs",
    "hypervisor_command_line", "auditd",
}

FAMILY = {
    "TA0001": "Initial Access", "TA0002": "Execution",
    "TA0003": "Persistence", "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion", "TA0006": "Credential Access",
    "TA0007": "Discovery", "TA0008": "Lateral Movement",
    "TA0009": "Collection", "TA0011": "Command and Control",
    "TA0010": "Exfiltration", "TA0040": "Impact",
}


def _dig(doc: Dict[str, Any], path: str) -> Any:
    cur: Any = doc
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _canonicalise(flat: Dict[str, Any]) -> Dict[str, Any]:
    """Lift a rule's own fixture into the CANONICAL evidence shape.

    A rule that fires on its flat Sysmon-shaped fixture but NOT on the
    canonical shape is dead in production no matter how green its own
    test is. That comparison is the whole point of this column.
    """
    g = {k.lower(): v for k, v in flat.items()}
    image = g.get("image") or g.get("newprocessname") or ""
    ev: Dict[str, Any] = {
        "event_id": "ctrl", "tenant_id": "ctrl",
        "source_vendor": "Microsoft", "source_product": "Sysmon",
        "source_event_id": "1", "event_type": "process_create",
        "event_time": "2026-09-22 16:20:00.000",
        "host": {"hostname": "CTRL"},
        "identity": {"username": g.get("user") or g.get("subjectusername")
                     or ""},
        "process": {
            "name": str(image).split("\\")[-1],
            "executable_path": image,
            "command_line": g.get("commandline") or g.get("command_line")
            or "",
            "parent_name": str(g.get("parentimage") or "").split("\\")[-1],
            "parent_executable_path": g.get("parentimage") or "",
            "parent_command_line": g.get("parentcommandline") or "",
            "original_file_name": g.get("originalfilename") or "",
            "integrity_level": g.get("integritylevel") or "",
            "hashes": {},
        },
        "network": {}, "file": {}, "registry": {}, "security": {},
    }
    if g.get("targetobject"):
        key = str(g["targetobject"])
        ev["event_type"] = "registry_event"
        ev["source_event_id"] = "13"
        ev["registry"] = {"key_path": key, "hive": key.split("\\")[0],
                          "value_name": key.rsplit("\\", 1)[-1],
                          "value_data": g.get("details") or "",
                          "action": "set_value"}
    if g.get("targetfilename"):
        ev["event_type"] = "file_create"
        ev["source_event_id"] = "11"
        ev["file"] = {"path": g["targetfilename"],
                      "name": str(g["targetfilename"]).split("\\")[-1]}
    if g.get("destinationip") or g.get("destination_ip"):
        ev["event_type"] = "network_connect"
        ev["source_event_id"] = "3"
        ev["network"] = {"dest_ip": g.get("destinationip")
                         or g.get("destination_ip"),
                         "dest_port": g.get("destinationport")}
    if g.get("queryname"):
        ev["event_type"] = "dns_query"
        ev["source_event_id"] = "22"
        ev["network"] = {"query": g["queryname"]}
    for k, v in flat.items():          # keep the flat keys too: the
        ev.setdefault(k, v)            # predicates accept either dialect
    return ev


#: Canonical evidence groups. A fixture that already speaks this dialect
#: must be used AS-IS: re-deriving it from flat Sysmon keys silently
#: destroyed `registry.action`, `file.extension` and the whole
#: `authentication` block, and then reported the RULE as dead. A
#: measurement that breaks its own input is worse than no measurement.
CANONICAL_GROUPS = ("process", "registry", "file", "network", "identity",
                    "security", "authentication", "cloud", "email")


def _is_canonical_shaped(ev: Dict[str, Any]) -> bool:
    if "event_type" in ev or "source_event_id" in ev:
        return True
    return any(isinstance(ev.get(g), dict) for g in CANONICAL_GROUPS)


def _canonical_control(ev: Dict[str, Any]) -> Dict[str, Any]:
    """The canonical-shape control input for one fixture."""
    return dict(ev) if _is_canonical_shaped(ev) else _canonicalise(ev)


#: Rules whose evidence does not come from a Windows ENDPOINT sensor.
#: They are NOT_APPLICABLE to a Windows endpoint corpus — reporting them
#: as UNSUPPORTED would blame the rule for the corpus we chose.
NON_ENDPOINT_PLATFORMS = {"linux", "macos", "identity", "cloud", "saas",
                          "network", "email", "hypervisor", "container"}


BENIGN = _canonicalise({"Image": "C:\\Windows\\System32\\svchost.exe",
                        "CommandLine": "svchost.exe -k netsvcs -p",
                        "ParentImage": "C:\\Windows\\System32\\services.exe",
                        "User": "NT AUTHORITY\\SYSTEM"})


async def _corpus_facts(tenant: str) -> Dict[str, Any]:
    from motor.motor_asyncio import AsyncIOMotorClient
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    by_type: collections.Counter = collections.Counter()
    field_pop: collections.Counter = collections.Counter()
    channels: collections.Counter = collections.Counter()
    total = 0
    async for d in db[CANONICAL].find({"tenant_id": tenant}, {"_id": 0}):
        total += 1
        by_type[d.get("event_type")] += 1
        channels[(d.get("source_product"), d.get("source_event_id"))] += 1
        for group in ("process", "registry", "file", "network", "identity",
                      "security"):
            blk = d.get(group) or {}
            if isinstance(blk, dict):
                for k, v in blk.items():
                    if v not in (None, "", [], {}, 0):
                        field_pop[f"{group}.{k}"] += 1
    evaluated = await db["edr_finding_evaluations"].count_documents(
        {"tenant_id": tenant})
    return {"tenant": tenant, "total": total, "by_type": dict(by_type),
            "field_pop": dict(field_pop), "evaluated": evaluated,
            "source_ids": {f"{p}:{i}": n for (p, i), n in channels.items()}}


def _row(rule: Any, facts: Dict[str, Any]) -> Dict[str, Any]:
    from detection_content.xdr_pipeline import evaluate_detection

    reqs = list(rule.telemetry_requirements or [])
    windows_source = not any(r in NOT_A_WINDOWS_ENDPOINT_SOURCE
                             for r in reqs)
    etypes, fields, chans = set(), set(), set()
    unmapped = []
    for r in reqs:
        br = TELEMETRY_BRIDGE.get(r)
        if not br:
            unmapped.append(r)
            continue
        etypes.update(br["event_types"])
        fields.update(br["fields"])
        chans.update(br["channels"])

    collected = {t: facts["by_type"].get(t, 0) for t in sorted(etypes)}
    fields_avail = {f: facts["field_pop"].get(f, 0) for f in sorted(fields)}

    # EVERY fixture is run, not just the last one, and a rule passes a
    # control only if ALL of its fixtures of that kind agree.
    tallies = {"pos": [], "pos_canon": [], "neg": [], "neg_canon": []}
    for fx in (rule.fixtures or []):
        ev = dict(getattr(fx, "event", {}) or {})
        want = bool(getattr(fx, "should_match", False))
        hit_flat = any(m.get("rule_id") == rule.rule_id
                       for m in (evaluate_detection(ev).get("detections")
                                 or []))
        hit_canon = any(m.get("rule_id") == rule.rule_id
                        for m in (evaluate_detection(_canonical_control(ev))
                                  .get("detections") or []))
        tallies["pos" if want else "neg"].append(hit_flat)
        tallies["pos_canon" if want else "neg_canon"].append(hit_canon)

    def _verdict(seen: List[bool], *, expect: bool, label: str) -> str:
        if not seen:
            return "NO_FIXTURE"
        ok = sum(1 for h in seen if h is expect)
        if ok == len(seen):
            return f"PASS({ok}/{len(seen)})"
        return f"{label}({ok}/{len(seen)})"

    pos = _verdict(tallies["pos"], expect=True, label="FAIL")
    pos_canon = _verdict(tallies["pos_canon"], expect=True, label="FAIL")
    neg = _verdict(tallies["neg"], expect=False, label="FAIL-false-positive")
    if neg == "NO_FIXTURE":
        neg = "PASS" if not any(
            m.get("rule_id") == rule.rule_id
            for m in (evaluate_detection(BENIGN).get("detections") or [])
        ) else "FAIL(fires on benign svchost)"

    platform = getattr(rule.platform, "value", str(rule.platform)).lower()
    if platform in NON_ENDPOINT_PLATFORMS:
        return {**_base(rule, reqs, etypes, fields, chans, collected,
                        fields_avail, facts, pos, pos_canon, neg,
                        windows_source and bool(chans)),
                "verdict": "NOT_APPLICABLE",
                "reason": (f"a {platform} rule; this acceptance corpus is a "
                           "WINDOWS endpoint, so it is out of scope here "
                           "rather than unsupported")}
    if pos_canon == "NO_FIXTURE":
        verdict, why = "NOT_TESTED", "the rule declares no fixture"
    elif pos_canon.startswith("FAIL"):
        verdict = "UNSUPPORTED"
        why = ("the rule does not fire on CANONICAL evidence " + pos_canon
               + (" — it DOES fire on its flat fixture, so this is a DIALECT "
                  "defect in the rule" if pos.startswith("PASS")
                  else " and fails its own fixture too"))
    elif not windows_source:
        verdict = "UNSUPPORTED"
        why = ("requires a source this Windows endpoint sensor does not "
               "observe: " + ", ".join(sorted(set(reqs)
                                              & NOT_A_WINDOWS_ENDPOINT_SOURCE)))
    elif unmapped:
        verdict, why = "NOT_TESTED", ("telemetry requirement not mapped to a "
                                      "canonical field: " + ", ".join(unmapped))
    elif etypes and not any(collected.values()):
        verdict = "PARTIAL"
        why = ("fires on canonical evidence, but the real endpoint "
               "collected 0 rows of " + ", ".join(sorted(etypes)))
    elif fields and not all(fields_avail.values()):
        missing = [f for f, n in fields_avail.items() if not n]
        verdict = "PARTIAL"
        why = ("fires on canonical evidence, but these canonical fields are "
               "never populated in the real corpus: " + ", ".join(missing))
    else:
        verdict = "SUPPORTED"
        why = ("fires on canonical evidence AND the required evidence is "
               "actually collected on the real endpoint")

    return {**_base(rule, reqs, etypes, fields, chans, collected,
                    fields_avail, facts, pos, pos_canon, neg,
                    windows_source and bool(chans)),
            "verdict": verdict, "reason": why}


def _base(rule, reqs, etypes, fields, chans, collected, fields_avail,
          facts, pos, pos_canon, neg, can_observe) -> Dict[str, Any]:
    return {
        "rule_id": rule.rule_id, "name": rule.name,
        "technique": rule.technique_id,
        "tactic": getattr(rule.tactic, "value", str(rule.tactic)),
        "family": FAMILY.get(getattr(rule, "tactic_id", "") or "", None)
        or getattr(rule.tactic, "value", str(rule.tactic)),
        "platform": getattr(rule.platform, "value", str(rule.platform)),
        "lane": rule.lane, "severity": rule.severity,
        "rule_version": rule.rule_version,
        "required_telemetry": reqs,
        "canonical_event_types": sorted(etypes),
        "canonical_fields": sorted(fields),
        "channels": sorted(chans),
        "sensor_can_observe": can_observe,
        "actually_collected": collected,
        "canonical_field_available": fields_avail,
        "positive_control_fixture_shape": pos,
        "positive_control_canonical_shape": pos_canon,
        "negative_control": neg,
        "real_corpus_evaluated": facts["evaluated"] > 0,
    }


def _render(rows: List[Dict[str, Any]], facts: Dict[str, Any]) -> str:
    v = collections.Counter(r["verdict"] for r in rows)
    out = ["# E3 · DETECTION COVERAGE MATRIX (measured)", "",
           f"Corpus: `{facts['tenant']}` · {facts['total']} canonical rows · "
           f"{facts['evaluated']} evaluation-ledger entries.", "",
           "Source event ids actually collected: "
           + ", ".join(f"`{k}`×{n}" for k, n in
                       sorted(facts["source_ids"].items())), "",
           "## Verdicts", "",
           "| verdict | rules |", "|---|---|"]
    for k in ("SUPPORTED", "PARTIAL", "UNSUPPORTED", "NOT_TESTED",
              "NOT_APPLICABLE"):
        out.append(f"| {k} | {v.get(k, 0)} |")
    out += ["", "**This is NOT an ATT&CK coverage percentage.** A technique "
            "may require telemetry this sensor does not collect or an engine "
            "NivXForge does not yet have.", "",
            "## By behaviour family", "",
            "| family | SUPPORTED | PARTIAL | UNSUPPORTED | NOT_TESTED | "
            "NOT_APPLICABLE |", "|---|---|---|---|---|---|"]
    fam: Dict[str, collections.Counter] = collections.defaultdict(
        collections.Counter)
    for r in rows:
        fam[r["family"]][r["verdict"]] += 1
    for f in sorted(fam):
        c = fam[f]
        out.append(f"| {f} | {c['SUPPORTED']} | {c['PARTIAL']} | "
                   f"{c['UNSUPPORTED']} | {c['NOT_TESTED']} | "
                   f"{c['NOT_APPLICABLE']} |")
    out += ["", "## Per rule", "",
            "| rule | technique | required telemetry | sensor can observe | "
            "collected | canonical field populated | +ctrl (fixture) | "
            "+ctrl (CANONICAL) | -ctrl | verdict | reason |",
            "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in sorted(rows, key=lambda x: (x["verdict"], x["rule_id"])):
        out.append(
            f"| {r['rule_id']} {r['name']} | {r['technique']} | "
            f"{', '.join(r['required_telemetry']) or '—'} | "
            f"{'yes' if r['sensor_can_observe'] else 'NO'} | "
            + (", ".join(f"{k}={n}" for k, n in
                         r['actually_collected'].items()) or "—") + " | "
            + (", ".join(f"{k}={n}" for k, n in
                         r['canonical_field_available'].items()) or "—")
            + f" | {r['positive_control_fixture_shape']} | "
            f"{r['positive_control_canonical_shape']} | "
            f"{r['negative_control']} | **{r['verdict']}** | {r['reason']} |")
    return "\n".join(out) + "\n"


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tenant", default=REAL_TENANT)
    ap.add_argument("--out",
                    default="/app/docs/E3_DETECTION_COVERAGE_MATRIX.md")
    args = ap.parse_args()

    from detection_content.library.registry import RUNTIME_DETECTION_RULES

    facts = await _corpus_facts(args.tenant)
    rows = [_row(r, facts) for r in RUNTIME_DETECTION_RULES]
    md = _render(rows, facts)
    with open(args.out, "w") as fh:
        fh.write(md)
    with open(args.out.replace(".md", ".json"), "w") as fh:
        json.dump({"corpus": facts, "rules": rows}, fh, indent=1,
                  default=str)
    v = collections.Counter(r["verdict"] for r in rows)
    print(json.dumps({"rules": len(rows), "verdicts": dict(v),
                      "written": args.out}, indent=1))
    for r in rows:
        if r["verdict"] == "UNSUPPORTED" and r["sensor_can_observe"]:
            print("  DEAD ON CANONICAL EVIDENCE:", r["rule_id"],
                  r["technique"], "—", r["reason"])


if __name__ == "__main__":
    asyncio.run(main())
