"""Convert a pytest junit-xml run into a frozen, machine-comparable baseline."""
from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


def build(xml_path: str) -> dict:
    root = ET.parse(xml_path).getroot()
    suite = root.find("testsuite") if root.tag == "testsuites" else root
    failures: list[dict] = []
    errors: list[dict] = []
    for case in suite.iter("testcase"):
        nodeid = f"{case.get('classname', '')}::{case.get('name', '')}"
        for child in case:
            if child.tag == "failure":
                failures.append({"nodeid": nodeid,
                                 "type": child.get("type") or "",
                                 "message": (child.get("message") or "")[:200]})
            elif child.tag == "error":
                errors.append({"nodeid": nodeid,
                               "type": child.get("type") or "",
                               "message": (child.get("message") or "")[:200]})
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "gate": "pre-P0-PROD-2",
        "totals": {
            "tests": int(suite.get("tests", 0)),
            "failed": len(failures),
            "errored": len(errors),
            "skipped": int(suite.get("skipped", 0)),
            "time_seconds": float(suite.get("time", 0.0)),
        },
        "failed": sorted(failures, key=lambda f: f["nodeid"]),
        "errored": sorted(errors, key=lambda f: f["nodeid"]),
    }


if __name__ == "__main__":
    print(json.dumps(build(sys.argv[1]), indent=2))
