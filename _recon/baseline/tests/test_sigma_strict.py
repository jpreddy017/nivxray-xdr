"""
P0.2b · Strict pySigma Parse — pytest gate.

Invariants under test:
  1. A well-formed Sigma rule parses cleanly (status=PARSED, rule present).
  2. A malformed YAML fails as PARSE_ERROR with error_type=YAMLError.
  3. A YAML document that is not a Sigma rule (no 'detection' section)
     fails as PARSE_ERROR NotASigmaRule.
  4. A Sigma-shaped rule that violates pySigma semantics fails as
     COMPILE_ERROR (SigmaError subclass name preserved).
  5. Surface metadata is populated even on failure, so downstream
     reports know WHICH rule blew up.
  6. Success case never sets error_type / error_message.
"""
from __future__ import annotations
import pytest

from detection_content.sigma_strict import (
    strict_parse,
    StrictParseStatus,
    is_pysigma_available,
)


GOOD_RULE = """
title: Suspicious Certutil Download
id: 00000000-0000-0000-0000-000000000001
status: experimental
description: Certutil download of remote payload (T1105)
author: nivxray
level: high
tags:
    - attack.t1105
    - attack.command_and_control
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\certutil.exe'
        CommandLine|contains:
            - 'urlcache'
            - 'http'
    condition: selection
falsepositives:
    - legitimate certutil administration
"""


NOT_SIGMA = """
title: just a doc
id: xxx
notes: this has no detection section
"""

BROKEN_YAML = """
title: broken
detection:
  selection: [1, 2
  condition: selection
"""


COMPILE_ERROR_RULE = """
title: bad detection semantics
id: 00000000-0000-0000-0000-000000000099
logsource:
    product: windows
    category: process_creation
detection:
    condition: selection
"""  # references undefined 'selection'


def test_good_rule_parses():
    r = strict_parse(GOOD_RULE)
    assert r.status == StrictParseStatus.PARSED, (r.status, r.error_message)
    assert r.rule is not None
    assert r.error_type is None
    assert r.error_message is None
    assert r.surface["product"] == "windows"
    assert r.surface["category"] == "process_creation"
    assert "attack.t1105" in (r.surface.get("tags") or [])


def test_broken_yaml_fails_as_parse_error():
    r = strict_parse(BROKEN_YAML)
    assert r.status == StrictParseStatus.PARSE_ERROR
    assert r.error_type == "YAMLError"
    assert r.error_message


def test_not_sigma_fails_as_parse_error_not_a_sigma_rule():
    r = strict_parse(NOT_SIGMA)
    assert r.status == StrictParseStatus.PARSE_ERROR
    assert r.error_type == "NotASigmaRule"
    # Surface still known
    assert r.surface["title"] == "just a doc"


@pytest.mark.skipif(not is_pysigma_available(),
                        reason="pySigma not installed")
def test_semantically_broken_rule_fails_as_compile_error():
    r = strict_parse(COMPILE_ERROR_RULE)
    assert r.status == StrictParseStatus.COMPILE_ERROR, (r.status, r.error_message)
    assert r.error_type          # a SigmaError subclass name
    assert r.error_message       # preserved


def test_result_to_dict_shape():
    r = strict_parse(GOOD_RULE)
    d = r.to_dict()
    for k in ("status", "error_type", "error_message",
                    "error_location", "surface"):
        assert k in d
    assert d["status"] == StrictParseStatus.PARSED


def test_never_silently_promotes_broken_rules():
    """No parser result can carry both status=PARSED and a live error."""
    for text in (BROKEN_YAML, NOT_SIGMA):
        r = strict_parse(text)
        if r.status != StrictParseStatus.PARSED:
            assert r.rule is None
        else:  # pragma: no cover — enforced by contract
            pytest.fail("Broken input parsed as PARSED")
