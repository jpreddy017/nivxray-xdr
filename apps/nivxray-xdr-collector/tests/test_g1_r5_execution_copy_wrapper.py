"""Regression guards for the R5 exact-50 PowerShell execution copy.

Two defects were proved by real Windows execution:
  1. the wrapper resolved the collector at `C:\\nivx\\nivxray-xdr-collector`
     while the monorepo puts it under `apps\\`, so the python tool never ran;
  2. after printing HARD STOP the wrapper still returned process exit code 0,
     so a failed prerequisite looked like a successful run.

pwsh is not available in this container, so these are static guards over the
published block. They verify the Windows path actually maps onto a file in
this repository and that no HARD STOP path can yield 0.
"""
from __future__ import annotations

import hashlib
import os
import re

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, os.pardir, os.pardir,
                                          os.pardir))
_PS1 = os.path.join(_REPO_ROOT, "memory",
                    "G1_R5_INFLIGHT50_RECONCILE_EXECUTION_COPY.ps1")
_COLLECTOR = os.path.abspath(os.path.join(_HERE, os.pardir))


@pytest.fixture(scope="module")
def block() -> str:
    with open(_PS1, encoding="utf-8") as fh:
        return fh.read()


def _assign(block: str, name: str) -> str:
    """The literal a `$Name = '...'`/"..." assignment carries."""
    match = re.search(r"^\$" + name + r"\s*=\s*['\"](.+?)['\"]\s*$",
                      block, re.MULTILINE)
    assert match, f"${name} is not assigned in the execution copy"
    return match.group(1)


def _expand(block: str, value: str) -> str:
    """Resolve $Work / $Repo / $ProofDir interpolation, innermost first."""
    for _ in range(5):
        found = re.findall(r"\$(\w+)", value)
        if not found:
            break
        for name in found:
            value = value.replace("$" + name, _assign(block, name))
    return value


def _to_repo_path(windows_path: str) -> str:
    """C:\\nivx\\apps\\<pkg>\\... -> the real path in this repository."""
    tail = windows_path.split("\\apps\\", 1)
    assert len(tail) == 2, (
        f"{windows_path} does not sit under the monorepo's apps\\ directory")
    return os.path.join(_REPO_ROOT, "apps", tail[1].replace("\\", os.sep))


def test_repo_variable_points_under_apps(block):
    assert _assign(block, "Repo") == r"$Work\apps\nivxray-xdr-collector"
    # the stale layout must not survive anywhere in the block
    assert r"$Work\nivxray-xdr-collector" not in block
    assert r"C:\nivx\nivxray-xdr-collector" not in block


def test_tool_path_resolves_to_a_real_file_in_this_repository(block):
    resolved = _to_repo_path(_expand(block, _assign(block, "Tool")))
    assert os.path.isfile(resolved), (
        f"the wrapper would look for the tool at a path that maps to "
        f"{resolved}, which does not exist")
    assert os.path.dirname(resolved) == os.path.join(_COLLECTOR, "scripts")
    assert os.path.basename(resolved) == "g1_r5_inflight50_reconcile.py"


def test_pinned_tool_sha_matches_the_tool_on_disk(block):
    resolved = _to_repo_path(_expand(block, _assign(block, "Tool")))
    with open(resolved, "rb") as fh:
        actual = hashlib.sha256(fh.read()).hexdigest().upper()
    assert _assign(block, "ExpectToolSha").upper() == actual


def test_identities_file_is_the_verified_bom_free_copy(block):
    assert _expand(block, _assign(block, "IdFile")).endswith(
        r"r5-inflight-identities-20260924T063436Z.utf8-nobom.json")


def test_hard_stop_returns_non_zero_to_the_parent_process(block):
    catch = block.split("\ncatch {", 1)
    assert len(catch) == 2, "the block has no catch handler"
    catch_body = catch[1].split("\n}", 1)[0]
    assert "HARD STOP" in catch_body
    assert re.search(r"^\s*return 1\s*$", catch_body, re.MULTILINE), (
        "a HARD STOP must return non-zero; this is the defect that made a "
        "failed prerequisite look like a successful run")

    # the only 0 in the block is the PASS path, and it requires BOTH a clean
    # python exit and the authoritative file existing
    assert ("if ($exit -eq 0 -and (Test-Path $OutFile)) { return 0 } "
            "else { return 1 }") in block

    # the return value is captured, defaulted, reported and surfaced
    assert "$NivxExit = Invoke-G1R5Inflight50Reconcile" in block
    assert "if ($null -eq $NivxExit) { $NivxExit = 1 }" in block
    assert "$global:LASTEXITCODE = $NivxExit" in block
    assert "if ($PSCommandPath) { exit $NivxExit }" in block
    # and it is never invoked bare (which discarded the status before)
    assert not re.search(r"^Invoke-G1R5Inflight50Reconcile\s*$", block,
                         re.MULTILINE)


def test_every_hard_stop_is_raised_inside_the_guarded_try(block):
    """A `throw` outside the try would escape the catch and skip `return 1`."""
    try_start = block.index("\ntry {")
    catch_start = block.index("\ncatch {")
    for match in re.finditer(r"^\s*throw ", block, re.MULTILINE):
        assert try_start < match.start() < catch_start, (
            f"a throw at offset {match.start()} is outside the guarded try, "
            "so it would bypass the non-zero return")


def test_read_only_reconciliation_invariants_are_preserved(block):
    for token in ("$ExpectCount     = 50",
                  "$ExpectCanonical = 22",
                  "$ExpectRetryable = 28",
                  "$ExpectTotalRows = 125452",
                  "delivered=3284,delivering=50,queued=121993,retrying=125,"
                  "dead_letter=0",
                  "python client User-Agent",
                  "edge_banned",
                  "BACKEND NOT READY/BOUND",
                  "DO NOT RETYPE PASSWORD",
                  "--expect-canonical",
                  "--expect-histogram"):
        assert token in block, token
    for forbidden in ("--apply", "$Apply", "Start-Service",
                      "DeliveryWorker(", "Outbox("):
        assert forbidden not in block, forbidden
