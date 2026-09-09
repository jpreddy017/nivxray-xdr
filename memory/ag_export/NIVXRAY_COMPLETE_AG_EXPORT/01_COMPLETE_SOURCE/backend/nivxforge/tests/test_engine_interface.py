"""Engine Protocol shape — Phase 0 contract test.

Verifies that a compliant sample engine satisfies the runtime-checkable
Protocol and that a non-compliant object is rejected. No production
engine exists yet.
"""

from nivxforge.core.cio import CIO
from nivxforge.engines.base import Engine


class _NoopEngine:
    """Minimal Protocol-compliant engine used only by tests."""
    name = "noop"

    def process(self, cio: CIO) -> CIO:
        cio.append("telemetry", engine=self.name, payload={"note": "noop"})
        return cio


def test_noop_engine_satisfies_protocol():
    assert isinstance(_NoopEngine(), Engine)


def test_engine_process_appends_via_cio():
    cio = CIO()
    out = _NoopEngine().process(cio)
    assert out is cio
    assert len(out.telemetry) == 1
    assert out.telemetry[0].provenance.engine == "noop"


def test_non_engine_object_is_rejected():
    class NotAnEngine:
        pass
    assert not isinstance(NotAnEngine(), Engine)
