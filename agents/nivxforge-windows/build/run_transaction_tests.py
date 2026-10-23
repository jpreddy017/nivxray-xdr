"""Portable, bounded installer/delivery/journal regression selection.

The repository also has a top-level tests package. Bind this backend-only run
explicitly rather than allowing cwd to select the wrong tests.edr package.
"""
import sys
import tempfile
import types
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend"))
tests = types.ModuleType("tests")
tests.__path__ = [str(ROOT / "backend/tests")]
sys.modules["tests"] = tests
selection = ["test_installer_transaction.py", "test_p0_installer_upgrade_repair.py",
             "test_p0_sensor_delivery_repair.py", "test_b5_gap1_journal_durability.py",
             "test_b5_gap1_paged_acquisition.py", "test_b5_gap1_stress_and_silent_loss.py",
             "test_b5_gap1_pre_canary_acceptance.py"]
with tempfile.TemporaryDirectory() as scratch:
    config = Path(scratch) / "pytest.ini"
    config.write_text("[pytest]\n")
    result = pytest.main(["-c", str(config), "--noconftest", "-p", "no:randomly", "-q",
                          *[str(ROOT / "backend/tests/edr" / f) for f in selection],
                          *sys.argv[1:]])
raise SystemExit(result)
