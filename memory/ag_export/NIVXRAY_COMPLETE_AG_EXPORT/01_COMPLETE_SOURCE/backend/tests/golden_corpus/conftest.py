"""Pytest local conftest for the Golden Investigation Corpus.

Registers the --update-baseline flag used by test_investigation_replay.
"""


def pytest_addoption(parser):
    parser.addoption(
        "--update-baseline",
        action="store_true",
        default=False,
        help="Overwrite Golden Investigation Corpus baselines with current fingerprints",
    )
