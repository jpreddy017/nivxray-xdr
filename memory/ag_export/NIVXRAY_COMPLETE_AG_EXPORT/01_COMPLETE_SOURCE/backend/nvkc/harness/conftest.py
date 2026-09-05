"""NVKC harness conftest — CLI option registration."""


def pytest_addoption(parser):
    parser.addoption(
        "--nvkc-update-baseline",
        action="store_true",
        default=False,
        help=("Owner-only: overwrite every NVKC sample's baseline with "
              "the current actual output (matches Golden Corpus governance)."),
    )
