import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="session", autouse=True)
def generate_examples() -> None:
    """Ensure benign sample files are materialised before tests run."""
    from examples.generate_benign_samples import main as generate

    generate()
