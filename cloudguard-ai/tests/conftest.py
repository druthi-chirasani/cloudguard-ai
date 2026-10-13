import copy
import json
from pathlib import Path

import pytest

DATA = Path(__file__).resolve().parent.parent / "data"


@pytest.fixture
def config():
    return json.loads((DATA / "sample_config.json").read_text(encoding="utf-8"))


@pytest.fixture
def audit():
    return json.loads((DATA / "sample_audit_logs.json").read_text(encoding="utf-8"))


@pytest.fixture
def clone():
    return copy.deepcopy
