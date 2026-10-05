from pathlib import Path

import pytest

from src.mapping.canonical import Catalogue
from src.registry import Registry, Snapshot

ROOT = Path(__file__).resolve().parents[1]
PACKS = ROOT / "packs"
CONFIGS = ROOT / "fixtures" / "configs" / "batfish_example_live"
GOLDEN = ROOT / "fixtures" / "golden"


@pytest.fixture(scope="session")
def catalogue() -> Catalogue:
    return Catalogue.load()


@pytest.fixture(scope="session")
def snapshot(catalogue: Catalogue) -> Snapshot:
    snap = Registry(PACKS, catalogue).snapshot()
    assert snap.errors == []
    return snap
