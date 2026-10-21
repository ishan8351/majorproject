from pathlib import Path
import pytest


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def simple_vpc_path(fixtures_dir) -> Path:
    return fixtures_dir / "simple_vpc"


@pytest.fixture
def multi_tier_path(fixtures_dir) -> Path:
    return fixtures_dir / "multi_tier"
