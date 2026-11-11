import shutil
from pathlib import Path
import pytest

from regradar.invariant.sandbox import SandboxRunner
from regradar.invariant.models import InvariantReport


@pytest.mark.skipif(shutil.which("tofu") is None, reason="OpenTofu binary not installed")
def test_sandbox_live_plan_simulation(simple_vpc_path: Path):
    runner = SandboxRunner()
    # Runs in an isolated temp directory, invokes tofu init & plan
    report = runner.simulate_and_verify(simple_vpc_path)

    assert isinstance(report, InvariantReport)
    assert report.is_safe is True
    assert report.zero_destruction_guarantee_met is True
    assert report.count_created >= 2  # VPC and Subnet created initially
    assert report.count_deleted == 0
    assert report.count_replaced == 0


def test_sandbox_offline_plan_simulation(fixtures_dir: Path):
    runner = SandboxRunner()
    plan_json_path = fixtures_dir / "sample_destructive_plan.json"
    import json

    with open(plan_json_path, "r", encoding="utf-8") as f:
        plan_data = json.load(f)

    report = runner.simulate_and_verify(
        base_dir=fixtures_dir,
        existing_plan_json=plan_data,
    )

    assert isinstance(report, InvariantReport)
    assert report.is_safe is False
    assert report.zero_destruction_guarantee_met is False
    assert report.count_replaced == 1
    assert report.count_deleted == 1
