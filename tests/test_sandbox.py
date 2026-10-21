from pathlib import Path
import pytest

from regradar.invariant.sandbox import SandboxRunner
from regradar.invariant.models import InvariantReport


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
