from pathlib import Path
from unittest.mock import MagicMock
import pytest

from regradar.invariant.models import InvariantReport
from regradar.remediation.models import ComplianceViolation, GatingStatus
from regradar.remediation.swarm_coordinator import SwarmCoordinator


def test_swarm_coordinator_with_mock_sandbox(simple_vpc_path: Path):
    # Mock sandbox that immediately accepts valid non-destructive plans
    mock_sandbox = MagicMock()
    mock_sandbox.simulate_and_verify.return_value = InvariantReport(
        is_safe=True,
        zero_destruction_guarantee_met=True,
        total_resources_evaluated=2,
        count_created=1,
    )

    coordinator = SwarmCoordinator(sandbox_runner=mock_sandbox)

    mock_violations = [
        ComplianceViolation(
            check_id="CKV_AWS_19",
            check_name="S3 Server Side Encryption",
            resource_id="aws_subnet.public",
            resource_type="aws_subnet",
            file_path="main.tf",
        ),
        ComplianceViolation(
            check_id="CKV_AWS_19",
            check_name="Root Network Violation",
            resource_id="aws_vpc.main",
            resource_type="aws_vpc",
            file_path="main.tf",
        ),
    ]

    result = coordinator.remediate_directory(
        target_dir=simple_vpc_path,
        apply_changes=False,
        precomputed_violations=mock_violations,
    )

    assert result.total_violations_found == 2
    # aws_vpc.main should be gated as critical root
    vpc_task = next(t for t in result.tasks if t.violation.resource_id == "aws_vpc.main")
    assert vpc_task.gating_status == GatingStatus.HUMAN_ESCALATION_REQUIRED

    # Subnet is safe leaf in simple_vpc
    subnet_task = next(t for t in result.tasks if t.violation.resource_id == "aws_subnet.public")
    assert subnet_task.gating_status == GatingStatus.AUTONOMOUS_ELIGIBLE
    assert result.patches_verified_and_accepted == 1
