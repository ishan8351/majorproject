from pathlib import Path
import pytest

from regradar.remediation.policy_engine import (
    CheckovPolicyEngine,
    CompositePolicyEngine,
    OPAPolicyEngine,
    RegRadarASTEngine,
)


@pytest.fixture
def benchmarks_dir() -> Path:
    return Path(__file__).parent / "fixtures" / "benchmarks"


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


def test_opa_policy_engine_statutory_detection(benchmarks_dir: Path):
    """Verifies that OPAPolicyEngine detects declarative Rego violations across frameworks."""
    opa = OPAPolicyEngine()
    assert opa.is_available() is True
    status = opa.get_status()
    assert status["engine_id"] == "opa"
    assert status["available"] is True
    assert status["rules_count"] == 15

    # Scan Healthcare HIPAA benchmark
    hipaa_dir = benchmarks_dir / "healthcare_hipaa_aws"
    violations = opa.scan_directory(hipaa_dir)
    check_ids = {v.check_id for v in violations}

    assert "CKV_AWS_19" in check_ids  # S3 secure_at_rest
    assert "CKV_AWS_21" in check_ids  # S3 versioning
    assert "CKV_AWS_16" in check_ids  # RDS encryption
    assert "CKV_AWS_36" in check_ids  # CloudTrail KMS
    assert "CKV_AWS_40" in check_ids  # IAM Wildcard

    # Framework mapping verification
    v_s3 = next(v for v in violations if v.check_id == "CKV_AWS_19")
    assert any("HIPAA" in f for f in v_s3.frameworks)
    assert any("GDPR" in f for f in v_s3.frameworks)


def test_opa_policy_engine_azure_and_pci(benchmarks_dir: Path):
    """Verifies Azure GDPR and PCI-DSS rules in OPA engine."""
    opa = OPAPolicyEngine()

    # Fintech PCI-DSS
    pci_dir = benchmarks_dir / "fintech_pci_aws"
    pci_violations = opa.scan_directory(pci_dir)
    pci_checks = {v.check_id for v in pci_violations}
    assert "CKV_AWS_24" in pci_checks  # Security group SSH unrestricted

    # E-commerce Azure GDPR
    azure_dir = benchmarks_dir / "ecommerce_gdpr_azure"
    azure_violations = opa.scan_directory(azure_dir)
    azure_checks = {v.check_id for v in azure_violations}
    assert "CKV_AZURE_3" in azure_checks or "CKV_AZURE_44" in azure_checks


def test_clean_workspace_produces_zero_violations(fixtures_dir: Path):
    """Ensures compliant infrastructure does NOT produce synthetic fake violations."""
    engine = CompositePolicyEngine.get_instance()
    simple_vpc_dir = fixtures_dir / "simple_vpc"
    violations = engine.scan_directory(simple_vpc_dir)
    # A standard compliant VPC with public subnet must not invent HIPAA/PCI violations
    assert len(violations) == 0


def test_composite_policy_engine_catalog():
    """Verifies engine catalog returns diagnostic metadata for all 3 engines."""
    engine = CompositePolicyEngine.get_instance()
    catalog = engine.get_catalog()
    assert catalog["total_engines"] == 3
    assert catalog["active_engines_count"] >= 2
    engine_ids = {e["engine_id"] for e in catalog["engines"]}
    assert "checkov" in engine_ids
    assert "opa" in engine_ids
    assert "ast" in engine_ids
