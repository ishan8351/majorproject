from pathlib import Path
import pytest

from regradar.parser.hcl_parser import HCLParser
from regradar.graph.builder import DependencyGraphBuilder
from regradar.graph.centrality import CentralityEngine
from regradar.models import RiskTier


def test_centrality_multi_tier(multi_tier_path: Path):
    parser = HCLParser()
    resources = parser.parse_directory(multi_tier_path)
    builder = DependencyGraphBuilder(resources)
    engine = CentralityEngine(builder.graph)

    summary = engine.get_summary()
    assert summary.total_resources == 10
    assert summary.has_cycles is False

    vpc_metrics = summary.metrics["aws_vpc.prod_vpc"]
    assert vpc_metrics.risk_tier == RiskTier.CRITICAL_ROOT
    assert vpc_metrics.auto_remediate is False
    assert vpc_metrics.descendant_count >= 5

    # Check leaf resource
    leaf_id = "aws_s3_bucket_server_side_encryption_configuration.log_encryption"
    leaf_metrics = summary.metrics[leaf_id]
    assert leaf_metrics.risk_tier == RiskTier.LEAF_SAFE
    assert leaf_metrics.auto_remediate is True
    assert leaf_metrics.descendant_count == 0
    assert leaf_metrics.out_degree == 0

    # Intermediate compute node
    ec2_metrics = summary.metrics["aws_instance.app_server"]
    assert ec2_metrics.risk_tier == RiskTier.LEAF_SAFE or ec2_metrics.risk_tier == RiskTier.INTERMEDIATE
    assert ec2_metrics.auto_remediate is True


def test_mermaid_and_dot_export(multi_tier_path: Path):
    parser = HCLParser()
    resources = parser.parse_directory(multi_tier_path)
    builder = DependencyGraphBuilder(resources)
    engine = CentralityEngine(builder.graph)

    mermaid_str = engine.to_mermaid()
    assert "flowchart TD" in mermaid_str
    assert "aws_vpc_prod_vpc" in mermaid_str
    assert "classDef critical" in mermaid_str

    dot_str = engine.to_dot()
    assert "digraph RegRadarDependencies" in dot_str
    assert '"aws_vpc.prod_vpc"' in dot_str
