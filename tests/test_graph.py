from pathlib import Path
import pytest
import networkx as nx

from regradar.parser.hcl_parser import HCLParser
from regradar.graph.builder import DependencyGraphBuilder
from regradar.models import TerraformResource


def test_graph_builder_simple_vpc(simple_vpc_path: Path):
    parser = HCLParser()
    resources = parser.parse_directory(simple_vpc_path)
    builder = DependencyGraphBuilder(resources)

    assert builder.is_dag is True
    assert builder.find_cycles() == []

    # Direction: aws_vpc.main -> aws_subnet.public
    assert builder.graph.has_edge("aws_vpc.main", "aws_subnet.public")
    assert not builder.graph.has_edge("aws_subnet.public", "aws_vpc.main")

    # Blast radius of VPC should be {aws_subnet.public}
    blast_radius = builder.get_blast_radius("aws_vpc.main")
    assert blast_radius == {"aws_subnet.public"}

    # Blast radius of Subnet should be empty
    assert builder.get_blast_radius("aws_subnet.public") == set()


def test_graph_builder_multi_tier_descendants(multi_tier_path: Path):
    parser = HCLParser()
    resources = parser.parse_directory(multi_tier_path)
    builder = DependencyGraphBuilder(resources)

    assert builder.is_dag is True

    # VPC should have cascading descendants across the entire network and compute stack
    vpc_blast_radius = builder.get_blast_radius("aws_vpc.prod_vpc")
    assert "aws_subnet.app_subnet" in vpc_blast_radius
    assert "aws_route_table.public_rt" in vpc_blast_radius
    assert "aws_route_table_association.public_assoc" in vpc_blast_radius
    assert "aws_security_group.app_sg" in vpc_blast_radius
    assert "aws_instance.app_server" in vpc_blast_radius

    # KMS key should have cascading blast radius to encryption configuration
    kms_blast = builder.get_blast_radius("aws_kms_key.data_key")
    assert "aws_s3_bucket_server_side_encryption_configuration.log_encryption" in kms_blast


def test_cycle_detection():
    # Construct artificial circular dependency to test safety detection
    r1 = TerraformResource(
        id="aws_resource.a",
        resource_type="aws_resource",
        name="a",
        file_path="dummy.tf",
        inferred_dependencies={"aws_resource.b"},
    )
    r2 = TerraformResource(
        id="aws_resource.b",
        resource_type="aws_resource",
        name="b",
        file_path="dummy.tf",
        inferred_dependencies={"aws_resource.a"},
    )

    builder = DependencyGraphBuilder({"aws_resource.a": r1, "aws_resource.b": r2})
    assert builder.is_dag is False
    cycles = builder.find_cycles()
    assert len(cycles) > 0
