from pathlib import Path
import pytest

from regradar.parser.hcl_parser import HCLParser
from regradar.parser.reference_extractor import ReferenceExtractor


def test_reference_extractor_simple_string():
    val = "${aws_vpc.main.id}"
    refs = ReferenceExtractor.extract_from_value(val)
    assert "aws_vpc.main" in refs


def test_reference_extractor_nested_list_and_dict():
    val = {
        "security_groups": ["${aws_security_group.web.id}", "sg-12345"],
        "nested": {
            "target": "aws_kms_key.app_key.arn"
        }
    }
    refs = ReferenceExtractor.extract_from_value(val)
    assert "aws_security_group.web" in refs
    assert "aws_kms_key.app_key" in refs
    assert len(refs) == 2


def test_reference_extractor_ignores_variables_and_locals():
    val = [
        "var.region",
        "local.common_tags",
        "aws_subnet.public.id"
    ]
    refs = ReferenceExtractor.extract_from_value(val)
    assert refs == {"aws_subnet.public"}


def test_reference_extractor_explicit_depends_on():
    config = {
        "depends_on": ["aws_iam_role.role", "aws_s3_bucket.logs"]
    }
    deps = ReferenceExtractor.extract_explicit_depends_on(config)
    assert deps == {"aws_iam_role.role", "aws_s3_bucket.logs"}


def test_parser_simple_vpc(simple_vpc_path: Path):
    parser = HCLParser()
    resources = parser.parse_directory(simple_vpc_path)

    assert len(resources) == 2
    assert "aws_vpc.main" in resources
    assert "aws_subnet.public" in resources

    subnet = resources["aws_subnet.public"]
    assert "aws_vpc.main" in subnet.inferred_dependencies


def test_parser_multi_tier(multi_tier_path: Path):
    parser = HCLParser()
    resources = parser.parse_directory(multi_tier_path)

    expected_ids = {
        "aws_vpc.prod_vpc",
        "aws_internet_gateway.gw",
        "aws_subnet.app_subnet",
        "aws_route_table.public_rt",
        "aws_route_table_association.public_assoc",
        "aws_security_group.app_sg",
        "aws_instance.app_server",
        "aws_kms_key.data_key",
        "aws_s3_bucket.audit_logs",
        "aws_s3_bucket_server_side_encryption_configuration.log_encryption",
    }

    assert set(resources.keys()) == expected_ids

    # Check EC2 references subnet and security group
    ec2 = resources["aws_instance.app_server"]
    assert "aws_subnet.app_subnet" in ec2.inferred_dependencies
    assert "aws_security_group.app_sg" in ec2.inferred_dependencies


def test_parser_file_not_found():
    parser = HCLParser()
    with pytest.raises(FileNotFoundError):
        parser.parse_file("non_existent_file.tf")
