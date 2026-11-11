"""
Unit tests for the Ontological Regulatory Knowledge Graph (Stream A).
"""

import pytest

from regradar.knowledge.catalog import STANDARDS, CONTROLS, REQUIREMENTS, CLOUD_RESOURCES, RULES
from regradar.knowledge.graph import RegulatoryKnowledgeGraph
from regradar.knowledge.models import EdgeType, RemediationRule
from regradar.remediation.models import RemediationStrategy


@pytest.fixture
def graph() -> RegulatoryKnowledgeGraph:
    return RegulatoryKnowledgeGraph()


def test_graph_initialization(graph: RegulatoryKnowledgeGraph):
    summary = graph.summary()
    assert summary["standards_count"] >= 4
    assert summary["controls_count"] >= 25
    assert summary["requirements_count"] >= 6
    assert summary["resources_count"] >= 8
    assert summary["rules_count"] >= 25
    assert summary["total_nodes"] > 50
    assert summary["total_edges"] > 60


def test_node_attributes(graph: RegulatoryKnowledgeGraph):
    raw_g = graph.raw_graph
    assert raw_g.has_node("standard:HIPAA")
    assert raw_g.nodes["standard:HIPAA"]["type"] == "standard"
    assert "Health Insurance" in raw_g.nodes["standard:HIPAA"]["name"]

    assert raw_g.has_node("control:HIPAA_164_312_a_2_iv")
    assert raw_g.nodes["control:HIPAA_164_312_a_2_iv"]["type"] == "control"
    assert raw_g.nodes["control:HIPAA_164_312_a_2_iv"]["control_id"] == "§164.312(a)(2)(iv)"

    assert raw_g.has_node("requirement:REQ_ENCRYPTION_AT_REST")
    assert raw_g.nodes["requirement:REQ_ENCRYPTION_AT_REST"]["type"] == "requirement"

    assert raw_g.has_node("resource:aws_s3_bucket")
    assert raw_g.nodes["resource:aws_s3_bucket"]["type"] == "resource"
    assert raw_g.nodes["resource:aws_s3_bucket"]["cloud_provider"] == "aws"

    assert raw_g.has_node("rule:CKV_AWS_19")
    assert raw_g.nodes["rule:CKV_AWS_19"]["type"] == "rule"


def test_graph_edge_relations(graph: RegulatoryKnowledgeGraph):
    raw_g = graph.raw_graph

    # Standard MANDATES Control
    mandates = raw_g.get_edge_data("standard:HIPAA", "control:HIPAA_164_312_a_2_iv")
    assert mandates is not None
    assert any(d.get("relation") == EdgeType.MANDATES.value for d in mandates.values())

    # Control REQUIRES_CONTROL Requirement
    requires = raw_g.get_edge_data("control:HIPAA_164_312_a_2_iv", "requirement:REQ_ENCRYPTION_AT_REST")
    assert requires is not None
    assert any(d.get("relation") == EdgeType.REQUIRES_CONTROL.value for d in requires.values())

    # Rule APPLIES_TO_RESOURCE Resource
    applies = raw_g.get_edge_data("rule:CKV_AWS_19", "resource:aws_s3_bucket")
    assert applies is not None
    assert any(d.get("relation") == EdgeType.APPLIES_TO_RESOURCE.value for d in applies.values())

    # Control REMEDIATED_BY Rule
    remediated = raw_g.get_edge_data("control:HIPAA_164_312_a_2_iv", "rule:CKV_AWS_19")
    assert remediated is not None
    assert any(d.get("relation") == EdgeType.REMEDIATED_BY.value for d in remediated.values())


def test_get_statutory_basis_for_s3_encryption(graph: RegulatoryKnowledgeGraph):
    basis = graph.get_statutory_basis("CKV_AWS_19")
    assert basis is not None
    assert basis.check_id == "CKV_AWS_19"
    assert "HIPAA" in basis.statute_reference

    std_ids = [s.id for s in basis.standards]
    assert "HIPAA" in std_ids
    assert "GDPR" in std_ids

    ctrl_ids = [c.id for c in basis.controls]
    assert "HIPAA_164_312_a_2_iv" in ctrl_ids
    assert "GDPR_Art_32_1_a" in ctrl_ids

    req_ids = [r.id for r in basis.requirements]
    assert "REQ_ENCRYPTION_AT_REST" in req_ids


def test_get_statutory_basis_unknown(graph: RegulatoryKnowledgeGraph):
    assert graph.get_statutory_basis("NON_EXISTENT_CHECK_XYZ") is None


def test_get_controls_for_resource(graph: RegulatoryKnowledgeGraph):
    # AWS S3 Bucket controls
    s3_controls = graph.get_controls_for_resource("aws_s3_bucket")
    assert len(s3_controls) > 0
    s3_ctrl_ids = {c.id for c in s3_controls}
    assert "HIPAA_164_312_a_2_iv" in s3_ctrl_ids
    assert "HIPAA_164_308_a_7_ii_A" in s3_ctrl_ids
    assert "NIST_AC_3" in s3_ctrl_ids

    # Azure Storage Account controls
    azure_controls = graph.get_controls_for_resource("azurerm_storage_account")
    assert len(azure_controls) > 0
    azure_ctrl_ids = {c.id for c in azure_controls}
    assert "PCI_DSS_4_1" in azure_ctrl_ids
    assert "HIPAA_164_312_e_1" in azure_ctrl_ids

    # Non-existent resource returns empty list
    assert graph.get_controls_for_resource("non_existent_provider_resource") == []


def test_find_remediation(graph: RegulatoryKnowledgeGraph):
    # Rule exists without resource filter
    rule = graph.find_remediation("CKV_AWS_19")
    assert rule is not None
    assert rule.check_id == "CKV_AWS_19"
    assert rule.strategy == RemediationStrategy.ADDITIVE_ATTACHMENT

    # Rule exists with matching resource filter
    rule_s3 = graph.find_remediation("CKV_AWS_19", resource_type="aws_s3_bucket")
    assert rule_s3 is not None

    # Rule exists but resource filter does not match
    rule_mismatch = graph.find_remediation("CKV_AWS_19", resource_type="aws_instance")
    assert rule_mismatch is None

    # Rule does not exist
    assert graph.find_remediation("UNKNOWN_999") is None


def test_get_rules_for_framework(graph: RegulatoryKnowledgeGraph):
    hipaa_rules = graph.get_rules_for_framework("HIPAA")
    hipaa_ids = {r.check_id for r in hipaa_rules}
    assert "CKV_AWS_19" in hipaa_ids
    assert "CKV_AWS_21" in hipaa_ids
    assert "CKV_AWS_16" in hipaa_ids

    pci_rules = graph.get_rules_for_framework("PCI_DSS")
    pci_ids = {r.check_id for r in pci_rules}
    assert "CKV_AWS_24" in pci_ids  # SSH restriction
    assert "CKV_AWS_7" in pci_ids   # KMS key rotation

    nist_rules = graph.get_rules_for_framework("NIST_SP_800_53")
    nist_ids = {r.check_id for r in nist_rules}
    assert "CKV_AWS_53" in nist_ids
    assert "CKV_AWS_79" in nist_ids


def test_get_rules_for_resource(graph: RegulatoryKnowledgeGraph):
    rds_rules = graph.get_rules_for_resource("aws_db_instance")
    rds_ids = {r.check_id for r in rds_rules}
    assert "CKV_AWS_16" in rds_ids   # Storage encryption
    assert "CKV_AWS_157" in rds_ids  # Multi-AZ
    assert "CKV_AWS_17" in rds_ids   # Backup retention
    assert "CKV_AWS_118" in rds_ids  # Monitoring

    nsg_rules = graph.get_rules_for_resource("azurerm_network_security_group")
    nsg_ids = {r.check_id for r in nsg_rules}
    assert "CKV_AZURE_9" in nsg_ids
    assert "CKV_AZURE_10" in nsg_ids


def test_get_rules_for_requirement(graph: RegulatoryKnowledgeGraph):
    ingress_rules = graph.get_rules_for_requirement("REQ_ZERO_PUBLIC_INGRESS")
    ingress_ids = {r.check_id for r in ingress_rules}
    assert "CKV_AWS_24" in ingress_ids  # SSH port 22
    assert "CKV_AWS_25" in ingress_ids  # RDP port 3389
    assert "CKV_AZURE_9" in ingress_ids # Azure SSH
    assert "CKV_AWS_53" in ingress_ids  # S3 public access block


def test_custom_catalog_graph_creation():
    custom_rules = {
        "CUSTOM_01": RemediationRule(
            check_id="CUSTOM_01",
            name="Custom Rule",
            description="Custom test rule",
            resource_type="aws_s3_bucket",
            framework="HIPAA",
            statute_reference="HIPAA §164.312",
            strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
            target_attribute="custom_attr",
            attribute_value="custom_val = true",
        )
    }
    custom_graph = RegulatoryKnowledgeGraph(
        standards=STANDARDS,
        controls=CONTROLS,
        requirements=REQUIREMENTS,
        cloud_resources=CLOUD_RESOURCES,
        rules=custom_rules,
    )
    assert custom_graph.summary()["rules_count"] == 1
    assert custom_graph.find_remediation("CUSTOM_01") is not None
