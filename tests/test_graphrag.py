"""
Unit tests for the Hybrid GraphRAG Retriever (Stream A).
"""

import pytest

from regradar.knowledge.graph import RegulatoryKnowledgeGraph
from regradar.knowledge.retriever import HybridGraphRAGRetriever
from regradar.knowledge.models import RegulatoryContext
from regradar.remediation.knowledge_base import RegulatoryKnowledgeBase


@pytest.fixture
def retriever() -> HybridGraphRAGRetriever:
    graph = RegulatoryKnowledgeGraph()
    return HybridGraphRAGRetriever(graph=graph)


def test_retriever_initialization(retriever: HybridGraphRAGRetriever):
    assert retriever.graph is not None
    assert retriever._rule_index.total_docs >= 25
    assert retriever._control_index.total_docs >= 25
    assert retriever._standard_index.total_docs >= 4
    assert retriever._req_index.total_docs >= 6


def test_direct_check_id_search(retriever: HybridGraphRAGRetriever):
    results = retriever.retrieve("CKV_AWS_19", top_k=3)
    assert len(results) > 0
    top = results[0]
    assert top.check_id == "CKV_AWS_19"
    assert top.resource_type == "aws_s3_bucket"
    assert top.score > 0.0
    assert "direct lexical match" in top.rationale


def test_statutory_concept_query(retriever: HybridGraphRAGRetriever):
    # Query mentions high-level legal mandate and technical requirement
    results = retriever.retrieve("HIPAA electronic protected health information encryption at rest", top_k=5)
    assert len(results) > 0

    check_ids = [r.check_id for r in results]
    # Should find at least one of the HIPAA encryption rules (S3, RDS, or Azure)
    assert any(cid in check_ids for cid in ["CKV_AWS_19", "CKV_AWS_16", "CKV_AZURE_3"])

    # Verify that multi-hop graph propagation rationale is recorded
    has_graph_rationale = any(
        "graph traversal" in r.rationale or "graph link" in r.rationale
        for r in results
    )
    assert has_graph_rationale


def test_resource_targeted_query(retriever: HybridGraphRAGRetriever):
    # Query with explicit resource_type filter for S3
    results = retriever.retrieve(
        query="encryption",
        resource_type="aws_s3_bucket",
        top_k=3,
    )
    assert len(results) > 0
    for r in results:
        assert r.resource_type == "aws_s3_bucket"
        assert "target resource match" in r.rationale

    check_ids = [r.check_id for r in results]
    assert "CKV_AWS_19" in check_ids or "CKV_AWS_145" in check_ids


def test_multi_standard_mapping(retriever: HybridGraphRAGRetriever):
    # Query referencing GDPR Art. 32
    results = retriever.retrieve("GDPR Art 32 security of processing resilience and recovery", top_k=5)
    assert len(results) > 0

    top_result = results[0]
    assert top_result.standards
    # Verify statutory basis was properly enriched
    assert len(top_result.controls) > 0


def test_zero_public_ingress_port_query(retriever: HybridGraphRAGRetriever):
    # Query regarding SSH port 22 restriction
    results = retriever.retrieve("SSH ingress port 22 public CIDR 0.0.0.0/0", top_k=3)
    assert len(results) > 0
    check_ids = [r.check_id for r in results]
    assert "CKV_AWS_24" in check_ids or "CKV_AZURE_9" in check_ids

    # Targeted to Azure NSG
    azure_results = retriever.retrieve(
        "SSH ingress port 22",
        resource_type="azurerm_network_security_group",
        top_k=2,
    )
    assert len(azure_results) > 0
    assert azure_results[0].check_id == "CKV_AZURE_9"
    assert azure_results[0].resource_type == "azurerm_network_security_group"


def test_audit_logging_query(retriever: HybridGraphRAGRetriever):
    results = retriever.retrieve("CloudTrail multi-region audit event logging", top_k=3)
    assert len(results) > 0
    check_ids = [r.check_id for r in results]
    assert "CKV_AWS_67" in check_ids


def test_regulatory_context_structure(retriever: HybridGraphRAGRetriever):
    results = retriever.retrieve("S3 object versioning", top_k=1)
    assert len(results) == 1
    ctx = results[0]

    assert isinstance(ctx, RegulatoryContext)
    assert ctx.check_id == "CKV_AWS_21"
    assert ctx.rule.strategy.value == "ADDITIVE_ATTACHMENT"
    assert "versioning" in ctx.rule.description.lower()
    assert ctx.resource_type == "aws_s3_bucket"
    assert ctx.score > 0.0
    assert len(ctx.controls) > 0
    assert len(ctx.requirements) > 0


def test_empty_or_nonsense_query(retriever: HybridGraphRAGRetriever):
    results = retriever.retrieve("xqzjjqwk randomnonexistentword999 zzzqqq111", top_k=3)
    assert len(results) == 0


def test_knowledge_base_query_integration():
    # Test querying through RegulatoryKnowledgeBase.query wrapper
    results = RegulatoryKnowledgeBase.query("database storage encryption at rest", top_k=3)
    assert len(results) > 0
    check_ids = [r.check_id for r in results]
    assert "CKV_AWS_16" in check_ids
