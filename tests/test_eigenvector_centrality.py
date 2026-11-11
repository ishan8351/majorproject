from pathlib import Path
from unittest.mock import patch
import networkx as nx
import pytest

from regradar.parser.hcl_parser import HCLParser
from regradar.graph.builder import DependencyGraphBuilder
from regradar.graph.centrality import CentralityEngine
from regradar.models import CentralityMetrics, RiskTier, TerraformResource


def test_eigenvector_and_pagerank_multi_tier(multi_tier_path: Path):
    parser = HCLParser()
    resources = parser.parse_directory(multi_tier_path)
    builder = DependencyGraphBuilder(resources)
    engine = CentralityEngine(builder.graph)

    metrics = engine.evaluate()
    assert len(metrics) == 10

    # Verify that all metrics contain eigenvector and pagerank
    total_pr = 0.0
    for node_id, m in metrics.items():
        assert hasattr(m, "eigenvector")
        assert hasattr(m, "pagerank")
        assert 0.0 <= m.eigenvector <= 1.0
        assert 0.0 <= m.pagerank <= 1.0
        total_pr += m.pagerank

    # PageRank scores should approximately sum to 1.0 across the graph
    assert pytest.approx(total_pr, rel=1e-2) == 1.0

    # Verify composite risk score formula
    denom = max(1, len(builder.graph.nodes) - 1)
    for node_id, m in metrics.items():
        desc_ratio = m.descendant_count / denom
        out_ratio = m.out_degree / denom
        expected_score = round(
            (0.40 * desc_ratio)
            + (0.25 * m.betweenness)
            + (0.20 * m.eigenvector)
            + (0.15 * out_ratio),
            4,
        )
        expected_score = min(1.0, max(0.0, expected_score))
        assert m.blast_radius_score == pytest.approx(expected_score, abs=1e-4)

    # Root resource (aws_vpc.prod_vpc)
    vpc = metrics["aws_vpc.prod_vpc"]
    assert vpc.risk_tier == RiskTier.CRITICAL_ROOT
    assert vpc.auto_remediate is False
    assert vpc.descendant_count >= 5

    # Leaf resource (log_encryption)
    leaf = metrics["aws_s3_bucket_server_side_encryption_configuration.log_encryption"]
    assert leaf.risk_tier == RiskTier.LEAF_SAFE
    assert leaf.auto_remediate is True
    assert leaf.descendant_count == 0
    assert leaf.out_degree == 0


def test_eigenvector_numpy_fallback():
    G = nx.DiGraph()
    G.add_edge("res_a", "res_b")
    G.add_edge("res_b", "res_c")

    engine = CentralityEngine(G)

    # Force nx.eigenvector_centrality_numpy to raise ModuleNotFoundError
    with patch("networkx.eigenvector_centrality_numpy", side_effect=ModuleNotFoundError("numpy missing")):
        eigen = engine._compute_eigenvector()
        assert len(eigen) == 3
        assert all(isinstance(v, float) for v in eigen.values())
        assert all(0.0 <= v <= 1.0 for v in eigen.values())


def test_eigenvector_power_iteration_failure_fallback():
    G = nx.DiGraph()
    G.add_edge("res_a", "res_b")

    engine = CentralityEngine(G)

    # Force both numpy and power iteration to fail
    with patch("networkx.eigenvector_centrality_numpy", side_effect=Exception("No numpy")), \
         patch("networkx.eigenvector_centrality", side_effect=Exception("Power iteration failed")):
        eigen = engine._compute_eigenvector()
        assert len(eigen) == 2
        # Should fall back to in_degree_centrality
        assert "res_a" in eigen
        assert "res_b" in eigen


def test_pagerank_fallback_to_python():
    G = nx.DiGraph()
    G.add_edge("res_a", "res_b")
    G.add_edge("res_b", "res_c")

    engine = CentralityEngine(G)

    # Simulate scipy/numpy missing in nx.pagerank
    with patch("networkx.pagerank", side_effect=ModuleNotFoundError("scipy missing")):
        pr = engine._compute_pagerank()
        assert len(pr) == 3
        assert pytest.approx(sum(pr.values()), rel=1e-2) == 1.0


def test_pagerank_complete_failure_fallback():
    G = nx.DiGraph()
    G.add_nodes_from(["res_a", "res_b", "res_c"])

    engine = CentralityEngine(G)

    with patch("networkx.pagerank", side_effect=Exception("Pagerank failed")), \
         patch("networkx.algorithms.link_analysis.pagerank_alg._pagerank_python", side_effect=Exception("Python PR failed")):
        pr = engine._compute_pagerank()
        assert len(pr) == 3
        # Should fall back to uniform distribution
        for v in pr.values():
            assert pytest.approx(v, abs=1e-4) == 1.0 / 3.0


def test_centrality_empty_graph():
    G = nx.DiGraph()
    engine = CentralityEngine(G)
    metrics = engine.evaluate()
    assert metrics == {}

    summary = engine.get_summary()
    assert summary.total_resources == 0
    assert summary.total_dependencies == 0
    assert summary.root_resources == []
    assert summary.leaf_resources == []
    assert summary.has_cycles is False


def test_centrality_single_node():
    G = nx.DiGraph()
    G.add_node("res_alone", resource_type="aws_s3_bucket")

    engine = CentralityEngine(G)
    metrics = engine.evaluate()

    assert len(metrics) == 1
    m = metrics["res_alone"]
    assert m.node_id == "res_alone"
    assert m.in_degree == 0
    assert m.out_degree == 0
    assert m.descendant_count == 0
    assert m.ancestor_count == 0
    assert m.risk_tier == RiskTier.LEAF_SAFE
    assert m.auto_remediate is True


def test_centrality_disconnected_graph():
    G = nx.DiGraph()
    G.add_edge("comp1_a", "comp1_b")
    G.add_edge("comp2_x", "comp2_y")

    engine = CentralityEngine(G)
    metrics = engine.evaluate()

    assert len(metrics) == 4
    for k in ["comp1_a", "comp1_b", "comp2_x", "comp2_y"]:
        assert k in metrics
        assert 0.0 <= metrics[k].eigenvector <= 1.0
        assert 0.0 <= metrics[k].pagerank <= 1.0


def test_centrality_cyclic_graph_resilience():
    G = nx.DiGraph()
    G.add_edge("cycle_a", "cycle_b")
    G.add_edge("cycle_b", "cycle_c")
    G.add_edge("cycle_c", "cycle_a")

    engine = CentralityEngine(G)
    summary = engine.get_summary()
    assert summary.has_cycles is True
    assert len(summary.metrics) == 3


def test_backward_compatibility_centrality_metrics():
    # Instantiation without eigenvector or pagerank defaults to 0.0
    m = CentralityMetrics(
        node_id="test_node",
        resource_type="aws_vpc",
        in_degree=0,
        out_degree=1,
        descendant_count=1,
        ancestor_count=0,
        betweenness=0.1,
        blast_radius_score=0.25,
        risk_tier=RiskTier.INTERMEDIATE,
        auto_remediate=True,
    )
    assert m.eigenvector == 0.0
    assert m.pagerank == 0.0
