from typing import Dict, Optional, TYPE_CHECKING
import networkx as nx

from regradar.models import CentralityMetrics, GraphSummary, RiskTier

if TYPE_CHECKING:
    from regradar.config import CentralityConfig


class CentralityEngine:
    """
    Computes graph-theoretic centrality metrics and evaluates the blast-radius risk
    gate for autonomous IaC compliance remediation.
    """

    def __init__(self, graph: nx.DiGraph, config: Optional["CentralityConfig"] = None):
        self.graph = graph
        self.num_nodes = graph.number_of_nodes()
        if config is None:
            from regradar.config import get_config
            self.config = get_config().centrality
        else:
            self.config = config

    def evaluate(self) -> Dict[str, CentralityMetrics]:
        """
        Calculates Betweenness Centrality, Degree Centrality, Eigenvector Centrality,
        PageRank, and Cascading Descendant Ratio to assign a deterministic Blast-Radius
        Risk Tier to every resource.
        """
        if self.num_nodes == 0:
            return {}

        # 1. Betweenness Centrality (bridges between resources)
        betweenness = nx.betweenness_centrality(self.graph)

        # 2. Eigenvector Centrality (influence on influential resources)
        eigenvector = self._compute_eigenvector()

        # 3. PageRank Centrality (link-based prestige / importance)
        pagerank = self._compute_pagerank()

        metrics: Dict[str, CentralityMetrics] = {}
        denom = max(1, self.num_nodes - 1)

        for node_id in self.graph.nodes:
            node_data = self.graph.nodes[node_id]
            res_type = node_data.get("resource_type", "unknown")

            in_deg = self.graph.in_degree(node_id)
            out_deg = self.graph.out_degree(node_id)

            descendants = nx.descendants(self.graph, node_id)
            ancestors = nx.ancestors(self.graph, node_id)

            desc_count = len(descendants)
            anc_count = len(ancestors)

            # Normalized ratios
            desc_ratio = desc_count / denom
            out_ratio = out_deg / denom
            b_score = betweenness.get(node_id, 0.0)
            e_score = eigenvector.get(node_id, 0.0)
            pr_score = pagerank.get(node_id, 0.0)

            # Composite Blast Radius Risk Score (0.0 to 1.0)
            # Composite Score S(v) = w_desc * desc_ratio + w_b * betweenness + w_e * eigenvector + w_out * out_ratio
            w = self.config.weights
            t = self.config.thresholds

            composite_score = (
                (w.descendant_ratio * desc_ratio)
                + (w.betweenness * b_score)
                + (w.eigenvector * e_score)
                + (w.out_degree_ratio * out_ratio)
            )
            composite_score = round(min(1.0, max(0.0, composite_score)), 4)

            # Determine Risk Tier and Remediation Policy
            # If a node is completely disconnected (isolated), it poses zero cascading blast radius
            if in_deg == 0 and out_deg == 0:
                composite_score = 0.0
                risk_tier = RiskTier.LEAF_SAFE
                auto_remediate = True
            elif composite_score >= t.critical_root_score or desc_ratio >= t.critical_root_descendant_ratio:
                risk_tier = RiskTier.CRITICAL_ROOT
                auto_remediate = False
            elif composite_score >= t.intermediate_score or desc_count > 0:
                risk_tier = RiskTier.INTERMEDIATE
                auto_remediate = True
            else:
                risk_tier = RiskTier.LEAF_SAFE
                auto_remediate = True

            metrics[node_id] = CentralityMetrics(
                node_id=node_id,
                resource_type=res_type,
                in_degree=in_deg,
                out_degree=out_deg,
                descendant_count=desc_count,
                ancestor_count=anc_count,
                betweenness=round(b_score, 4),
                blast_radius_score=composite_score,
                risk_tier=risk_tier,
                auto_remediate=auto_remediate,
                eigenvector=round(e_score, 4),
                pagerank=round(pr_score, 4),
            )

        return metrics

    def _compute_eigenvector(self) -> Dict[str, float]:
        """
        Computes eigenvector centrality with robust fallback:
        Tries nx.eigenvector_centrality_numpy, then falls back to nx.eigenvector_centrality
        with max_iter=2000 and tol=1e-06.
        """
        if self.num_nodes == 0:
            return {}
        try:
            return nx.eigenvector_centrality_numpy(self.graph)
        except (ModuleNotFoundError, ImportError, AttributeError, Exception):
            pass

        try:
            return nx.eigenvector_centrality(
                self.graph,
                max_iter=self.config.solver.max_iter,
                tol=self.config.solver.tol,
            )
        except Exception:
            try:
                return nx.in_degree_centrality(self.graph)
            except Exception:
                return {n: 0.0 for n in self.graph.nodes}

    def _compute_pagerank(self) -> Dict[str, float]:
        """
        Computes PageRank centrality with robust fallback:
        Tries nx.pagerank(self.graph), then falls back to pure-Python pagerank.
        """
        if self.num_nodes == 0:
            return {}
        try:
            return nx.pagerank(self.graph)
        except (ModuleNotFoundError, ImportError, AttributeError):
            try:
                from networkx.algorithms.link_analysis.pagerank_alg import _pagerank_python
                return _pagerank_python(self.graph)
            except Exception:
                n = self.num_nodes
                return {node: 1.0 / n for node in self.graph.nodes}
        except Exception:
            try:
                from networkx.algorithms.link_analysis.pagerank_alg import _pagerank_python
                return _pagerank_python(self.graph)
            except Exception:
                n = self.num_nodes
                return {node: 1.0 / n for node in self.graph.nodes}

    def get_summary(self) -> GraphSummary:
        """Generates a complete graph summary report."""
        metrics = self.evaluate()
        roots = [n for n in self.graph.nodes if self.graph.in_degree(n) == 0]
        leaves = [n for n in self.graph.nodes if self.graph.out_degree(n) == 0]
        has_cycles = not nx.is_directed_acyclic_graph(self.graph)

        return GraphSummary(
            total_resources=self.num_nodes,
            total_dependencies=self.graph.number_of_edges(),
            root_resources=roots,
            leaf_resources=leaves,
            has_cycles=has_cycles,
            metrics=metrics,
        )

    def to_mermaid(self) -> str:
        """Exports the dependency DAG into a Mermaid markdown diagram."""
        lines = ["```mermaid", "flowchart TD"]

        metrics = self.evaluate()

        for node_id, m in metrics.items():
            # Style nodes by Risk Tier
            if m.risk_tier == RiskTier.CRITICAL_ROOT:
                style = ":::critical"
            elif m.risk_tier == RiskTier.INTERMEDIATE:
                style = ":::intermediate"
            else:
                style = ":::leaf"

            label = f"{node_id}<br/>[BR: {m.blast_radius_score}]"
            lines.append(f'    {node_id.replace(".", "_")}["{label}"]{style}')

        for src, dst in self.graph.edges:
            src_clean = src.replace(".", "_")
            dst_clean = dst.replace(".", "_")
            lines.append(f"    {src_clean} --> {dst_clean}")

        lines.append("    classDef critical fill:#ffcccc,stroke:#cc0000,stroke-width:2px;")
        lines.append("    classDef intermediate fill:#fff2cc,stroke:#d6b656,stroke-width:1px;")
        lines.append("    classDef leaf fill:#d5e8d4,stroke:#82b366,stroke-width:1px;")
        lines.append("```")

        return "\n".join(lines)

    def to_dot(self) -> str:
        """Exports the graph in Graphviz DOT format."""
        lines = ["digraph RegRadarDependencies {", '    rankdir="TB";', "    node [shape=box, style=filled];"]

        metrics = self.evaluate()
        for node_id, m in metrics.items():
            if m.risk_tier == RiskTier.CRITICAL_ROOT:
                color = "tomato"
            elif m.risk_tier == RiskTier.INTERMEDIATE:
                color = "gold"
            else:
                color = "palegreen"

            label = f"{node_id}\\nScore: {m.blast_radius_score}"
            lines.append(f'    "{node_id}" [label="{label}", fillcolor="{color}"];')

        for src, dst in self.graph.edges:
            lines.append(f'    "{src}" -> "{dst}";')

        lines.append("}")
        return "\n".join(lines)
