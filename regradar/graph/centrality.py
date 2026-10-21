from typing import Dict, Optional
import networkx as nx

from regradar.models import CentralityMetrics, GraphSummary, RiskTier


class CentralityEngine:
    """
    Computes graph-theoretic centrality metrics and evaluates the blast-radius risk
    gate for autonomous IaC compliance remediation.
    """

    def __init__(self, graph: nx.DiGraph):
        self.graph = graph
        self.num_nodes = graph.number_of_nodes()

    def evaluate(self) -> Dict[str, CentralityMetrics]:
        """
        Calculates Betweenness Centrality, Degree Centrality, and Cascading Descendant Ratio
        to assign a deterministic Blast-Radius Risk Tier to every resource.
        """
        if self.num_nodes == 0:
            return {}

        # 1. Betweenness Centrality (bridges between resources)
        betweenness = nx.betweenness_centrality(self.graph)

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

            # Composite Blast Radius Risk Score (0.0 to 1.0)
            # 50% Cascading Descendants, 30% Betweenness, 20% Direct Fan-out
            composite_score = (0.50 * desc_ratio) + (0.30 * b_score) + (0.20 * out_ratio)
            composite_score = round(min(1.0, max(0.0, composite_score)), 4)

            # Determine Risk Tier and Remediation Policy
            if composite_score >= 0.40 or desc_ratio >= 0.35:
                risk_tier = RiskTier.CRITICAL_ROOT
                auto_remediate = False
            elif composite_score >= 0.15 or desc_count > 0:
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
            )

        return metrics

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
