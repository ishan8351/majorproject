from typing import Dict, List, Set
import networkx as nx

from regradar.models import TerraformResource


class DependencyGraphBuilder:
    """
    Constructs a Directed Acyclic Graph (DAG) modeling cross-resource bindings.

    Direction Convention:
      Dependency -> Dependent
      (e.g., aws_vpc.main -> aws_subnet.public -> aws_instance.web)
      This ensures that nx.descendants(node) directly yields the cascading blast radius
      of modifying that node.
    """

    def __init__(self, resources: Dict[str, TerraformResource]):
        self.resources = resources
        self.graph = nx.DiGraph()
        self._build_graph()

    def _build_graph(self) -> None:
        # Add all resources as nodes
        for res_id, res in self.resources.items():
            self.graph.add_node(
                res_id,
                resource_type=res.resource_type,
                name=res.name,
                file_path=res.file_path,
            )

        # Add directed edges: dependency -> dependent
        for res_id, res in self.resources.items():
            for dep_id in res.all_dependencies:
                if self.graph.has_node(dep_id):
                    self.graph.add_edge(dep_id, res_id)

    @property
    def is_dag(self) -> bool:
        """Returns True if the dependency graph is strictly acyclic."""
        return nx.is_directed_acyclic_graph(self.graph)

    def find_cycles(self) -> List[List[str]]:
        """Returns any circular dependency cycles if present."""
        if self.is_dag:
            return []
        return list(nx.simple_cycles(self.graph))

    def get_roots(self) -> List[str]:
        """Returns root nodes (resources that do not depend on any other resource)."""
        return [n for n in self.graph.nodes if self.graph.in_degree(n) == 0]

    def get_leaves(self) -> List[str]:
        """Returns leaf nodes (resources that no other resource depends on)."""
        return [n for n in self.graph.nodes if self.graph.out_degree(n) == 0]

    def get_dependents(self, node_id: str) -> List[str]:
        """Returns resources that directly depend on the given node."""
        if not self.graph.has_node(node_id):
            return []
        return list(self.graph.successors(node_id))

    def get_blast_radius(self, node_id: str) -> Set[str]:
        """
        Calculates the complete downstream cascading blast radius.
        Any mutation to node_id could affect all returned resources.
        """
        if not self.graph.has_node(node_id):
            return set()
        return nx.descendants(self.graph, node_id)
