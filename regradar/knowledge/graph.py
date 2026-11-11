"""
Multi-relational Regulatory Knowledge Graph for RegRadar.

Models statutory standards, controls, technical requirements, cloud resources,
and remediation rules in a directed multi-relational graph using NetworkX.
"""

from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx

from regradar.knowledge.catalog import get_default_catalog
from regradar.knowledge.models import (
    CloudResourceNode,
    ControlNode,
    EdgeType,
    RemediationRule,
    RequirementNode,
    StandardNode,
    StatutoryBasis,
)


class RegulatoryKnowledgeGraph:
    """
    In-memory multi-relational regulatory knowledge graph.

    Nodes:
      - standard:<id>       (StandardNode)
      - control:<id>        (ControlNode)
      - requirement:<id>    (RequirementNode)
      - resource:<id>       (CloudResourceNode)
      - rule:<check_id>     (RemediationRule)

    Edges:
      - MANDATES:             StandardNode -> ControlNode
      - REQUIRES_CONTROL:     ControlNode -> RequirementNode
      - APPLIES_TO_RESOURCE:  RequirementNode -> CloudResourceNode, Rule -> CloudResourceNode
      - REMEDIATED_BY:        ControlNode -> RemediationRule, RequirementNode -> RemediationRule
    """

    def __init__(
        self,
        standards: Optional[Dict[str, StandardNode]] = None,
        controls: Optional[Dict[str, ControlNode]] = None,
        requirements: Optional[Dict[str, RequirementNode]] = None,
        cloud_resources: Optional[Dict[str, CloudResourceNode]] = None,
        rules: Optional[Dict[str, RemediationRule]] = None,
    ):
        self._graph = nx.MultiDiGraph()

        if standards is None or controls is None or requirements is None or cloud_resources is None or rules is None:
            (
                default_std,
                default_ctrl,
                default_req,
                default_res,
                default_rules,
            ) = get_default_catalog()
            self._standards = standards or default_std
            self._controls = controls or default_ctrl
            self._requirements = requirements or default_req
            self._cloud_resources = cloud_resources or default_res
            self._rules = rules or default_rules
        else:
            self._standards = standards
            self._controls = controls
            self._requirements = requirements
            self._cloud_resources = cloud_resources
            self._rules = rules

        self._build_graph()

    @property
    def raw_graph(self) -> nx.MultiDiGraph:
        """Access the underlying NetworkX MultiDiGraph."""
        return self._graph

    # -----------------------------------------------------------------------
    # Graph Construction
    # -----------------------------------------------------------------------
    def _build_graph(self) -> None:
        """Populates nodes and multi-relational edges."""
        # 1. Add Standards
        for std_id, std in self._standards.items():
            node_key = f"standard:{std_id}"
            self._graph.add_node(
                node_key,
                type="standard",
                entity=std,
                id=std.id,
                name=std.name,
                description=std.description,
            )

        # 2. Add Controls and MANDATES edges (Standard -> Control)
        for ctrl_id, ctrl in self._controls.items():
            ctrl_key = f"control:{ctrl_id}"
            self._graph.add_node(
                ctrl_key,
                type="control",
                entity=ctrl,
                id=ctrl.id,
                control_id=ctrl.control_id,
                standard_id=ctrl.standard_id,
                name=ctrl.title,
                description=ctrl.description,
            )
            # Edge: Standard MANDATES Control
            std_key = f"standard:{ctrl.standard_id}"
            if self._graph.has_node(std_key):
                self._graph.add_edge(
                    std_key,
                    ctrl_key,
                    key=EdgeType.MANDATES.value,
                    relation=EdgeType.MANDATES.value,
                )

        # 3. Add Requirements
        for req_id, req in self._requirements.items():
            req_key = f"requirement:{req_id}"
            self._graph.add_node(
                req_key,
                type="requirement",
                entity=req,
                id=req.id,
                name=req.name,
                description=req.description,
            )

        # 4. Add Cloud Resources
        for res_id, res in self._cloud_resources.items():
            res_key = f"resource:{res_id}"
            self._graph.add_node(
                res_key,
                type="resource",
                entity=res,
                id=res.id,
                resource_type=res.resource_type,
                cloud_provider=res.cloud_provider,
                service=res.service,
            )

        # 5. Add Remediation Rules & Connect Relations
        for check_id, rule in self._rules.items():
            rule_key = f"rule:{check_id}"
            self._graph.add_node(
                rule_key,
                type="rule",
                entity=rule,
                id=rule.check_id,
                name=rule.name,
                resource_type=rule.resource_type,
                framework=rule.framework,
                description=rule.description,
            )

            # Edge: Rule APPLIES_TO_RESOURCE Resource
            res_key = f"resource:{rule.resource_type}"
            if self._graph.has_node(res_key):
                self._graph.add_edge(
                    rule_key,
                    res_key,
                    key=EdgeType.APPLIES_TO_RESOURCE.value,
                    relation=EdgeType.APPLIES_TO_RESOURCE.value,
                )

            # Requirement relations
            if rule.requirement_id:
                req_key = f"requirement:{rule.requirement_id}"
                if self._graph.has_node(req_key):
                    # Requirement APPLIES_TO_RESOURCE Resource
                    if self._graph.has_node(res_key) and not self._graph.has_edge(
                        req_key, res_key, key=EdgeType.APPLIES_TO_RESOURCE.value
                    ):
                        self._graph.add_edge(
                            req_key,
                            res_key,
                            key=EdgeType.APPLIES_TO_RESOURCE.value,
                            relation=EdgeType.APPLIES_TO_RESOURCE.value,
                        )

                    # Requirement REMEDIATED_BY Rule
                    self._graph.add_edge(
                        req_key,
                        rule_key,
                        key=EdgeType.REMEDIATED_BY.value,
                        relation=EdgeType.REMEDIATED_BY.value,
                    )

            # Control relations
            for ctrl_id in rule.control_ids:
                ctrl_key = f"control:{ctrl_id}"
                if self._graph.has_node(ctrl_key):
                    # Control REMEDIATED_BY Rule
                    self._graph.add_edge(
                        ctrl_key,
                        rule_key,
                        key=EdgeType.REMEDIATED_BY.value,
                        relation=EdgeType.REMEDIATED_BY.value,
                    )

                    # Control REQUIRES_CONTROL Requirement
                    if rule.requirement_id:
                        req_key = f"requirement:{rule.requirement_id}"
                        if self._graph.has_node(req_key) and not self._graph.has_edge(
                            ctrl_key, req_key, key=EdgeType.REQUIRES_CONTROL.value
                        ):
                            self._graph.add_edge(
                                ctrl_key,
                                req_key,
                                key=EdgeType.REQUIRES_CONTROL.value,
                                relation=EdgeType.REQUIRES_CONTROL.value,
                            )

    # -----------------------------------------------------------------------
    # Core Queries
    # -----------------------------------------------------------------------
    def get_statutory_basis(self, check_id: str) -> Optional[StatutoryBasis]:
        """
        Traverses backwards from a check ID to discover its underlying legal
        authorities, standard mandates, controls, and requirements.
        """
        rule = self._rules.get(check_id)
        if not rule:
            return None

        rule_key = f"rule:{check_id}"
        if not self._graph.has_node(rule_key):
            return None

        # 1. Discover Controls connected via REMEDIATED_BY or listed in control_ids
        control_nodes: List[ControlNode] = []
        seen_controls: Set[str] = set()

        # Inward edges to rule
        for pred in self._graph.predecessors(rule_key):
            node_data = self._graph.nodes[pred]
            if node_data.get("type") == "control":
                ctrl = node_data["entity"]
                if ctrl.id not in seen_controls:
                    seen_controls.add(ctrl.id)
                    control_nodes.append(ctrl)

        for ctrl_id in rule.control_ids:
            if ctrl_id in self._controls and ctrl_id not in seen_controls:
                seen_controls.add(ctrl_id)
                control_nodes.append(self._controls[ctrl_id])

        # 2. Discover Standards that MANDATE these controls
        standard_nodes: List[StandardNode] = []
        seen_standards: Set[str] = set()

        for ctrl in control_nodes:
            ctrl_key = f"control:{ctrl.id}"
            if self._graph.has_node(ctrl_key):
                for pred in self._graph.predecessors(ctrl_key):
                    pred_data = self._graph.nodes[pred]
                    if pred_data.get("type") == "standard":
                        std = pred_data["entity"]
                        if std.id not in seen_standards:
                            seen_standards.add(std.id)
                            standard_nodes.append(std)

            # Fallback direct lookup via standard_id
            if ctrl.standard_id in self._standards and ctrl.standard_id not in seen_standards:
                seen_standards.add(ctrl.standard_id)
                standard_nodes.append(self._standards[ctrl.standard_id])

        # 3. Discover Requirements
        requirement_nodes: List[RequirementNode] = []
        seen_reqs: Set[str] = set()

        if rule.requirement_id and rule.requirement_id in self._requirements:
            seen_reqs.add(rule.requirement_id)
            requirement_nodes.append(self._requirements[rule.requirement_id])

        for ctrl in control_nodes:
            ctrl_key = f"control:{ctrl.id}"
            if self._graph.has_node(ctrl_key):
                for succ in self._graph.successors(ctrl_key):
                    succ_data = self._graph.nodes[succ]
                    if succ_data.get("type") == "requirement":
                        req = succ_data["entity"]
                        if req.id not in seen_reqs:
                            seen_reqs.add(req.id)
                            requirement_nodes.append(req)

        return StatutoryBasis(
            check_id=rule.check_id,
            rule_name=rule.name,
            standards=standard_nodes,
            controls=control_nodes,
            requirements=requirement_nodes,
            statute_reference=rule.statute_reference,
            description=rule.description,
        )

    def get_controls_for_resource(self, resource_type: str) -> List[ControlNode]:
        """
        Retrieves all regulatory controls governing a specific cloud resource type
        by traversing graph relations.
        """
        res_key = f"resource:{resource_type}"
        matched_controls: List[ControlNode] = []
        seen: Set[str] = set()

        # Path 1: Rules applying to resource -> Controls that remediate them
        for check_id, rule in self._rules.items():
            if rule.resource_type == resource_type:
                for ctrl_id in rule.control_ids:
                    if ctrl_id in self._controls and ctrl_id not in seen:
                        seen.add(ctrl_id)
                        matched_controls.append(self._controls[ctrl_id])

        # Path 2: Graph predecessors of resource node
        if self._graph.has_node(res_key):
            for pred in self._graph.predecessors(res_key):
                pred_data = self._graph.nodes[pred]
                if pred_data.get("type") == "requirement":
                    # Controls requiring this requirement
                    for ctrl_pred in self._graph.predecessors(pred):
                        ctrl_data = self._graph.nodes[ctrl_pred]
                        if ctrl_data.get("type") == "control":
                            ctrl = ctrl_data["entity"]
                            if ctrl.id not in seen:
                                seen.add(ctrl.id)
                                matched_controls.append(ctrl)

        return matched_controls

    def find_remediation(
        self, check_id: str, resource_type: Optional[str] = None
    ) -> Optional[RemediationRule]:
        """
        Looks up a remediation rule by check ID and optional resource type filter.
        """
        rule = self._rules.get(check_id)
        if not rule:
            return None
        if resource_type and rule.resource_type != resource_type:
            return None
        return rule

    # -----------------------------------------------------------------------
    # Helper Inspection & Query Methods
    # -----------------------------------------------------------------------
    def get_standards(self) -> List[StandardNode]:
        return list(self._standards.values())

    def get_controls(self, standard_id: Optional[str] = None) -> List[ControlNode]:
        if standard_id:
            return [c for c in self._controls.values() if c.standard_id == standard_id]
        return list(self._controls.values())

    def get_requirements(self) -> List[RequirementNode]:
        return list(self._requirements.values())

    def get_resources(self) -> List[CloudResourceNode]:
        return list(self._cloud_resources.values())

    def get_rules(self) -> List[RemediationRule]:
        return list(self._rules.values())

    def get_rules_for_framework(self, framework_id: str) -> List[RemediationRule]:
        """Returns all rules associated with a framework/standard."""
        fw_upper = framework_id.upper()
        results: List[RemediationRule] = []
        for rule in self._rules.values():
            basis = self.get_statutory_basis(rule.check_id)
            if basis:
                matches = any(
                    s.id.upper() == fw_upper or fw_upper in s.name.upper()
                    for s in basis.standards
                )
                if matches or fw_upper in rule.framework.upper() or fw_upper in rule.statute_reference.upper():
                    results.append(rule)
        return results

    def get_rules_for_resource(self, resource_type: str) -> List[RemediationRule]:
        """Returns all rules targeting a specific resource type."""
        return [r for r in self._rules.values() if r.resource_type == resource_type]

    def get_rules_for_requirement(self, requirement_id: str) -> List[RemediationRule]:
        """Returns all rules associated with a requirement."""
        return [r for r in self._rules.values() if r.requirement_id == requirement_id]

    def summary(self) -> Dict[str, Any]:
        """Returns entity count summary of the knowledge graph."""
        return {
            "total_nodes": self._graph.number_of_nodes(),
            "total_edges": self._graph.number_of_edges(),
            "standards_count": len(self._standards),
            "controls_count": len(self._controls),
            "requirements_count": len(self._requirements),
            "resources_count": len(self._cloud_resources),
            "rules_count": len(self._rules),
        }
