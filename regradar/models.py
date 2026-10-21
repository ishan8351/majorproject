from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field


class RiskTier(str, Enum):
    """
    Blast-Radius Risk Tier for Infrastructure-as-Code resources.
    - CRITICAL_ROOT: High-impact foundation (e.g. VPC, Root IAM, Core KMS).
                     Mutations require human approval.
    - INTERMEDIATE: Moderate impact, connected components. Gated with strict invariant checks.
    - LEAF_SAFE: Low blast-radius leaf node (e.g. tags, bucket encryption).
                 Eligible for autonomous multi-agent remediation.
    """
    CRITICAL_ROOT = "CRITICAL_ROOT"
    INTERMEDIATE = "INTERMEDIATE"
    LEAF_SAFE = "LEAF_SAFE"


class TerraformResource(BaseModel):
    """Represents an individual declarative IaC resource block."""
    id: str  # e.g., "aws_instance.web" or "aws_vpc.main"
    resource_type: str  # e.g., "aws_instance"
    name: str  # e.g., "web"
    file_path: str
    attributes: Dict[str, Any] = Field(default_factory=dict)
    explicit_dependencies: Set[str] = Field(default_factory=set)
    inferred_dependencies: Set[str] = Field(default_factory=set)

    @property
    def all_dependencies(self) -> Set[str]:
        return self.explicit_dependencies.union(self.inferred_dependencies)


class CentralityMetrics(BaseModel):
    """Graph-theoretic centrality and blast-radius evaluation."""
    node_id: str
    resource_type: str
    in_degree: int  # Number of resources this resource depends on
    out_degree: int  # Number of resources directly depending on this resource
    descendant_count: int  # Total cascading downstream blast radius
    ancestor_count: int  # Total upstream dependencies
    betweenness: float  # Betweenness centrality score
    blast_radius_score: float  # Normalized composite risk score [0.0, 1.0]
    risk_tier: RiskTier
    auto_remediate: bool  # Whether autonomous LLM agent remediation is permitted


class GraphSummary(BaseModel):
    """Summary of the parsed resource dependency graph."""
    total_resources: int
    total_dependencies: int
    root_resources: List[str]  # Resources with no upstream dependencies
    leaf_resources: List[str]  # Resources with no downstream dependents
    has_cycles: bool = False
    metrics: Dict[str, CentralityMetrics] = Field(default_factory=dict)
