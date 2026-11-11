from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from regradar.remediation.models import RemediationAction, RemediationStrategy


class EdgeType(str, Enum):
    """Ontological graph relationship edge types."""
    MANDATES = "MANDATES"
    REQUIRES_CONTROL = "REQUIRES_CONTROL"
    APPLIES_TO_RESOURCE = "APPLIES_TO_RESOURCE"
    REMEDIATED_BY = "REMEDIATED_BY"


class StandardNode(BaseModel):
    """
    Top-level statutory regulatory framework or industry standard.
    Examples: HIPAA, GDPR, NIST SP 800-53, PCI-DSS.
    """
    id: str  # e.g., "HIPAA", "GDPR", "NIST_SP_800_53", "PCI_DSS"
    name: str  # e.g., "Health Insurance Portability and Accountability Act"
    description: str
    version: Optional[str] = None
    jurisdiction: Optional[str] = None


class ControlNode(BaseModel):
    """
    Specific legal statute, section, or security control within a standard.
    Examples: HIPAA §164.312(a)(2)(iv), GDPR Art. 32(1)(a), NIST SC-13, PCI-DSS 3.4.
    """
    id: str  # e.g., "HIPAA_164_312_a_2_iv"
    control_id: str  # e.g., "§164.312(a)(2)(iv)"
    standard_id: str  # e.g., "HIPAA"
    title: str
    description: str
    family: Optional[str] = None


class RequirementNode(BaseModel):
    """
    Abstract technical or organizational security requirement.
    Examples: "Encryption at Rest", "Zero Public Ingress", "Audit Logging".
    """
    id: str  # e.g., "REQ_ENCRYPTION_AT_REST"
    name: str  # e.g., "Encryption at Rest"
    description: str
    category: Optional[str] = None


class CloudResourceNode(BaseModel):
    """
    Declarative cloud infrastructure resource type.
    Examples: "aws_s3_bucket", "aws_db_instance", "azurerm_storage_account".
    """
    id: str  # e.g., "aws_s3_bucket"
    resource_type: str  # e.g., "aws_s3_bucket"
    cloud_provider: str  # "aws" or "azure"
    service: str  # "s3", "rds", "kms", "storage", etc.
    description: Optional[str] = None


class RemediationRule(BaseModel):
    """
    Correlates a static compliance rule (Checkov ID) with statutory mandates,
    remediation strategies, HCL templates, and validation constraints.
    """
    check_id: str  # e.g., "CKV_AWS_19"
    name: str
    description: str
    resource_type: str
    framework: str  # primary framework or composite
    statute_reference: str  # human-readable statutory citation
    control_ids: List[str] = Field(default_factory=list)
    requirement_id: Optional[str] = None
    strategy: RemediationStrategy
    target_attribute: Optional[str] = None
    attribute_value: Optional[str] = None
    additive_resource_template: Optional[str] = None
    validation_rules: List[str] = Field(default_factory=list)

    def to_action(self) -> RemediationAction:
        """Converts rule to a backward-compatible RemediationAction."""
        return RemediationAction(
            check_id=self.check_id,
            framework=self.framework,
            statute_reference=self.statute_reference,
            strategy=self.strategy,
            target_attribute=self.target_attribute,
            attribute_value=self.attribute_value,
            additive_resource_template=self.additive_resource_template,
            description=self.description,
        )


class StatutoryBasis(BaseModel):
    """Detailed statutory justification for a compliance rule."""
    check_id: str
    rule_name: str
    standards: List[StandardNode] = Field(default_factory=list)
    controls: List[ControlNode] = Field(default_factory=list)
    requirements: List[RequirementNode] = Field(default_factory=list)
    statute_reference: str
    description: str


class RegulatoryContext(BaseModel):
    """Retrieved regulatory context for hybrid GraphRAG."""
    check_id: str
    rule: RemediationRule
    resource_type: str
    standards: List[str] = Field(default_factory=list)
    controls: List[ControlNode] = Field(default_factory=list)
    requirements: List[RequirementNode] = Field(default_factory=list)
    score: float = 0.0
    rationale: str = ""
