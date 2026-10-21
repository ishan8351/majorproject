from enum import Enum
from typing import Dict, List, Optional, Tuple
from pydantic import BaseModel, Field


class ComplianceFramework(str, Enum):
    HIPAA = "HIPAA"
    GDPR = "GDPR"
    NIST_SP_800_53 = "NIST SP 800-53"
    PCI_DSS = "PCI-DSS"
    CIS_BENCHMARK = "CIS Benchmark"


class GatingStatus(str, Enum):
    AUTONOMOUS_ELIGIBLE = "AUTONOMOUS_ELIGIBLE"
    HUMAN_ESCALATION_REQUIRED = "HUMAN_ESCALATION_REQUIRED"


class RemediationStrategy(str, Enum):
    IN_PLACE_ATTRIBUTE = "IN_PLACE_ATTRIBUTE"
    ADDITIVE_ATTACHMENT = "ADDITIVE_ATTACHMENT"


class ComplianceViolation(BaseModel):
    """Represents a compliance violation detected by static linters (Checkov)."""
    check_id: str  # e.g., "CKV_AWS_21", "CKV_AWS_135"
    check_name: str
    resource_id: str  # e.g., "aws_s3_bucket.audit_logs"
    resource_type: str
    file_path: str
    line_range: Optional[Tuple[int, int]] = None
    frameworks: List[str] = Field(default_factory=list)
    guideline_url: Optional[str] = None


class RemediationAction(BaseModel):
    """Remediation instruction mapped from regulatory knowledge base."""
    check_id: str
    framework: str
    statute_reference: str  # e.g. "HIPAA §164.312(a)(2)(iv)"
    strategy: RemediationStrategy
    target_attribute: Optional[str] = None
    attribute_value: Optional[str] = None
    additive_resource_template: Optional[str] = None
    description: str


class RemediationTask(BaseModel):
    """Correlates a compliance violation with the blast-radius risk gate."""
    violation: ComplianceViolation
    risk_tier: str
    blast_radius_score: float
    gating_status: GatingStatus
    action: Optional[RemediationAction] = None
    reason: str


class PatchProposal(BaseModel):
    """Synthesized HCL patch proposed for an eligible compliance violation."""
    resource_id: str
    target_file: str
    strategy: RemediationStrategy
    original_snippet: str = ""
    remediated_snippet: str = ""
    modified_content: str = ""
    is_verified: bool = False
    attempts: int = 1
    feedback_history: List[str] = Field(default_factory=list)


class SwarmExecutionResult(BaseModel):
    """Summary of closed-loop multi-agent remediation run."""
    target_path: str
    total_violations_found: int
    autonomous_remediations_eligible: int
    human_escalations_required: int
    patches_verified_and_accepted: int
    patches_rejected_and_escalated: int
    tasks: List[RemediationTask] = Field(default_factory=list)
    accepted_patches: List[PatchProposal] = Field(default_factory=list)
    remediated_files: Dict[str, str] = Field(default_factory=dict)
