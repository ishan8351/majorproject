"""
Structured Role Prompts and Context Formatters for the Neuro-Symbolic Agent Swarm.

Defines role-specialized system prompts, Pydantic structured output models, and rich
context formatters incorporating AST topology, GraphRAG regulatory ontology,
and plan verification diagnostics.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, TYPE_CHECKING
from pydantic import BaseModel, Field

from regradar.invariant.models import InvariantViolation
from regradar.models import CentralityMetrics, GraphSummary, RiskTier
from regradar.remediation.models import (
    ComplianceViolation,
    GatingStatus,
    PatchProposal,
    RemediationAction,
    RemediationStrategy,
    RemediationTask,
)

if TYPE_CHECKING:
    from regradar.knowledge.models import RegulatoryContext
    from regradar.invariant.semantic_verifier import SemanticViolation


# ==============================================================================
# Structured Output Models
# ==============================================================================

class AuditorDecision(BaseModel):
    """Structured decision produced by the AuditorAgent."""
    resource_id: str
    gating_status: GatingStatus
    risk_tier: str
    blast_radius_score: float
    reason: str


class PolicyPlan(BaseModel):
    """Structured policy plan formulated by the PolicyPlannerAgent."""
    check_id: str
    framework: str
    statute_reference: str
    strategy: RemediationStrategy
    target_attribute: Optional[str] = None
    attribute_value: Optional[str] = None
    additive_resource_template: Optional[str] = None
    description: str
    rationale: str

    def to_action(self) -> RemediationAction:
        """Converts plan to RemediationAction."""
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


class SynthesizerOutput(BaseModel):
    """Structured patch code synthesized by the SynthesizerAgent."""
    resource_id: str
    strategy: RemediationStrategy
    remediated_snippet: str
    modified_content: str
    explanation: str = ""


class SupervisorDiagnosis(BaseModel):
    """Structured diagnostic evaluation produced by the SupervisorAgent."""
    is_acceptable: bool
    failure_type: Optional[str] = None  # e.g., "FORCES_REPLACEMENT", "UNINTENDED_DELETION", "SCHEMA_DROP", "UNMET_REQUIREMENT", "SECURITY_REGRESSION"
    root_cause: str
    actionable_feedback: str
    recommended_strategy: Optional[RemediationStrategy] = None
    retry_permitted: bool = True


# ==============================================================================
# Role Prompts & Context Formatters
# ==============================================================================

class AuditorPrompt:
    """Prompt builder for AuditorAgent."""

    SYSTEM_PROMPT = """You are the Senior Infrastructure Security Auditor & Blast-Radius Controller for RegRadar.
Your mission is to evaluate compliance violations against resource dependency topology and graph centrality metrics.

SAFETY POLICY & GATING RULES:
1. FOUNDATIONAL NODES (CRITICAL_ROOT):
   - Resources with high centrality (betweenness/eigenvector) or cascading downstream blast radius (VPCs, Subnets with dependents, Root IAM, Core KMS, Transit Gateways) MUST NOT be mutated autonomously by AI agents.
   - For these nodes, you MUST set gating_status="HUMAN_ESCALATION_REQUIRED".
2. INTERMEDIATE & LEAF NODES (INTERMEDIATE, LEAF_SAFE):
   - Leaf or bounded intermediate resources (S3 bucket configurations, security group ingress rules, KMS key rotation, logging setups) are safe for autonomous compliance repair.
   - For these nodes, if a known remediation path exists, set gating_status="AUTONOMOUS_ELIGIBLE".
3. If no verified zero-destruction remediation action is known for the check, escalate to human review.

You must output a single, valid JSON object matching the AuditorDecision schema."""

    @classmethod
    def format(
        cls,
        violation: ComplianceViolation,
        metrics: Optional[CentralityMetrics] = None,
        graph_summary: Optional[GraphSummary] = None,
    ) -> str:
        """Formats compliance violation alongside AST topology and graph centrality metrics."""
        lines = [
            f"# Compliance Violation Audit Request",
            f"- Resource ID: {violation.resource_id}",
            f"- Resource Type: {violation.resource_type}",
            f"- Check ID: {violation.check_id} ({violation.check_name})",
            f"- Target File: {violation.file_path}",
            "",
            "## Graph Centrality & Blast-Radius Assessment:",
        ]

        if metrics:
            lines.extend(
                [
                    f"- Risk Tier: {metrics.risk_tier.value}",
                    f"- Blast Radius Score: {metrics.blast_radius_score:.4f}",
                    f"- In-Degree (Dependencies): {metrics.in_degree}",
                    f"- Out-Degree (Direct Dependents): {metrics.out_degree}",
                    f"- Total Cascading Descendants: {metrics.descendant_count}",
                    f"- Upstream Ancestor Count: {metrics.ancestor_count}",
                    f"- Betweenness Centrality: {metrics.betweenness:.4f}",
                    f"- Eigenvector Centrality: {metrics.eigenvector:.4f}",
                    f"- PageRank Centrality: {metrics.pagerank:.4f}",
                ]
            )
        else:
            lines.append("- Centrality Metrics: Unindexed / Leaf Default (Blast Radius: 0.0, Risk Tier: LEAF_SAFE)")

        if graph_summary:
            lines.extend(
                [
                    "",
                    "## Graph Topology Overview:",
                    f"- Total Resources in DAG: {graph_summary.total_resources}",
                    f"- Total Directed Dependencies: {graph_summary.total_dependencies}",
                    f"- Is Root Foundation: {violation.resource_id in graph_summary.root_resources}",
                    f"- Is Leaf Safe: {violation.resource_id in graph_summary.leaf_resources}",
                ]
            )

        lines.extend(
            [
                "",
                "Assess whether autonomous agent remediation is permitted under safety invariants, "
                "or if human escalation is required. Provide your structured AuditorDecision."
            ]
        )
        return "\n".join(lines)


class PolicyPlannerPrompt:
    """Prompt builder for PolicyPlannerAgent."""

    SYSTEM_PROMPT = """You are the Regulatory Policy Planner & Compliance Architect for RegRadar.
Your mission is to map compliance violations to statutory standards (HIPAA, GDPR, NIST SP 800-53, PCI-DSS)
and formulate precise remediation actions using retrieved ontological knowledge from GraphRAG.

REMEDIATION STRATEGY SELECTION:
1. ADDITIVE_ATTACHMENT:
   - Strongly preferred for stateful resources (e.g. aws_s3_bucket encryption, versioning, public access block; aws_security_group_rule).
   - Prevents drift and eliminates risk of resource recreation ("forces replacement").
2. IN_PLACE_ATTRIBUTE:
   - Use only when an additive resource block does not exist for the cloud provider, and the attribute modification is verified non-destructive.

You must output a single, valid JSON object matching the PolicyPlan schema."""

    @classmethod
    def format(
        cls,
        violation: ComplianceViolation,
        contexts: List[RegulatoryContext],
        current_snippet: Optional[str] = None,
    ) -> str:
        """Formats the violation and GraphRAG regulatory retrieval context."""
        lines = [
            f"# Regulatory Compliance Policy Planning",
            f"- Violation Check: {violation.check_id} ({violation.check_name})",
            f"- Target Resource: {violation.resource_id} [{violation.resource_type}]",
            f"- File: {violation.file_path}",
            "",
            "## Retrieved GraphRAG Regulatory Context:",
        ]

        if contexts:
            for i, ctx in enumerate(contexts, 1):
                lines.extend(
                    [
                        f"### Match #{i} (Score: {ctx.score:.2f})",
                        f"- Primary Statute Citation: {ctx.rule.statute_reference}",
                        f"- Regulatory Standards: {', '.join(ctx.standards)}",
                        f"- Recommended Strategy: {ctx.rule.strategy.value}",
                        f"- Rule Description: {ctx.rule.description}",
                        f"- Target Attribute: {ctx.rule.target_attribute or 'N/A'}",
                        f"- Rationale: {ctx.rationale}",
                    ]
                )
                if ctx.controls:
                    ctrl_strs = [f"{c.control_id} ({c.title})" for c in ctx.controls[:3]]
                    lines.append(f"- Statutory Controls: {'; '.join(ctrl_strs)}")
                if ctx.requirements:
                    req_strs = [r.name for r in ctx.requirements[:3]]
                    lines.append(f"- Core Security Requirements: {', '.join(req_strs)}")
        else:
            lines.append("- No direct GraphRAG match found. Use standard compliance best practices.")

        if current_snippet:
            lines.extend(
                [
                    "",
                    "## Current HCL Resource Snippet:",
                    "```hcl",
                    current_snippet.strip(),
                    "```",
                ]
            )

        lines.extend(
            [
                "",
                "Formulate the definitive remediation action, specifying statutory citation, strategy, "
                "and HCL template. Provide your structured PolicyPlan."
            ]
        )
        return "\n".join(lines)


class SynthesizerPrompt:
    """Prompt builder for SynthesizerAgent."""

    SYSTEM_PROMPT = """You are the Zero-Destruction IaC Code Synthesizer for RegRadar.
Your mission is to generate minimal, semantically valid HCL code patches enforcing compliance.

STRICT ZERO-DESTRUCTION RULES:
1. ZERO STATE REPLACEMENT:
   - NEVER modify immutable identifier attributes (e.g., bucket name, vpc cidr, database identifier, availability zone) that trigger "forces replacement" (recreation) in Terraform/OpenTofu.
2. PREFER ADDITIVE ATTACHMENTS:
   - For stateful cloud resources (e.g. AWS S3 buckets), attach configuration via external additive blocks (e.g., `aws_s3_bucket_server_side_encryption_configuration`, `aws_s3_bucket_versioning`, `aws_s3_bucket_public_access_block`) referencing `{resource_id}.id` rather than modifying inline attributes.
3. PRESERVE EXISTING CONFIGURATION:
   - Never drop, truncate, or overwrite existing resource blocks, tags, dependencies, or unmanaged attributes.
4. VALID HCL SYNTAX:
   - Ensure all braces, quotes, block nesting, and references are valid and uncorrupted.
5. CLEAN APPENDS:
   - When generating an additive attachment, cleanly append it to the file content.

You must output a single, valid JSON object matching the SynthesizerOutput schema."""

    @classmethod
    def format(
        cls,
        task: RemediationTask,
        file_content: str,
        feedback: Optional[str] = None,
    ) -> str:
        """Formats synthesis prompt with target file content, task action, and supervisor feedback."""
        action = task.action
        lines = [
            f"# Zero-Destruction HCL Patch Synthesis Request",
            f"- Target Resource ID: {task.violation.resource_id}",
            f"- Resource Type: {task.violation.resource_type}",
            f"- Check ID: {task.violation.check_id} ({task.violation.check_name})",
            f"- Target File: {task.violation.file_path}",
        ]

        if action:
            lines.extend(
                [
                    f"- Enforcing Statute: {action.statute_reference} ({action.framework})",
                    f"- Remediation Strategy: {action.strategy.value}",
                    f"- Target Attribute: {action.target_attribute or 'N/A'}",
                    f"- Attribute Value Template: {action.attribute_value or 'N/A'}",
                    f"- Additive Resource Template: {action.additive_resource_template or 'N/A'}",
                    f"- Description: {action.description}",
                ]
            )

        if feedback:
            lines.extend(
                [
                    "",
                    "## CRITICAL SUPERVISOR FEEDBACK FROM PREVIOUS FAILED ATTEMPT:",
                    f"> {feedback}",
                    "Carefully correct the patch according to this feedback to eliminate all invariant violations.",
                ]
            )

        lines.extend(
            [
                "",
                "## Current File Content:",
                "```hcl",
                file_content.strip(),
                "```",
                "",
                "Generate the remediated HCL snippet and the full modified file content. "
                "Ensure zero state replacement and full invariant safety. Provide your structured SynthesizerOutput.",
            ]
        )
        return "\n".join(lines)


class SupervisorPrompt:
    """Prompt builder for SupervisorAgent."""

    SYSTEM_PROMPT = """You are the Swarm Supervisor & Invariant Gatekeeper for RegRadar.
Your mission is to inspect pre-flight dry-run plan simulation diffs and semantic verification results
to diagnose failures, prevent dangerous mutations, and provide actionable instructions for patch self-correction.

DIAGNOSTIC CRITERIA:
1. FORCES_REPLACEMENT:
   - Any plan action showing `["delete", "create"]` or action_reason containing `forces replacement`.
   - Actionable instruction: Instruct the synthesizer to revert in-place modification of immutable identifiers and switch to an external additive resource block.
2. UNINTENDED_DELETION:
   - Any resource or block deleted without intent.
   - Actionable instruction: Instruct the synthesizer to restore the missing block.
3. SCHEMA_DROP:
   - Drops in existing tags, lifecycle policies, or nested attributes.
   - Actionable instruction: Instruct the synthesizer to preserve all existing attributes.
4. UNMET_REQUIREMENT / SECURITY_REGRESSION:
   - Plan state failed semantic verification (e.g. required encryption not present or TLS downgraded).
   - Actionable instruction: Explicitly specify the missing or downgraded attribute to be enforced.

You must output a single, valid JSON object matching the SupervisorDiagnosis schema."""

    @classmethod
    def format(
        cls,
        proposal: PatchProposal,
        task: RemediationTask,
        invariant_violations: Optional[List[InvariantViolation]] = None,
        semantic_violations: Optional[List[Any]] = None,
        raw_diff: Optional[str] = None,
    ) -> str:
        """Formats supervisor diagnostic context from plan verification failures."""
        lines = [
            f"# Invariant Verification Failure Diagnosis",
            f"- Resource ID: {proposal.resource_id}",
            f"- Target File: {proposal.target_file}",
            f"- Remediation Strategy Attempted: {proposal.strategy.value}",
            f"- Current Attempt: {proposal.attempts}",
            "",
            "## Synthesized Snippet Under Verification:",
            "```hcl",
            proposal.remediated_snippet.strip(),
            "```",
        ]

        if invariant_violations:
            lines.extend(["", "## Detected Invariant Violations (Pre-flight Plan Dry-Run):"])
            for iv in invariant_violations:
                lines.append(f"- [{iv.violation_type.value}] {iv.resource_address}: {iv.message}")
                if iv.action_reason:
                    lines.append(f"  Reason: {iv.action_reason}")
                if iv.problematic_attributes:
                    lines.append(f"  Attributes: {', '.join(iv.problematic_attributes)}")

        if semantic_violations:
            lines.extend(["", "## Detected Semantic Verification Failures:"])
            for sv in semantic_violations:
                lines.append(f"- [{sv.violation_type.value}] {sv.resource_address}.{sv.attribute_path}: {sv.message}")
                lines.append(f"  Expected: {sv.expected} | Actual: {sv.actual}")

        if raw_diff:
            lines.extend(
                [
                    "",
                    "## Raw Execution Plan Diff:",
                    "```diff",
                    raw_diff.strip(),
                    "```",
                ]
            )

        if proposal.feedback_history:
            lines.extend(
                [
                    "",
                    "## Prior Attempt Feedback History:",
                    *[f"- {h}" for h in proposal.feedback_history],
                ]
            )

        lines.extend(
            [
                "",
                "Diagnose the failure root cause and provide clear, actionable instructions for the SynthesizerAgent "
                "to self-correct the patch on the next attempt. Provide your structured SupervisorDiagnosis.",
            ]
        )
        return "\n".join(lines)
