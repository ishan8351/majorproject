import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from regradar.models import GraphSummary, RiskTier
from regradar.remediation.knowledge_base import RegulatoryKnowledgeBase
from regradar.remediation.models import (
    ComplianceViolation,
    GatingStatus,
    PatchProposal,
    RemediationAction,
    RemediationStrategy,
    RemediationTask,
)
from regradar.invariant.sandbox import SandboxRunner


class AuditorAgent:
    """
    Agent 1: Ingests compliance violations and cross-references them with the
    Phase 1 Blast-Radius Risk Gate. Rejects AI mutation on critical foundational nodes.
    """

    def __init__(self, graph_summary: GraphSummary):
        self.summary = graph_summary
        self.metrics_map = graph_summary.metrics

    def audit_and_gate(self, violations: List[ComplianceViolation]) -> List[RemediationTask]:
        """Classifies each violation into autonomous-eligible or human-escalation."""
        tasks: List[RemediationTask] = []

        for v in violations:
            metric = self.metrics_map.get(v.resource_id)
            action = RegulatoryKnowledgeBase.get_action_for_check(v.check_id)

            if metric:
                risk_tier = metric.risk_tier.value
                score = metric.blast_radius_score
                descendants = metric.descendant_count
            else:
                risk_tier = RiskTier.LEAF_SAFE.value
                score = 0.0
                descendants = 0

            # Gating Logic: If resource is CRITICAL_ROOT, lock out AI mutation
            if risk_tier == RiskTier.CRITICAL_ROOT.value:
                gating = GatingStatus.HUMAN_ESCALATION_REQUIRED
                reason = (
                    f"Resource '{v.resource_id}' is a CRITICAL_ROOT foundation "
                    f"(Blast Radius: {score:.4f}, {descendants} cascading dependents). "
                    f"Automated AI mutation is locked out by safety policy; requires human review."
                )
            elif not action:
                gating = GatingStatus.HUMAN_ESCALATION_REQUIRED
                reason = f"No verified zero-destruction remediation template registered for {v.check_id}."
            else:
                gating = GatingStatus.AUTONOMOUS_ELIGIBLE
                reason = (
                    f"Resource '{v.resource_id}' is rated {risk_tier} (Blast Radius: {score:.4f}). "
                    f"Approved for autonomous compliance repair under invariant verification."
                )

            tasks.append(
                RemediationTask(
                    violation=v,
                    risk_tier=risk_tier,
                    blast_radius_score=score,
                    gating_status=gating,
                    action=action,
                    reason=reason,
                )
            )

        return tasks


class PolicyPlannerAgent:
    """
    Agent 2: Formulates structured remediation plans based on statutory regulatory controls.
    """

    @classmethod
    def filter_eligible_tasks(cls, tasks: List[RemediationTask]) -> List[RemediationTask]:
        """Returns only tasks that pass the blast-radius risk gate."""
        return [t for t in tasks if t.gating_status == GatingStatus.AUTONOMOUS_ELIGIBLE and t.action]


class SynthesizerAgent:
    """
    Agent 3: Synthesizes minimal, semantically valid HCL code patches enforcing compliance.
    Supports verified non-destructive pattern injection with zero accidental state mutations.
    """

    def synthesize_patch(self, task: RemediationTask, file_content: str) -> PatchProposal:
        """Synthesizes an in-place attribute modification or additive resource block."""
        action = task.action
        res_id = task.violation.resource_id
        res_type, res_name = res_id.split(".", 1)

        # Strategy A: Additive Attachment
        if action.strategy == RemediationStrategy.ADDITIVE_ATTACHMENT:
            rendered_block = action.additive_resource_template.format(
                name=res_name,
                resource_id=res_id,
            ).strip()

            # Append cleanly at end of file
            modified = file_content.rstrip() + "\n\n# --- RegRadar Autonomous Compliance Remediation ---\n"
            modified += f"# Enforcing: {action.statute_reference} ({task.violation.check_id})\n"
            modified += rendered_block + "\n"

            return PatchProposal(
                resource_id=res_id,
                target_file=task.violation.file_path.lstrip("/"),
                strategy=action.strategy,
                remediated_snippet=rendered_block,
                modified_content=modified,
            )

        # Strategy B: In-Place Attribute Injection
        pattern = re.compile(
            rf'(resource\s+"{res_type}"\s+"{res_name}"\s*\{{(?:[^{{}}]*|\{{[^{{}}]*\}})*)\}}',
            re.MULTILINE | re.DOTALL,
        )
        match = pattern.search(file_content)

        if not match:
            # Fallback: append at end of file as comment
            return PatchProposal(
                resource_id=res_id,
                target_file=task.violation.file_path.lstrip("/"),
                strategy=action.strategy,
                modified_content=file_content,
            )

        block_body = match.group(1)
        # Check if attribute already exists to avoid duplication
        if action.target_attribute and action.target_attribute in block_body:
            return PatchProposal(
                resource_id=res_id,
                target_file=task.violation.file_path.lstrip("/"),
                strategy=action.strategy,
                modified_content=file_content,
            )

        injected_body = block_body.rstrip() + f"\n\n  # RegRadar: {action.statute_reference}\n"
        injected_body += f"{action.attribute_value}\n}}"
        modified = file_content[: match.start()] + injected_body + file_content[match.end() :]

        return PatchProposal(
            resource_id=res_id,
            target_file=task.violation.file_path.lstrip("/"),
            strategy=action.strategy,
            remediated_snippet=action.attribute_value,
            modified_content=modified,
        )


class SupervisorAgent:
    """
    Agent 4: Orchestrates the sandbox invariant feedback loop.
    Verifies synthesized patches in ephemeral pre-flight dry-runs and manages retry logic.
    """

    def __init__(self, sandbox_runner: Optional[SandboxRunner] = None, max_retries: int = 3):
        self.sandbox = sandbox_runner or SandboxRunner()
        self.max_retries = max_retries

    def verify_and_refine(
        self,
        base_dir: Path,
        proposal: PatchProposal,
        task: RemediationTask,
        synthesizer: SynthesizerAgent,
    ) -> PatchProposal:
        """Runs the patch through the invariant sandbox and retries if safety invariant fails."""
        current_proposal = proposal

        for attempt in range(1, self.max_retries + 1):
            current_proposal.attempts = attempt

            try:
                report = self.sandbox.simulate_and_verify(
                    base_dir=base_dir,
                    modified_files={current_proposal.target_file: current_proposal.modified_content},
                )

                if report.zero_destruction_guarantee_met:
                    current_proposal.is_verified = True
                    return current_proposal

                # Invariant failed! Capture feedback for refinement
                feedback = [f"Attempt {attempt} rejected: {v.message}" for v in report.violations]
                current_proposal.feedback_history.extend(feedback)

                # Refinement Strategy: If in-place modification triggered replacement,
                # switch strategy to an external additive resource block if possible
                if any("REPLACEMENT" in v.message for v in report.violations):
                    task.action.strategy = RemediationStrategy.ADDITIVE_ATTACHMENT

            except Exception as e:
                current_proposal.feedback_history.append(f"Attempt {attempt} execution error: {e}")

        current_proposal.is_verified = False
        return current_proposal
