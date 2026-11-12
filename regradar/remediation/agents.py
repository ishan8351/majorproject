"""
Neuro-Symbolic Multi-Agent Remediation Swarm for RegRadar.

Implements specialized collaborative agents:
- AuditorAgent: Phase 1 AST & DAG blast-radius risk gating.
- PolicyPlannerAgent: Ontological regulatory grounding & plan formulation (GraphRAG).
- SynthesizerAgent: Zero-destruction HCL code synthesis.
- SupervisorAgent: Pre-flight plan dry-run invariant verification and self-correction.
"""

from __future__ import annotations

import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from regradar.invariant.models import InvariantReport
from regradar.invariant.sandbox import SandboxRunner
from regradar.models import CentralityMetrics, GraphSummary, RiskTier
from regradar.remediation.knowledge_base import RegulatoryKnowledgeBase
from regradar.remediation.llm.client import BaseLLMClient, get_llm_client
from regradar.remediation.llm.prompts import (
    AuditorDecision,
    AuditorPrompt,
    PolicyPlan,
    PolicyPlannerPrompt,
    SupervisorDiagnosis,
    SupervisorPrompt,
    SynthesizerOutput,
    SynthesizerPrompt,
)

if TYPE_CHECKING:
    from regradar.knowledge.models import RegulatoryContext
    from regradar.knowledge.retriever import HybridGraphRAGRetriever
    from regradar.invariant.semantic_verifier import SemanticInvariantVerifier, SemanticVerificationResult
from regradar.remediation.models import (
    ComplianceViolation,
    GatingStatus,
    PatchProposal,
    RemediationAction,
    RemediationStrategy,
    RemediationTask,
)
from regradar.remediation.state_machine import (
    RemediationContext,
    RemediationState,
    SwarmStateMachine,
)

logger = logging.getLogger(__name__)


class AuditorAgent:
    """
    Agent 1: Ingests compliance violations and cross-references them with the
    AST/DAG Graph Centrality and Blast-Radius Risk Gate.
    Locks out autonomous AI mutations on critical foundational infrastructure.
    """

    def __init__(
        self,
        graph_summary: GraphSummary,
        llm_client: Optional[BaseLLMClient] = None,
        deterministic: bool = False,
    ):
        self.summary = graph_summary
        self.metrics_map: Dict[str, CentralityMetrics] = graph_summary.metrics
        self.llm_client = llm_client
        self.deterministic = deterministic

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

            # Compute baseline safety gating
            if risk_tier == RiskTier.CRITICAL_ROOT.value:
                baseline_gating = GatingStatus.HUMAN_ESCALATION_REQUIRED
                baseline_reason = (
                    f"Resource '{v.resource_id}' is a CRITICAL_ROOT foundation "
                    f"(Blast Radius: {score:.4f}, {descendants} cascading dependents). "
                    f"Automated AI mutation is locked out by safety policy; requires human review."
                )
            elif not action:
                baseline_gating = GatingStatus.HUMAN_ESCALATION_REQUIRED
                baseline_reason = (
                    f"No verified zero-destruction remediation template registered for {v.check_id}."
                )
            else:
                baseline_gating = GatingStatus.AUTONOMOUS_ELIGIBLE
                baseline_reason = (
                    f"Resource '{v.resource_id}' is rated {risk_tier} (Blast Radius: {score:.4f}). "
                    f"Approved for autonomous compliance repair under invariant verification."
                )

            # Check if LLM client is active and requested
            if self.llm_client and not self.deterministic:
                try:
                    prompt = AuditorPrompt.format(
                        violation=v,
                        metrics=metric,
                        graph_summary=self.summary,
                    )
                    decision = self.llm_client.generate_structured(
                        prompt=prompt,
                        response_model=AuditorDecision,
                        system_prompt=AuditorPrompt.SYSTEM_PROMPT,
                        max_tokens=384,
                    )
                    # Hard safety invariant: NEVER allow LLM to override CRITICAL_ROOT or missing action
                    if risk_tier == RiskTier.CRITICAL_ROOT.value:
                        gating = GatingStatus.HUMAN_ESCALATION_REQUIRED
                        reason = decision.reason or baseline_reason
                    elif not action:
                        gating = GatingStatus.HUMAN_ESCALATION_REQUIRED
                        reason = baseline_reason
                    else:
                        gating = decision.gating_status
                        reason = decision.reason
                except Exception as e:
                    logger.warning("AuditorAgent LLM completion failed; falling back to deterministic: %s", e)
                    gating = baseline_gating
                    reason = baseline_reason
            else:
                gating = baseline_gating
                reason = baseline_reason

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
    Agent 2: Formulates structured remediation plans grounded in statutory regulatory controls
    via GraphRAG knowledge graph retrieval.
    """

    def __init__(
        self,
        retriever: Optional[HybridGraphRAGRetriever] = None,
        llm_client: Optional[BaseLLMClient] = None,
        deterministic: bool = False,
    ):
        self.retriever = retriever or RegulatoryKnowledgeBase.get_retriever()
        self.llm_client = llm_client
        self.deterministic = deterministic

    @classmethod
    def filter_eligible_tasks(cls, tasks: List[RemediationTask]) -> List[RemediationTask]:
        """Returns only tasks that pass the blast-radius risk gate."""
        return [t for t in tasks if t.gating_status == GatingStatus.AUTONOMOUS_ELIGIBLE and t.action]

    def plan_remediation(
        self,
        task: RemediationTask,
        contexts: Optional[List[RegulatoryContext]] = None,
        file_content: Optional[str] = None,
    ) -> RemediationTask:
        """Enriches the task with GraphRAG regulatory retrieval context and LLM planning."""
        retrieved_contexts = contexts
        if retrieved_contexts is None and self.retriever:
            try:
                retrieved_contexts = self.retriever.retrieve(
                    query=f"{task.violation.check_id} {task.violation.check_name}",
                    resource_type=task.violation.resource_type,
                    top_k=2,
                )
            except Exception as e:
                logger.warning("GraphRAG retrieval failed: %s", e)
                retrieved_contexts = []

        # If LLM is active and not deterministic, formulate structured policy plan
        if self.llm_client and not self.deterministic and retrieved_contexts:
            try:
                prompt = PolicyPlannerPrompt.format(
                    violation=task.violation,
                    contexts=retrieved_contexts,
                    current_snippet=file_content,
                )
                plan = self.llm_client.generate_structured(
                    prompt=prompt,
                    response_model=PolicyPlan,
                    system_prompt=PolicyPlannerPrompt.SYSTEM_PROMPT,
                    max_tokens=512,
                )
                task.action = plan.to_action()
            except Exception as e:
                logger.warning("PolicyPlannerAgent LLM planning failed; falling back to knowledge base: %s", e)

        # Fallback to top retrieved context rule if action was missing
        if not task.action and retrieved_contexts:
            task.action = retrieved_contexts[0].rule.to_action()

        return task


class SynthesizerAgent:
    """
    Agent 3: Synthesizes minimal, semantically valid HCL code patches enforcing compliance.
    Supports verified non-destructive pattern injection and additive attachment blocks.
    """

    def __init__(
        self,
        llm_client: Optional[BaseLLMClient] = None,
        deterministic: bool = False,
    ):
        self.llm_client = llm_client
        self.deterministic = deterministic

    def synthesize_patch(
        self,
        task: RemediationTask,
        file_content: str,
        feedback: Optional[str] = None,
    ) -> PatchProposal:
        """Synthesizes an in-place attribute modification or additive resource block."""
        action = task.action
        res_id = task.violation.resource_id
        res_type, res_name = res_id.split(".", 1)

        # Attempt LLM-driven synthesis if client configured and not deterministic
        if self.llm_client and not self.deterministic:
            try:
                prompt = SynthesizerPrompt.format(
                    task=task,
                    file_content=file_content,
                    feedback=feedback,
                )
                output = self.llm_client.generate_structured(
                    prompt=prompt,
                    response_model=SynthesizerOutput,
                    system_prompt=SynthesizerPrompt.SYSTEM_PROMPT,
                    max_tokens=1024,
                )
                if output.modified_content and output.modified_content != file_content:
                    return PatchProposal(
                        resource_id=res_id,
                        target_file=task.violation.file_path.lstrip("/"),
                        strategy=output.strategy,
                        remediated_snippet=output.remediated_snippet,
                        modified_content=output.modified_content,
                    )
            except Exception as e:
                logger.warning("SynthesizerAgent LLM synthesis failed; falling back to deterministic: %s", e)

        # --------------------------------------------------------------------------
        # Deterministic Synthesis (Verified Knowledge Base Patterns)
        # --------------------------------------------------------------------------

        # Strategy A: Additive Attachment
        if action and action.strategy == RemediationStrategy.ADDITIVE_ATTACHMENT:
            rendered_block = action.additive_resource_template.format(
                name=res_name,
                resource_id=res_id,
            ).strip()

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
        if action and action.strategy == RemediationStrategy.IN_PLACE_ATTRIBUTE:
            header_pattern = re.compile(rf'resource\s+"{res_type}"\s+"{res_name}"\s*\{{')
            match = header_pattern.search(file_content)

            if not match:
                return PatchProposal(
                    resource_id=res_id,
                    target_file=task.violation.file_path.lstrip("/"),
                    strategy=action.strategy,
                    modified_content=file_content,
                )

            start_idx = match.start()
            depth = 0
            end_idx = None
            for i in range(match.end() - 1, len(file_content)):
                if file_content[i] == '{':
                    depth += 1
                elif file_content[i] == '}':
                    depth -= 1
                    if depth == 0:
                        end_idx = i + 1
                        break

            if end_idx is None:
                return PatchProposal(
                    resource_id=res_id,
                    target_file=task.violation.file_path.lstrip("/"),
                    strategy=action.strategy,
                    modified_content=file_content,
                )

            block_text = file_content[start_idx:end_idx]
            inner = block_text[:-1]

            # Avoid duplicate injection if attribute is already present
            if action.target_attribute and action.target_attribute in inner:
                return PatchProposal(
                    resource_id=res_id,
                    target_file=task.violation.file_path.lstrip("/"),
                    strategy=action.strategy,
                    modified_content=file_content,
                )

            injected = inner.rstrip() + f"\n\n  # RegRadar: {action.statute_reference}\n"
            injected += f"{action.attribute_value}\n}}"
            modified = file_content[:start_idx] + injected + file_content[end_idx:]

            return PatchProposal(
                resource_id=res_id,
                target_file=task.violation.file_path.lstrip("/"),
                strategy=action.strategy,
                remediated_snippet=action.attribute_value or "",
                modified_content=modified,
            )

        # Default fallback if action was None
        return PatchProposal(
            resource_id=res_id,
            target_file=task.violation.file_path.lstrip("/"),
            strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
            modified_content=file_content,
        )


class SupervisorAgent:
    """
    Agent 4: Orchestrates the sandbox invariant feedback loop.
    Verifies synthesized patches in ephemeral pre-flight dry-runs and manages
    diagnostic self-correction retry cycles.
    """

    def __init__(
        self,
        sandbox_runner: Optional[SandboxRunner] = None,
        semantic_verifier: Optional[Any] = None,
        llm_client: Optional[BaseLLMClient] = None,
        max_retries: Optional[int] = None,
        deterministic: Optional[bool] = None,
    ):
        from regradar.config import get_config
        cfg = get_config().llm.swarm
        self.sandbox = sandbox_runner or SandboxRunner()
        if semantic_verifier is None:
            from regradar.invariant.semantic_verifier import SemanticInvariantVerifier
            self.semantic_verifier = SemanticInvariantVerifier()
        else:
            self.semantic_verifier = semantic_verifier
        self.llm_client = llm_client
        self.max_retries = max_retries if max_retries is not None else cfg.max_retries
        self.deterministic = deterministic if deterministic is not None else cfg.deterministic

    def verify_and_refine(
        self,
        base_dir: Path,
        proposal: PatchProposal,
        task: RemediationTask,
        synthesizer: SynthesizerAgent,
        state_context: Optional[RemediationContext] = None,
        file_content: Optional[str] = None,
    ) -> PatchProposal:
        """Runs the patch through the invariant sandbox and retries if safety invariant fails."""
        current_proposal = proposal
        base_path = Path(base_dir)

        # Cache baseline file content before patches
        target_path = base_path / current_proposal.target_file
        orig_content = file_content
        if orig_content is None and target_path.exists():
            orig_content = target_path.read_text(encoding="utf-8")
        elif orig_content is None:
            orig_content = current_proposal.modified_content

        for attempt in range(1, self.max_retries + 1):
            current_proposal.attempts = attempt

            if state_context:
                SwarmStateMachine.transition(
                    state_context,
                    RemediationState.SANDBOX_SIMULATE,
                    message=f"Pre-flight sandbox dry-run simulation (Attempt {attempt}/{self.max_retries})",
                    attempt=attempt,
                )

            try:
                report = self.sandbox.simulate_and_verify(
                    base_dir=base_path,
                    modified_files={current_proposal.target_file: current_proposal.modified_content},
                )

                if state_context:
                    state_context.invariant_report = report

                # --------------------------------------------------------------
                # Phase A: Invariant Sandbox Verification (Zero Destruction)
                # --------------------------------------------------------------
                if not report.zero_destruction_guarantee_met:
                    # Invariant violation encountered!
                    failure_feedback = self._diagnose_invariant_failure(
                        proposal=current_proposal,
                        task=task,
                        report=report,
                        attempt=attempt,
                    )
                    current_proposal.feedback_history.append(failure_feedback)
                    if state_context:
                        state_context.record_feedback(failure_feedback)

                    # Trigger Strategy Refinement: Switch in-place to additive if replacement detected
                    is_replacement = any(
                        "REPLACEMENT" in v.message.upper()
                        or v.violation_type.value == "FORCES_REPLACEMENT"
                        or (v.action_reason and "replace" in v.action_reason.lower())
                        for v in report.violations
                    )
                    if is_replacement and task.action:
                        task.action.strategy = RemediationStrategy.ADDITIVE_ATTACHMENT

                    if attempt < self.max_retries:
                        if state_context:
                            SwarmStateMachine.transition(
                                state_context,
                                RemediationState.RETRY_WITH_FEEDBACK,
                                message=f"Invariant failed: {failure_feedback}",
                            )
                            SwarmStateMachine.transition(
                                state_context,
                                RemediationState.SYNTHESIZE,
                                message=f"Re-synthesizing patch with feedback (Attempt {attempt+1})",
                            )

                        prev_history = list(current_proposal.feedback_history)
                        current_proposal = synthesizer.synthesize_patch(
                            task=task,
                            file_content=orig_content,
                            feedback=failure_feedback,
                        )
                        current_proposal.attempts = attempt + 1
                        current_proposal.feedback_history = prev_history
                        continue
                    else:
                        if state_context:
                            SwarmStateMachine.transition(
                                state_context,
                                RemediationState.ESCALATE,
                                message=f"Safety invariants failed after {self.max_retries} attempts: {failure_feedback}",
                            )
                        current_proposal.is_verified = False
                        return current_proposal

                # --------------------------------------------------------------
                # Phase B: Semantic Invariant Verification
                # --------------------------------------------------------------
                if state_context:
                    SwarmStateMachine.transition(
                        state_context,
                        RemediationState.SEMANTIC_VERIFY,
                        message="Sandbox plan safe; verifying semantic compliance requirements",
                    )

                # Only run semantic verification if plan changes were returned
                if report.changes:
                    semantic_result = self.semantic_verifier.verify_remediation_task(
                        changes=report.changes,
                        task=task,
                    )
                    if state_context:
                        state_context.semantic_result = semantic_result

                    if not semantic_result.is_valid:
                        sem_feedback = self._diagnose_semantic_failure(
                            proposal=current_proposal,
                            task=task,
                            result=semantic_result,
                            attempt=attempt,
                        )
                        current_proposal.feedback_history.append(sem_feedback)
                        if state_context:
                            state_context.record_feedback(sem_feedback)

                        if attempt < self.max_retries:
                            if state_context:
                                SwarmStateMachine.transition(
                                    state_context,
                                    RemediationState.RETRY_WITH_FEEDBACK,
                                    message=f"Semantic verification failed: {sem_feedback}",
                                )
                                SwarmStateMachine.transition(
                                    state_context,
                                    RemediationState.SYNTHESIZE,
                                    message=f"Re-synthesizing patch to satisfy semantic requirements (Attempt {attempt+1})",
                                )

                            prev_history = list(current_proposal.feedback_history)
                            current_proposal = synthesizer.synthesize_patch(
                                task=task,
                                file_content=orig_content,
                                feedback=sem_feedback,
                            )
                            current_proposal.attempts = attempt + 1
                            current_proposal.feedback_history = prev_history
                            continue
                        else:
                            if state_context:
                                SwarmStateMachine.transition(
                                    state_context,
                                    RemediationState.ESCALATE,
                                    message=f"Semantic requirements unfulfilled after {self.max_retries} attempts",
                                )
                            current_proposal.is_verified = False
                            return current_proposal

                # --------------------------------------------------------------
                # Both Invariants Met: Accept Patch
                # --------------------------------------------------------------
                current_proposal.is_verified = True
                if state_context:
                    SwarmStateMachine.transition(
                        state_context,
                        RemediationState.ACCEPT,
                        message="Zero destruction guarantee met and semantic compliance verified",
                    )
                return current_proposal

            except Exception as e:
                err_msg = f"Attempt {attempt} execution error: {e}"
                current_proposal.feedback_history.append(err_msg)
                if state_context:
                    state_context.record_feedback(err_msg)

        current_proposal.is_verified = False
        if state_context and not state_context.is_terminal:
            SwarmStateMachine.transition(
                state_context,
                RemediationState.ESCALATE,
                message=f"Remediation failed to converge after {self.max_retries} attempts",
            )
        return current_proposal

    def _diagnose_invariant_failure(
        self,
        proposal: PatchProposal,
        task: RemediationTask,
        report: InvariantReport,
        attempt: int,
    ) -> str:
        """Diagnoses invariant failure using LLM or deterministic fallback."""
        if self.llm_client and not self.deterministic:
            try:
                prompt = SupervisorPrompt.format(
                    proposal=proposal,
                    task=task,
                    invariant_violations=report.violations,
                )
                diagnosis = self.llm_client.generate_structured(
                    prompt=prompt,
                    response_model=SupervisorDiagnosis,
                    system_prompt=SupervisorPrompt.SYSTEM_PROMPT,
                    max_tokens=384,
                )
                if diagnosis.recommended_strategy and task.action:
                    task.action.strategy = diagnosis.recommended_strategy
                return (
                    f"Attempt {attempt} rejected [{diagnosis.failure_type or 'INVARIANT_FAILURE'}]: "
                    f"{diagnosis.actionable_feedback}"
                )
            except Exception as e:
                logger.warning("SupervisorAgent LLM diagnosis failed; falling back to deterministic: %s", e)

        # Deterministic diagnosis
        violation_msgs = [v.message for v in report.violations]
        joined = "; ".join(violation_msgs)
        is_replacement = any(
            "REPLACEMENT" in v.message.upper()
            or v.violation_type.value == "FORCES_REPLACEMENT"
            or (v.action_reason and "replace" in v.action_reason.lower())
            for v in report.violations
        )
        if is_replacement:
            if task.action:
                task.action.strategy = RemediationStrategy.ADDITIVE_ATTACHMENT
            return (
                f"Attempt {attempt} rejected [FORCES_REPLACEMENT]: Plan triggers resource recreation. "
                f"Switch to ADDITIVE_ATTACHMENT using an external configuration resource to prevent deletion."
            )
        return f"Attempt {attempt} rejected: {joined}"

    def _diagnose_semantic_failure(
        self,
        proposal: PatchProposal,
        task: RemediationTask,
        result: SemanticVerificationResult,
        attempt: int,
    ) -> str:
        """Diagnoses semantic failure using LLM or deterministic fallback."""
        if self.llm_client and not self.deterministic:
            try:
                prompt = SupervisorPrompt.format(
                    proposal=proposal,
                    task=task,
                    semantic_violations=result.violations,
                )
                diagnosis = self.llm_client.generate_structured(
                    prompt=prompt,
                    response_model=SupervisorDiagnosis,
                    system_prompt=SupervisorPrompt.SYSTEM_PROMPT,
                    max_tokens=384,
                )
                if diagnosis.recommended_strategy and task.action:
                    task.action.strategy = diagnosis.recommended_strategy
                return (
                    f"Attempt {attempt} rejected [{diagnosis.failure_type or 'SEMANTIC_FAILURE'}]: "
                    f"{diagnosis.actionable_feedback}"
                )
            except Exception as e:
                logger.warning("SupervisorAgent semantic LLM diagnosis failed; falling back to deterministic: %s", e)

        # Deterministic diagnosis
        msgs = [v.message for v in result.violations]
        return f"Attempt {attempt} rejected [SEMANTIC_FAILURE]: {'; '.join(msgs)}"
