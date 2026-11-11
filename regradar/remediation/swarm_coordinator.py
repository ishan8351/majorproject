"""
End-to-End Swarm Coordinator for RegRadar.

Orchestrates the multi-agent closed-loop governance workflow:
  Phase 1 AST & DAG Gating (AuditorAgent)
    -> Regulatory Context Retrieval via Hybrid GraphRAG (PolicyPlannerAgent)
    -> Non-Destructive HCL Code Synthesis (SynthesizerAgent)
    -> Pre-Flight Ephemeral Sandboxed Plan Simulation (SupervisorAgent)
    -> Semantic Invariant Verification & Regression Prevention
    -> Closed-Loop Diagnostic Self-Correction or Human Escalation
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Union, TYPE_CHECKING

from regradar.graph.builder import DependencyGraphBuilder
from regradar.graph.centrality import CentralityEngine
from regradar.invariant.sandbox import SandboxRunner
from regradar.parser.hcl_parser import HCLParser
from regradar.remediation.agents import (
    AuditorAgent,
    PolicyPlannerAgent,
    SupervisorAgent,
    SynthesizerAgent,
)
from regradar.remediation.knowledge_base import RegulatoryKnowledgeBase
from regradar.remediation.llm.client import BaseLLMClient
from regradar.remediation.models import (
    GatingStatus,
    PatchProposal,
    RemediationTask,
    SwarmExecutionResult,
)
from regradar.remediation.scanner import CheckovScanner
from regradar.remediation.state_machine import (
    RemediationContext,
    RemediationState,
    SwarmStateMachine,
)

if TYPE_CHECKING:
    from regradar.knowledge.retriever import HybridGraphRAGRetriever
    from regradar.invariant.semantic_verifier import SemanticInvariantVerifier


class SwarmCoordinator:
    """
    Coordinates the end-to-end multi-agent compliance remediation lifecycle.
    """

    def __init__(
        self,
        sandbox_runner: Optional[SandboxRunner] = None,
        semantic_verifier: Optional[Any] = None,
        retriever: Optional[HybridGraphRAGRetriever] = None,
        llm_client: Optional[BaseLLMClient] = None,
        deterministic: Optional[bool] = None,
        max_retries: Optional[int] = None,
    ):
        from regradar.config import get_config
        cfg = get_config().llm.swarm
        self.sandbox_runner = sandbox_runner or SandboxRunner()
        if semantic_verifier is None:
            from regradar.invariant.semantic_verifier import SemanticInvariantVerifier
            self.semantic_verifier = SemanticInvariantVerifier()
        else:
            self.semantic_verifier = semantic_verifier
        self.retriever = retriever or RegulatoryKnowledgeBase.get_retriever()
        self.llm_client = llm_client
        self.deterministic = deterministic if deterministic is not None else cfg.deterministic
        self.max_retries = max_retries if max_retries is not None else cfg.max_retries

        self.policy_planner = PolicyPlannerAgent(
            retriever=self.retriever,
            llm_client=self.llm_client,
            deterministic=self.deterministic,
        )
        self.synthesizer = SynthesizerAgent(
            llm_client=self.llm_client,
            deterministic=self.deterministic,
        )
        self.supervisor = SupervisorAgent(
            sandbox_runner=self.sandbox_runner,
            semantic_verifier=self.semantic_verifier,
            llm_client=self.llm_client,
            max_retries=self.max_retries,
            deterministic=self.deterministic,
        )

    def remediate_directory(
        self,
        target_dir: Union[str, Path],
        apply_changes: bool = False,
        precomputed_violations: Optional[List] = None,
    ) -> SwarmExecutionResult:
        """Executes full closed-loop remediation on a Terraform codebase."""
        path = Path(target_dir).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Target directory not found: {path}")

        # Step 1: Phase 1 Graph & Centrality Assessment
        parser = HCLParser()
        resources = parser.parse_directory(path)
        builder = DependencyGraphBuilder(resources)
        centrality_engine = CentralityEngine(builder.graph)
        graph_summary = centrality_engine.get_summary()

        # Step 2: Ingest Compliance Violations
        if precomputed_violations is not None:
            violations = precomputed_violations
        else:
            scanner = CheckovScanner()
            violations = scanner.scan_directory(path)

        # Step 3: Auditor Agent Risk Gating
        auditor = AuditorAgent(
            graph_summary,
            llm_client=self.llm_client,
            deterministic=self.deterministic,
        )
        tasks = auditor.audit_and_gate(violations)

        eligible_tasks = PolicyPlannerAgent.filter_eligible_tasks(tasks)
        human_tasks = [t for t in tasks if t.gating_status == GatingStatus.HUMAN_ESCALATION_REQUIRED]

        accepted_patches: List[PatchProposal] = []
        rejected_patches: List[PatchProposal] = []
        remediated_files: Dict[str, str] = {}
        contexts: List[RemediationContext] = []

        # Cache file contents
        file_contents: Dict[str, str] = {}
        for tf_file in path.glob("*.tf"):
            file_contents[tf_file.name] = tf_file.read_text(encoding="utf-8")

        # Track contexts for escalated human tasks
        for ht in human_tasks:
            ctx = RemediationContext(
                task=ht,
                current_state=RemediationState.AUDIT,
                max_retries=self.max_retries,
            )
            SwarmStateMachine.transition(
                ctx,
                RemediationState.ESCALATE,
                message=ht.reason,
            )
            contexts.append(ctx)

        # Step 4: Iterative Synthesis, Sandboxed Simulation, and Semantic Invariant Verification
        for task in eligible_tasks:
            target_file_name = Path(task.violation.file_path).name
            current_content = file_contents.get(target_file_name, "")
            if not current_content:
                continue

            # Initialize state machine context for this autonomous task
            ctx = RemediationContext(
                task=task,
                current_state=RemediationState.AUDIT,
                max_retries=self.max_retries,
            )
            contexts.append(ctx)

            # State: GRAPH_RAG_RETRIEVE
            SwarmStateMachine.transition(
                ctx,
                RemediationState.GRAPH_RAG_RETRIEVE,
                message=f"Querying GraphRAG retriever for check '{task.violation.check_id}'",
            )
            retrieved_contexts = self.retriever.retrieve(
                query=f"{task.violation.check_id} {task.violation.check_name}",
                resource_type=task.violation.resource_type,
                top_k=2,
            )
            if retrieved_contexts:
                ctx.regulatory_context = retrieved_contexts[0]

            # State: PLAN
            SwarmStateMachine.transition(
                ctx,
                RemediationState.PLAN,
                message="Grounding violation in statutory requirements and formulating remediation plan",
            )
            task = self.policy_planner.plan_remediation(
                task=task,
                contexts=retrieved_contexts,
                file_content=current_content,
            )
            ctx.task = task

            # State: SYNTHESIZE
            SwarmStateMachine.transition(
                ctx,
                RemediationState.SYNTHESIZE,
                message="Synthesizing initial zero-destruction patch",
            )
            proposal = self.synthesizer.synthesize_patch(
                task=task,
                file_content=current_content,
            )
            ctx.patch_proposal = proposal

            # Supervisor pre-flight simulation and closed-loop verification
            verified_proposal = self.supervisor.verify_and_refine(
                base_dir=path,
                proposal=proposal,
                task=task,
                synthesizer=self.synthesizer,
                state_context=ctx,
                file_content=current_content,
            )

            if verified_proposal.is_verified:
                accepted_patches.append(verified_proposal)
                file_contents[target_file_name] = verified_proposal.modified_content
                remediated_files[target_file_name] = verified_proposal.modified_content

                if apply_changes:
                    target_full_path = path / target_file_name
                    target_full_path.write_text(verified_proposal.modified_content, encoding="utf-8")
            else:
                rejected_patches.append(verified_proposal)

        return SwarmExecutionResult(
            target_path=str(path),
            total_violations_found=len(violations),
            autonomous_remediations_eligible=len(eligible_tasks),
            human_escalations_required=len(human_tasks),
            patches_verified_and_accepted=len(accepted_patches),
            patches_rejected_and_escalated=len(rejected_patches),
            tasks=tasks,
            accepted_patches=accepted_patches,
            remediated_files=remediated_files,
            contexts=contexts,
        )
