from pathlib import Path
from typing import Dict, List, Optional, Union

from regradar.parser.hcl_parser import HCLParser
from regradar.graph.builder import DependencyGraphBuilder
from regradar.graph.centrality import CentralityEngine
from regradar.remediation.scanner import CheckovScanner
from regradar.remediation.models import (
    GatingStatus,
    PatchProposal,
    RemediationTask,
    SwarmExecutionResult,
)
from regradar.remediation.agents import (
    AuditorAgent,
    PolicyPlannerAgent,
    SynthesizerAgent,
    SupervisorAgent,
)
from regradar.invariant.sandbox import SandboxRunner


class SwarmCoordinator:
    """
    Coordinates the end-to-end multi-agent compliance remediation lifecycle:
      Phase 1 AST & DAG Gating
        -> Static Violation Audit (Checkov)
        -> Ontological Regulatory Grounding (HIPAA / GDPR / NIST)
        -> Multi-Agent Code Patch Synthesis
        -> Phase 2 Sandboxed Invariant Verification
        -> Verified Safe Patch Delivery
    """

    def __init__(self, sandbox_runner: Optional[SandboxRunner] = None):
        self.sandbox_runner = sandbox_runner or SandboxRunner()
        self.synthesizer = SynthesizerAgent()
        self.supervisor = SupervisorAgent(sandbox_runner=self.sandbox_runner)

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
        auditor = AuditorAgent(graph_summary)
        tasks = auditor.audit_and_gate(violations)

        eligible_tasks = PolicyPlannerAgent.filter_eligible_tasks(tasks)
        human_tasks = [t for t in tasks if t.gating_status == GatingStatus.HUMAN_ESCALATION_REQUIRED]

        accepted_patches: List[PatchProposal] = []
        rejected_patches: List[PatchProposal] = []
        remediated_files: Dict[str, str] = {}

        # Cache file contents
        file_contents: Dict[str, str] = {}
        for tf_file in path.glob("*.tf"):
            file_contents[tf_file.name] = tf_file.read_text(encoding="utf-8")

        # Step 4: Iterative Synthesis & Sandboxed Invariant Verification
        for task in eligible_tasks:
            target_file_name = Path(task.violation.file_path).name
            current_content = file_contents.get(target_file_name, "")
            if not current_content:
                continue

            proposal = self.synthesizer.synthesize_patch(task, current_content)

            # Pre-flight Invariant Sandbox Check
            verified_proposal = self.supervisor.verify_and_refine(
                base_dir=path,
                proposal=proposal,
                task=task,
                synthesizer=self.synthesizer,
            )

            if verified_proposal.is_verified:
                accepted_patches.append(verified_proposal)
                file_contents[target_file_name] = verified_proposal.modified_content
                remediated_files[target_file_name] = verified_proposal.modified_content

                # Apply in place if requested
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
        )
