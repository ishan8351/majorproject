import argparse
import difflib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax

from regradar.parser.hcl_parser import HCLParser
from regradar.graph.builder import DependencyGraphBuilder
from regradar.graph.centrality import CentralityEngine
from regradar.models import CentralityMetrics, GraphSummary, RiskTier
from regradar.invariant.models import InvariantReport
from regradar.invariant.plan_parser import PlanParser
from regradar.invariant.invariant_engine import InvariantEngine
from regradar.invariant.sandbox import SandboxRunner
from regradar.remediation.models import (
    ComplianceViolation,
    GatingStatus,
    PatchProposal,
    RemediationStrategy,
    RemediationTask,
    SwarmExecutionResult,
)
from regradar.remediation.swarm_coordinator import SwarmCoordinator
from regradar.remediation.scanner import CheckovScanner
from regradar.remediation.agents import (
    AuditorAgent,
    PolicyPlannerAgent,
    SynthesizerAgent,
    SupervisorAgent,
)
from regradar.remediation.knowledge_base import RegulatoryKnowledgeBase
from regradar.benchmark.evaluator import BenchmarkEvaluator
from regradar.benchmark.report_generator import ReportGenerator

console = Console()


def scan_directory(
    target_dir: str,
    export_json: str = None,
    export_mermaid: str = None,
    export_dot: str = None,
) -> int:
    path = Path(target_dir).resolve()
    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] Path does not exist: {path}")
        return 1

    console.print(
        Panel(
            f"[bold cyan]RegRadar Phase 1: AST Dependency & Blast-Radius Engine[/bold cyan]\n"
            f"[dim]Scanning target:[/dim] {path}",
            border_style="cyan",
        )
    )

    parser = HCLParser()
    try:
        if path.is_file():
            resources = parser.parse_file(path)
        else:
            resources = parser.parse_directory(path)
    except Exception as e:
        console.print(f"[bold red]Failed to parse HCL:[/bold red] {e}")
        return 1

    if not resources:
        console.print("[yellow]No Terraform resources discovered.[/yellow]")
        return 0

    builder = DependencyGraphBuilder(resources)
    engine = CentralityEngine(builder.graph)
    summary = engine.get_summary()

    table = Table(
        title="Infrastructure Dependency & Blast-Radius Risk Analysis",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Resource Identifier", style="bold", min_width=25)
    table.add_column("Type", style="dim")
    table.add_column("Direct Dependents", justify="center")
    table.add_column("Cascading Impact", justify="center")
    table.add_column("Betweenness", justify="right")
    table.add_column("Risk Score", justify="right")
    table.add_column("Risk Tier", justify="center")
    table.add_column("Auto-Remediate?", justify="center")

    sorted_metrics = sorted(
        summary.metrics.values(),
        key=lambda m: (m.blast_radius_score, m.descendant_count),
        reverse=True,
    )

    for m in sorted_metrics:
        if m.risk_tier == RiskTier.CRITICAL_ROOT:
            tier_styled = "[bold red]CRITICAL_ROOT[/bold red]"
            auto_styled = "[red]NO (Human Gate)[/red]"
        elif m.risk_tier == RiskTier.INTERMEDIATE:
            tier_styled = "[bold yellow]INTERMEDIATE[/bold yellow]"
            auto_styled = "[yellow]YES (Strict Invariant)[/yellow]"
        else:
            tier_styled = "[bold green]LEAF_SAFE[/bold green]"
            auto_styled = "[green]YES (Autonomous)[/green]"

        table.add_row(
            m.node_id,
            m.resource_type,
            str(m.out_degree),
            f"{m.descendant_count} nodes",
            f"{m.betweenness:.4f}",
            f"{m.blast_radius_score:.4f}",
            tier_styled,
            auto_styled,
        )

    console.print(table)
    console.print(
        f"\n[dim]Summary: {summary.total_resources} resources, "
        f"{summary.total_dependencies} dependencies. "
        f"Roots: {len(summary.root_resources)}, Leaves: {len(summary.leaf_resources)}[/dim]\n"
    )

    if export_json:
        with open(export_json, "w", encoding="utf-8") as f:
            f.write(summary.model_dump_json(indent=2))
        console.print(f"[green]Saved JSON summary to:[/green] {export_json}")

    if export_mermaid:
        with open(export_mermaid, "w", encoding="utf-8") as f:
            f.write(engine.to_mermaid())
        console.print(f"[green]Saved Mermaid diagram to:[/green] {export_mermaid}")

    if export_dot:
        with open(export_dot, "w", encoding="utf-8") as f:
            f.write(engine.to_dot())
        console.print(f"[green]Saved DOT graph to:[/green] {export_dot}")

    return 0


def render_invariant_report(report: InvariantReport) -> int:
    title = (
        "[bold green]✔ ZERO-DESTRUCTION INVARIANT PRESERVED[/bold green]"
        if report.is_safe
        else "[bold red]✘ INVARIANT VIOLATION DETECTED[/bold red]"
    )

    console.print(
        Panel(
            f"{title}\n"
            f"[dim]Total Resources Evaluated:[/dim] {report.total_resources_evaluated} | "
            f"[green]Create:[/green] {report.count_created} | "
            f"[yellow]Update:[/yellow] {report.count_updated} | "
            f"[red]Delete:[/red] {report.count_deleted} | "
            f"[bold red]Replace:[/bold red] {report.count_replaced}",
            border_style="green" if report.is_safe else "red",
        )
    )

    if report.violations:
        viol_table = Table(
            title="Invariant Violations (Rejected Mutations)",
            show_header=True,
            header_style="bold red",
        )
        viol_table.add_column("Resource Address", style="bold")
        viol_table.add_column("Violation Type", justify="center")
        viol_table.add_column("Planned Actions", justify="center")
        viol_table.add_column("Diagnostic Message")

        for v in report.violations:
            viol_table.add_row(
                v.resource_address,
                f"[bold red]{v.violation_type.value}[/bold red]",
                ", ".join(v.actions),
                v.message,
            )
        console.print(viol_table)
        return 1

    console.print("[bold green]All changes pass state-preservation invariants.[/bold green]\n")
    return 0


def verify_plan_file(plan_path: str) -> int:
    path = Path(plan_path).resolve()
    if not path.is_file():
        console.print(f"[bold red]Plan file not found:[/bold red] {path}")
        return 1

    try:
        changes = PlanParser.parse_json_file(path)
    except Exception as e:
        console.print(f"[bold red]Error parsing plan file:[/bold red] {e}")
        return 1

    engine = InvariantEngine()
    report = engine.verify(changes)
    return render_invariant_report(report)


def verify_sandbox(target_dir: str) -> int:
    path = Path(target_dir).resolve()
    if not path.exists():
        console.print(f"[bold red]Target directory not found:[/bold red] {path}")
        return 1

    console.print(
        Panel(
            f"[bold cyan]RegRadar Phase 2: Sandboxed Dry-Run Invariant Enforcement[/bold cyan]\n"
            f"[dim]Executing pre-flight plan simulation in ephemeral sandbox:[/dim] {path}",
            border_style="cyan",
        )
    )

    runner = SandboxRunner()
    try:
        report = runner.simulate_and_verify(path)
    except Exception as e:
        console.print(f"[bold red]Sandbox execution error:[/bold red] {e}")
        return 1

    return render_invariant_report(report)


def remediate_directory(target_dir: str, apply_changes: bool = False) -> int:
    path = Path(target_dir).resolve()
    if not path.exists():
        console.print(f"[bold red]Target directory not found:[/bold red] {path}")
        return 1

    console.print(
        Panel(
            f"[bold cyan]RegRadar Phase 3: Multi-Agent Autonomous Compliance Remediation[/bold cyan]\n"
            f"[dim]Closed-loop agent swarm with dry-run invariant verification:[/dim] {path}",
            border_style="cyan",
        )
    )

    coordinator = SwarmCoordinator()
    try:
        result: SwarmExecutionResult = coordinator.remediate_directory(
            path, apply_changes=apply_changes
        )
    except Exception as e:
        console.print(f"[bold red]Remediation execution error:[/bold red] {e}")
        return 1

    table = Table(
        title="Regulatory Compliance Audit & Blast-Radius Gating",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Resource", style="bold")
    table.add_column("Rule / Check ID", justify="center")
    table.add_column("Statute / Framework", style="dim")
    table.add_column("Blast Radius", justify="center")
    table.add_column("Gating Decision", justify="center")

    for task in result.tasks:
        if task.gating_status == GatingStatus.AUTONOMOUS_ELIGIBLE:
            gate_styled = "[bold green]AUTONOMOUS_ELIGIBLE[/bold green]"
        else:
            gate_styled = "[bold red]HUMAN_ESCALATION[/bold red]"

        framework_str = task.action.statute_reference if task.action else "General Policy"

        table.add_row(
            task.violation.resource_id,
            task.violation.check_id,
            framework_str,
            f"{task.blast_radius_score:.4f} ({task.risk_tier})",
            gate_styled,
        )

    console.print(table)

    console.print(
        Panel(
            f"[bold]Remediation Swarm Execution Summary:[/bold]\n"
            f"• Total Violations Found: {result.total_violations_found}\n"
            f"• Autonomous Remediation Eligible: [green]{result.autonomous_remediations_eligible}[/green]\n"
            f"• Human Review Gated: [yellow]{result.human_escalations_required}[/yellow]\n"
            f"• Invariant Verified & Accepted Patches: [bold green]{result.patches_verified_and_accepted}[/bold green]\n"
            f"• Rejected / Unsafe Mutations: [bold red]{result.patches_rejected_and_escalated}[/bold red]",
            border_style="green" if result.patches_verified_and_accepted > 0 else "yellow",
        )
    )

    if result.accepted_patches:
        console.print("[bold green]Verified Non-Destructive Patches Synthesized:[/bold green]")
        for p in result.accepted_patches:
            console.print(f"\n[cyan]File: {p.target_file} | Resource: {p.resource_id}[/cyan]")
            syntax = Syntax(p.remediated_snippet, "hcl", theme="monokai", line_numbers=True)
            console.print(syntax)

    if apply_changes:
        console.print("\n[bold green]✔ All verified patches successfully written to disk![/bold green]")
    else:
        console.print("\n[dim]Dry-run mode: Patches verified in sandbox. Run with '--apply' to persist.[/dim]")

    return 0


def run_benchmark(
    target_dir: str,
    include_ablation: bool = True,
    export_markdown: Optional[str] = None,
    export_latex: Optional[str] = None,
    export_csv: Optional[str] = None,
) -> int:
    path = Path(target_dir).resolve()
    if not path.exists():
        console.print(f"[bold red]Target directory not found:[/bold red] {path}")
        return 1

    evaluator = BenchmarkEvaluator()

    # Check if target is a corpus directory (contains subdirectories with .tf files)
    subdirs_with_tf = [p for p in path.iterdir() if p.is_dir() and list(p.glob("*.tf"))] if path.is_dir() else []
    if subdirs_with_tf:
        corpus_result = evaluator.evaluate_corpus(path)
        ReportGenerator.render_console(corpus_result)

        if export_markdown:
            md_text = ReportGenerator.generate_markdown_report(corpus_result)
            Path(export_markdown).write_text(md_text, encoding="utf-8")
            console.print(f"[bold green]Saved Markdown report to:[/bold green] {export_markdown}")

        if export_latex:
            tex_text = ReportGenerator.generate_latex_table(corpus_result)
            Path(export_latex).write_text(tex_text, encoding="utf-8")
            console.print(f"[bold green]Saved LaTeX table to:[/bold green] {export_latex}")

        if export_csv:
            ReportGenerator.export_csv(corpus_result, export_csv)
            console.print(f"[bold green]Saved CSV telemetry to:[/bold green] {export_csv}")

        return 0

    result = evaluator.evaluate_target(path)

    ablation = None
    if include_ablation:
        ablation = evaluator.run_comparative_ablation(path)

    ReportGenerator.render_console(result, ablation)

    if export_markdown:
        md_text = ReportGenerator.generate_markdown_report(result, ablation)
        Path(export_markdown).write_text(md_text, encoding="utf-8")
        console.print(f"[bold green]Saved Markdown report to:[/bold green] {export_markdown}")

    if export_latex and ablation:
        tex_text = ReportGenerator.generate_latex_table(ablation)
        Path(export_latex).write_text(tex_text, encoding="utf-8")
        console.print(f"[bold green]Saved LaTeX table to:[/bold green] {export_latex}")

    if export_csv:
        target_data = ablation if ablation else result
        ReportGenerator.export_csv(target_data, export_csv)
        console.print(f"[bold green]Saved CSV telemetry to:[/bold green] {export_csv}")

    return 0


def review_directory(
    target_dir: str,
    apply_changes: bool = False,
    non_interactive: bool = False,
    export_json: Optional[str] = None,
    input_func: Any = input,
    precomputed_violations: Optional[List[ComplianceViolation]] = None,
    precomputed_summary: Optional[GraphSummary] = None,
    coordinator: Optional[SwarmCoordinator] = None,
) -> int:
    """
    Interactive Human-in-the-Loop compliance review and blast-radius gatekeeper.
    - Automatically verifies and approves LEAF_SAFE patches.
    - Surfaces high-risk CRITICAL_ROOT and INTERMEDIATE components for operator review.
    - Previews unified diffs and supports [A]pprove & Apply / [R]eject / [S]kip / [Q]uit.
    """
    path = Path(target_dir).resolve()
    if not path.exists():
        console.print(f"[bold red]Target path not found:[/bold red] {path}")
        return 1

    mode_label = "[bold red]APPLY (Persist to Disk)[/bold red]" if apply_changes else "[bold green]DRY-RUN (Simulate Only)[/bold green]"
    interact_label = "[bold yellow]Non-Interactive[/bold yellow]" if non_interactive else "[bold cyan]Interactive Operator Review[/bold cyan]"

    console.print(
        Panel(
            f"[bold cyan]RegRadar: Interactive Compliance Review & Human-in-the-Loop Gating[/bold cyan]\n"
            f"[dim]Target:[/dim] {path}\n"
            f"[dim]Mode:[/dim] {mode_label} | {interact_label}",
            border_style="cyan",
        )
    )

    # 1. Parse Dependency Graph & Centrality
    if precomputed_summary is not None:
        summary = precomputed_summary
    else:
        parser = HCLParser()
        try:
            if path.is_file():
                resources = parser.parse_file(path)
            else:
                resources = parser.parse_directory(path)
        except Exception as e:
            console.print(f"[bold red]HCL Parsing error:[/bold red] {e}")
            return 1

        if not resources:
            console.print("[yellow]No Terraform resources found to evaluate.[/yellow]")
            return 0

        builder = DependencyGraphBuilder(resources)
        centrality_engine = CentralityEngine(builder.graph)
        summary = centrality_engine.get_summary()

    # 2. Ingest Compliance Violations
    if precomputed_violations is not None:
        violations = precomputed_violations
    else:
        scanner = CheckovScanner()
        try:
            violations = scanner.scan_directory(path)
        except Exception as e:
            console.print(f"[yellow]Compliance scanner warning: {e}[/yellow]")
            violations = []

    if not violations:
        console.print("[bold green]✔ No compliance violations found. Everything in compliance![/bold green]")
        if export_json:
            empty_data = {
                "target_dir": str(path),
                "apply_mode": apply_changes,
                "non_interactive": non_interactive,
                "total_violations": 0,
                "autonomous_approved": 0,
                "human_approved": 0,
                "human_rejected": 0,
                "human_skipped": 0,
                "decisions": [],
                "counts": {
                    "autonomous_approved": 0,
                    "human_approved": 0,
                    "human_rejected": 0,
                    "human_skipped": 0,
                },
            }
            out_json_path = Path(export_json).resolve()
            out_json_path.parent.mkdir(parents=True, exist_ok=True)
            out_json_path.write_text(json.dumps(empty_data, indent=2), encoding="utf-8")
        return 0

    # 3. Blast-Radius Gatekeeper (AuditorAgent)
    auditor = AuditorAgent(summary, deterministic=True)
    tasks = auditor.audit_and_gate(violations)

    autonomous_tasks = PolicyPlannerAgent.filter_eligible_tasks(tasks)
    human_tasks = [t for t in tasks if t not in autonomous_tasks]

    # Cache file contents
    base_dir = path if path.is_dir() else path.parent
    file_contents: Dict[str, str] = {}
    if path.is_file():
        file_contents[path.name] = path.read_text(encoding="utf-8")
    else:
        for tf_file in path.glob("*.tf"):
            file_contents[tf_file.name] = tf_file.read_text(encoding="utf-8")

    review_decisions: List[Dict[str, Any]] = []
    accepted_patches: List[PatchProposal] = []
    counts = {
        "autonomous_approved": 0,
        "human_approved": 0,
        "human_rejected": 0,
        "human_skipped": 0,
    }

    # 4. Phase 1: Autonomous Remediation for LEAF_SAFE components
    if autonomous_tasks:
        console.print(
            f"\n[bold green]► Phase 1: Autonomous Invariant Verification for LEAF_SAFE Components ({len(autonomous_tasks)} item(s))[/bold green]"
        )
        coord = coordinator or SwarmCoordinator(deterministic=True)
        for at in autonomous_tasks:
            t_file = Path(at.violation.file_path).name
            cur_content = file_contents.get(t_file, "")
            if not cur_content:
                continue

            planned_task = coord.policy_planner.plan_remediation(at, file_content=cur_content)
            proposal = coord.synthesizer.synthesize_patch(planned_task, cur_content)

            verified = coord.supervisor.verify_and_refine(
                base_dir=base_dir,
                proposal=proposal,
                task=planned_task,
                synthesizer=coord.synthesizer,
                file_content=cur_content,
            )

            if verified.is_verified:
                counts["autonomous_approved"] += 1
                accepted_patches.append(verified)
                file_contents[t_file] = verified.modified_content

                if apply_changes:
                    (base_dir / t_file).write_text(verified.modified_content, encoding="utf-8")
                    status_note = "[bold green]VERIFIED & APPLIED TO DISK[/bold green]"
                else:
                    status_note = "[green]VERIFIED (DRY-RUN)[/green]"

                console.print(
                    f"  ✔ [bold]{at.violation.resource_id}[/bold] ({at.violation.check_id}) -> {status_note}"
                )

                review_decisions.append({
                    "resource_id": at.violation.resource_id,
                    "check_id": at.violation.check_id,
                    "risk_tier": at.risk_tier,
                    "blast_radius_score": at.blast_radius_score,
                    "decision": "AUTONOMOUS_APPROVED",
                    "applied": apply_changes,
                    "file": t_file,
                })
            else:
                human_tasks.append(at)

    # 5. Phase 2: Human Sign-Off for High-Risk CRITICAL_ROOT & INTERMEDIATE components
    if human_tasks:
        console.print(
            f"\n[bold yellow]► Phase 2: Human-in-the-Loop Operator Review ({len(human_tasks)} item(s) flagged)[/bold yellow]\n"
        )

        synthesizer = SynthesizerAgent(deterministic=True)
        abort_review = False

        for idx, ht in enumerate(human_tasks, start=1):
            t_file = Path(ht.violation.file_path).name
            cur_content = file_contents.get(t_file, "")
            metric = summary.metrics.get(ht.violation.resource_id)
            desc_count = metric.descendant_count if metric else 0
            anc_count = metric.ancestor_count if metric else 0
            blast_score = metric.blast_radius_score if metric else ht.blast_radius_score
            tier_val = metric.risk_tier.value if metric else ht.risk_tier

            if abort_review:
                counts["human_skipped"] += 1
                review_decisions.append({
                    "resource_id": ht.violation.resource_id,
                    "check_id": ht.violation.check_id,
                    "risk_tier": tier_val,
                    "blast_radius_score": blast_score,
                    "decision": "SKIPPED",
                    "applied": False,
                    "file": t_file,
                    "reason": "Review aborted by operator",
                })
                continue

            # Synthesize candidate patch proposal
            patch_proposal = None
            if cur_content:
                patch_proposal = synthesizer.synthesize_patch(ht, cur_content)

            # Warning Panel
            warning_msg = (
                f"[bold red]⚠️  HIGH-RISK INFRASTRUCTURE MUTATION REQUIRING SECURITY SIGN-OFF[/bold red]\n\n"
                f"• [bold]Resource Identifier:[/bold] {ht.violation.resource_id} ([bold red]{tier_val}[/bold red])\n"
                f"• [bold]Blast-Radius Impact:[/bold] Composite Risk Score = {blast_score:.4f} | "
                f"Cascading Dependents = [bold red]{desc_count} nodes[/bold red] | "
                f"Upstream Dependencies = {anc_count} nodes\n"
                f"• [bold]Compliance Finding:[/bold] {ht.violation.check_id} - {ht.violation.check_name}\n"
                f"• [bold]Statutory Mandate:[/bold] {ht.action.statute_reference if ht.action else 'Security Baseline'}\n"
                f"• [bold]Gating Reason:[/bold] {ht.reason}"
            )
            console.print(
                Panel(
                    warning_msg,
                    title=f"[bold]Item {idx}/{len(human_tasks)}: Human Sign-Off Required[/bold]",
                    border_style="red",
                )
            )

            # Diff / Patch Preview
            if patch_proposal and patch_proposal.modified_content and patch_proposal.modified_content != cur_content:
                console.print(f"[bold cyan]Proposed Zero-Destruction Patch Diff for {t_file}:[/bold cyan]")
                diff = difflib.unified_diff(
                    cur_content.splitlines(keepends=True),
                    patch_proposal.modified_content.splitlines(keepends=True),
                    fromfile=f"a/{t_file}",
                    tofile=f"b/{t_file}",
                )
                diff_str = "".join(diff)
                if diff_str:
                    syntax = Syntax(diff_str, "diff", theme="monokai", line_numbers=True)
                    console.print(syntax)
                else:
                    syntax = Syntax(patch_proposal.remediated_snippet, "hcl", theme="monokai", line_numbers=True)
                    console.print(syntax)
            elif patch_proposal and patch_proposal.remediated_snippet:
                console.print(f"[bold cyan]Synthesized HCL Snippet for {t_file}:[/bold cyan]")
                syntax = Syntax(patch_proposal.remediated_snippet, "hcl", theme="monokai", line_numbers=True)
                console.print(syntax)
            else:
                console.print(
                    "[yellow]No automated remediation template registered for this check. "
                    "Manual engineering review required.[/yellow]"
                )

            # Non-interactive handling
            if non_interactive:
                console.print(
                    f"[yellow]Non-interactive mode active: Skipping human sign-off prompt for {ht.violation.resource_id}.[/yellow]\n"
                )
                counts["human_skipped"] += 1
                review_decisions.append({
                    "resource_id": ht.violation.resource_id,
                    "check_id": ht.violation.check_id,
                    "risk_tier": tier_val,
                    "blast_radius_score": blast_score,
                    "decision": "SKIPPED",
                    "applied": False,
                    "file": t_file,
                    "reason": "Non-interactive mode active",
                })
                continue

            # Prompt Operator
            choice = ""
            while choice not in ("a", "r", "s", "q"):
                try:
                    prompt_input = input_func("[A]pprove & Apply / [R]eject / [S]kip / [Q]uit: ")
                    choice = (prompt_input or "").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    choice = "q"
                    break

            if choice == "a":
                counts["human_approved"] += 1
                was_applied = False
                if patch_proposal and patch_proposal.modified_content:
                    file_contents[t_file] = patch_proposal.modified_content
                    accepted_patches.append(patch_proposal)
                    if apply_changes:
                        (base_dir / t_file).write_text(patch_proposal.modified_content, encoding="utf-8")
                        was_applied = True
                        console.print(f"[bold green]✔ Patch approved and written to {t_file}![/bold green]\n")
                    else:
                        console.print(
                            f"[bold green]✔ Patch approved (Dry-run mode: run with '--apply' to persist to disk).[/bold green]\n"
                        )
                else:
                    console.print(f"[green]✔ Task marked as approved for manual implementation.[/green]\n")

                review_decisions.append({
                    "resource_id": ht.violation.resource_id,
                    "check_id": ht.violation.check_id,
                    "risk_tier": tier_val,
                    "blast_radius_score": blast_score,
                    "decision": "APPROVED",
                    "applied": was_applied,
                    "file": t_file,
                })

            elif choice == "r":
                counts["human_rejected"] += 1
                console.print(f"[bold red]✘ Patch rejected for {ht.violation.resource_id}.[/bold red]\n")
                review_decisions.append({
                    "resource_id": ht.violation.resource_id,
                    "check_id": ht.violation.check_id,
                    "risk_tier": tier_val,
                    "blast_radius_score": blast_score,
                    "decision": "REJECTED",
                    "applied": False,
                    "file": t_file,
                })

            elif choice == "s":
                counts["human_skipped"] += 1
                console.print(f"[yellow]Patch skipped for {ht.violation.resource_id}.[/yellow]\n")
                review_decisions.append({
                    "resource_id": ht.violation.resource_id,
                    "check_id": ht.violation.check_id,
                    "risk_tier": tier_val,
                    "blast_radius_score": blast_score,
                    "decision": "SKIPPED",
                    "applied": False,
                    "file": t_file,
                })

            elif choice == "q":
                abort_review = True
                console.print("[bold red]Operator quit review session.[/bold red]\n")
                review_decisions.append({
                    "resource_id": ht.violation.resource_id,
                    "check_id": ht.violation.check_id,
                    "risk_tier": tier_val,
                    "blast_radius_score": blast_score,
                    "decision": "QUIT",
                    "applied": False,
                    "file": t_file,
                })

    # 6. Render Review Summary Table
    table = Table(
        title="Interactive Compliance Review Decisions Summary",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Resource Identifier", style="bold")
    table.add_column("Rule ID", justify="center")
    table.add_column("Risk Tier", justify="center")
    table.add_column("Blast Radius", justify="right")
    table.add_column("Decision", justify="center")
    table.add_column("Applied?", justify="center")

    for d in review_decisions:
        dec = d["decision"]
        if dec in ("APPROVED", "AUTONOMOUS_APPROVED"):
            dec_styled = f"[bold green]{dec}[/bold green]"
        elif dec == "REJECTED":
            dec_styled = "[bold red]REJECTED[/bold red]"
        elif dec == "SKIPPED":
            dec_styled = "[yellow]SKIPPED[/yellow]"
        else:
            dec_styled = "[bold red]QUIT[/bold red]"

        applied_styled = "[green]YES[/green]" if d["applied"] else "[dim]NO[/dim]"
        table.add_row(
            d["resource_id"],
            d["check_id"],
            d["risk_tier"],
            f"{d['blast_radius_score']:.4f}",
            dec_styled,
            applied_styled,
        )

    console.print(table)

    summary_panel = (
        f"[bold]Review Session Results:[/bold]\n"
        f"• Total Violations Audited: {len(violations)}\n"
        f"• Autonomous LEAF_SAFE Approved: [bold green]{counts['autonomous_approved']}[/bold green]\n"
        f"• Human Operator Approved: [green]{counts['human_approved']}[/green]\n"
        f"• Human Operator Rejected: [red]{counts['human_rejected']}[/red]\n"
        f"• Skipped / Pending Review: [yellow]{counts['human_skipped']}[/yellow]\n"
        f"• Persistence Mode: {'[green]Applied to disk[/green]' if apply_changes else '[yellow]Dry-run (not applied)[/yellow]'}"
    )
    console.print(Panel(summary_panel, border_style="cyan"))

    # 7. JSON Export if requested
    if export_json:
        export_data = {
            "target_dir": str(path),
            "apply_mode": apply_changes,
            "non_interactive": non_interactive,
            "total_violations": len(violations),
            "autonomous_approved": counts["autonomous_approved"],
            "human_approved": counts["human_approved"],
            "human_rejected": counts["human_rejected"],
            "human_skipped": counts["human_skipped"],
            "decisions": review_decisions,
            "counts": counts,
        }
        out_json_path = Path(export_json).resolve()
        out_json_path.parent.mkdir(parents=True, exist_ok=True)
        out_json_path.write_text(json.dumps(export_data, indent=2), encoding="utf-8")
        console.print(f"[bold green]Saved review decisions to:[/bold green] {export_json}")

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="RegRadar: Autonomous, Zero-Destruction Compliance Remediation for IaC"
    )
    parser.add_argument(
        "--config",
        dest="config_path",
        default=None,
        help="Path to custom RegRadar configuration file (JSON/TOML/YAML)",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Sub-commands")

    # Command: scan (Phase 1)
    scan_p = subparsers.add_parser("scan", help="Scan Terraform directory and compute blast-radius")
    scan_p.add_argument("path", nargs="?", default=".", help="Path to Terraform directory")
    scan_p.add_argument("--json", dest="export_json", help="Path to export JSON report")
    scan_p.add_argument("--mermaid", dest="export_mermaid", help="Path to export Mermaid diagram")
    scan_p.add_argument("--dot", dest="export_dot", help="Path to export Graphviz DOT")

    # Command: verify-plan (Phase 2)
    plan_p = subparsers.add_parser("verify-plan", help="Verify plan JSON file against Invariants")
    plan_p.add_argument("plan_file", help="Path to execution plan JSON file")

    # Command: verify-sandbox (Phase 2)
    sb_p = subparsers.add_parser("verify-sandbox", help="Run ephemeral dry-run sandbox and verify invariants")
    sb_p.add_argument("path", nargs="?", default=".", help="Path to Terraform directory")

    # Command: remediate (Phase 3)
    rem_p = subparsers.add_parser("remediate", help="Autonomous multi-agent compliance remediation")
    rem_p.add_argument("path", nargs="?", default=".", help="Path to Terraform directory")
    rem_p.add_argument("--apply", action="store_true", help="Apply verified patches to disk")

    # Command: benchmark (Phase 4)
    bm_p = subparsers.add_parser("benchmark", help="Empirical evaluation & comparative ablation")
    bm_p.add_argument("path", nargs="?", default=".", help="Path to Terraform directory")
    bm_p.add_argument("--no-ablation", action="store_true", help="Omit comparative ablation study")
    bm_p.add_argument("--markdown", dest="export_markdown", help="Export Markdown report file")
    bm_p.add_argument("--latex", dest="export_latex", help="Export LaTeX report table")
    bm_p.add_argument("--csv", dest="export_csv", help="Export CSV telemetry summary file")

    # Command: review (Stream F - Developer CI/CD Integration & Human-in-the-Loop Review)
    review_p = subparsers.add_parser("review", help="Interactive compliance review & human-in-the-loop gating")
    review_p.add_argument("path", nargs="?", default=".", help="Path to Terraform directory")
    review_p.add_argument("--apply", action="store_true", help="Automatically writes approved patches")
    review_p.add_argument("--non-interactive", "-y", action="store_true", help="Automatically processes without terminal prompt (useful for CI scripts)")
    review_p.add_argument("--json", dest="export_json", help="Exports review decisions to a JSON file")

    # Command: serve (Web Studio & Interactive GUI)
    serve_p = subparsers.add_parser("serve", help="Launch RegRadar Web Studio & Governance GUI")
    serve_p.add_argument("--host", default=None, help="Host interface to bind (default from config: 127.0.0.1)")
    serve_p.add_argument("--port", type=int, default=None, help="Port to listen on (default from config: 8000)")
    serve_p.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    serve_p.add_argument("--workspace", default=None, help="Path to production Terraform directory to manage")
    serve_p.add_argument("--provider", default=None, help="Active LLM provider: 'gemini', 'openai', 'anthropic', 'deepseek', 'ollama', 'mock'")

    args = parser.parse_args()

    # Load custom configuration if specified
    if getattr(args, "config_path", None):
        from regradar.config import load_config
        load_config(args.config_path)

    if not args.subcommand or args.subcommand == "scan":
        target_path = getattr(args, "path", ".")
        export_json = getattr(args, "export_json", None)
        export_mermaid = getattr(args, "export_mermaid", None)
        export_dot = getattr(args, "export_dot", None)
        sys.exit(
            scan_directory(
                target_path,
                export_json=export_json,
                export_mermaid=export_mermaid,
                export_dot=export_dot,
            )
        )
    elif args.subcommand == "verify-plan":
        sys.exit(verify_plan_file(args.plan_file))
    elif args.subcommand == "verify-sandbox":
        sys.exit(verify_sandbox(args.path))
    elif args.subcommand == "remediate":
        sys.exit(remediate_directory(args.path, apply_changes=args.apply))
    elif args.subcommand == "benchmark":
        sys.exit(
            run_benchmark(
                args.path,
                include_ablation=not args.no_ablation,
                export_markdown=args.export_markdown,
                export_latex=args.export_latex,
                export_csv=getattr(args, "export_csv", None),
            )
        )
    elif args.subcommand == "review":
        sys.exit(
            review_directory(
                args.path,
                apply_changes=args.apply,
                non_interactive=args.non_interactive,
                export_json=args.export_json,
            )
        )
    elif args.subcommand == "serve":
        from regradar.api.server import run_server
        from regradar.config import get_config
        import os
        if getattr(args, "workspace", None):
            os.environ["REGRADAR_WORKSPACE"] = str(Path(args.workspace).resolve())
        if getattr(args, "provider", None):
            os.environ["REGRADAR_LLM_PROVIDER"] = args.provider.lower()
        cfg = get_config()
        effective_host = args.host if args.host is not None else cfg.server.host
        effective_port = args.port if args.port is not None else cfg.server.port
        console.print(f"[bold cyan]Launching RegRadar Web Studio at:[/bold cyan] http://{effective_host}:{effective_port}")
        run_server(host=args.host, port=args.port, reload=args.reload, config_path=getattr(args, "config_path", None))
        sys.exit(0)


if __name__ == "__main__":
    main()
