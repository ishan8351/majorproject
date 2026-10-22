import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax

from regradar.parser.hcl_parser import HCLParser
from regradar.graph.builder import DependencyGraphBuilder
from regradar.graph.centrality import CentralityEngine
from regradar.models import RiskTier
from regradar.invariant.models import InvariantReport
from regradar.invariant.plan_parser import PlanParser
from regradar.invariant.invariant_engine import InvariantEngine
from regradar.invariant.sandbox import SandboxRunner
from regradar.remediation.models import GatingStatus, SwarmExecutionResult
from regradar.remediation.swarm_coordinator import SwarmCoordinator
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
) -> int:
    path = Path(target_dir).resolve()
    if not path.exists():
        console.print(f"[bold red]Target directory not found:[/bold red] {path}")
        return 1

    evaluator = BenchmarkEvaluator()
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

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="RegRadar: Autonomous, Zero-Destruction Compliance Remediation for IaC"
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

    args = parser.parse_args()

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
            )
        )


if __name__ == "__main__":
    main()
