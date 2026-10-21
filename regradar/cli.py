import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from regradar.parser.hcl_parser import HCLParser
from regradar.graph.builder import DependencyGraphBuilder
from regradar.graph.centrality import CentralityEngine
from regradar.models import RiskTier

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

    # Create Display Table
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

    # Sort descending by blast radius score
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


def main():
    parser = argparse.ArgumentParser(
        description="RegRadar: AST Parsing & Blast-Radius Engine for IaC"
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to Terraform directory or .tf file (default: current directory)",
    )
    parser.add_argument("--json", dest="export_json", help="Path to export JSON report")
    parser.add_argument(
        "--mermaid", dest="export_mermaid", help="Path to export Mermaid diagram"
    )
    parser.add_argument("--dot", dest="export_dot", help="Path to export Graphviz DOT")

    args = parser.parse_args()
    sys.exit(
        scan_directory(
            args.path,
            export_json=args.export_json,
            export_mermaid=args.export_mermaid,
            export_dot=args.export_dot,
        )
    )


if __name__ == "__main__":
    main()
