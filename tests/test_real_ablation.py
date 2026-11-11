from pathlib import Path
import pytest

from regradar.benchmark.baselines import UnconstrainedBaseline
from regradar.benchmark.evaluator import BenchmarkEvaluator
from regradar.benchmark.models import (
    BenchmarkMetrics,
    ComparativeAblationResult,
    CorpusBenchmarkResult,
)
from regradar.benchmark.report_generator import ReportGenerator
from regradar.cli import run_benchmark
from regradar.graph.builder import DependencyGraphBuilder
from regradar.graph.centrality import CentralityEngine
from regradar.models import RiskTier
from regradar.parser.hcl_parser import HCLParser
from regradar.remediation.llm.client import MockLLMClient
from regradar.remediation.scanner import CheckovScanner


@pytest.fixture
def benchmarks_dir() -> Path:
    return Path(__file__).parent / "fixtures" / "benchmarks"


# ---------------------------------------------------------------------------
# 1. Benchmark Corpus Fixture Verification
# ---------------------------------------------------------------------------

def test_benchmark_fixtures_exist_and_parse(benchmarks_dir: Path):
    """Verifies that all 4 enterprise benchmark architectures exist and parse cleanly."""
    expected_suites = [
        "healthcare_hipaa_aws",
        "fintech_pci_aws",
        "ecommerce_gdpr_azure",
        "multicloud_hybrid",
    ]

    for suite_name in expected_suites:
        suite_path = benchmarks_dir / suite_name
        assert suite_path.is_dir(), f"Suite directory missing: {suite_path}"
        main_tf = suite_path / "main.tf"
        assert main_tf.is_file(), f"main.tf missing in {suite_name}"

        parser = HCLParser()
        resources = parser.parse_directory(suite_path)
        assert len(resources) >= 4, f"Insufficient resources parsed for {suite_name}"


def test_statutory_violations_detected(benchmarks_dir: Path):
    """Verifies that CheckovScanner accurately detects all statutory compliance smells."""
    scanner = CheckovScanner()

    # 1. Healthcare HIPAA
    hipaa_violations = scanner.scan_directory(benchmarks_dir / "healthcare_hipaa_aws")
    hipaa_check_ids = {v.check_id for v in hipaa_violations}
    assert "CKV_AWS_19" in hipaa_check_ids  # S3 Unencrypted
    assert "CKV_AWS_16" in hipaa_check_ids  # RDS Storage Unencrypted
    assert "CKV_AWS_21" in hipaa_check_ids  # S3 Versioning Missing
    assert "CKV_AWS_36" in hipaa_check_ids  # CloudTrail KMS Missing
    assert "CKV_AWS_40" in hipaa_check_ids  # IAM Wildcard Admin

    # 2. FinTech PCI-DSS
    pci_violations = scanner.scan_directory(benchmarks_dir / "fintech_pci_aws")
    pci_check_ids = {v.check_id for v in pci_violations}
    assert "CKV_AWS_24" in pci_check_ids   # Open SSH port 22
    assert "CKV_AWS_135" in pci_check_ids  # EBS volume unencrypted
    assert "CKV_AWS_23" in pci_check_ids   # Missing SG description
    assert "CKV_AWS_145" in pci_check_ids  # S3 unencrypted with KMS

    # 3. E-Commerce GDPR
    gdpr_violations = scanner.scan_directory(benchmarks_dir / "ecommerce_gdpr_azure")
    gdpr_check_ids = {v.check_id for v in gdpr_violations}
    assert "CKV_AZURE_3" in gdpr_check_ids   # HTTP Allowed / Secure Transfer Disabled
    assert "CKV_AZURE_33" in gdpr_check_ids  # Public blob access
    assert "CKV_AZURE_44" in gdpr_check_ids  # Insecure TLS < 1.2
    assert "CKV_AZURE_9" in gdpr_check_ids   # Open inbound SSH 22

    # 4. Multi-Cloud Hybrid
    hybrid_violations = scanner.scan_directory(benchmarks_dir / "multicloud_hybrid")
    hybrid_check_ids = {v.check_id for v in hybrid_violations}
    assert "CKV_AWS_19" in hybrid_check_ids  # AWS S3 Unencrypted
    assert "CKV_AWS_21" in hybrid_check_ids  # AWS S3 Missing Versioning
    assert "CKV_GCP_2" in hybrid_check_ids   # GCP Firewall Open SSH 22
    assert "CKV_GCP_29" in hybrid_check_ids  # GCP Storage Non-Uniform Access


def test_graph_centrality_on_benchmark_corpus(benchmarks_dir: Path):
    """Verifies graph dependency builder and centrality engine identify critical foundational roots."""
    parser = HCLParser()

    # Healthcare HIPAA: aws_vpc.hipaa_vpc must be critical root
    res_hipaa = parser.parse_directory(benchmarks_dir / "healthcare_hipaa_aws")
    builder_hipaa = DependencyGraphBuilder(res_hipaa)
    engine_hipaa = CentralityEngine(builder_hipaa.graph)
    summary_hipaa = engine_hipaa.get_summary()
    assert "aws_vpc.hipaa_vpc" in summary_hipaa.metrics
    assert summary_hipaa.metrics["aws_vpc.hipaa_vpc"].risk_tier == RiskTier.CRITICAL_ROOT

    # FinTech PCI-DSS: aws_vpc.fintech_vpc must be critical root
    res_pci = parser.parse_directory(benchmarks_dir / "fintech_pci_aws")
    builder_pci = DependencyGraphBuilder(res_pci)
    engine_pci = CentralityEngine(builder_pci.graph)
    summary_pci = engine_pci.get_summary()
    assert "aws_vpc.fintech_vpc" in summary_pci.metrics
    assert summary_pci.metrics["aws_vpc.fintech_vpc"].risk_tier == RiskTier.CRITICAL_ROOT

    # E-Commerce Azure: azurerm_resource_group.rg_gdpr must be critical root
    res_azure = parser.parse_directory(benchmarks_dir / "ecommerce_gdpr_azure")
    builder_azure = DependencyGraphBuilder(res_azure)
    engine_azure = CentralityEngine(builder_azure.graph)
    summary_azure = engine_azure.get_summary()
    assert "azurerm_resource_group.rg_gdpr" in summary_azure.metrics
    assert summary_azure.metrics["azurerm_resource_group.rg_gdpr"].risk_tier == RiskTier.CRITICAL_ROOT


# ---------------------------------------------------------------------------
# 2. Empirical Ablation Engine & Unconstrained Baseline
# ---------------------------------------------------------------------------

def test_empirical_unconstrained_baseline_execution(benchmarks_dir: Path):
    """Tests realistic empirical prompt mutation execution using MockLLMClient."""
    scanner = CheckovScanner()
    hipaa_path = benchmarks_dir / "healthcare_hipaa_aws"
    violations = scanner.scan_directory(hipaa_path)

    # Use deterministic MockLLMClient
    mock_llm = MockLLMClient()
    metrics, destructive = UnconstrainedBaseline.evaluate(
        violations=violations,
        target_dir=hipaa_path,
        llm_client=mock_llm,
        execute_prompts=True,
    )

    assert metrics.initial_violations == len(violations)
    assert metrics.forced_replacements_triggered > 0
    assert metrics.gated_root_nodes_mutated > 0
    assert metrics.avoided_production_outages > 0
    assert metrics.invariant_preservation_rate < 100.0
    assert metrics.destructive_mutations_blocked == 0
    assert destructive == metrics.destructive_mutations_attempted


def test_evaluator_evaluate_corpus(benchmarks_dir: Path):
    """Tests BenchmarkEvaluator.evaluate_corpus across all 4 enterprise architectures."""
    evaluator = BenchmarkEvaluator()
    corpus_result = evaluator.evaluate_corpus(benchmarks_dir)

    assert isinstance(corpus_result, CorpusBenchmarkResult)
    assert len(corpus_result) == 4
    assert "healthcare_hipaa_aws" in corpus_result.results
    assert "fintech_pci_aws" in corpus_result.results
    assert "ecommerce_gdpr_azure" in corpus_result.results
    assert "multicloud_hybrid" in corpus_result.results

    # Neuro-Symbolic RegRadar guarantees 100% Invariant Preservation
    assert corpus_result.regradar_avg_invariant_preservation_rate == 100.0
    assert corpus_result.regradar_avg_remediation_rate > 0.0
    assert corpus_result.total_avoided_outages > 0
    assert corpus_result.total_destructive_prevented > 0
    assert corpus_result.total_gated_roots_protected > 0

    # Indexing and iterating support
    hipaa_res = corpus_result["healthcare_hipaa_aws"]
    assert isinstance(hipaa_res, ComparativeAblationResult)
    assert hipaa_res.regradar_metrics.invariant_preservation_rate == 100.0

    count = 0
    for name, ab in corpus_result:
        count += 1
        assert ab.regradar_metrics.invariant_preservation_rate == 100.0
    assert count == 4


# ---------------------------------------------------------------------------
# 3. Enhanced Exporters (CSV, LaTeX, Markdown)
# ---------------------------------------------------------------------------

def test_report_generator_csv_export(benchmarks_dir: Path, tmp_path: Path):
    """Tests CSV telemetry generation and direct file export."""
    evaluator = BenchmarkEvaluator()
    corpus_result = evaluator.evaluate_corpus(benchmarks_dir)

    csv_text = ReportGenerator.generate_csv_telemetry(corpus_result)
    assert "Benchmark Suite" in csv_text
    assert "Target Architecture" in csv_text
    assert "RegRadar (Neuro-Symbolic)" in csv_text
    assert "Unconstrained LLM Baseline" in csv_text
    assert "Forced Replacements Triggered" in csv_text
    assert "Avoided Production Outages" in csv_text

    # File export
    csv_file = tmp_path / "telemetry_corpus.csv"
    ReportGenerator.export_csv(corpus_result, csv_file)
    assert csv_file.exists()
    content = csv_file.read_text(encoding="utf-8")
    assert "Healthcare HIPAA Architecture (AWS)" in content
    assert "FinTech PCI-DSS Cardholder Architecture (AWS)" in content


def test_report_generator_latex_corpus_export(benchmarks_dir: Path, tmp_path: Path):
    """Tests publication-ready multi-suite comparative LaTeX table export."""
    evaluator = BenchmarkEvaluator()
    corpus_result = evaluator.evaluate_corpus(benchmarks_dir)

    latex_table = ReportGenerator.generate_latex_corpus_table(corpus_result)
    assert r"\begin{table*}" in latex_table
    assert r"\label{tab:regradar_corpus_ablation}" in latex_table
    assert r"\textbf{RegRadar (Ours)}" in latex_table
    assert "Unconstrained Baseline" in latex_table
    assert r"\end{table*}" in latex_table

    # Polymorphic generate_latex_table with corpus input
    poly_latex = ReportGenerator.generate_latex_table(corpus_result)
    assert r"\begin{table*}" in poly_latex


def test_report_generator_markdown_corpus_export(benchmarks_dir: Path):
    """Tests comprehensive GitHub-Flavored Markdown multi-suite report generation."""
    evaluator = BenchmarkEvaluator()
    corpus_result = evaluator.evaluate_corpus(benchmarks_dir)

    md_report = ReportGenerator.generate_corpus_markdown_report(corpus_result)
    assert "# RegRadar Multi-Tier Benchmark Corpus & Empirical Ablation Report" in md_report
    assert "## Executive Summary" in md_report
    assert "Healthcare HIPAA (AWS)" in md_report
    assert "FinTech PCI-DSS (AWS)" in md_report
    assert "E-Commerce GDPR (Azure)" in md_report
    assert "Multi-Cloud Hybrid (AWS & GCP)" in md_report
    assert "Zero-Destruction Invariant Guarantee" in md_report

    # Polymorphic generate_markdown_report with corpus input
    poly_md = ReportGenerator.generate_markdown_report(corpus_result)
    assert "# RegRadar Multi-Tier Benchmark Corpus & Empirical Ablation Report" in poly_md


def test_cli_corpus_benchmark_integration(benchmarks_dir: Path, tmp_path: Path):
    """Tests CLI execution of benchmark on the corpus directory with all exports."""
    md_file = tmp_path / "corpus_report.md"
    tex_file = tmp_path / "corpus_table.tex"
    csv_file = tmp_path / "corpus_telemetry.csv"

    ret = run_benchmark(
        target_dir=str(benchmarks_dir),
        include_ablation=True,
        export_markdown=str(md_file),
        export_latex=str(tex_file),
        export_csv=str(csv_file),
    )

    assert ret == 0
    assert md_file.exists()
    assert tex_file.exists()
    assert csv_file.exists()

    assert len(md_file.read_text(encoding="utf-8")) > 200
    assert len(tex_file.read_text(encoding="utf-8")) > 200
    assert len(csv_file.read_text(encoding="utf-8")) > 200
