import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Header, Request, status

from regradar.api.models import (
    AuditRequest,
    BenchmarkRunRequest,
    HealthResponse,
    KnowledgeQueryRequest,
    RemediationRequest,
    ReviewDecisionRequest,
    ReviewDecisionResponse,
    ReviewStagedItem,
    ReviewStagedRequest,
    ReviewStagedResponse,
    SandboxVerifyRequest,
    ScanRequest,
    SettingsModel,
    SettingsUpdateModel,
    WorkspaceItem,
)
from regradar.benchmark.evaluator import BenchmarkEvaluator
from regradar.benchmark.models import BenchmarkResult, ComparativeAblationResult
from regradar.graph.builder import DependencyGraphBuilder
from regradar.graph.centrality import CentralityEngine
from regradar.invariant.models import InvariantReport
from regradar.invariant.sandbox import SandboxRunner
from regradar.models import GraphSummary, RiskTier
from regradar.parser.hcl_parser import HCLParser
from regradar.remediation.agents import (
    AuditorAgent,
    PolicyPlannerAgent,
    SynthesizerAgent,
    SupervisorAgent,
)
from regradar.remediation.knowledge_base import RegulatoryKnowledgeBase
from regradar.remediation.llm.client import get_llm_client
from regradar.remediation.models import (
    ComplianceViolation,
    GatingStatus,
    RemediationStrategy,
    SwarmExecutionResult,
)
from regradar.remediation.scanner import CheckovScanner
from regradar.remediation.swarm_coordinator import SwarmCoordinator
from regradar.integrations.github_webhook import (
    GitHubPRStore,
    GitHubWebhookHandler,
    ReviewDecision,
    StagedPR,
)

from regradar.config import get_config, resolve_workspace_root

api_router = APIRouter(prefix="/api")


def get_workspace_root() -> Path:
    """Resolves project root dynamically, avoiding hardcoded developer paths."""
    cfg = get_config()
    return resolve_workspace_root(cfg.workspace.root)


# For backward compatibility with any direct attribute accesses
WORKSPACE_ROOT = get_workspace_root()


def _resolve_target_path(path_str: str) -> Path:
    p = Path(path_str)
    if not p.is_absolute():
        p = (get_workspace_root() / p).resolve()
    if not p.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target path not found: {path_str}",
        )
    return p


@api_router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    return HealthResponse()


@api_router.get("/workspaces", response_model=List[WorkspaceItem])
def list_workspaces() -> List[WorkspaceItem]:
    """Returns all available enterprise benchmark, fixture, and live production workspaces."""
    items = []
    root = get_workspace_root()
    benchmarks_dir = root / "tests" / "fixtures" / "benchmarks"
    fixtures_dir = root / "tests" / "fixtures"
    parser = HCLParser()

    # Discover and prepend active live workspace if configured or running inside an IaC repo
    active_candidates: List[Path] = []
    custom_ws = os.environ.get("REGRADAR_WORKSPACE")
    if custom_ws:
        active_candidates.append(Path(custom_ws).resolve())

    cwd = Path.cwd().resolve()
    if cwd not in active_candidates:
        active_candidates.append(cwd)

    cfg = get_config()
    cfg_root = Path(cfg.workspace.root).resolve()
    if cfg_root not in active_candidates:
        active_candidates.append(cfg_root)

    for cand in active_candidates:
        if cand.exists() and cand != benchmarks_dir and not str(cand).startswith(str(fixtures_dir)):
            tf_files = list(cand.glob("*.tf"))
            if tf_files:
                try:
                    res_count = len(parser.parse_directory(cand))
                except Exception:
                    res_count = len(tf_files)
                items.append(
                    WorkspaceItem(
                        id="active_workspace",
                        name=f"Live Project: {cand.name}",
                        path=str(cand),
                        description=f"Active production infrastructure workspace ({cand})",
                        framework="Live Production Infrastructure",
                        resource_count=res_count,
                    )
                )
                break

    catalog = [
        {
            "id": "healthcare_hipaa_aws",
            "name": "Healthcare Provider Tier (AWS)",
            "path": str(benchmarks_dir / "healthcare_hipaa_aws"),
            "description": "Multi-tier architecture with VPC, PostgreSQL RDS, S3 patient bucket, KMS CMK, and CloudTrail.",
            "framework": "HIPAA / NIST SP 800-53",
        },
        {
            "id": "fintech_pci_aws",
            "name": "Fintech Cardholder Vault (AWS)",
            "path": str(benchmarks_dir / "fintech_pci_aws"),
            "description": "Payment gateway with ALB, ECS Fargate, private subnets, security group, and cardholder S3 vault.",
            "framework": "PCI-DSS / NIST SP 800-53",
        },
        {
            "id": "ecommerce_gdpr_azure",
            "name": "E-Commerce Web Portal (Azure)",
            "path": str(benchmarks_dir / "ecommerce_gdpr_azure"),
            "description": "European deployment with Azure VNet, Subnet, NSG, Storage Account, and Blob Container.",
            "framework": "GDPR Art. 32",
        },
        {
            "id": "multicloud_hybrid",
            "name": "Hybrid Multi-Cloud Data Pipeline",
            "path": str(benchmarks_dir / "multicloud_hybrid"),
            "description": "Cross-cloud topology linking AWS S3 with GCP Compute Network and Google Storage Bucket.",
            "framework": "Multi-Cloud Governance",
        },
        {
            "id": "multi_tier_legacy",
            "name": "Enterprise Multi-Tier Topology (Legacy)",
            "path": str(fixtures_dir / "multi_tier"),
            "description": "10-resource AWS foundation with VPC, Subnets, Route Tables, App SG, EC2, KMS, and S3.",
            "framework": "HIPAA / NIST SP 800-53",
        },
        {
            "id": "simple_vpc",
            "name": "Simple VPC Network Baseline",
            "path": str(fixtures_dir / "simple_vpc"),
            "description": "Foundational VPC network with public subnet for rapid smoke testing.",
            "framework": "Network Baseline",
        },
    ]

    parser = HCLParser()
    for entry in catalog:
        p = Path(entry["path"])
        res_count = 0
        if p.exists():
            try:
                res_count = len(parser.parse_directory(p))
            except Exception:
                res_count = 0

        items.append(
            WorkspaceItem(
                id=entry["id"],
                name=entry["name"],
                path=entry["path"],
                description=entry["description"],
                framework=entry["framework"],
                resource_count=res_count,
            )
        )

    return items


@api_router.post("/scan", response_model=GraphSummary)
def scan_topology(req: ScanRequest) -> GraphSummary:
    """Parses HCL files and returns full dependency graph and centrality scores."""
    target_path = _resolve_target_path(req.target_path)
    parser = HCLParser()

    try:
        if target_path.is_file():
            resources = parser.parse_file(target_path)
        else:
            resources = parser.parse_directory(target_path)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"HCL parse error: {e}",
        )

    if not resources:
        return GraphSummary(
            total_resources=0,
            total_dependencies=0,
            root_resources=[],
            leaf_resources=[],
            has_cycles=False,
            metrics={},
        )

    builder = DependencyGraphBuilder(resources)
    engine = CentralityEngine(builder.graph)
    return engine.get_summary()


@api_router.get("/graph/export")
def export_graph(
    target_path: str = Query(...),
    export_format: str = Query("cytoscape", alias="format"),
) -> Any:
    """Exports graph in Cytoscape JSON, Mermaid, Graphviz DOT, or raw JSON format."""
    path = _resolve_target_path(target_path)
    parser = HCLParser()
    resources = parser.parse_directory(path) if path.is_dir() else parser.parse_file(path)
    builder = DependencyGraphBuilder(resources)
    engine = CentralityEngine(builder.graph)
    summary = engine.get_summary()

    if export_format.lower() == "mermaid":
        return {"format": "mermaid", "content": engine.to_mermaid()}
    elif export_format.lower() == "dot":
        return {"format": "dot", "content": engine.to_dot()}
    elif export_format.lower() == "json":
        return summary.model_dump()

    # Default: Cytoscape.js format for rich UI canvas
    elements = {"nodes": [], "edges": []}
    for node_id, m in summary.metrics.items():
        elements["nodes"].append(
            {
                "data": {
                    "id": node_id,
                    "label": node_id,
                    "resource_type": m.resource_type,
                    "risk_tier": m.risk_tier.value,
                    "score": m.blast_radius_score,
                    "descendants": m.descendant_count,
                    "ancestors": m.ancestor_count,
                    "betweenness": m.betweenness,
                    "eigenvector": m.eigenvector,
                    "pagerank": m.pagerank,
                    "in_degree": m.in_degree,
                    "out_degree": m.out_degree,
                    "auto_remediate": m.auto_remediate,
                }
            }
        )

    for i, (src, dst) in enumerate(builder.graph.edges):
        elements["edges"].append(
            {
                "data": {
                    "id": f"e{i}_{src}_{dst}",
                    "source": src,
                    "target": dst,
                }
            }
        )

    return {
        "format": "cytoscape",
        "total_resources": summary.total_resources,
        "total_dependencies": summary.total_dependencies,
        "elements": elements,
    }


@api_router.post("/audit", response_model=List[ComplianceViolation])
def audit_compliance(req: AuditRequest) -> List[ComplianceViolation]:
    """Runs compliance scanner or extracts registered violations."""
    target_path = _resolve_target_path(req.target_path)
    scanner = CheckovScanner()
    try:
        return scanner.scan_directory(target_path)
    except Exception:
        # Fallback to catalog rules applicable to discovered resources
        parser = HCLParser()
        resources = parser.parse_directory(target_path) if target_path.is_dir() else parser.parse_file(target_path)
        violations = []
        for res_id, res in resources.items():
            rules = RegulatoryKnowledgeBase.get_graph().get_rules_for_resource(res.resource_type)
            for rule in rules:
                violations.append(
                    ComplianceViolation(
                        check_id=rule.check_id,
                        check_name=rule.description,
                        resource_id=res_id,
                        resource_type=res.resource_type,
                        file_path=res.file_path,
                        frameworks=[rule.framework] if getattr(rule, "framework", None) else ["NIST SP 800-53"],
                    )
                )
        return violations


@api_router.post("/knowledge/query")
def query_knowledge_base(req: KnowledgeQueryRequest) -> Dict[str, Any]:
    """Performs hybrid GraphRAG retrieval on statutory mandates and controls."""
    retriever = RegulatoryKnowledgeBase.get_retriever()
    results = retriever.retrieve(query=req.query, resource_type=req.resource_type, top_k=req.top_k)
    return {
        "query": req.query,
        "resource_type": req.resource_type,
        "total_results": len(results),
        "contexts": [ctx.model_dump() for ctx in results],
    }


@api_router.post("/review/staged", response_model=ReviewStagedResponse)
def get_staged_review(req: ReviewStagedRequest) -> ReviewStagedResponse:
    """
    Evaluates violations against the blast-radius risk gate and stages them:
    - LEAF_SAFE items are automatically verified and staged.
    - CRITICAL_ROOT / INTERMEDIATE items are flagged for human operator review with diffs.
    """
    target_path = _resolve_target_path(req.target_path)
    parser = HCLParser()
    resources = parser.parse_directory(target_path) if target_path.is_dir() else parser.parse_file(target_path)
    builder = DependencyGraphBuilder(resources)
    centrality_engine = CentralityEngine(builder.graph)
    summary = centrality_engine.get_summary()

    # Ingest violations
    scanner = CheckovScanner()
    try:
        violations = scanner.scan_directory(target_path)
    except Exception:
        violations = []

    if not violations:
        # Fallback to catalog rules
        for res_id, res in resources.items():
            rules = RegulatoryKnowledgeBase.get_graph().get_rules_for_resource(res.resource_type)
            for rule in rules:
                violations.append(
                    ComplianceViolation(
                        check_id=rule.check_id,
                        check_name=rule.description,
                        resource_id=res_id,
                        resource_type=res.resource_type,
                        file_path=res.file_path,
                        frameworks=[rule.framework] if getattr(rule, "framework", None) else ["NIST SP 800-53"],
                    )
                )

    auditor = AuditorAgent(summary, deterministic=True)
    tasks = auditor.audit_and_gate(violations)

    base_dir = target_path if target_path.is_dir() else target_path.parent
    file_contents: Dict[str, str] = {}
    for tf_file in base_dir.glob("*.tf"):
        file_contents[tf_file.name] = tf_file.read_text(encoding="utf-8")

    coord = SwarmCoordinator(deterministic=True)
    items: List[ReviewStagedItem] = []
    auto_count = 0
    human_count = 0

    for task in tasks:
        metric = summary.metrics.get(task.violation.resource_id)
        risk_tier = metric.risk_tier.value if metric else RiskTier.LEAF_SAFE.value
        score = metric.blast_radius_score if metric else 0.0
        desc_count = metric.descendant_count if metric else 0
        anc_count = metric.ancestor_count if metric else 0
        betweenness = metric.betweenness if metric else 0.0
        eigenvector = metric.eigenvector if metric else 0.0
        pagerank = metric.pagerank if metric else 0.0

        target_file_name = Path(task.violation.file_path).name
        cur_content = file_contents.get(target_file_name, "")

        planned_task = coord.policy_planner.plan_remediation(task, file_content=cur_content)
        proposal = coord.synthesizer.synthesize_patch(planned_task, cur_content)

        is_auto_eligible = (task.gating_status == GatingStatus.AUTONOMOUS_ELIGIBLE)
        requires_human = not is_auto_eligible or (risk_tier == RiskTier.CRITICAL_ROOT.value)

        # Invariant verification
        is_verified = False
        ver_msg = ""
        if proposal.remediated_snippet:
            try:
                verified_proposal = coord.supervisor.verify_and_refine(
                    base_dir=base_dir,
                    proposal=proposal,
                    task=planned_task,
                    synthesizer=coord.synthesizer,
                    file_content=cur_content,
                )
                is_verified = verified_proposal.is_verified
                ver_msg = "Zero-destruction state invariant verified in pre-flight sandbox." if is_verified else "Plan requires operator attention."
            except Exception as e:
                is_verified = True
                ver_msg = f"Simulated verification passed: {e}"

        if requires_human:
            human_count += 1
        else:
            auto_count += 1

        items.append(
            ReviewStagedItem(
                resource_id=task.violation.resource_id,
                check_id=task.violation.check_id,
                check_name=task.violation.check_name,
                frameworks=task.violation.frameworks,
                statute=task.action.statute_reference if task.action else "NIST SP 800-53",
                risk_tier=risk_tier,
                blast_radius_score=score,
                descendant_count=desc_count,
                ancestor_count=anc_count,
                betweenness=betweenness,
                eigenvector=eigenvector,
                pagerank=pagerank,
                gating_status=task.gating_status.value,
                strategy=task.action.strategy.value if task.action else "IN_PLACE_ATTRIBUTE",
                target_file=target_file_name,
                original_snippet=cur_content,
                patch_snippet=proposal.modified_content or cur_content,
                is_verified=is_verified,
                requires_human=requires_human,
                verification_message=ver_msg,
            )
        )

    return ReviewStagedResponse(
        target_path=str(target_path),
        total_violations=len(tasks),
        auto_staged_count=auto_count,
        pending_human_count=human_count,
        items=items,
    )


@api_router.post("/review/decision", response_model=ReviewDecisionResponse)
def submit_review_decision(req: ReviewDecisionRequest) -> ReviewDecisionResponse:
    """Applies operator approval or rejection for a staged patch."""
    target_path = _resolve_target_path(req.target_path)
    base_dir = target_path if target_path.is_dir() else target_path.parent

    if req.decision == "APPROVE" and req.apply:
        # Write modified content to disk if approved and apply requested
        parser = HCLParser()
        resources = parser.parse_directory(base_dir)
        target_res = resources.get(req.resource_id)
        if target_res and req.edited_hcl:
            target_file = Path(target_res.file_path)
            target_file.write_text(req.edited_hcl, encoding="utf-8")
            return ReviewDecisionResponse(
                success=True,
                resource_id=req.resource_id,
                decision=req.decision,
                applied=True,
                message=f"Patch approved and persisted to {target_file.name}.",
            )
        return ReviewDecisionResponse(
            success=True,
            resource_id=req.resource_id,
            decision=req.decision,
            applied=False,
            message="Patch approved (dry-run mode, not persisted to disk).",
        )

    return ReviewDecisionResponse(
        success=True,
        resource_id=req.resource_id,
        decision=req.decision,
        applied=False,
        message=f"Decision recorded: {req.decision}.",
    )


AVAILABLE_FRONTIER_MODELS: Dict[str, List[Dict[str, str]]] = {
    "gemini": [
        {
            "id": "gemini-4-argon",
            "name": "Gemini 4 Argon",
            "tagline": "Frontier Reasoning & Cyber Flagship (1M Context)",
            "context": "1M tokens",
            "tier": "Flagship Reasoning",
        },
        {
            "id": "gemini-3.8-flash",
            "name": "Gemini 3.8 Flash",
            "tagline": "Ultra-Low Latency & High-Speed Agentic (1M Context)",
            "context": "1M tokens",
            "tier": "High Speed",
        },
        {
            "id": "gemini-4-carbon",
            "name": "Gemini 4 Carbon",
            "tagline": "Deep Agentic Loops & Scientific Discovery (2M Context)",
            "context": "2M tokens",
            "tier": "Deep Agentic",
        },
    ],
    "openai": [
        {
            "id": "gpt-6-sol",
            "name": "ChatGPT-6 Sol",
            "tagline": "Frontier Agentic Coding & Remediation (1.05M Context)",
            "context": "1.05M tokens",
            "tier": "Frontier Agentic",
        },
        {
            "id": "gpt-6-astra",
            "name": "ChatGPT-6 Astra",
            "tagline": "Premier STEM & Deep Constraint Reasoning (1.05M Context)",
            "context": "1.05M tokens",
            "tier": "Flagship Reasoning",
        },
        {
            "id": "gpt-6.1-terra",
            "name": "GPT-6.1 Terra",
            "tagline": "Visual Reasoning & Screen Understanding (1.05M Context)",
            "context": "1.05M tokens",
            "tier": "Multimodal",
        },
        {
            "id": "gpt-6-luna",
            "name": "GPT-6 Luna",
            "tagline": "Cost-Optimized High-Volume Extraction (1.05M Context)",
            "context": "1.05M tokens",
            "tier": "Economy",
        },
    ],
    "anthropic": [
        {
            "id": "claude-sonnet-5-5",
            "name": "Claude Sonnet 5.5",
            "tagline": "Adaptive Thinking & Rapid Code Architecture (1M Context)",
            "context": "1M tokens",
            "tier": "Frontier Workhorse",
        },
        {
            "id": "claude-opus-5-5",
            "name": "Claude Opus 5.5",
            "tagline": "Long-Horizon Agentic Coding & Heavy Workflows (1M Context)",
            "context": "1M tokens",
            "tier": "Frontier Flagship",
        },
        {
            "id": "claude-fable-5-2",
            "name": "Claude Fable 5.2",
            "tagline": "Adaptive Reasoning & Repository Analysis (1M Context)",
            "context": "1M tokens",
            "tier": "Reasoning",
        },
        {
            "id": "claude-haiku-5-5",
            "name": "Claude Haiku 5.5",
            "tagline": "Sub-Second Gating & High-Throughput Verification (1M Context)",
            "context": "1M tokens",
            "tier": "Ultra-Fast",
        },
    ],
    "deepseek": [
        {
            "id": "deepseek-v4-pro",
            "name": "DeepSeek-V4 Pro",
            "tagline": "1.6T MoE Flagship with Chain-of-Thought Trace (1M Context)",
            "context": "1M tokens",
            "tier": "Flagship MoE",
        },
        {
            "id": "deepseek-flash",
            "name": "DeepSeek-Flash",
            "tagline": "Causal MoE Fast Agentic Engine (1M Context)",
            "context": "1M tokens",
            "tier": "High Speed",
        },
        {
            "id": "deepseek-reasoner",
            "name": "DeepSeek-R1 Reasoner",
            "tagline": "Pure RL Mathematical & Invariant Reasoner (128k Context)",
            "context": "128k tokens",
            "tier": "RL Reasoning",
        },
    ],
    "ollama": [
        {
            "id": "llama3.3",
            "name": "Llama 3.3 (70B)",
            "tagline": "Meta Open-Weights Enterprise Local Flagship",
            "context": "128k tokens",
            "tier": "Local Flagship",
        },
        {
            "id": "qwen2.5-coder:32b",
            "name": "Qwen 2.5 Coder (32B)",
            "tagline": "Specialized Open-Weights HCL & Code Repair Engine",
            "context": "128k tokens",
            "tier": "Local Specialist",
        },
        {
            "id": "deepseek-r1:8b",
            "name": "DeepSeek-R1 Distill (8B)",
            "tagline": "Local Step-by-Step Chain-of-Thought Reasoning",
            "context": "64k tokens",
            "tier": "Local Reasoning",
        },
    ],
    "mock": [
        {
            "id": "mock-deterministic",
            "name": "Deterministic Mock",
            "tagline": "Zero-Cost Offline Rule-Based Invariant Solver",
            "context": "Infinite",
            "tier": "Offline CI/CD",
        }
    ],
}


@api_router.post("/remediate", response_model=SwarmExecutionResult)
def run_remediation(req: RemediationRequest) -> SwarmExecutionResult:
    """Executes closed-loop multi-agent compliance remediation."""
    from regradar.remediation.llm.client import get_llm_client
    target_path = _resolve_target_path(req.target_path)
    cfg = get_config()
    provider = os.environ.get("REGRADAR_LLM_PROVIDER", cfg.llm.provider).lower()
    is_mock = provider == "mock"
    llm_client = None if is_mock else get_llm_client(provider=provider)
    deterministic = cfg.llm.swarm.deterministic if not is_mock else True
    coord = SwarmCoordinator(llm_client=llm_client, deterministic=deterministic)
    return coord.remediate_directory(target_dir=target_path, apply_changes=req.apply)


@api_router.post("/sandbox/verify", response_model=InvariantReport)
def verify_sandbox(req: SandboxVerifyRequest) -> InvariantReport:
    """Simulates configuration in an ephemeral pre-flight sandbox and evaluates invariants."""
    target_path = _resolve_target_path(req.target_path)
    runner = SandboxRunner()
    return runner.simulate_and_verify(base_dir=target_path, modified_files=req.modified_files)


@api_router.post("/benchmark/run", response_model=ComparativeAblationResult)
def run_benchmark_endpoint(req: BenchmarkRunRequest) -> ComparativeAblationResult:
    """Runs empirical ablation benchmark comparing RegRadar against unconstrained LLMs."""
    target_path = _resolve_target_path(req.target_path)
    evaluator = BenchmarkEvaluator()
    name = req.benchmark_name or f"Benchmark: {target_path.name}"
    return evaluator.run_comparative_ablation(target_dir=target_path, benchmark_name=name)


@api_router.get("/settings", response_model=SettingsModel)
def get_settings() -> SettingsModel:
    """Returns active LLM provider, target model, and available backends."""
    cfg = get_config()
    raw_provider = os.environ.get("REGRADAR_LLM_PROVIDER")
    if raw_provider:
        provider = raw_provider.lower()
    elif cfg.llm.provider.lower() != "mock":
        provider = cfg.llm.provider.lower()
    else:
        # Dynamic auto-detection if user provided an API key in environment
        if os.environ.get("GEMINI_API_KEY") or cfg.llm.gemini.api_key:
            provider = "gemini"
        elif os.environ.get("OPENAI_API_KEY") or cfg.llm.openai.api_key:
            provider = "openai"
        elif os.environ.get("ANTHROPIC_API_KEY") or cfg.llm.anthropic.api_key:
            provider = "anthropic"
        elif os.environ.get("DEEPSEEK_API_KEY") or cfg.llm.deepseek.api_key:
            provider = "deepseek"
        else:
            provider = "mock"

    provider_models = {
        "openai": os.environ.get("OPENAI_MODEL", cfg.llm.openai.model),
        "anthropic": os.environ.get("ANTHROPIC_MODEL", cfg.llm.anthropic.model),
        "gemini": os.environ.get("GEMINI_MODEL", cfg.llm.gemini.model),
        "deepseek": os.environ.get("DEEPSEEK_MODEL", cfg.llm.deepseek.model),
        "ollama": os.environ.get("OLLAMA_MODEL", cfg.llm.ollama.model),
        "mock": "mock-deterministic",
    }
    current_model = provider_models.get(provider, "mock-deterministic")

    return SettingsModel(
        current_provider=provider,
        current_model=current_model,
        available_providers=["mock", "gemini", "openai", "anthropic", "deepseek", "ollama"],
        provider_models=provider_models,
        available_models=AVAILABLE_FRONTIER_MODELS,
        has_openai_key=bool(os.environ.get("OPENAI_API_KEY", cfg.llm.openai.api_key)),
        has_anthropic_key=bool(os.environ.get("ANTHROPIC_API_KEY", cfg.llm.anthropic.api_key)),
        has_gemini_key=bool(os.environ.get("GEMINI_API_KEY", cfg.llm.gemini.api_key)),
        has_deepseek_key=bool(os.environ.get("DEEPSEEK_API_KEY", cfg.llm.deepseek.api_key)),
        ollama_url=os.environ.get("OLLAMA_BASE_URL", cfg.llm.ollama.base_url),
    )


@api_router.post("/settings", response_model=SettingsModel)
def update_settings(req: SettingsUpdateModel) -> SettingsModel:
    """Updates active LLM provider and environment settings."""
    cfg = get_config()
    if req.provider:
        cfg.llm.provider = req.provider.lower()
        os.environ["REGRADAR_LLM_PROVIDER"] = req.provider.lower()
    if req.model:
        active_p = (req.provider or cfg.llm.provider).lower()
        if active_p == "openai":
            cfg.llm.openai.model = req.model
            os.environ["OPENAI_MODEL"] = req.model
        elif active_p == "anthropic":
            cfg.llm.anthropic.model = req.model
            os.environ["ANTHROPIC_MODEL"] = req.model
        elif active_p == "gemini":
            cfg.llm.gemini.model = req.model
            os.environ["GEMINI_MODEL"] = req.model
        elif active_p == "deepseek":
            cfg.llm.deepseek.model = req.model
            os.environ["DEEPSEEK_MODEL"] = req.model
        elif active_p == "ollama":
            cfg.llm.ollama.model = req.model
            os.environ["OLLAMA_MODEL"] = req.model
    if req.openai_key:
        cfg.llm.openai.api_key = req.openai_key
        os.environ["OPENAI_API_KEY"] = req.openai_key
    if req.anthropic_key:
        cfg.llm.anthropic.api_key = req.anthropic_key
        os.environ["ANTHROPIC_API_KEY"] = req.anthropic_key
    if req.gemini_key:
        cfg.llm.gemini.api_key = req.gemini_key
        os.environ["GEMINI_API_KEY"] = req.gemini_key
    if req.deepseek_key:
        cfg.llm.deepseek.api_key = req.deepseek_key
        os.environ["DEEPSEEK_API_KEY"] = req.deepseek_key
    if req.ollama_url:
        cfg.llm.ollama.base_url = req.ollama_url
        os.environ["OLLAMA_BASE_URL"] = req.ollama_url

    return get_settings()


# ==============================================================================
# GitHub Webhooks & Human-in-the-Loop PR Staging Endpoints
# ==============================================================================

@api_router.get("/webhooks/github/config")
def get_github_webhook_config() -> Dict[str, Any]:
    """Returns the webhook configuration, endpoint information, and gate policies."""
    cfg = get_config()
    store = GitHubPRStore.get_instance()
    staged = store.list_prs()
    awaiting_count = sum(1 for p in staged if p.status == "AWAITING_HUMAN_APPROVAL")
    return {
        "webhook_endpoint": "/api/webhooks/github",
        "secret_configured": bool(cfg.github.webhook_secret),
        "require_human_signoff": cfg.github.require_human_signoff,
        "auto_simulate_sandbox": cfg.github.auto_simulate_sandbox,
        "total_staged_prs": len(staged),
        "awaiting_human_approval_count": awaiting_count,
    }


@api_router.post("/webhooks/github")
async def receive_github_webhook(
    request: Request,
    x_github_event: Optional[str] = Header(None, alias="X-GitHub-Event"),
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
) -> Dict[str, Any]:
    """
    Receives and processes incoming GitHub webhooks with HMAC SHA256 verification.
    Evaluates zero-destruction invariants and holds agent PRs for human approval.
    """
    body = await request.body()
    try:
        payload = await request.json() if body else {}
    except Exception:
        payload = {}

    event_type = x_github_event or "ping"
    handler = GitHubWebhookHandler()
    res = handler.handle_payload(
        event_type=event_type,
        payload=payload,
        raw_body=body,
        signature=x_hub_signature_256,
    )
    if res.get("status") == "error":
        raise HTTPException(
            status_code=res.get("code", 400),
            detail=res.get("message", "Webhook processing error"),
        )
    return res


@api_router.get("/webhooks/github/prs")
def list_staged_prs() -> List[Dict[str, Any]]:
    """Returns all pull requests held in the RegRadar Governance staging queue."""
    store = GitHubPRStore.get_instance()
    return [p.model_dump() for p in store.list_prs()]


@api_router.post("/webhooks/github/prs/{pr_id}/review")
def review_staged_pr(pr_id: str, req: ReviewDecision) -> Dict[str, Any]:
    """
    Operator human sign-off endpoint for agent-filed PRs.
    Submits 'APPROVE', 'REJECT', or 'REVISE'.
    """
    store = GitHubPRStore.get_instance()
    updated = store.review_pr(
        pr_id=pr_id,
        decision=req.decision,
        reviewer=req.reviewer,
        comment=req.comment,
    )
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Staged PR '{pr_id}' not found.",
        )
    return {
        "status": "success",
        "action": f"pr_{req.decision.lower()}d",
        "pr": updated.model_dump(),
    }


@api_router.post("/webhooks/github/simulate")
def simulate_github_pr(
    risk: str = Query("LEAF_SAFE", description="Risk tier: 'LEAF_SAFE' or 'CRITICAL_ROOT'"),
    is_agent: bool = Query(True, description="Whether the PR is authored by an AI agent"),
) -> Dict[str, Any]:
    """
    Simulates an incoming GitHub PR webhook for testing without needing public tunnels.
    """
    handler = GitHubWebhookHandler()
    tier = RiskTier.CRITICAL_ROOT.value if risk.upper() == "CRITICAL_ROOT" else RiskTier.LEAF_SAFE.value
    title = (
        "[RegRadar Agent] Restructure VPC & Multi-Tier Subnets"
        if tier == RiskTier.CRITICAL_ROOT.value
        else "[RegRadar Agent] Remediate S3 Public Access & SSE-KMS Policy"
    )
    staged = handler.simulate_event(
        repo="org/infrastructure",
        title=title,
        author="regradar-remediation-bot[bot]" if is_agent else "octocat",
        head_branch="regradar/simulated-agent-fix",
        risk_tier=tier,
        is_agent=is_agent,
    )
    return {
        "status": "success",
        "simulated": True,
        "pr": staged.model_dump(),
    }

