from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "1.0.0"
    engine: str = "RegRadar Neuro-Symbolic Governance"


class WorkspaceItem(BaseModel):
    id: str
    name: str
    path: str
    description: str
    framework: str
    resource_count: int


class ScanRequest(BaseModel):
    target_path: str


class AuditRequest(BaseModel):
    target_path: str


class KnowledgeQueryRequest(BaseModel):
    query: str
    resource_type: Optional[str] = None
    top_k: int = 5


class ReviewStagedRequest(BaseModel):
    target_path: str


class ReviewStagedItem(BaseModel):
    resource_id: str
    check_id: str
    check_name: str
    frameworks: List[str] = Field(default_factory=list)
    statute: str
    risk_tier: str
    blast_radius_score: float
    descendant_count: int
    ancestor_count: int
    betweenness: float = 0.0
    eigenvector: float = 0.0
    pagerank: float = 0.0
    gating_status: str
    strategy: str
    target_file: str
    original_snippet: str = ""
    patch_snippet: str = ""
    is_verified: bool = False
    requires_human: bool = False
    verification_message: str = ""


class ReviewStagedResponse(BaseModel):
    target_path: str
    total_violations: int
    auto_staged_count: int
    pending_human_count: int
    items: List[ReviewStagedItem] = Field(default_factory=list)


class ReviewDecisionRequest(BaseModel):
    target_path: str
    resource_id: str
    check_id: str
    decision: str  # "APPROVE", "REJECT", "SKIP"
    apply: bool = False
    edited_hcl: Optional[str] = None


class ReviewDecisionResponse(BaseModel):
    success: bool
    resource_id: str
    decision: str
    applied: bool
    message: str


class RemediationRequest(BaseModel):
    target_path: str
    apply: bool = False
    provider: Optional[str] = None


class SandboxVerifyRequest(BaseModel):
    target_path: str
    modified_files: Optional[Dict[str, str]] = None


class BenchmarkRunRequest(BaseModel):
    target_path: str
    benchmark_name: Optional[str] = None
    include_ablation: bool = True


class SettingsModel(BaseModel):
    current_provider: str
    current_model: str
    available_providers: List[str]
    provider_models: Dict[str, str] = Field(default_factory=dict)
    available_models: Dict[str, List[Dict[str, str]]] = Field(default_factory=dict)
    has_openai_key: bool
    has_anthropic_key: bool
    has_gemini_key: bool = False
    has_deepseek_key: bool = False
    ollama_url: str


class SettingsUpdateModel(BaseModel):
    provider: Optional[str] = None
    model: Optional[str] = None
    openai_key: Optional[str] = None
    anthropic_key: Optional[str] = None
    gemini_key: Optional[str] = None
    deepseek_key: Optional[str] = None
    ollama_url: Optional[str] = None
