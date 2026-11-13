"""
Centralized Configuration Engine for RegRadar.

Provides unified, hierarchical configuration management across:
  - Workspace roots and target IaC directories
  - Server, host, port, and CORS security policies
  - Graph centrality formulas, risk tier thresholds, and solver options
  - LLM providers, model specifications, endpoints, timeouts, and swarm retries
  - Dry-run sandbox binaries, cache directories, and cloud provider mock settings

Precedence:
  1. Explicit CLI / function arguments (highest)
  2. Environment variables (REGRADAR_*, OPENAI_*, etc.)
  3. Configuration file (regradar.json, regradar.toml, regradar.yaml)
  4. Built-in defaults (safe backwards-compatible defaults)
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field

try:
    import tomllib  # Python 3.11+ standard library
except ImportError:
    tomllib = None  # type: ignore

try:
    import yaml  # Optional PyYAML if installed
except ImportError:
    yaml = None  # type: ignore


# ==============================================================================
# Configuration Data Models
# ==============================================================================

class WorkspaceConfig(BaseModel):
    """Configuration for target workspaces, repositories, and fixture paths."""
    root: Optional[str] = Field(
        default=None,
        description="Root path of the workspace or repository. If None, resolved dynamically.",
    )
    scan_paths: List[str] = Field(
        default_factory=lambda: ["tests/fixtures/benchmarks", "tests/fixtures"],
        description="Relative or absolute directories searched for IaC benchmarks and fixtures.",
    )


class ServerConfig(BaseModel):
    """Configuration for the RegRadar Web Studio API server."""
    host: str = Field(default="127.0.0.1", description="Host interface to bind server.")
    port: int = Field(default=8000, description="Port for HTTP API server.")
    reload: bool = Field(default=False, description="Enable Uvicorn auto-reload for dev.")
    cors_origins: List[str] = Field(
        default_factory=lambda: ["*"],
        description="Allowed CORS origins list (e.g. ['http://localhost:8000']).",
    )


class CentralityWeights(BaseModel):
    """Relative weights in the composite blast-radius formula S(v)."""
    descendant_ratio: float = Field(default=0.40, description="Weight for cascading downstream blast radius.")
    betweenness: float = Field(default=0.25, description="Weight for betweenness centrality.")
    eigenvector: float = Field(default=0.20, description="Weight for eigenvector centrality.")
    out_degree_ratio: float = Field(default=0.15, description="Weight for direct downstream dependents.")


class CentralityThresholds(BaseModel):
    """Thresholds determining risk tier classifications."""
    critical_root_score: float = Field(
        default=0.40,
        description="Composite score threshold >= triggering CRITICAL_ROOT gating.",
    )
    critical_root_descendant_ratio: float = Field(
        default=0.35,
        description="Cascading descendant ratio threshold >= triggering CRITICAL_ROOT gating.",
    )
    intermediate_score: float = Field(
        default=0.15,
        description="Composite score threshold >= triggering INTERMEDIATE gating.",
    )


class CentralitySolver(BaseModel):
    """Parameters for numerical graph centrality solvers."""
    max_iter: int = Field(default=2000, description="Maximum iterations for eigenvector centrality.")
    tol: float = Field(default=1e-06, description="Convergence tolerance for eigenvector centrality.")


class CentralityConfig(BaseModel):
    """Graph-theoretic dependency and blast-radius configuration."""
    weights: CentralityWeights = Field(default_factory=CentralityWeights)
    thresholds: CentralityThresholds = Field(default_factory=CentralityThresholds)
    solver: CentralitySolver = Field(default_factory=CentralitySolver)


class OpenAIProviderConfig(BaseModel):
    """OpenAI API provider configuration (e.g., gpt-6-astra, gpt-6.1-sol, gpt-6-sol, gpt-6-luna, gpt-oss-120b, o3-mini, gpt-4o)."""
    model: str = Field(default="gpt-6-astra", description="Target OpenAI model name (e.g., gpt-6-astra, gpt-6.1-sol, gpt-6-sol, gpt-6-luna, gpt-oss-120b, o3-mini, gpt-4o).")
    base_url: str = Field(default="https://api.openai.com/v1", description="OpenAI API base URL.")
    timeout: float = Field(default=30.0, description="HTTP request timeout in seconds.")
    api_key: Optional[str] = Field(default=None, description="OpenAI API key (or from OPENAI_API_KEY).")


class AnthropicProviderConfig(BaseModel):
    """Anthropic API provider configuration (e.g., claude-fable-5-2, claude-opus-5-5, claude-sonnet-5-5, claude-haiku-5-5)."""
    model: str = Field(default="claude-sonnet-5-5", description="Target Anthropic model name (e.g., claude-fable-5-2, claude-opus-5-5, claude-sonnet-5-5, claude-haiku-5-5, claude-3-7-sonnet-20250219).")
    base_url: str = Field(default="https://api.anthropic.com/v1", description="Anthropic API base URL.")
    timeout: float = Field(default=30.0, description="HTTP request timeout in seconds.")
    version: str = Field(default="2023-06-01", description="Anthropic API protocol version header.")
    api_key: Optional[str] = Field(default=None, description="Anthropic API key (or from ANTHROPIC_API_KEY).")


class OllamaProviderConfig(BaseModel):
    """Local Ollama LLM provider configuration (e.g., qwen3-coder, qwen3.8, gpt-oss:20b, gpt-oss:120b, nemotron-3.5-lightning, llama3.3)."""
    model: str = Field(default="qwen3-coder", description="Target Ollama model name (e.g., qwen3-coder, qwen3.8, gpt-oss:20b, gpt-oss:120b, nemotron-3.5-lightning, llama3.3).")
    base_url: str = Field(default="http://localhost:11434", description="Ollama API base URL.")
    timeout: float = Field(default=60.0, description="HTTP request timeout in seconds.")


class GeminiProviderConfig(BaseModel):
    """Google Gemini API provider configuration (e.g., gemini-4-argon, gemini-4-carbon, gemini-4-hydrogen, gemini-3.8-flash, gemini-3.5-flash-lite)."""
    model: str = Field(default="gemini-4-argon", description="Target Gemini model name (e.g., gemini-4-argon, gemini-4-carbon, gemini-4-hydrogen, gemini-3.8-flash, gemini-3.5-flash-lite, gemini-2.5-pro, gemini-2.5-flash).")
    base_url: str = Field(
        default="https://generativelanguage.googleapis.com/v1beta",
        description="Google Generative Language API base URL.",
    )
    timeout: float = Field(default=30.0, description="HTTP request timeout in seconds.")
    api_key: Optional[str] = Field(default=None, description="Gemini API key (or from GEMINI_API_KEY).")


class DeepSeekProviderConfig(BaseModel):
    """DeepSeek API provider configuration (e.g., deepseek-v4-pro, deepseek-flash, deepseek-reasoner, deepseek-chat)."""
    model: str = Field(default="deepseek-v4-pro", description="Target DeepSeek model name (e.g., deepseek-v4-pro, deepseek-flash, deepseek-reasoner, deepseek-chat).")
    base_url: str = Field(default="https://api.deepseek.com", description="DeepSeek API base URL.")
    timeout: float = Field(default=30.0, description="HTTP request timeout in seconds.")
    api_key: Optional[str] = Field(default=None, description="DeepSeek API key (or from DEEPSEEK_API_KEY).")


class SwarmConfig(BaseModel):
    """Closed-loop multi-agent swarm orchestration settings."""
    max_retries: int = Field(default=3, description="Maximum sandbox diagnostic refinement iterations.")
    temperature: float = Field(default=0.0, description="LLM sampling temperature.")
    deterministic: bool = Field(default=False, description="Enforce deterministic knowledge-base synthesis.")


class LLMConfig(BaseModel):
    """LLM client and agent swarm configuration."""
    provider: str = Field(
        default="gemini",
        description="Active provider: 'gemini', 'openai', 'anthropic', 'deepseek', 'ollama'.",
    )
    openai: OpenAIProviderConfig = Field(default_factory=OpenAIProviderConfig)
    anthropic: AnthropicProviderConfig = Field(default_factory=AnthropicProviderConfig)
    gemini: GeminiProviderConfig = Field(default_factory=GeminiProviderConfig)
    deepseek: DeepSeekProviderConfig = Field(default_factory=DeepSeekProviderConfig)
    ollama: OllamaProviderConfig = Field(default_factory=OllamaProviderConfig)
    swarm: SwarmConfig = Field(default_factory=SwarmConfig)


class SandboxConfig(BaseModel):
    """Execution sandbox and mock cloud configuration."""
    binary_name: str = Field(default="tofu", description="Preferred IaC binary ('tofu' or 'terraform').")
    plugin_cache_dir: Optional[str] = Field(default=None, description="Custom Terraform/OpenTofu plugin cache path.")
    mock_aws_region: str = Field(default="us-east-1", description="Default mock AWS region.")
    mock_gcp_project: str = Field(default="mock-project", description="Default mock GCP project ID.")
    mock_gcp_region: str = Field(default="us-central1", description="Default mock GCP region.")
    offline_replacement_rules: Dict[str, List[str]] = Field(
        default_factory=lambda: {
            "aws_s3_bucket": ["bucket"],
            "aws_vpc": ["cidr_block"],
            "aws_db_instance": ["engine", "db_name", "name"],
        },
        description="Attributes that trigger forced replacements during offline AST simulations.",
    )


class GitHubConfig(BaseModel):
    """Configuration for GitHub Webhooks and Automated CI/CD Gating."""
    webhook_secret: str = Field(
        default="",
        description="HMAC SHA256 secret for validating incoming GitHub webhook payloads.",
    )
    github_token: Optional[str] = Field(
        default=None,
        description="GitHub personal access token or app token for dispatching review comments and merge actions.",
    )
    require_human_signoff: bool = Field(
        default=True,
        description="Require explicit operator sign-off in the Studio before agent PRs are merged or applied.",
    )
    auto_simulate_sandbox: bool = Field(
        default=True,
        description="Automatically trigger sandbox invariant simulation on incoming PR webhooks.",
    )
    default_branch: str = Field(
        default="main",
        description="Default target branch for pull requests.",
    )


class RegRadarConfig(BaseModel):
    """Root configuration model for RegRadar."""
    workspace: WorkspaceConfig = Field(default_factory=WorkspaceConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)
    centrality: CentralityConfig = Field(default_factory=CentralityConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    github: GitHubConfig = Field(default_factory=GitHubConfig)


# ==============================================================================
# Dynamic Workspace Root Resolver
# ==============================================================================

def resolve_workspace_root(candidate: Optional[Union[str, Path]] = None) -> Path:
    """
    Dynamically resolves the absolute project/workspace root directory.
    Eliminates all hardcoded developer paths (/home/ishan/...).

    Resolution order:
      1. Explicit candidate path if valid and existing
      2. REGRADAR_WORKSPACE_ROOT environment variable
      3. Current working directory (if contains 'regradar' package or 'requirements.txt')
      4. Parent directory containing the 'regradar' package
      5. Fallback to Path.cwd()
    """
    if candidate:
        p = Path(candidate).resolve()
        if p.exists():
            return p

    env_root = os.environ.get("REGRADAR_WORKSPACE_ROOT")
    if env_root:
        p = Path(env_root).resolve()
        if p.exists():
            return p

    cwd = Path.cwd().resolve()
    if (cwd / "regradar").exists() or (cwd / "requirements.txt").exists():
        return cwd

    pkg_root = Path(__file__).parent.parent.resolve()
    if (pkg_root / "regradar").exists():
        return pkg_root

    return cwd


# ==============================================================================
# Configuration Loader & Discoverer
# ==============================================================================

def find_config_file(custom_path: Optional[Union[str, Path]] = None) -> Optional[Path]:
    """
    Searches for a RegRadar configuration file.

    Supported formats:
      - JSON: regradar.json, .regradar.json
      - TOML: regradar.toml, .regradar.toml
      - YAML: regradar.yaml, regradar.yml (if pyyaml installed or JSON-compatible)
    """
    if custom_path:
        p = Path(custom_path).resolve()
        if p.is_file():
            return p
        raise FileNotFoundError(f"Specified configuration file not found: {custom_path}")

    env_path = os.environ.get("REGRADAR_CONFIG")
    if env_path:
        p = Path(env_path).resolve()
        if p.is_file():
            return p

    search_dir = resolve_workspace_root()
    candidate_names = [
        "regradar.json",
        ".regradar.json",
        "regradar.toml",
        ".regradar.toml",
        "regradar.yaml",
        "regradar.yml",
        ".regradar.yaml",
        ".regradar.yml",
    ]

    for name in candidate_names:
        candidate = search_dir / name
        if candidate.is_file():
            return candidate

    return None


def parse_config_file(file_path: Path) -> Dict[str, Any]:
    """Parses a configuration file by format (JSON, TOML, or YAML)."""
    text = file_path.read_text(encoding="utf-8")
    suffix = file_path.suffix.lower()

    if suffix in (".json",):
        return json.loads(text)

    if suffix in (".toml",):
        if tomllib is not None:
            return tomllib.loads(text)
        raise ImportError(
            "tomllib standard library unavailable to parse TOML configuration."
        )

    if suffix in (".yaml", ".yml"):
        if yaml is not None:
            return yaml.safe_load(text) or {}
        # Fallback: attempt json parsing in case it is JSON-formatted YAML
        try:
            return json.loads(text)
        except Exception:
            raise ImportError(
                f"PyYAML is not installed to parse '{file_path.name}'. "
                "Install pyyaml or use JSON/TOML configuration."
            )

    # Attempt JSON by default
    return json.loads(text)


def apply_env_overrides(config_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Overrides configuration dictionary with environment variables."""
    # Workspace root
    if "REGRADAR_WORKSPACE_ROOT" in os.environ:
        config_dict.setdefault("workspace", {})["root"] = os.environ["REGRADAR_WORKSPACE_ROOT"]

    # Server settings
    if "REGRADAR_SERVER_HOST" in os.environ:
        config_dict.setdefault("server", {})["host"] = os.environ["REGRADAR_SERVER_HOST"]
    if "REGRADAR_SERVER_PORT" in os.environ:
        try:
            config_dict.setdefault("server", {})["port"] = int(os.environ["REGRADAR_SERVER_PORT"])
        except ValueError:
            pass
    if "REGRADAR_CORS_ORIGINS" in os.environ:
        raw_cors = os.environ["REGRADAR_CORS_ORIGINS"]
        origins = [o.strip() for o in raw_cors.split(",") if o.strip()]
        config_dict.setdefault("server", {})["cors_origins"] = origins

    # LLM Settings
    if "REGRADAR_LLM_PROVIDER" in os.environ:
        config_dict.setdefault("llm", {})["provider"] = os.environ["REGRADAR_LLM_PROVIDER"].lower()
    if "OPENAI_API_KEY" in os.environ:
        config_dict.setdefault("llm", {}).setdefault("openai", {})["api_key"] = os.environ["OPENAI_API_KEY"]
    if "OPENAI_MODEL" in os.environ:
        config_dict.setdefault("llm", {}).setdefault("openai", {})["model"] = os.environ["OPENAI_MODEL"]
    if "OPENAI_BASE_URL" in os.environ:
        config_dict.setdefault("llm", {}).setdefault("openai", {})["base_url"] = os.environ["OPENAI_BASE_URL"]
    if "ANTHROPIC_API_KEY" in os.environ:
        config_dict.setdefault("llm", {}).setdefault("anthropic", {})["api_key"] = os.environ["ANTHROPIC_API_KEY"]
    if "ANTHROPIC_MODEL" in os.environ:
        config_dict.setdefault("llm", {}).setdefault("anthropic", {})["model"] = os.environ["ANTHROPIC_MODEL"]
    if "ANTHROPIC_BASE_URL" in os.environ:
        config_dict.setdefault("llm", {}).setdefault("anthropic", {})["base_url"] = os.environ["ANTHROPIC_BASE_URL"]
    if "GEMINI_API_KEY" in os.environ:
        config_dict.setdefault("llm", {}).setdefault("gemini", {})["api_key"] = os.environ["GEMINI_API_KEY"]
    if "GEMINI_MODEL" in os.environ:
        config_dict.setdefault("llm", {}).setdefault("gemini", {})["model"] = os.environ["GEMINI_MODEL"]
    if "GEMINI_BASE_URL" in os.environ:
        config_dict.setdefault("llm", {}).setdefault("gemini", {})["base_url"] = os.environ["GEMINI_BASE_URL"]
    if "DEEPSEEK_API_KEY" in os.environ:
        config_dict.setdefault("llm", {}).setdefault("deepseek", {})["api_key"] = os.environ["DEEPSEEK_API_KEY"]
    if "DEEPSEEK_MODEL" in os.environ:
        config_dict.setdefault("llm", {}).setdefault("deepseek", {})["model"] = os.environ["DEEPSEEK_MODEL"]
    if "DEEPSEEK_BASE_URL" in os.environ:
        config_dict.setdefault("llm", {}).setdefault("deepseek", {})["base_url"] = os.environ["DEEPSEEK_BASE_URL"]
    if "OLLAMA_BASE_URL" in os.environ:
        config_dict.setdefault("llm", {}).setdefault("ollama", {})["base_url"] = os.environ["OLLAMA_BASE_URL"]
    if "OLLAMA_MODEL" in os.environ:
        config_dict.setdefault("llm", {}).setdefault("ollama", {})["model"] = os.environ["OLLAMA_MODEL"]
    if "REGRADAR_MAX_RETRIES" in os.environ:
        try:
            config_dict.setdefault("llm", {}).setdefault("swarm", {})["max_retries"] = int(os.environ["REGRADAR_MAX_RETRIES"])
        except ValueError:
            pass

    # Centrality Settings
    if "REGRADAR_CRITICAL_THRESHOLD" in os.environ:
        try:
            config_dict.setdefault("centrality", {}).setdefault("thresholds", {})["critical_root_score"] = float(
                os.environ["REGRADAR_CRITICAL_THRESHOLD"]
            )
        except ValueError:
            pass

    # Sandbox Settings
    if "REGRADAR_SANDBOX_BINARY" in os.environ:
        config_dict.setdefault("sandbox", {})["binary_name"] = os.environ["REGRADAR_SANDBOX_BINARY"]
    if "TF_PLUGIN_CACHE_DIR" in os.environ:
        config_dict.setdefault("sandbox", {})["plugin_cache_dir"] = os.environ["TF_PLUGIN_CACHE_DIR"]

    # GitHub Settings
    if "GITHUB_WEBHOOK_SECRET" in os.environ:
        config_dict.setdefault("github", {})["webhook_secret"] = os.environ["GITHUB_WEBHOOK_SECRET"]
    if "GITHUB_TOKEN" in os.environ:
        config_dict.setdefault("github", {})["github_token"] = os.environ["GITHUB_TOKEN"]
    if "REGRADAR_REQUIRE_HUMAN_SIGNOFF" in os.environ:
        config_dict.setdefault("github", {})["require_human_signoff"] = (
            os.environ["REGRADAR_REQUIRE_HUMAN_SIGNOFF"].lower() in ("1", "true", "yes")
        )

    return config_dict


def load_config(custom_path: Optional[Union[str, Path]] = None) -> RegRadarConfig:
    """
    Loads and resolves the global RegRadar configuration.
    Merges configuration file with environment variables and defaults.
    """
    config_dict: Dict[str, Any] = {}
    found_file = find_config_file(custom_path)
    if found_file:
        config_dict = parse_config_file(found_file)

    config_dict = apply_env_overrides(config_dict)
    config = RegRadarConfig.model_validate(config_dict)

    # Dynamically set workspace root if not explicitly provided
    if not config.workspace.root:
        config.workspace.root = str(resolve_workspace_root())

    return config


# ==============================================================================
# Global Configuration Singleton
# ==============================================================================

_GLOBAL_CONFIG: Optional[RegRadarConfig] = None


def get_config() -> RegRadarConfig:
    """Returns the active global RegRadar configuration singleton."""
    global _GLOBAL_CONFIG
    if _GLOBAL_CONFIG is None:
        _GLOBAL_CONFIG = load_config()
    return _GLOBAL_CONFIG


def set_config(config: RegRadarConfig) -> None:
    """Sets or replaces the global configuration singleton."""
    global _GLOBAL_CONFIG
    _GLOBAL_CONFIG = config


def reset_config() -> None:
    """Resets the global configuration singleton to reload from scratch."""
    global _GLOBAL_CONFIG
    _GLOBAL_CONFIG = None
