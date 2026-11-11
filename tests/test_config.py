import json
import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from regradar.api.server import create_app
from regradar.config import (
    CentralityConfig,
    LLMConfig,
    RegRadarConfig,
    ServerConfig,
    WorkspaceConfig,
    get_config,
    load_config,
    reset_config,
    resolve_workspace_root,
    set_config,
)


@pytest.fixture(autouse=True)
def clean_config_and_env(monkeypatch):
    """Resets global config and environment before each test."""
    reset_config()
    for k in list(os.environ.keys()):
        if any(k.startswith(pfx) for pfx in ("REGRADAR_", "OPENAI_", "ANTHROPIC_", "GEMINI_", "DEEPSEEK_", "OLLAMA_")):
            monkeypatch.delenv(k, raising=False)
    yield
    reset_config()


def test_default_config():
    cfg = get_config()
    assert cfg.server.host == "127.0.0.1"
    assert cfg.server.port == 8000
    assert cfg.server.cors_origins == ["*"]
    assert cfg.centrality.weights.descendant_ratio == 0.40
    assert cfg.centrality.weights.betweenness == 0.25
    assert cfg.centrality.weights.eigenvector == 0.20
    assert cfg.centrality.weights.out_degree_ratio == 0.15
    assert cfg.centrality.thresholds.critical_root_score == 0.40
    assert cfg.centrality.thresholds.critical_root_descendant_ratio == 0.35
    assert cfg.centrality.thresholds.intermediate_score == 0.15
    assert cfg.llm.provider == "mock"
    assert cfg.llm.openai.model == "gpt-6-sol"
    assert cfg.llm.anthropic.model == "claude-sonnet-5-5"
    assert cfg.llm.gemini.model == "gemini-4-argon"
    assert cfg.llm.deepseek.model == "deepseek-v4-pro"
    assert cfg.llm.ollama.model == "llama3.3"
    assert cfg.sandbox.binary_name == "tofu"
    assert cfg.sandbox.mock_aws_region == "us-east-1"


def test_resolve_workspace_root_dynamic():
    root = resolve_workspace_root()
    assert root.exists()
    assert (root / "regradar").is_dir()
    assert (root / "regradar" / "config.py").is_file()


def test_resolve_workspace_root_env_override(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("REGRADAR_WORKSPACE_ROOT", str(tmp_path))
    root = resolve_workspace_root()
    assert root == tmp_path.resolve()


def test_load_config_from_json(tmp_path: Path):
    cfg_data = {
        "server": {
            "host": "0.0.0.0",
            "port": 9000,
            "cors_origins": ["https://mycompany.com"],
        },
        "centrality": {
            "thresholds": {
                "critical_root_score": 0.30,
            }
        },
        "llm": {
            "provider": "ollama",
            "ollama": {
                "model": "codellama",
                "base_url": "http://192.168.1.50:11434",
            },
        },
    }
    cfg_file = tmp_path / "custom_regradar.json"
    cfg_file.write_text(json.dumps(cfg_data), encoding="utf-8")

    cfg = load_config(cfg_file)
    assert cfg.server.host == "0.0.0.0"
    assert cfg.server.port == 9000
    assert cfg.server.cors_origins == ["https://mycompany.com"]
    assert cfg.centrality.thresholds.critical_root_score == 0.30
    # Unspecified fields retain defaults
    assert cfg.centrality.thresholds.critical_root_descendant_ratio == 0.35
    assert cfg.llm.provider == "ollama"
    assert cfg.llm.ollama.model == "codellama"
    assert cfg.llm.ollama.base_url == "http://192.168.1.50:11434"


def test_load_config_from_toml(tmp_path: Path):
    try:
        import tomllib
    except ImportError:
        pytest.skip("tomllib not available")

    toml_content = """
    [server]
    host = "10.0.0.1"
    port = 8080
    cors_origins = ["https://app.internal"]

    [llm]
    provider = "openai"

    [llm.openai]
    model = "gpt-4o-mini"
    """
    cfg_file = tmp_path / "custom_regradar.toml"
    cfg_file.write_text(toml_content, encoding="utf-8")

    cfg = load_config(cfg_file)
    assert cfg.server.host == "10.0.0.1"
    assert cfg.server.port == 8080
    assert cfg.server.cors_origins == ["https://app.internal"]
    assert cfg.llm.provider == "openai"
    assert cfg.llm.openai.model == "gpt-4o-mini"


def test_env_var_overrides(monkeypatch):
    monkeypatch.setenv("REGRADAR_SERVER_PORT", "9999")
    monkeypatch.setenv("REGRADAR_SERVER_HOST", "127.0.0.2")
    monkeypatch.setenv("REGRADAR_CORS_ORIGINS", "https://foo.com, https://bar.com")
    monkeypatch.setenv("REGRADAR_LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-3-haiku")
    monkeypatch.setenv("REGRADAR_CRITICAL_THRESHOLD", "0.25")
    monkeypatch.setenv("REGRADAR_SANDBOX_BINARY", "terraform")

    cfg = load_config()
    assert cfg.server.port == 9999
    assert cfg.server.host == "127.0.0.2"
    assert cfg.server.cors_origins == ["https://foo.com", "https://bar.com"]
    assert cfg.llm.provider == "anthropic"
    assert cfg.llm.anthropic.model == "claude-3-haiku"
    assert cfg.centrality.thresholds.critical_root_score == 0.25
    assert cfg.sandbox.binary_name == "terraform"


def test_gemini_and_deepseek_env_overrides(monkeypatch):
    monkeypatch.setenv("REGRADAR_LLM_PROVIDER", "gemini")
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSySecret")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-2.0-flash-lite")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-deepseek-key")
    monkeypatch.setenv("DEEPSEEK_MODEL", "deepseek-reasoner")

    cfg = load_config()
    assert cfg.llm.provider == "gemini"
    assert cfg.llm.gemini.api_key == "AIzaSySecret"
    assert cfg.llm.gemini.model == "gemini-2.0-flash-lite"
    assert cfg.llm.deepseek.api_key == "sk-deepseek-key"
    assert cfg.llm.deepseek.model == "deepseek-reasoner"


def test_singleton_set_and_reset():
    custom_cfg = RegRadarConfig(
        server=ServerConfig(port=7777),
    )
    set_config(custom_cfg)
    assert get_config().server.port == 7777

    reset_config()
    assert get_config().server.port == 8000


def test_server_with_custom_cors():
    custom_cfg = RegRadarConfig(
        server=ServerConfig(cors_origins=["https://trusted-domain.com"]),
    )
    app = create_app(custom_config=custom_cfg)
    client = TestClient(app)

    # Pre-flight OPTIONS request from trusted domain
    res = client.options(
        "/api/health",
        headers={
            "Origin": "https://trusted-domain.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert res.headers.get("access-control-allow-origin") == "https://trusted-domain.com"


def test_centrality_engine_custom_config():
    import networkx as nx
    from regradar.config import CentralityConfig, CentralityThresholds
    from regradar.graph.centrality import CentralityEngine
    from regradar.models import RiskTier

    g = nx.DiGraph()
    g.add_node("aws_vpc.main", resource_type="aws_vpc")
    g.add_node("aws_subnet.public", resource_type="aws_subnet")
    g.add_edge("aws_vpc.main", "aws_subnet.public")

    # With default threshold (0.40), aws_vpc.main composite score might be below critical root
    # But with a very low threshold (0.05), it should be classified as CRITICAL_ROOT
    strict_config = CentralityConfig(
        thresholds=CentralityThresholds(critical_root_score=0.05, critical_root_descendant_ratio=0.10)
    )
    engine = CentralityEngine(g, config=strict_config)
    metrics = engine.evaluate()
    assert metrics["aws_vpc.main"].risk_tier == RiskTier.CRITICAL_ROOT


def test_sandbox_runner_custom_config(tmp_path: Path):
    from regradar.config import SandboxConfig
    from regradar.invariant.sandbox import SandboxRunner

    custom_cfg = SandboxConfig(
        binary_name="terraform",
        plugin_cache_dir=str(tmp_path / "cache"),
        offline_replacement_rules={"custom_resource": ["critical_attr"]},
    )
    set_config(RegRadarConfig(sandbox=custom_cfg))
    runner = SandboxRunner()
    assert runner.binary_name == "terraform"
    assert runner.custom_plugin_cache_dir == str(tmp_path / "cache")


def test_llm_clients_custom_config():
    from regradar.config import LLMConfig, OpenAIProviderConfig, OllamaProviderConfig
    from regradar.remediation.llm.client import OpenAIClient, OllamaClient

    custom_cfg = RegRadarConfig(
        llm=LLMConfig(
            openai=OpenAIProviderConfig(model="gpt-4o-custom", timeout=45.0),
            ollama=OllamaProviderConfig(model="mistral-custom", base_url="http://10.0.0.9:11434"),
        )
    )
    set_config(custom_cfg)

    openai_client = OpenAIClient(api_key="sk-test")
    assert openai_client.model == "gpt-4o-custom"
    assert openai_client.timeout == 45.0

    ollama_client = OllamaClient()
    assert ollama_client.model == "mistral-custom"
    assert ollama_client.base_url == "http://10.0.0.9:11434"


def test_checkov_scanner_custom_env(monkeypatch):
    from regradar.remediation.scanner import CheckovScanner
    monkeypatch.setenv("REGRADAR_CHECKOV_PATH", "/usr/local/bin/custom-checkov")
    scanner = CheckovScanner()
    assert scanner.checkov_bin == "/usr/local/bin/custom-checkov"
