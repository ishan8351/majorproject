import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from regradar.api.server import create_app


@pytest.fixture
def client() -> TestClient:
    app = create_app()
    return TestClient(app)


def test_api_health(client: TestClient):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "RegRadar" in data["engine"]


def test_api_workspaces(client: TestClient):
    res = client.get("/api/workspaces")
    assert res.status_code == 200
    workspaces = res.json()
    assert isinstance(workspaces, list)
    assert len(workspaces) >= 4
    ids = [w["id"] for w in workspaces]
    assert "healthcare_hipaa_aws" in ids
    assert "simple_vpc" in ids


def test_api_scan_simple_vpc(client: TestClient, simple_vpc_path: Path):
    res = client.post("/api/scan", json={"target_path": str(simple_vpc_path)})
    assert res.status_code == 200
    data = res.json()
    assert data["total_resources"] == 2
    assert "aws_vpc.main" in data["metrics"]
    assert "aws_subnet.public" in data["metrics"]


def test_api_scan_not_found(client: TestClient):
    res = client.post("/api/scan", json={"target_path": "/nonexistent/path"})
    assert res.status_code == 404


def test_api_graph_export_cytoscape(client: TestClient, simple_vpc_path: Path):
    res = client.get(f"/api/graph/export?target_path={simple_vpc_path}&format=cytoscape")
    assert res.status_code == 200
    data = res.json()
    assert data["format"] == "cytoscape"
    assert "elements" in data
    assert len(data["elements"]["nodes"]) == 2
    assert len(data["elements"]["edges"]) == 1


def test_api_graph_export_mermaid(client: TestClient, simple_vpc_path: Path):
    res = client.get(f"/api/graph/export?target_path={simple_vpc_path}&format=mermaid")
    assert res.status_code == 200
    data = res.json()
    assert data["format"] == "mermaid"
    assert "flowchart TD" in data["content"]


def test_api_knowledge_query(client: TestClient):
    res = client.post(
        "/api/knowledge/query",
        json={"query": "enforce S3 encryption at rest with AES256", "top_k": 3},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["total_results"] > 0
    assert "contexts" in data
    assert any("CKV_AWS_19" in ctx.get("check_id", "") for ctx in data["contexts"])


def test_api_review_staged_and_decision(client: TestClient, simple_vpc_path: Path):
    res = client.post("/api/review/staged", json={"target_path": str(simple_vpc_path)})
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert "auto_staged_count" in data

    # Test review decision endpoint
    decision_res = client.post(
        "/api/review/decision",
        json={
            "target_path": str(simple_vpc_path),
            "resource_id": "aws_subnet.public",
            "check_id": "CKV_AWS_19",
            "decision": "APPROVE",
            "apply": False,
        },
    )
    assert decision_res.status_code == 200
    dec_data = decision_res.json()
    assert dec_data["success"] is True
    assert dec_data["decision"] == "APPROVE"


def test_api_settings_get_and_update(client: TestClient):
    get_res = client.get("/api/settings")
    assert get_res.status_code == 200
    settings = get_res.json()
    assert "current_provider" in settings
    assert "current_model" in settings
    assert "available_providers" in settings
    assert "available_models" in settings
    assert "gemini" in settings["available_providers"]
    assert "deepseek" in settings["available_providers"]
    assert "gemini-4-argon" in [m["id"] for m in settings["available_models"]["gemini"]]
    assert "gpt-6-sol" in [m["id"] for m in settings["available_models"]["openai"]]
    assert "has_gemini_key" in settings
    assert "has_deepseek_key" in settings

    update_res = client.post(
        "/api/settings",
        json={
            "provider": "gemini",
            "model": "gemini-4-argon",
            "gemini_key": "AIzaSyTestKey",
            "deepseek_key": "sk-deepseek-test",
            "ollama_url": "http://localhost:11434",
        },
    )
    assert update_res.status_code == 200
    updated = update_res.json()
    assert updated["current_provider"] == "gemini"
    assert updated["current_model"] == "gemini-4-argon"
    assert updated["has_gemini_key"] is True
    assert updated["has_deepseek_key"] is True

    # Clean up and restore mock provider for subsequent test isolation
    client.post("/api/settings", json={"provider": "mock"})
    from regradar.config import reset_config
    reset_config()
    for k in (
        "REGRADAR_LLM_PROVIDER",
        "GEMINI_API_KEY",
        "DEEPSEEK_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "OLLAMA_BASE_URL",
        "GEMINI_MODEL",
        "DEEPSEEK_MODEL",
        "OPENAI_MODEL",
        "ANTHROPIC_MODEL",
        "OLLAMA_MODEL",
    ):
        os.environ.pop(k, None)
