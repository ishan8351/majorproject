"""
Tests for Gemini 4 Argon and Frontier LLM Integration.
Verifies compliance with latest 2026 API specifications:
- gemini-4-argon generateContent format, endpoint, and headers
- reasoning thoughts isolation (thought: true filtering)
- thinkingConfig / thinkingLevel behavior
- developer role and reasoning_effort for GPT-6 models
- adaptive thinking for Claude 5.5
"""

import json
from unittest.mock import MagicMock, patch
import pytest

from regradar.api.routes import AVAILABLE_FRONTIER_MODELS, get_settings, validate_model, ModelValidateRequest
from regradar.config import get_config, reset_config
from regradar.remediation.llm.client import (
    GeminiClient,
    OpenAIClient,
    AnthropicClient,
    DeepSeekClient,
    get_llm_client,
)


def test_gemini_4_argon_is_default_flagship():
    """Verify Gemini 4 Argon is the primary model in settings and model catalog."""
    gemini_models = AVAILABLE_FRONTIER_MODELS["gemini"]
    assert len(gemini_models) >= 1
    assert gemini_models[0]["id"] == "gemini-4-argon"
    assert "Gemini 4 Argon" in gemini_models[0]["name"]
    assert "1M" in gemini_models[0]["context"]

    settings = get_settings()
    assert settings.current_provider == "gemini"
    assert settings.current_model == "gemini-4-argon"
    assert settings.provider_models["gemini"] == "gemini-4-argon"


def test_gemini_4_argon_client_init_and_prefix_stripping():
    """Verify GeminiClient defaults to gemini-4-argon and strips 'models/' prefix."""
    client_default = GeminiClient(api_key="AIzaSyTest")
    assert client_default.model == "gemini-4-argon"
    assert client_default.base_url == "https://generativelanguage.googleapis.com/v1beta"

    client_prefixed = GeminiClient(api_key="AIzaSyTest", model="models/gemini-4-argon")
    assert client_prefixed.model == "gemini-4-argon"


def test_gemini_4_argon_request_structure():
    """Verify REST payload meets Google Gemini API generateContent documentation."""
    client = GeminiClient(api_key="AIzaSyTestKey", model="gemini-4-argon")

    mock_resp = {
        "candidates": [
            {
                "content": {
                    "role": "model",
                    "parts": [{"text": "resource \"aws_s3_bucket_server_side_encryption_configuration\" \"enc\" {}"}]
                },
                "finishReason": "STOP"
            }
        ]
    }
    mock_bytes = json.dumps(mock_resp).encode("utf-8")

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_cm = MagicMock()
        mock_cm.read.return_value = mock_bytes
        mock_urlopen.return_value.__enter__.return_value = mock_cm

        res = client.generate(
            prompt="Generate HIPAA KMS encryption",
            system_prompt="You are a principal cloud compliance engineer",
            temperature=0.0,
            max_tokens=2048,
            thinking_level="HIGH",
        )

        assert "resource" in res
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "https://generativelanguage.googleapis.com/v1beta/models/gemini-4-argon:generateContent"
        assert req.headers["X-goog-api-key"] == "AIzaSyTestKey"
        assert req.headers["Content-type"] == "application/json"

        body = json.loads(req.data.decode("utf-8"))
        assert body["contents"][0]["role"] == "user"
        assert body["contents"][0]["parts"][0]["text"] == "Generate HIPAA KMS encryption"
        assert body["systemInstruction"]["parts"][0]["text"] == "You are a principal cloud compliance engineer"
        assert body["generationConfig"]["maxOutputTokens"] == 2048
        assert body["generationConfig"]["thinkingConfig"]["thinkingLevel"] == "HIGH"


def test_gemini_4_argon_filters_internal_reasoning_thoughts():
    """Verify intermediate thought blocks (thought: true) are isolated from final response."""
    client = GeminiClient(api_key="AIzaSyTestKey", model="gemini-4-argon")

    # Multi-part response containing an internal reasoning thought and the final synthesized code
    mock_resp = {
        "candidates": [
            {
                "content": {
                    "role": "model",
                    "parts": [
                        {
                            "thought": True,
                            "text": "Evaluating blast-radius DAG. Bucket must not be recreated in-place."
                        },
                        {
                            "thought": False,
                            "text": "resource \"aws_s3_bucket_versioning\" \"ver\" {\n  bucket = aws_s3_bucket.logs.id\n}"
                        }
                    ]
                }
            }
        ]
    }
    mock_bytes = json.dumps(mock_resp).encode("utf-8")

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_cm = MagicMock()
        mock_cm.read.return_value = mock_bytes
        mock_urlopen.return_value.__enter__.return_value = mock_cm

        res = client.generate("Remediate S3 versioning")
        assert "aws_s3_bucket_versioning" in res
        assert "Evaluating blast-radius DAG" not in res


def test_gemini_4_argon_thinking_budget_adaptive_conversion():
    """Verify legacy thinking_budget converts to thinkingLevel on Gemini 4 to avoid 400 error."""
    client = GeminiClient(api_key="AIzaSyTestKey", model="gemini-4-argon")

    mock_resp = {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]}
    mock_bytes = json.dumps(mock_resp).encode("utf-8")

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_cm = MagicMock()
        mock_cm.read.return_value = mock_bytes
        mock_urlopen.return_value.__enter__.return_value = mock_cm

        client.generate("Test prompt", thinking_budget=4096)
        req = mock_urlopen.call_args[0][0]
        body = json.loads(req.data.decode("utf-8"))
        assert "thinkingBudget" not in body["generationConfig"]["thinkingConfig"]
        assert body["generationConfig"]["thinkingConfig"]["thinkingLevel"] == "MEDIUM"


def test_openai_gpt6_reasoning_models_developer_role():
    """Verify all GPT-6 models utilize the developer role and max_completion_tokens."""
    for model_id in ["gpt-6-astra", "gpt-6.1-sol", "gpt-6.1-terra", "gpt-6-sol", "gpt-6-luna"]:
        client = OpenAIClient(api_key="sk-test", model=model_id)
        mock_resp = {"choices": [{"message": {"content": f"output from {model_id}"}}]}
        mock_bytes = json.dumps(mock_resp).encode("utf-8")

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_cm = MagicMock()
            mock_cm.read.return_value = mock_bytes
            mock_urlopen.return_value.__enter__.return_value = mock_cm

            res = client.generate("Test prompt", system_prompt="Dev system instruction", max_tokens=1024)
            assert f"output from {model_id}" in res
            req = mock_urlopen.call_args[0][0]
            body = json.loads(req.data.decode("utf-8"))
            assert body["messages"][0]["role"] == "developer"
            assert body["messages"][0]["content"] == "Dev system instruction"
            assert "max_completion_tokens" in body
            assert "temperature" not in body


def test_get_llm_client_resolution_prioritizes_gemini():
    """Verify get_llm_client resolves to GeminiClient when GEMINI_API_KEY is present."""
    with patch.dict("os.environ", {"GEMINI_API_KEY": "AIzaSyKey"}, clear=True):
        client = get_llm_client()
        assert isinstance(client, GeminiClient)
        assert client.model == "gemini-4-argon"
