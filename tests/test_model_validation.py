import pytest
from unittest.mock import patch, MagicMock

from regradar.api.routes import validate_model, ModelValidateRequest


def test_validate_model_missing_key():
    req = ModelValidateRequest(provider="openai", model="chatgpt-6-sol", api_key="")
    with patch.dict("os.environ", {}, clear=True):
        res = validate_model(req)
        assert res.valid is False
        assert "No API key provided" in res.error


def test_validate_model_online():
    mock_client = MagicMock()
    mock_client.generate.return_value = "pong"

    with patch("regradar.remediation.llm.client.GeminiClient", return_value=mock_client):
        req = ModelValidateRequest(provider="gemini", model="gemini-4-argon", api_key="test-key")
        res = validate_model(req)
        assert res.valid is True
        assert "online and responsive" in res.message
        assert res.latency_ms is not None
        mock_client.generate.assert_called_once_with("ping", max_tokens=1, temperature=0.0)


def test_validate_model_busy_rate_limited():
    mock_client = MagicMock()
    mock_client.generate.side_effect = Exception("429 Resource Exhausted / Quota exceeded")

    with patch("regradar.remediation.llm.client.OpenAIClient", return_value=mock_client):
        req = ModelValidateRequest(provider="openai", model="chatgpt-6-sol", api_key="sk-test")
        res = validate_model(req)
        assert res.valid is False
        assert "busy or rate-limited" in res.error


def test_validate_model_auth_failed():
    mock_client = MagicMock()
    mock_client.generate.side_effect = Exception("401 Unauthorized: invalid_api_key")

    with patch("regradar.remediation.llm.client.AnthropicClient", return_value=mock_client):
        req = ModelValidateRequest(provider="anthropic", model="claude-sonnet-5.5", api_key="bad-key")
        res = validate_model(req)
        assert res.valid is False
        assert "Authentication failed" in res.error
