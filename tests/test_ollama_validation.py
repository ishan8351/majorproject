import json
from unittest.mock import patch, MagicMock
from io import BytesIO

from regradar.api.routes import validate_ollama, OllamaValidateRequest


def test_ollama_validate_offline():
    # Pinging an offline port should return connected=False without raising an exception
    req = OllamaValidateRequest(url="http://127.0.0.1:54321")
    resp = validate_ollama(req)
    assert resp.connected is False
    assert resp.version is None
    assert len(resp.models) == 0
    assert "Cannot reach Ollama" in (resp.error or "")


def test_ollama_validate_online_with_models():
    def mock_urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        mock_resp = MagicMock()
        if "/api/version" in url:
            mock_resp.read.return_value = json.dumps({"version": "0.5.4"}).encode("utf-8")
        elif "/api/tags" in url:
            mock_resp.read.return_value = json.dumps({
                "models": [
                    {
                        "name": "qwen2.5-coder:32b",
                        "size": 19000000000,
                        "modified_at": "2026-11-10T10:00:00Z"
                    },
                    {
                        "name": "deepseek-r1:70b",
                        "size": 42000000000,
                        "modified_at": "2026-11-11T12:00:00Z"
                    }
                ]
            }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        return mock_resp

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        req = OllamaValidateRequest(url="http://localhost:11434")
        resp = validate_ollama(req)
        assert resp.connected is True
        assert resp.version == "0.5.4"
        assert len(resp.models) == 2
        assert resp.models[0].name == "qwen2.5-coder:32b"
        assert "GB" in resp.models[0].size
        assert resp.models[1].name == "deepseek-r1:70b"
        assert "Discovered 2 local models" in resp.message


def test_ollama_validate_online_empty_models():
    def mock_urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        mock_resp = MagicMock()
        if "/api/version" in url:
            mock_resp.read.return_value = json.dumps({"version": "0.5.1"}).encode("utf-8")
        elif "/api/tags" in url:
            mock_resp.read.return_value = json.dumps({"models": []}).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        return mock_resp

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        req = OllamaValidateRequest(url="http://localhost:11434")
        resp = validate_ollama(req)
        assert resp.connected is True
        assert resp.version == "0.5.1"
        assert len(resp.models) == 0
        assert "no models are installed" in resp.message
