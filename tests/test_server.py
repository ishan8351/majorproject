from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from regradar.api.server import create_app


@pytest.fixture
def client() -> TestClient:
    app = create_app()
    return TestClient(app)


def test_server_serves_index_html(client: TestClient):
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers.get("content-type", "")
    assert "RegRadar" in res.text
    assert "Topology & Blast DAG" in res.text


def test_server_serves_static_assets(client: TestClient):
    css_res = client.get("/css/style.css")
    assert css_res.status_code == 200
    assert "text/css" in css_res.headers.get("content-type", "")
    assert "--risk-critical" in css_res.text

    theme_res = client.get("/css/theme.css")
    assert theme_res.status_code == 200
    assert "obsidian" in theme_res.text
    assert "alabaster" in theme_res.text

    icons_res = client.get("/js/icons.js")
    assert icons_res.status_code == 200
    assert "RegIcons" in icons_res.text

    gh_res = client.get("/js/github.js")
    assert gh_res.status_code == 200
    assert "GitHubModule" in gh_res.text

    js_res = client.get("/js/app.js")
    assert js_res.status_code == 200
    assert "TopologyModule" in js_res.text or "AppState" in js_res.text


def test_index_html_zero_emojis_and_four_themes(client: TestClient):
    res = client.get("/")
    assert res.status_code == 200
    html = res.text

    # Verify 4 themes exist in segmented picker
    assert 'data-theme-val="obsidian"' in html
    assert 'data-theme-val="midnight"' in html
    assert 'data-theme-val="polar"' in html
    assert 'data-theme-val="alabaster"' in html

    # Verify GitHub nav tab and view exist
    assert 'data-tab="github"' in html
    assert 'id="view-github"' in html

    # Verify zero emojis in index.html
    import re
    emoji_pattern = re.compile(
        '[\U00010000-\U0010ffff]|'
        '[\u2600-\u27bf]|'
        '[\u2300-\u23ff]|'
        '[\u2b50-\u2b55]|'
        '[\u203c\u2049\u20e3\u2122\u2139\u2194-\u2199\u21a9-\u21aa]'
    )
    matches = emoji_pattern.findall(html)
    assert len(matches) == 0, f"Found unexpected emojis in index.html: {matches}"


def test_server_api_mounted_with_static(client: TestClient):
    # Ensure /api/health still works seamlessly alongside static files
    health_res = client.get("/api/health")
    assert health_res.status_code == 200
    assert health_res.json()["status"] == "ok"
