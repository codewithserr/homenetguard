import pytest
from homenetguard.storage import database
from homenetguard.dashboard.app import create_app


@pytest.fixture
def cfg(tmp_path):
    return {
        "storage": {"db_path": str(tmp_path / "test.db"), "reports_path": str(tmp_path / "reports")},
        "dashboard": {"host": "127.0.0.1", "port": 5000, "auto_open_browser": False},
        "geoip": {"enabled": False},
        "threat_intelligence": {"abuseipdb": {"enabled": False}, "virustotal": {"enabled": False}},
        "alerts": {"email": {"enabled": False}, "telegram": {"enabled": False}},
        "logging": {"level": "ERROR", "file": str(tmp_path / "test.log")},
    }


@pytest.fixture
def client(cfg, tmp_path):
    database.init_db(str(tmp_path / "test.db"))
    app = create_app(cfg)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_docs_index_returns_200(client):
    res = client.get("/docs")
    assert res.status_code == 200


def test_docs_getting_started_section(client):
    res = client.get("/docs/getting-started")
    assert res.status_code == 200


def test_docs_article_what_is(client):
    res = client.get("/docs/getting-started/what-is-homenetguard")
    assert res.status_code == 200


def test_docs_article_installation(client):
    res = client.get("/docs/getting-started/installation")
    assert res.status_code == 200


def test_docs_article_cli_reference(client):
    res = client.get("/docs/cli-reference/cli-reference")
    assert res.status_code == 200


def test_docs_article_troubleshooting(client):
    res = client.get("/docs/troubleshooting/troubleshooting")
    assert res.status_code == 200


def test_docs_unknown_article_returns_index(client):
    res = client.get("/docs/getting-started/nonexistent-article")
    assert res.status_code == 404


def test_docs_unknown_section_returns_index(client):
    res = client.get("/docs/nonexistent-section")
    assert res.status_code == 404


def test_api_docs_content_returns_json(client):
    res = client.get("/api/v1/docs/content")
    assert res.status_code == 200
    data = res.get_json()
    assert "sections" in data
    assert len(data["sections"]) == 6


def test_api_docs_search(client):
    res = client.get("/api/v1/docs/search?q=firewall")
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, list)


def test_docs_index_contains_all_sections(client):
    res = client.get("/docs")
    html = res.data.decode()
    assert "Getting Started" in html
    assert "User Guide" in html
    assert "CLI Reference" in html
    assert "Troubleshooting" in html


def test_docs_nav_item_active_on_docs_page(client):
    res = client.get("/docs")
    html = res.data.decode()
    assert 'href="/docs"' in html


def test_docs_article_advanced_section(client):
    res = client.get("/docs/advanced/dns-sinkhole-config")
    assert res.status_code == 200
