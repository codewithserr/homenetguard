import pytest
from homenetguard.storage import database, repository
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


def test_index_returns_200(client):
    res = client.get("/")
    assert res.status_code == 200


def test_alerts_view_returns_200(client):
    res = client.get("/alerts")
    assert res.status_code == 200


def test_flows_view_returns_200(client):
    res = client.get("/flows")
    assert res.status_code == 200


def test_dns_view_returns_200(client):
    res = client.get("/dns")
    assert res.status_code == 200


def test_reports_view_returns_200(client):
    res = client.get("/reports")
    assert res.status_code == 200


def test_api_stats_returns_json(client):
    res = client.get("/api/stats")
    assert res.status_code == 200
    data = res.get_json()
    assert "total_flows" in data


def test_api_flows_returns_list(client):
    res = client.get("/api/flows")
    assert res.status_code == 200
    assert isinstance(res.get_json(), list)


def test_api_alerts_empty(client):
    res = client.get("/api/alerts")
    assert res.status_code == 200
    assert res.get_json() == []


def test_api_alerts_filter_severity(client):
    repository.insert_alert("port_scan", "high", "High severity alert")
    repository.insert_alert("flood", "critical", "Critical alert")
    res = client.get("/api/alerts?severity=high")
    data = res.get_json()
    assert all(a["severity"] == "high" for a in data)


def test_api_ack_alert(client):
    repository.insert_alert("flood", "high", "Test flood")
    alerts = repository.get_unacknowledged_alerts()
    alert_id = alerts[0]["id"]
    res = client.post(f"/api/alerts/{alert_id}/acknowledge")
    assert res.status_code == 200
    assert res.get_json()["ok"] is True
    assert repository.get_unacknowledged_alerts() == []


def test_api_clear_alerts(client):
    repository.insert_alert("flood", "high", "Test1")
    repository.insert_alert("port_scan", "medium", "Test2")
    res = client.post("/api/alerts/clear")
    assert res.status_code == 200
    assert res.get_json()["cleared"] == 2


def test_api_top_ips_empty(client):
    res = client.get("/api/top-ips")
    assert res.status_code == 200
    assert isinstance(res.get_json(), list)


def test_api_protocols_empty(client):
    res = client.get("/api/protocols")
    assert res.status_code == 200


def test_api_dns_empty(client):
    res = client.get("/api/dns")
    assert res.status_code == 200
    assert res.get_json() == []


def test_config_view_returns_200(client):
    res = client.get("/config")
    assert res.status_code == 200
