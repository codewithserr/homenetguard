import pytest
from homenetguard.storage import database, repository
from homenetguard.dashboard.app import create_app


@pytest.fixture
def cfg(tmp_path):
    return {
        "storage": {"db_path": str(tmp_path / "test.db"), "reports_path": str(tmp_path / "reports")},
        "dashboard": {"host": "127.0.0.1", "port": 8080, "auto_open_browser": False},
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


def test_api_status(client):
    res = client.get("/api/v1/status")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "running"
    assert "version" in data


def test_api_flows_empty(client):
    res = client.get("/api/v1/flows")
    assert res.status_code == 200
    data = res.get_json()
    assert "flows" in data
    assert isinstance(data["flows"], list)


def test_api_alerts_empty(client):
    res = client.get("/api/v1/alerts")
    assert res.status_code == 200
    assert isinstance(res.get_json(), list)


def test_api_alerts_ack(client):
    repository.insert_alert("port_scan", "high", "Test alert", src_ip="1.2.3.4")
    alerts = repository.get_all_alerts()
    alert_id = alerts[0]["id"]
    res = client.post(f"/api/v1/alerts/{alert_id}/ack")
    assert res.status_code == 200
    assert res.get_json()["ok"] is True


def test_api_devices_empty(client):
    res = client.get("/api/v1/devices")
    assert res.status_code == 200
    assert isinstance(res.get_json(), list)


def test_api_firewall_rules_empty(client):
    res = client.get("/api/v1/firewall/rules")
    assert res.status_code == 200
    assert isinstance(res.get_json(), list)


def test_api_sinkhole_rules_empty(client):
    res = client.get("/api/v1/sinkhole/rules")
    assert res.status_code == 200


def test_api_ml_status(client):
    res = client.get("/api/v1/ml/status")
    assert res.status_code == 200
    data = res.get_json()
    assert "trained" in data


def test_swagger_docs_available(client):
    res = client.get("/api/docs")
    # Swagger UI returns HTML
    assert res.status_code == 200


def test_api_v2_devices(client):
    res = client.get("/api/v2/devices")
    assert res.status_code == 200
    assert isinstance(res.get_json(), list)


def test_api_v2_compliance(client):
    res = client.get("/api/v2/compliance")
    assert res.status_code == 200
    data = res.get_json()
    assert "checks" in data
    assert "score" in data
    assert 0 <= data["score"] <= 100
