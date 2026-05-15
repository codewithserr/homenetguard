import pytest
from datetime import UTC, datetime, timedelta
from homenetguard.storage import database, repository


@pytest.fixture(autouse=True)
def in_memory_db(tmp_path):
    db_file = str(tmp_path / "test.db")
    database.init_db(db_file)
    yield


def test_insert_and_get_flow():
    flow = {
        "timestamp": datetime.now(UTC).isoformat(),
        "src_ip": "192.168.1.1",
        "dst_ip": "8.8.8.8",
        "src_port": 12345,
        "dst_port": 53,
        "protocol": "UDP",
        "bytes": 128,
        "packets": 1,
        "direction": "outbound",
        "interface": "eth0",
    }
    repository.insert_flow(flow)
    flows = repository.get_recent_flows(limit=10)
    assert len(flows) == 1
    assert flows[0]["src_ip"] == "192.168.1.1"


def test_insert_and_get_alert():
    repository.insert_alert(
        alert_type="port_scan",
        severity="high",
        src_ip="10.0.0.1",
        dst_ip="192.168.1.100",
        description="Port scan detected from 10.0.0.1",
    )
    alerts = repository.get_unacknowledged_alerts()
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "port_scan"


def test_acknowledge_alert():
    repository.insert_alert(
        alert_type="flood",
        severity="high",
        src_ip="1.2.3.4",
        description="Flood detected",
    )
    alerts = repository.get_unacknowledged_alerts()
    alert_id = alerts[0]["id"]
    repository.acknowledge_alert(alert_id)
    assert repository.get_unacknowledged_alerts() == []


def test_insert_dns_query():
    repository.insert_dns_query(
        timestamp=datetime.now(UTC).isoformat(),
        src_ip="192.168.1.5",
        queried_domain="example.com",
        query_type="A",
        response_ip="93.184.216.34",
    )
    queries = repository.get_recent_dns_queries(limit=10)
    assert len(queries) == 1
    assert queries[0]["queried_domain"] == "example.com"


def test_upsert_ip_reputation():
    repository.upsert_ip_reputation(
        ip_address="1.2.3.4",
        abuse_score=90,
        is_blacklisted=True,
        source="abuseipdb",
    )
    rep = repository.get_ip_reputation("1.2.3.4")
    assert rep is not None
    assert rep["is_blacklisted"] == 1


def test_upsert_ip_reputation_updates_existing():
    repository.upsert_ip_reputation("5.5.5.5", abuse_score=10, is_blacklisted=False, source="test")
    repository.upsert_ip_reputation("5.5.5.5", abuse_score=95, is_blacklisted=True, source="abuseipdb")
    rep = repository.get_ip_reputation("5.5.5.5")
    assert rep is not None
    assert rep["abuse_score"] == 95
    assert rep["is_blacklisted"] == 1


def test_get_flow_stats():
    now = datetime.now(UTC)
    for i in range(3):
        repository.insert_flow({
            "timestamp": now.isoformat(),
            "src_ip": f"10.0.0.{i}",
            "dst_ip": "8.8.8.8",
            "protocol": "TCP",
            "bytes": 1000,
        })
    stats = repository.get_flow_stats(since=now - timedelta(minutes=1))
    assert stats["total_flows"] == 3
    assert stats["total_bytes"] == 3000


def test_get_top_ips():
    now = datetime.now(UTC)
    repository.insert_flow({"timestamp": now.isoformat(), "src_ip": "1.1.1.1", "dst_ip": "8.8.8.8", "protocol": "TCP", "bytes": 5000})
    repository.insert_flow({"timestamp": now.isoformat(), "src_ip": "2.2.2.2", "dst_ip": "8.8.8.8", "protocol": "TCP", "bytes": 1000})
    top = repository.get_top_ips(limit=5)
    assert top[0]["ip"] == "1.1.1.1"
    assert top[0]["total_bytes"] == 5000


def test_clear_all_alerts():
    repository.insert_alert(alert_type="flood", severity="high", description="Test")
    repository.insert_alert(alert_type="port_scan", severity="high", description="Test2")
    count = repository.clear_all_alerts()
    assert count == 2
    assert repository.get_unacknowledged_alerts() == []


def test_insert_and_get_report():
    repository.insert_report(
        report_type="daily",
        file_path="/tmp/report.html",
        fmt="html",
        period_start="2026-05-14T00:00:00",
        period_end="2026-05-14T23:59:59",
    )
    reports = repository.get_reports()
    assert len(reports) == 1
    assert reports[0]["report_type"] == "daily"
