import pytest
from datetime import UTC, datetime, timedelta
from homenetguard.analysis.traffic_analyzer import TrafficAnalyzer
from homenetguard.storage import database, repository


@pytest.fixture(autouse=True)
def in_memory_db(tmp_path):
    database.init_db(str(tmp_path / "test.db"))


@pytest.fixture
def populated_db():
    now = datetime.now(UTC)
    flows = [
        {"timestamp": now.isoformat(), "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8",
         "protocol": "TCP", "bytes": 5000, "dst_port": 80},
        {"timestamp": now.isoformat(), "src_ip": "10.0.0.1", "dst_ip": "1.1.1.1",
         "protocol": "UDP", "bytes": 3000, "dst_port": 53},
        {"timestamp": now.isoformat(), "src_ip": "10.0.0.2", "dst_ip": "8.8.8.8",
         "protocol": "TCP", "bytes": 1000, "dst_port": 443},
    ]
    for f in flows:
        repository.insert_flow(f)


def test_get_top_talkers(populated_db):
    analyzer = TrafficAnalyzer()
    top = analyzer.get_top_talkers(limit=5, minutes=60)
    assert top[0]["ip"] == "10.0.0.1"
    assert top[0]["total_bytes"] == 8000


def test_get_protocol_distribution(populated_db):
    analyzer = TrafficAnalyzer()
    dist = analyzer.get_protocol_distribution(minutes=60)
    protocols = {d["protocol"] for d in dist}
    assert "TCP" in protocols
    assert "UDP" in protocols


def test_record_and_get_bps():
    analyzer = TrafficAnalyzer()
    analyzer.record_bytes(1500)
    analyzer.record_bytes(500)
    assert analyzer.get_current_bps() == 2000


def test_format_bytes():
    analyzer = TrafficAnalyzer()
    assert "KB" in analyzer.format_bytes(2048)
    assert "MB" in analyzer.format_bytes(2 * 1024 * 1024)
    assert "B" in analyzer.format_bytes(500)


def test_get_summary_stats(populated_db):
    analyzer = TrafficAnalyzer()
    stats = analyzer.get_summary_stats(minutes=60)
    assert stats["total_flows"] == 3
    assert stats["total_bytes"] == 9000
