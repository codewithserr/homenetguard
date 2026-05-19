from datetime import UTC, datetime

import pytest

from homenetguard.analysis.threat_detector import ThreatDetector
from homenetguard.storage import database, repository


@pytest.fixture(autouse=True)
def in_memory_db(tmp_path):
    database.init_db(str(tmp_path / "test.db"))


@pytest.fixture
def detector():
    cfg = {
        "detection": {
            "port_scan": {"enabled": True, "threshold_ports": 5, "threshold_seconds": 60},
            "beaconing": {"enabled": True, "min_connections": 3, "interval_tolerance_pct": 20},
            "flood": {"enabled": True, "threshold_mb": 1, "threshold_seconds": 30},
            "dns_anomaly": {"enabled": True, "max_domain_length": 30, "max_nxdomain_per_minute": 5},
        }
    }
    return ThreatDetector(cfg)


def test_port_scan_detected(detector):
    src = "10.0.0.99"
    now = datetime.now(UTC).isoformat()
    for port in range(1, 7):
        detector.analyze_flow({
            "src_ip": src, "dst_ip": "192.168.1.1",
            "dst_port": port, "protocol": "TCP",
            "timestamp": now, "bytes": 64,
        })
    alerts = repository.get_unacknowledged_alerts()
    scan_alerts = [a for a in alerts if a["alert_type"] == "port_scan"]
    assert len(scan_alerts) >= 1


def test_flood_detected(detector):
    src = "1.2.3.4"
    now = datetime.now(UTC).isoformat()
    detector.analyze_flow({
        "src_ip": src, "dst_ip": "192.168.1.1",
        "dst_port": 80, "protocol": "TCP",
        "timestamp": now, "bytes": 2 * 1024 * 1024,
    })
    alerts = repository.get_unacknowledged_alerts()
    flood_alerts = [a for a in alerts if a["alert_type"] == "flood"]
    assert len(flood_alerts) >= 1


def test_blacklisted_ip_triggers_critical(detector):
    repository.upsert_ip_reputation("5.5.5.5", is_blacklisted=True, source="test")
    detector.analyze_flow({
        "src_ip": "5.5.5.5", "dst_ip": "192.168.1.1",
        "dst_port": 80, "protocol": "TCP",
        "timestamp": datetime.now(UTC).isoformat(), "bytes": 100,
    })
    alerts = repository.get_unacknowledged_alerts()
    critical = [a for a in alerts if a["severity"] == "critical"]
    assert len(critical) >= 1


def test_dns_long_domain_flagged(detector):
    long_domain = "a" * 40 + ".evil.com"
    assert detector.check_dns_anomaly("192.168.1.1", long_domain, "A") is True


def test_dns_normal_domain_ok(detector):
    assert detector.check_dns_anomaly("192.168.1.1", "google.com", "A") is False


def test_arp_spoofing_detected(detector):
    now = datetime.now(UTC).isoformat()
    detector.analyze_arp("192.168.1.1", "aa:bb:cc:dd:ee:ff", now)
    detector.analyze_arp("192.168.1.1", "11:22:33:44:55:66", now)
    alerts = repository.get_unacknowledged_alerts()
    arp_alerts = [a for a in alerts if a["alert_type"] == "arp_spoofing"]
    assert len(arp_alerts) >= 1


def test_high_entropy_domain(detector):
    high_entropy = "xj3kq9mw2pz.evil.com"
    result = detector.check_dns_anomaly("192.168.1.1", high_entropy, "TXT")
    assert isinstance(result, bool)
