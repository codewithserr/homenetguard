import pytest

from homenetguard.analysis.dns_analyzer import DNSAnalyzer
from homenetguard.analysis.threat_detector import ThreatDetector
from homenetguard.storage import database, repository


@pytest.fixture(autouse=True)
def in_memory_db(tmp_path):
    database.init_db(str(tmp_path / "test.db"))


def test_process_normal_dns():
    analyzer = DNSAnalyzer()
    analyzer.process_dns_packet("192.168.1.1", "google.com", "A", "142.250.80.46")
    queries = repository.get_recent_dns_queries()
    assert len(queries) == 1
    assert queries[0]["is_suspicious"] == 0
    assert queries[0]["response_ip"] == "142.250.80.46"


def test_process_suspicious_long_domain():
    cfg = {"detection": {"dns_anomaly": {"enabled": True, "max_domain_length": 20, "max_nxdomain_per_minute": 5}}}
    detector = ThreatDetector(cfg)
    analyzer = DNSAnalyzer(threat_detector=detector)
    long_domain = "a" * 25 + ".evil.com"
    analyzer.process_dns_packet("192.168.1.1", long_domain, "A")
    queries = repository.get_recent_dns_queries()
    assert queries[0]["is_suspicious"] == 1
    alerts = repository.get_unacknowledged_alerts()
    assert any(a["alert_type"] == "dns_anomaly" for a in alerts)


def test_top_domains():
    analyzer = DNSAnalyzer()
    for _ in range(3):
        analyzer.process_dns_packet("192.168.1.1", "example.com", "A")
    analyzer.process_dns_packet("192.168.1.1", "other.com", "A")
    top = analyzer.get_top_domains()
    assert top[0]["domain"] == "example.com"
    assert top[0]["count"] == 3


def test_get_suspicious_domains():
    cfg = {"detection": {"dns_anomaly": {"enabled": True, "max_domain_length": 10, "max_nxdomain_per_minute": 5}}}
    detector = ThreatDetector(cfg)
    analyzer = DNSAnalyzer(threat_detector=detector)
    analyzer.process_dns_packet("192.168.1.1", "ok.com", "A")
    analyzer.process_dns_packet("192.168.1.1", "verylongdomainname.evil.com", "A")
    suspicious = analyzer.get_suspicious_domains()
    assert len(suspicious) == 1
    assert "verylongdomainname" in suspicious[0]["queried_domain"]
