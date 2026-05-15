import pytest
from homenetguard.analysis.geo_lookup import GeoLookup
from homenetguard.analysis.reputation import is_private_ip, ReputationChecker
from homenetguard.storage import database, repository


@pytest.fixture(autouse=True)
def in_memory_db(tmp_path):
    database.init_db(str(tmp_path / "test.db"))


# ─── GeoLookup ──────────────────────────────────────────────────
def test_geo_lookup_no_db_returns_empty():
    geo = GeoLookup("/nonexistent/path.mmdb")
    result = geo.lookup("8.8.8.8")
    assert result["country"] is None
    assert result["city"] is None


def test_geo_lookup_private_ip_returns_empty():
    geo = GeoLookup("/nonexistent/path.mmdb")
    result = geo.lookup("192.168.1.1")
    assert result["country"] is None


def test_geo_lookup_close_no_reader():
    geo = GeoLookup("/nonexistent/path.mmdb")
    geo.close()  # should not raise


# ─── is_private_ip ──────────────────────────────────────────────
@pytest.mark.parametrize("ip,expected", [
    ("192.168.1.1", True),
    ("10.0.0.1", True),
    ("172.16.0.1", True),
    ("127.0.0.1", True),
    ("8.8.8.8", False),
    ("1.1.1.1", False),
    ("203.0.113.1", False),
])
def test_is_private_ip(ip, expected):
    assert is_private_ip(ip) == expected


# ─── ReputationChecker ──────────────────────────────────────────
def test_reputation_private_ip_returns_none():
    checker = ReputationChecker({"threat_intelligence": {"abuseipdb": {"enabled": False}}})
    assert checker.check_ip("192.168.1.100") is None


def test_reputation_cached_result():
    repository.upsert_ip_reputation("8.8.8.8", abuse_score=0, is_blacklisted=False, source="test")
    checker = ReputationChecker({
        "threat_intelligence": {"abuseipdb": {"enabled": True, "api_key": "key", "cache_hours": 24}}
    })
    result = checker.check_ip("8.8.8.8")
    assert result is not None
    assert result["ip_address"] == "8.8.8.8"


def test_reputation_disabled_returns_none():
    checker = ReputationChecker({
        "threat_intelligence": {"abuseipdb": {"enabled": False, "api_key": "", "cache_hours": 24}}
    })
    result = checker.check_ip("8.8.8.8")
    assert result is None
