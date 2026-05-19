from homenetguard.analysis.cryptomining_detector import (
    MINING_POOL_DOMAINS,
    STRATUM_PORTS,
    is_cryptomining_traffic,
)


def test_stratum_port_detected():
    for port in [3333, 4444, 8333, 14433, 45700]:
        assert is_cryptomining_traffic(port) is True


def test_normal_ports_not_detected():
    for port in [80, 443, 22, 53, 8080]:
        assert is_cryptomining_traffic(port) is False


def test_known_pool_domain_detected():
    assert is_cryptomining_traffic(80, dst_domain="pool.supportxmr.com") is True
    assert is_cryptomining_traffic(80, dst_domain="ethermine.org") is True
    assert is_cryptomining_traffic(80, dst_domain="nanopool.org") is True


def test_subdomain_of_pool_detected():
    assert is_cryptomining_traffic(80, dst_domain="us.pool.supportxmr.com") is True


def test_normal_domain_not_detected():
    assert is_cryptomining_traffic(80, dst_domain="google.com") is False
    assert is_cryptomining_traffic(443, dst_domain="github.com") is False


def test_stratum_ports_set_not_empty():
    assert len(STRATUM_PORTS) >= 5


def test_mining_pool_domains_not_empty():
    assert len(MINING_POOL_DOMAINS) >= 10


def test_none_domain_uses_port_only():
    assert is_cryptomining_traffic(3333, dst_domain=None) is True
    assert is_cryptomining_traffic(80, dst_domain=None) is False
