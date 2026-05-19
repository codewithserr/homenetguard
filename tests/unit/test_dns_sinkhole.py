import pytest

from homenetguard.active.dns_sinkhole import DNSSinkhole
from homenetguard.storage import database


@pytest.fixture(autouse=True)
def in_memory_db(tmp_path):
    database.init_db(str(tmp_path / "test.db"))


def test_add_and_is_blocked():
    sink = DNSSinkhole()
    sink.add_domain("evil.com")
    assert sink.is_blocked("evil.com") is True


def test_subdomain_of_blocked_is_blocked():
    sink = DNSSinkhole()
    sink.add_domain("evil.com")
    assert sink.is_blocked("www.evil.com") is True
    assert sink.is_blocked("sub.sub.evil.com") is True


def test_unrelated_domain_not_blocked():
    sink = DNSSinkhole()
    sink.add_domain("evil.com")
    assert sink.is_blocked("google.com") is False
    assert sink.is_blocked("notevil.com") is False


def test_remove_domain():
    sink = DNSSinkhole()
    sink.add_domain("bad.com")
    assert sink.is_blocked("bad.com") is True
    sink.remove_domain("bad.com")
    assert sink.is_blocked("bad.com") is False


def test_list_rules():
    sink = DNSSinkhole()
    sink.add_domain("a.com", reason="test", source="unit-test")
    sink.add_domain("b.com")
    rules = sink.list_rules()
    domains = [r["domain"] for r in rules]
    assert "a.com" in domains
    assert "b.com" in domains


def test_domain_normalized_lowercase():
    sink = DNSSinkhole()
    sink.add_domain("EVIL.COM")
    assert sink.is_blocked("evil.com") is True
    assert sink.is_blocked("www.evil.com") is True


def test_empty_sinkhole_blocks_nothing():
    sink = DNSSinkhole()
    assert sink.is_blocked("anything.com") is False
