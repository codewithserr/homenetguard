from unittest.mock import patch

import pytest

from homenetguard.active.firewall import FirewallManager
from homenetguard.storage import database


@pytest.fixture(autouse=True)
def in_memory_db(tmp_path):
    database.init_db(str(tmp_path / "test.db"))


@pytest.fixture
def fw():
    return FirewallManager(backend="iptables")


def test_protected_ips_includes_localhost(fw):
    protected = fw._get_protected_ips()
    assert "127.0.0.1" in protected
    assert "::1" in protected


def test_cannot_block_localhost(fw):
    with pytest.raises(ValueError, match="protected"):
        fw.block_ip("127.0.0.1")


def test_cannot_block_loopback(fw):
    with pytest.raises(ValueError, match="protected"):
        fw.block_ip("::1")


def test_block_ip_saves_to_db(fw):
    with patch.object(fw, "_apply_block"):
        rule_id = fw.block_ip("1.2.3.4", reason="test block")
    assert isinstance(rule_id, int)
    assert rule_id > 0
    rules = fw.list_rules()
    assert any(r["target"] == "1.2.3.4" for r in rules)


def test_unblock_removes_from_db(fw):
    with patch.object(fw, "_apply_block"):
        rule_id = fw.block_ip("5.6.7.8", reason="test")
    with patch.object(fw, "_remove_block"):
        ok = fw.unblock(rule_id)
    assert ok is True
    rules = fw.list_rules()
    assert not any(r["id"] == rule_id and r["is_active"] for r in rules)


def test_unblock_nonexistent_returns_false(fw):
    result = fw.unblock(99999)
    assert result is False


def test_list_rules_initially_empty(fw):
    rules = fw.list_rules()
    assert isinstance(rules, list)


def test_save_rule_cidr(fw):
    with patch.object(fw, "_apply_block"):
        _rule_id = fw.block_cidr("10.0.0.0/8", reason="block subnet")
    rules = fw.list_rules()
    assert any(r["rule_type"] == "cidr" and "10.0.0.0" in r["target"] for r in rules)
