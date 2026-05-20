import pytest
from homenetguard.dashboard.terminal import CommandParser, ParseError

def test_parse_block_ip():
    result = CommandParser.parse("block 192.168.1.5")
    assert result == {"cmd": "block", "args": ["192.168.1.5"]}

def test_parse_block_ip_with_reason():
    result = CommandParser.parse("block 192.168.1.5 suspicious traffic")
    assert result == {"cmd": "block", "args": ["192.168.1.5", "suspicious traffic"]}

def test_parse_ping_with_flag():
    result = CommandParser.parse("ping 8.8.8.8 -c 4")
    assert result == {"cmd": "ping", "args": ["8.8.8.8", "-c", "4"]}

def test_parse_empty_raises():
    with pytest.raises(ParseError, match="empty"):
        CommandParser.parse("   ")

def test_parse_unknown_command_raises():
    with pytest.raises(ParseError, match="unknown command"):
        CommandParser.parse("rm -rf /")

def test_parse_rejects_shell_metacharacters():
    for bad in ["block 1.2.3.4 && rm -rf", "ping 8.8.8.8; ls", "dig $(whoami)", "nmap 1.2.3.4 | cat"]:
        with pytest.raises(ParseError, match="invalid"):
            CommandParser.parse(bad)

def test_parse_help():
    result = CommandParser.parse("help")
    assert result == {"cmd": "help", "args": []}

def test_parse_devices():
    result = CommandParser.parse("devices")
    assert result == {"cmd": "devices", "args": []}

def test_parse_case_insensitive():
    result = CommandParser.parse("Block 192.168.1.1")
    assert result["cmd"] == "block"

def test_parse_unmatched_quote_raises():
    with pytest.raises(ParseError, match="parse error"):
        CommandParser.parse('block "unterminated')

def test_parse_newline_rejected():
    with pytest.raises(ParseError, match="invalid"):
        CommandParser.parse("block 192.168.1.1\nevil command")


from unittest.mock import MagicMock, patch
from homenetguard.dashboard.terminal import AppCommandRouter

def test_router_block_calls_firewall(tmp_db):
    with patch("homenetguard.dashboard.terminal.FirewallManager") as MockFW:
        instance = MockFW.return_value
        instance.block_ip.return_value = 42
        router = AppCommandRouter(db_path=tmp_db)
        result = router.execute({"cmd": "block", "args": ["192.168.1.5", "test reason"]})
    assert result["ok"] is True
    assert result["rule_id"] == 42
    instance.block_ip.assert_called_once_with("192.168.1.5", reason="test reason")

def test_router_unblock_by_ip(tmp_db):
    with patch("homenetguard.dashboard.terminal.FirewallManager") as MockFW:
        instance = MockFW.return_value
        instance.list_rules.return_value = [{"id": 7, "target": "10.0.0.1"}]
        instance.unblock.return_value = True
        router = AppCommandRouter(db_path=tmp_db)
        result = router.execute({"cmd": "unblock", "args": ["10.0.0.1"]})
    assert result["ok"] is True
    instance.unblock.assert_called_once_with(7)

def test_router_quarantine_calls_manager(tmp_db):
    with patch("homenetguard.dashboard.terminal.QuarantineManager") as MockQM:
        instance = MockQM.return_value
        instance.quarantine.return_value = True
        router = AppCommandRouter(db_path=tmp_db)
        result = router.execute({"cmd": "quarantine", "args": ["aa:bb:cc:dd:ee:ff"]})
    assert result["ok"] is True
    instance.quarantine.assert_called_once_with("aa:bb:cc:dd:ee:ff")

def test_router_sinkhole_calls_dns(tmp_db):
    with patch("homenetguard.dashboard.terminal.DNSSinkhole") as MockDS:
        instance = MockDS.return_value
        router = AppCommandRouter(db_path=tmp_db)
        result = router.execute({"cmd": "sinkhole", "args": ["evil.com"]})
    assert result["ok"] is True
    instance.add_domain.assert_called_once_with("evil.com", reason="terminal")

def test_router_help_returns_commands(tmp_db):
    router = AppCommandRouter(db_path=tmp_db)
    result = router.execute({"cmd": "help", "args": []})
    assert result["ok"] is True
    assert "commands" in result
    assert "block" in result["commands"]
    assert "ping" in result["commands"]
