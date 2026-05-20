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

def test_router_block_calls_firewall():
    with patch("homenetguard.dashboard.terminal.FirewallManager") as MockFW:
        instance = MockFW.return_value
        instance.block_ip.return_value = 42
        router = AppCommandRouter()
        result = router.execute({"cmd": "block", "args": ["192.168.1.5", "test reason"]})
    assert result["ok"] is True
    assert result["rule_id"] == 42
    instance.block_ip.assert_called_once_with("192.168.1.5", reason="test reason")

def test_router_unblock_by_ip():
    with patch("homenetguard.dashboard.terminal.FirewallManager") as MockFW:
        instance = MockFW.return_value
        instance.list_rules.return_value = [{"id": 7, "target": "10.0.0.1"}]
        instance.unblock.return_value = True
        router = AppCommandRouter()
        result = router.execute({"cmd": "unblock", "args": ["10.0.0.1"]})
    assert result["ok"] is True
    instance.unblock.assert_called_once_with(7)

def test_router_quarantine_calls_manager():
    with patch("homenetguard.dashboard.terminal.QuarantineManager") as MockQM:
        instance = MockQM.return_value
        instance.quarantine.return_value = True
        router = AppCommandRouter()
        result = router.execute({"cmd": "quarantine", "args": ["aa:bb:cc:dd:ee:ff"]})
    assert result["ok"] is True
    instance.quarantine.assert_called_once_with("aa:bb:cc:dd:ee:ff")

def test_router_sinkhole_calls_dns():
    with patch("homenetguard.dashboard.terminal.DNSSinkhole") as MockDS:
        instance = MockDS.return_value
        router = AppCommandRouter()
        result = router.execute({"cmd": "sinkhole", "args": ["evil.com"]})
    assert result["ok"] is True
    instance.add_domain.assert_called_once_with("evil.com", reason="terminal")

def test_router_help_returns_commands():
    router = AppCommandRouter()
    result = router.execute({"cmd": "help", "args": []})
    assert result["ok"] is True
    assert "commands" in result
    assert "block" in result["commands"]
    assert "ping" in result["commands"]


from unittest.mock import patch, MagicMock
from homenetguard.dashboard.terminal import NetUtilRunner, ParseError

def test_netutil_ping_yields_lines():
    runner = NetUtilRunner()
    mock_proc = MagicMock()
    mock_proc.stdout = iter(["PING 8.8.8.8\n", "64 bytes\n"])
    mock_proc.returncode = 0
    mock_proc.__enter__ = lambda s: s
    mock_proc.__exit__ = MagicMock(return_value=False)
    with patch("homenetguard.dashboard.terminal.subprocess.Popen", return_value=mock_proc):
        lines = list(runner.run({"cmd": "ping", "args": ["8.8.8.8", "-c", "2"]}))
    assert any("PING" in l["line"] for l in lines)

def test_netutil_rejects_unknown_binary():
    runner = NetUtilRunner()
    with pytest.raises(ParseError, match="not allowed"):
        list(runner.run({"cmd": "curl", "args": ["http://evil.com"]}))

def test_netutil_ping_count_capped_at_10():
    runner = NetUtilRunner()
    cmd = runner._build_argv({"cmd": "ping", "args": ["8.8.8.8", "-c", "999"]})
    c_idx = cmd.index("-c")
    assert int(cmd[c_idx + 1]) <= 10

def test_netutil_nmap_rejects_range():
    runner = NetUtilRunner()
    with pytest.raises(ParseError, match="single IP"):
        runner._build_argv({"cmd": "nmap", "args": ["192.168.1.0/24"]})

def test_netutil_nmap_rejects_bad_flag():
    runner = NetUtilRunner()
    with pytest.raises(ParseError, match="flag not allowed"):
        runner._build_argv({"cmd": "nmap", "args": ["192.168.1.1", "--script", "vuln"]})

def test_netutil_dig_allows_valid_type():
    runner = NetUtilRunner()
    cmd = runner._build_argv({"cmd": "dig", "args": ["example.com", "MX"]})
    assert "MX" in cmd

def test_netutil_dig_rejects_invalid_type():
    runner = NetUtilRunner()
    with pytest.raises(ParseError, match="record type"):
        runner._build_argv({"cmd": "dig", "args": ["example.com", "AXFR"]})
