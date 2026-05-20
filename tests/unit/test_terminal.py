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
