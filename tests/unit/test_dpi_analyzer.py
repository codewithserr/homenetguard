import pytest
from homenetguard.analysis.dpi_analyzer import identify_application, _is_bittorrent, _is_stratum


def test_identify_http_by_port():
    assert identify_application(b"", 80) == "HTTP"
    assert identify_application(b"", 8080) == "HTTP"


def test_identify_https_by_port():
    assert identify_application(b"", 443) == "HTTPS"


def test_identify_dns_by_port():
    assert identify_application(b"", 53) == "DNS"
    assert identify_application(b"", 0, src_port=53) == "DNS"


def test_identify_http_by_payload():
    result = identify_application(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", 12345)
    assert result == "HTTP"


def test_identify_tls_by_payload():
    tls_client_hello = b"\x16\x03\x01\x00\x10" + b"\x00" * 16
    result = identify_application(tls_client_hello, 12345)
    assert result == "TLS"


def test_identify_ssh_by_payload():
    result = identify_application(b"SSH-2.0-OpenSSH_8.0", 22)
    assert result == "SSH"


def test_bittorrent_detection():
    assert _is_bittorrent(b"\x13BitTorrent protocol" + b"\x00" * 40) is True
    assert _is_bittorrent(b"d1:ad2:id20:aaaaaaaaaaaaaaaaaaaaee") is True
    assert _is_bittorrent(b"GET / HTTP/1.1") is False


def test_stratum_detection():
    assert _is_stratum(b'{"method":"mining.subscribe","id":1}') is True
    assert _is_stratum(b'{"mining.notify":true}') is True
    assert _is_stratum(b"GET / HTTP/1.1") is False


def test_unknown_returns_none_or_port_hint():
    result = identify_application(b"\x00\x01\x02\x03", 9999)
    assert result is None or isinstance(result, str)
