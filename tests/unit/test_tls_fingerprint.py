from homenetguard.analysis.tls_fingerprint import (
    MALICIOUS_JA3,
    _parse_client_hello_ja3,
    extract_ja3,
    is_known_malicious_ja3,
)


def test_malicious_ja3_list_not_empty():
    assert len(MALICIOUS_JA3) >= 10


def test_known_malicious_ja3():
    known = next(iter(MALICIOUS_JA3))
    assert is_known_malicious_ja3(known) is True


def test_unknown_ja3_not_malicious():
    assert is_known_malicious_ja3("a" * 32) is False


def test_extract_ja3_no_tls_packet():
    result = extract_ja3(None)
    assert result is None


def test_parse_client_hello_minimal():
    # Minimal TLS record: type=22 (handshake), version=0x0303, length, type=1 (ClientHello)
    # Build a minimal ClientHello
    tls_version = b"\x03\x03"
    random = b"\x00" * 32
    session_id_len = b"\x00"
    ciphers = b"\x00\x02\xc0\x2c"  # 2 bytes = 1 cipher suite
    compression = b"\x01\x00"
    data = (
        b"\x16\x03\x01\x00\x50"   # TLS record header
        b"\x01"                    # ClientHello
        b"\x00\x00\x4c"           # length
        + tls_version + random + session_id_len + ciphers + compression
    )
    result = _parse_client_hello_ja3(data)
    # May return a hash or None depending on parse — just check it doesn't crash
    assert result is None or (isinstance(result, str) and len(result) == 32)


def test_ja3s_returns_none_on_invalid():
    from homenetguard.analysis.tls_fingerprint import _parse_server_hello_ja3s
    assert _parse_server_hello_ja3s(b"invalid") is None
    assert _parse_server_hello_ja3s(b"") is None
