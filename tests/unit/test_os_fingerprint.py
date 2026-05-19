from unittest.mock import MagicMock

from homenetguard.analysis.os_fingerprint import _normalize_ttl, fingerprint_os


def _make_syn_packet(ttl: int, window: int) -> MagicMock:
    pkt = MagicMock()
    pkt.haslayer.side_effect = lambda layer: layer in ("TCP", "IP")
    tcp = MagicMock()
    tcp.flags = 0x02  # SYN
    tcp.window = window
    pkt.__getitem__ = lambda self, key: tcp if key == "TCP" else None
    ip = MagicMock()
    ip.ttl = ttl
    pkt.getlayer.side_effect = lambda layer: ip if layer in ("IP", "IPv6") else None
    return pkt


def test_windows_fingerprint():
    pkt = _make_syn_packet(ttl=128, window=65535)
    result = fingerprint_os(pkt)
    assert result is not None
    os_name, conf = result
    assert "Windows" in os_name
    assert 0.5 <= conf <= 1.0


def test_linux_fingerprint():
    pkt = _make_syn_packet(ttl=64, window=29200)
    result = fingerprint_os(pkt)
    assert result is not None
    os_name, conf = result
    assert "Linux" in os_name or "macOS" in os_name


def test_non_syn_returns_none():
    pkt = MagicMock()
    pkt.haslayer.side_effect = lambda layer: layer == "TCP"
    tcp = MagicMock()
    tcp.flags = 0x10  # ACK only, not SYN
    pkt.__getitem__ = lambda self, key: tcp
    result = fingerprint_os(pkt)
    assert result is None


def test_no_ip_returns_none():
    pkt = MagicMock()
    pkt.haslayer.return_value = False
    result = fingerprint_os(pkt)
    assert result is None


def test_normalize_ttl():
    assert _normalize_ttl(64) == 64
    assert _normalize_ttl(128) == 128
    assert _normalize_ttl(255) == 255
    assert _normalize_ttl(50) == 64   # rounds up to 64 bucket
    assert _normalize_ttl(100) == 128  # rounds up to 128 bucket
