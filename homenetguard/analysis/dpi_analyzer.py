from __future__ import annotations

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

_PORT_MAP: dict[int, str] = {
    80: "HTTP", 8080: "HTTP", 8000: "HTTP",
    443: "HTTPS", 8443: "HTTPS",
    53: "DNS",
    21: "FTP", 20: "FTP",
    22: "SSH",
    25: "SMTP", 587: "SMTP", 465: "SMTP",
    110: "POP3", 995: "POP3",
    143: "IMAP", 993: "IMAP",
    6881: "BitTorrent", 6882: "BitTorrent", 6883: "BitTorrent",
    3333: "Stratum", 4444: "Stratum", 8333: "Stratum", 14433: "Stratum", 45700: "Stratum",
}

_HTTP_METHODS = {b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE", b"PATC", b"OPTI"}
_TLS_HELLO = b"\x16\x03"
_SSH_BANNER = b"SSH-"
_FTP_GREETING = b"220 "
_DNS_PORT = 53


def identify_application(packet_bytes: bytes, dst_port: int, src_port: int = 0) -> str | None:
    """Identify application-layer protocol from packet payload and ports."""
    if not packet_bytes:
        return _PORT_MAP.get(dst_port) or _PORT_MAP.get(src_port)

    try:
        payload = _extract_payload(packet_bytes)
    except Exception:
        payload = b""

    if dst_port == _DNS_PORT or src_port == _DNS_PORT:
        return "DNS"

    if payload:
        if payload[:2] == _TLS_HELLO:
            return "TLS"
        if payload[:4] in _HTTP_METHODS:
            return "HTTP"
        if payload[:4] == _SSH_BANNER:
            return "SSH"
        if payload[:4] == _FTP_GREETING:
            return "FTP"
        if _is_bittorrent(payload):
            return "BitTorrent"
        if _is_stratum(payload):
            return "Stratum"

    return _PORT_MAP.get(dst_port) or _PORT_MAP.get(src_port)


def _extract_payload(raw: bytes) -> bytes:
    try:
        import dpkt
        eth = dpkt.ethernet.Ethernet(raw)
        ip = eth.data
        if hasattr(ip, "data"):
            tcp_udp = ip.data
            if hasattr(tcp_udp, "data"):
                return bytes(tcp_udp.data)
    except Exception:
        pass
    return raw[:64] if raw else b""


def _is_bittorrent(payload: bytes) -> bool:
    return payload[:20] == b"\x13BitTorrent protocol" or payload[:4] == b"d1:a"


def _is_stratum(payload: bytes) -> bool:
    try:
        text = payload[:128].decode("utf-8", errors="ignore")
        return '"method":"mining.' in text or '"mining.' in text
    except Exception:
        return False
