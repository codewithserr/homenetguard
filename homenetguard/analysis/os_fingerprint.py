from __future__ import annotations

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

# (ttl_range, window_size_range, os_name, confidence)
_SIGNATURES: list[tuple[range, range, str, float]] = [
    (range(128, 129), range(65535, 65536), "Windows 10/11", 0.85),
    (range(128, 129), range(8192, 8193),   "Windows (legacy)", 0.75),
    (range(64, 65),   range(65535, 65536), "Linux 5.x",    0.80),
    (range(64, 65),   range(29200, 29201), "Linux (kernel)", 0.75),
    (range(64, 65),   range(65228, 65229), "macOS",         0.85),
    (range(64, 65),   range(65535, 65536), "macOS/Linux",   0.65),
    (range(255, 256), range(4128, 4129),   "Cisco/Router",  0.80),
    (range(255, 256), range(8192, 8193),   "Router/IoT",    0.70),
    (range(64, 65),   range(5840, 5841),   "Android",       0.75),
    (range(64, 65),   range(65535, 65536), "iOS",           0.70),
]

# Wider TTL buckets
_TTL_BUCKETS = [(range(1, 65), 64), (range(65, 129), 128), (range(129, 256), 255)]


def fingerprint_os(packet) -> tuple[str, float] | None:
    """
    Passive OS fingerprinting from a TCP SYN packet.
    Returns (os_name, confidence) or None if not a SYN or insufficient data.
    """
    try:
        if not packet.haslayer("TCP"):
            return None
        tcp = packet["TCP"]
        # Only SYN (flags=0x02) or SYN-ACK (0x12)
        if not (tcp.flags & 0x02):
            return None

        ip = packet.getlayer("IP") or packet.getlayer("IPv6")
        if ip is None:
            return None

        ttl = getattr(ip, "ttl", 64)
        window = tcp.window

        # Normalize TTL to nearest bucket
        norm_ttl = _normalize_ttl(ttl)

        for ttl_r, win_r, os_name, conf in _SIGNATURES:
            if norm_ttl in ttl_r and window in win_r:
                return (os_name, conf)

        # Fallback: TTL-only guess
        if norm_ttl == 128:
            return ("Windows", 0.55)
        if norm_ttl == 64:
            return ("Linux/macOS", 0.50)
        if norm_ttl == 255:
            return ("Network Device", 0.60)

        return None
    except Exception as exc:
        logger.debug("OS fingerprint error: %s", exc)
        return None


def _normalize_ttl(ttl: int) -> int:
    for r, bucket in _TTL_BUCKETS:
        if ttl in r:
            return bucket
    return ttl
