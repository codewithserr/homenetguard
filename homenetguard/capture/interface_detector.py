from __future__ import annotations

import socket

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

_CANDIDATES = ["eth0", "wlan0", "en0", "en1", "ens33", "ens3", "ens160"]


def get_active_interface() -> str:
    try:
        from scapy.interfaces import conf  # type: ignore[import]
        iface = str(conf.iface)
        if iface and iface not in ("lo", "lo0", "None"):
            logger.debug("Scapy detected interface: %s", iface)
            return iface
    except Exception:
        pass

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
        sock.close()
        logger.debug("Active interface IP: %s", local_ip)
        return _ip_to_interface(local_ip) or _CANDIDATES[0]
    except OSError:
        pass

    return _CANDIDATES[0]


def _ip_to_interface(ip: str) -> str | None:
    try:
        import netifaces  # type: ignore[import]  # noqa: F401
        import netifaces as ni
        for iface in ni.interfaces():
            addrs = ni.ifaddresses(iface)
            for addr in addrs.get(ni.AF_INET, []):
                if addr.get("addr") == ip:
                    return iface
    except ImportError:
        pass
    return None


def list_interfaces() -> list[str]:
    try:
        from scapy.arch import get_if_list  # type: ignore[import]
        return [i for i in get_if_list() if i not in ("lo", "lo0")]
    except Exception:
        return _CANDIDATES
