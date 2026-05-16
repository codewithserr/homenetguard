from __future__ import annotations

import socket
import threading
import time
from datetime import UTC, datetime
from typing import Any

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)


def _load_oui_db(oui_path: str = "config/oui/oui.txt") -> dict[str, str]:
    db: dict[str, str] = {}
    try:
        with open(oui_path) as f:
            for line in f:
                if "(hex)" in line:
                    parts = line.split("(hex)")
                    if len(parts) == 2:
                        prefix = parts[0].strip().replace("-", ":").upper()
                        vendor = parts[1].strip()
                        db[prefix] = vendor
    except FileNotFoundError:
        pass
    return db


_OUI_DB: dict[str, str] | None = None


def lookup_vendor(mac: str) -> str:
    global _OUI_DB
    if _OUI_DB is None:
        _OUI_DB = _load_oui_db()
    prefix = mac.upper()[:8]
    return _OUI_DB.get(prefix, "Unknown")


def _detect_subnet() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        return "192.168.1.0/24"


def _resolve_hostname(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


class DeviceScanner:
    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._cfg = config or {}
        self._running = False
        self._thread: threading.Thread | None = None

    def scan(self, subnet: str = "auto") -> list[dict[str, Any]]:
        """ARP scan of subnet. Returns list of discovered devices."""
        if subnet == "auto":
            subnet = self._cfg.get("device_scanner", {}).get("subnet", "auto")
            if subnet == "auto":
                subnet = _detect_subnet()

        logger.info("Scanning subnet %s", subnet)
        discovered = self._arp_scan(subnet)
        self._update_device_db(discovered)
        return discovered

    def start_periodic_scan(self, interval_seconds: int = 300) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._scan_loop, args=(interval_seconds,),
            daemon=True, name="device-scanner",
        )
        self._thread.start()
        logger.info("Periodic device scan started (every %ds)", interval_seconds)

    def stop(self) -> None:
        self._running = False

    def _scan_loop(self, interval: int) -> None:
        while self._running:
            try:
                self.scan()
            except Exception as exc:
                logger.error("Device scan error: %s", exc)
            time.sleep(interval)

    def _arp_scan(self, subnet: str) -> list[dict[str, Any]]:
        try:
            from scapy.all import ARP, Ether, srp  # type: ignore[import]
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
            answered, _ = srp(pkt, timeout=2, verbose=False)
            results = []
            for _, rcv in answered:
                mac = rcv[Ether].src.upper()
                ip = rcv[ARP].psrc
                results.append({
                    "mac": mac,
                    "ip": ip,
                    "vendor": lookup_vendor(mac),
                    "hostname": _resolve_hostname(ip),
                })
            return results
        except Exception as exc:
            logger.warning("ARP scan failed: %s", exc)
            return []

    def _update_device_db(self, discovered: list[dict[str, Any]]) -> list[str]:
        from homenetguard.storage.database import get_connection
        new_macs: list[str] = []
        now = datetime.now(UTC).isoformat()
        with get_connection() as conn:
            for d in discovered:
                mac = d["mac"]
                existing = conn.execute(
                    "SELECT id FROM devices WHERE mac_address=?", (mac,)
                ).fetchone()
                if existing:
                    conn.execute(
                        "UPDATE devices SET ip_address=?, last_seen=?, vendor=COALESCE(vendor,?) WHERE mac_address=?",
                        (d["ip"], now, d.get("vendor"), mac),
                    )
                else:
                    conn.execute(
                        "INSERT INTO devices (mac_address, ip_address, vendor, hostname, first_seen, last_seen) VALUES (?,?,?,?,?,?)",
                        (mac, d["ip"], d.get("vendor"), d.get("hostname"), now, now),
                    )
                    new_macs.append(mac)
                conn.execute(
                    "INSERT INTO device_ip_history (mac_address, ip_address, seen_at) VALUES (?,?,?)",
                    (mac, d["ip"], now),
                )
        if new_macs:
            logger.info("New devices discovered: %s", new_macs)
        return new_macs
