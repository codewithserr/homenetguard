from __future__ import annotations

import threading
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from homenetguard.analysis.dns_analyzer import DNSAnalyzer
from homenetguard.analysis.geo_lookup import GeoLookup
from homenetguard.analysis.reputation import is_private_ip
from homenetguard.analysis.threat_detector import ThreatDetector
from homenetguard.analysis.traffic_analyzer import TrafficAnalyzer
from homenetguard.storage import repository
from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

try:
    from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Packet, sniff  # type: ignore[import]  # noqa: F401
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False


class Sniffer:
    def __init__(
        self,
        config: dict[str, Any],
        on_packet: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self._cfg = config
        self._on_packet = on_packet
        self._running = False
        self._thread: threading.Thread | None = None
        self._interface = config.get("network", {}).get("interface", "auto")
        self._capture_filter = config.get("network", {}).get("capture_filter", "")

        geo_path = config.get("geoip", {}).get("db_path", "config/geoip/GeoLite2-City.mmdb")
        self._geo = GeoLookup(geo_path)
        self._threat = ThreatDetector(config)
        self._dns = DNSAnalyzer(self._threat)
        self._traffic = TrafficAnalyzer()
        self._packets_captured = 0
        self._started_at: datetime | None = None

    def start(self, interface: str | None = None) -> None:
        if not _SCAPY_AVAILABLE:
            raise RuntimeError("scapy not installed — cannot capture packets")
        if self._running:
            logger.warning("Sniffer already running")
            return

        iface = interface or self._interface
        if iface == "auto":
            from homenetguard.capture.interface_detector import get_active_interface
            iface = get_active_interface()

        self._running = True
        self._started_at = datetime.now(UTC)
        logger.info("Starting capture on %s", iface)
        self._thread = threading.Thread(
            target=self._capture_loop,
            args=(iface,),
            daemon=True,
            name="sniffer",
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        logger.info("Sniffer stopped. Captured %d packets", self._packets_captured)

    def is_running(self) -> bool:
        return self._running

    def get_stats(self) -> dict[str, Any]:
        uptime = 0
        if self._started_at:
            uptime = int((datetime.now(UTC) - self._started_at).total_seconds())
        return {
            "running": self._running,
            "packets_captured": self._packets_captured,
            "uptime_seconds": uptime,
            "current_bps": self._traffic.get_current_bps(),
        }

    def get_traffic_analyzer(self) -> TrafficAnalyzer:
        return self._traffic

    def _capture_loop(self, iface: str) -> None:
        def stop_filter(_: Any) -> bool:
            return not self._running

        try:
            sniff(
                iface=iface,
                prn=self._process_packet,
                filter=self._capture_filter or None,
                store=False,
                stop_filter=stop_filter,
            )
        except Exception as exc:
            logger.error("Capture error on %s: %s", iface, exc)
            self._running = False

    def _process_packet(self, pkt: Any) -> None:
        self._packets_captured += 1
        try:
            flow = self._packet_to_flow(pkt)
            if flow:
                self._traffic.record_bytes(flow.get("bytes", 0))
                repository.insert_flow(flow)
                self._threat.analyze_flow(flow)
                if self._on_packet:
                    self._on_packet(flow)
        except Exception as exc:
            logger.debug("Packet processing error: %s", exc)

    def _packet_to_flow(self, pkt: Any) -> dict[str, Any] | None:
        if not _SCAPY_AVAILABLE:
            return None

        try:
            if pkt.haslayer("ARP"):
                arp = pkt["ARP"]
                self._threat.analyze_arp(
                    arp.psrc, arp.hwsrc, datetime.now(UTC).isoformat()
                )

            if not pkt.haslayer("IP"):
                return None

            ip = pkt["IP"]
            src_ip: str = ip.src
            dst_ip: str = ip.dst
            byte_count: int = len(pkt)
            proto = "OTHER"
            src_port = None
            dst_port = None

            if pkt.haslayer("TCP"):
                proto = "TCP"
                src_port = pkt["TCP"].sport
                dst_port = pkt["TCP"].dport
            elif pkt.haslayer("UDP"):
                proto = "UDP"
                src_port = pkt["UDP"].sport
                dst_port = pkt["UDP"].dport
                if pkt.haslayer("DNS") and pkt["DNS"].qr == 0 and pkt.haslayer("DNSQR"):
                    domain = pkt["DNSQR"].qname.decode("utf-8", errors="replace").rstrip(".")
                    qtype = str(pkt["DNSQR"].qtype)
                    self._dns.process_dns_packet(src_ip, domain, qtype)
            elif pkt.haslayer("ICMP"):
                proto = "ICMP"

            src_geo = self._geo.lookup(src_ip)
            dst_geo = self._geo.lookup(dst_ip)

            return {
                "timestamp": datetime.now(UTC).isoformat(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto,
                "bytes": byte_count,
                "packets": 1,
                "direction": self._classify_direction(src_ip, dst_ip),
                "src_country": src_geo.get("country"),
                "dst_country": dst_geo.get("country"),
                "src_city": src_geo.get("city"),
                "dst_city": dst_geo.get("city"),
            }
        except Exception as exc:
            logger.debug("Failed to parse packet: %s", exc)
            return None

    @staticmethod
    def _classify_direction(src: str, dst: str) -> str:
        src_private = is_private_ip(src)
        dst_private = is_private_ip(dst)
        if src_private and not dst_private:
            return "outbound"
        if not src_private and dst_private:
            return "inbound"
        return "local"
