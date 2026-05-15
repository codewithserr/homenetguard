from __future__ import annotations

import math
import time
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from homenetguard.storage import repository
from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)


class ThreatDetector:
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config.get("detection", {})
        self._port_scan_tracker: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"ports": set(), "first_seen": time.monotonic()}
        )
        self._flood_tracker: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"bytes": 0, "first_seen": time.monotonic()}
        )
        self._arp_tracker: dict[str, set[str]] = defaultdict(set)

    def analyze_flow(self, flow: dict[str, Any]) -> None:
        src_ip = flow.get("src_ip", "")
        dst_ip = flow.get("dst_ip", "")
        dst_port = flow.get("dst_port")
        protocol = flow.get("protocol", "")
        byte_count = flow.get("bytes", 0)
        timestamp = flow.get("timestamp", datetime.now(UTC).isoformat())

        self._check_blacklisted_ip(src_ip, dst_ip, timestamp)

        ps_cfg = self._cfg.get("port_scan", {})
        if ps_cfg.get("enabled") and dst_port and protocol in ("TCP", "UDP"):
            self._check_port_scan(src_ip, dst_ip, dst_port, timestamp, ps_cfg)

        flood_cfg = self._cfg.get("flood", {})
        if flood_cfg.get("enabled") and byte_count:
            self._check_flood(src_ip, byte_count, timestamp, flood_cfg)

    def analyze_arp(self, ip: str, mac: str, timestamp: str) -> None:
        self._arp_tracker[ip].add(mac)
        if len(self._arp_tracker[ip]) > 1:
            macs = list(self._arp_tracker[ip])
            repository.insert_alert(
                alert_type="arp_spoofing",
                severity="high",
                src_ip=ip,
                description=f"ARP spoofing: {ip} seen with MACs {macs}",
                raw_data={"ip": ip, "macs": macs},
                timestamp=timestamp,
            )

    def _check_blacklisted_ip(self, src_ip: str, dst_ip: str, timestamp: str) -> None:
        for ip in (src_ip, dst_ip):
            if not ip:
                continue
            rep = repository.get_ip_reputation(ip)
            if rep and rep.get("is_blacklisted"):
                repository.insert_alert(
                    alert_type="blacklisted_ip",
                    severity="critical",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    description=(
                        f"Traffic with blacklisted IP {ip} "
                        f"(score={rep.get('abuse_score', '?')})"
                    ),
                    timestamp=timestamp,
                )

    def _check_port_scan(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        timestamp: str,
        cfg: dict[str, Any],
    ) -> None:
        threshold_ports = cfg.get("threshold_ports", 15)
        threshold_seconds = cfg.get("threshold_seconds", 60)
        tracker = self._port_scan_tracker[src_ip]
        now = time.monotonic()

        if now - tracker["first_seen"] > threshold_seconds:
            tracker["ports"] = set()
            tracker["first_seen"] = now

        tracker["ports"].add(dst_port)

        if len(tracker["ports"]) >= threshold_ports:
            repository.insert_alert(
                alert_type="port_scan",
                severity="high",
                src_ip=src_ip,
                dst_ip=dst_ip,
                description=(
                    f"Port scan: {src_ip} contacted {len(tracker['ports'])} "
                    f"distinct ports in {threshold_seconds}s"
                ),
                raw_data={"ports": list(tracker["ports"])[:50]},
                timestamp=timestamp,
            )
            tracker["ports"] = set()
            tracker["first_seen"] = now

    def _check_flood(
        self,
        src_ip: str,
        byte_count: int,
        timestamp: str,
        cfg: dict[str, Any],
    ) -> None:
        threshold_bytes = cfg.get("threshold_mb", 10) * 1024 * 1024
        threshold_seconds = cfg.get("threshold_seconds", 30)
        tracker = self._flood_tracker[src_ip]
        now = time.monotonic()

        if now - tracker["first_seen"] > threshold_seconds:
            tracker["bytes"] = 0
            tracker["first_seen"] = now

        tracker["bytes"] += byte_count

        if tracker["bytes"] >= threshold_bytes:
            mb = tracker["bytes"] / (1024 * 1024)
            repository.insert_alert(
                alert_type="flood",
                severity="high",
                src_ip=src_ip,
                description=f"Traffic flood from {src_ip}: {mb:.1f} MB in {threshold_seconds}s",
                raw_data={"bytes": tracker["bytes"]},
                timestamp=timestamp,
            )
            tracker["bytes"] = 0
            tracker["first_seen"] = now

    def check_dns_anomaly(self, src_ip: str, domain: str, query_type: str) -> bool:
        dns_cfg = self._cfg.get("dns_anomaly", {})
        if not dns_cfg.get("enabled", True):
            return False
        max_len = dns_cfg.get("max_domain_length", 50)
        if len(domain) > max_len:
            return True
        if self._high_entropy(domain):
            return True
        return False

    @staticmethod
    def _high_entropy(domain: str) -> bool:
        subdomain = domain.split(".")[0] if "." in domain else domain
        if len(subdomain) < 10:
            return False
        freq: dict[str, float] = {}
        for c in subdomain:
            freq[c] = freq.get(c, 0) + 1
        entropy = -sum(
            (v / len(subdomain)) * math.log2(v / len(subdomain))
            for v in freq.values()
        )
        return entropy > 3.5
