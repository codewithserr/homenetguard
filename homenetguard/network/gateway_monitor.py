from __future__ import annotations

import socket
import subprocess
import threading
import time
from typing import Any

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)


class GatewayMonitor:
    def __init__(self) -> None:
        self._running = False
        self._last_stats: dict[str, Any] = {}

    def get_gateway_ip(self) -> str:
        """Detect gateway IP from routing table."""
        try:
            import platform
            if platform.system() == "Darwin":
                out = subprocess.check_output(["route", "-n", "get", "default"], text=True, timeout=5)
                for line in out.splitlines():
                    if "gateway:" in line:
                        return line.split("gateway:")[1].strip()
            else:
                out = subprocess.check_output(["ip", "route", "show", "default"], text=True, timeout=5)
                parts = out.split()
                if "via" in parts:
                    return parts[parts.index("via") + 1]
        except Exception:
            pass
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local = s.getsockname()[0]
            s.close()
            parts = local.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
        except Exception:
            return "192.168.1.1"

    def ping_latency(self, host: str, count: int = 4) -> dict[str, float]:
        """Measure latency to host. Returns {avg_ms, min_ms, max_ms, loss_pct}."""
        results: list[float] = []
        lost = 0
        for _ in range(count):
            ms = self._tcp_ping(host, 80)
            if ms is None:
                lost += 1
            else:
                results.append(ms)

        if not results:
            return {"avg_ms": -1, "min_ms": -1, "max_ms": -1, "loss_pct": 100.0}
        return {
            "avg_ms": sum(results) / len(results),
            "min_ms": min(results),
            "max_ms": max(results),
            "loss_pct": (lost / count) * 100,
        }

    def start_monitoring(self, interval_seconds: int = 30) -> None:
        if self._running:
            return
        self._running = True
        threading.Thread(
            target=self._monitor_loop, args=(interval_seconds,),
            daemon=True, name="gateway-monitor",
        ).start()

    def stop(self) -> None:
        self._running = False

    def get_last_stats(self) -> dict[str, Any]:
        return self._last_stats

    def _monitor_loop(self, interval: int) -> None:
        gw = self.get_gateway_ip()
        logger.info("Monitoring gateway %s", gw)
        while self._running:
            try:
                stats = self.ping_latency(gw)
                self._last_stats = {"gateway": gw, **stats}
                if stats["loss_pct"] > 50:
                    logger.warning("Gateway %s packet loss %.0f%%", gw, stats["loss_pct"])
            except Exception as exc:
                logger.error("Gateway monitor error: %s", exc)
            time.sleep(interval)

    def _tcp_ping(self, host: str, port: int) -> float | None:
        import time as t
        try:
            start = t.monotonic()
            s = socket.create_connection((host, port), timeout=2)
            elapsed = (t.monotonic() - start) * 1000
            s.close()
            return elapsed
        except Exception:
            return None
