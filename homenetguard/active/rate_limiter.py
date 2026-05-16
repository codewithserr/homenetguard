from __future__ import annotations

import platform
import shutil
import subprocess
from typing import Any

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)


class RateLimiter:
    def __init__(self) -> None:
        self._available = platform.system() == "Linux" and shutil.which("tc") is not None
        if not self._available:
            logger.warning("Rate limiter unavailable — requires Linux + tc (iproute2)")

    def throttle_ip(self, ip: str, max_kbps: int, interface: str = "eth0") -> bool:
        if not self._available:
            logger.warning("tc not available — cannot throttle %s", ip)
            return False
        try:
            subprocess.run(
                ["tc", "qdisc", "add", "dev", interface, "root", "handle", "1:", "htb", "default", "10"],
                capture_output=True, check=False,
            )
            class_id = abs(hash(ip)) % 9000 + 1000
            subprocess.run([
                "tc", "class", "add", "dev", interface, "parent", "1:", "classid",
                f"1:{class_id}", "htb", "rate", f"{max_kbps}kbit",
            ], capture_output=True, check=True)
            subprocess.run([
                "tc", "filter", "add", "dev", interface, "protocol", "ip",
                "parent", "1:0", "prio", "1", "u32", "match", "ip", "dst", ip,
                "flowid", f"1:{class_id}",
            ], capture_output=True, check=True)
            logger.info("Throttled %s to %d kbps", ip, max_kbps)
            return True
        except subprocess.CalledProcessError as exc:
            logger.error("tc throttle error for %s: %s", ip, exc)
            return False

    def remove_throttle(self, ip: str, interface: str = "eth0") -> bool:
        if not self._available:
            return False
        try:
            class_id = abs(hash(ip)) % 9000 + 1000
            subprocess.run(
                ["tc", "class", "del", "dev", interface, "classid", f"1:{class_id}"],
                capture_output=True,
            )
            logger.info("Removed throttle for %s", ip)
            return True
        except Exception as exc:
            logger.error("tc remove error: %s", exc)
            return False

    def list_throttled(self) -> list[dict[str, Any]]:
        if not self._available:
            return []
        try:
            result = subprocess.run(["tc", "class", "show"], capture_output=True, text=True)
            return [{"raw": line} for line in result.stdout.splitlines() if "htb" in line]
        except Exception:
            return []
