from __future__ import annotations

from typing import Any

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)


class QuarantineManager:
    def __init__(self) -> None:
        from homenetguard.active.firewall import FirewallManager
        self._fw = FirewallManager()

    def quarantine(self, mac: str) -> bool:
        """Block all outbound traffic from device except to gateway."""
        try:
            from homenetguard.storage.database import get_connection
            from homenetguard.network.gateway_monitor import GatewayMonitor
            gw = GatewayMonitor().get_gateway_ip()

            with get_connection() as conn:
                row = conn.execute(
                    "SELECT ip_address FROM devices WHERE mac_address=?", (mac.upper(),)
                ).fetchone()
                if not row:
                    logger.warning("Device %s not found in DB", mac)
                    return False
                ip = row["ip_address"]
                conn.execute(
                    "UPDATE devices SET is_quarantined=1 WHERE mac_address=?", (mac.upper(),)
                )

            # Block all outbound except gateway
            self._fw.block_ip(ip, direction="outbound", reason=f"Quarantine {mac}", auto=True)
            logger.info("Device %s (%s) quarantined", mac, ip)
            return True
        except Exception as exc:
            logger.error("Quarantine failed for %s: %s", mac, exc)
            return False

    def release(self, mac: str) -> bool:
        """Remove quarantine rules for device."""
        try:
            from homenetguard.storage.database import get_connection
            with get_connection() as conn:
                conn.execute(
                    "UPDATE devices SET is_quarantined=0 WHERE mac_address=?", (mac.upper(),)
                )
                rules = conn.execute(
                    "SELECT id FROM firewall_rules WHERE reason LIKE ? AND is_active=1",
                    (f"Quarantine {mac}%",),
                ).fetchall()
                for r in rules:
                    self._fw.unblock(r["id"])
            logger.info("Device %s released from quarantine", mac)
            return True
        except Exception as exc:
            logger.error("Release failed for %s: %s", mac, exc)
            return False

    def list_quarantined(self) -> list[dict[str, Any]]:
        from homenetguard.storage.database import get_connection
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM devices WHERE is_quarantined=1"
            ).fetchall()
        return [dict(r) for r in rows]
