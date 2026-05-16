from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

_HIGH_RISK_COUNTRIES = {"RU", "KP", "IR", "CN", "SY", "BY"}
_INSECURE_PORTS = {21, 23, 80, 5900}  # FTP, Telnet, HTTP, VNC


class ComplianceChecker:
    def run_checks(self) -> list[dict[str, Any]]:
        checks = [
            self._check_unencrypted_traffic(),
            self._check_high_risk_countries(),
            self._check_critical_alert_ratio(),
            self._check_zombie_devices(),
            self._check_blacklisted_contacts(),
        ]
        return checks

    def generate_score(self, checks: list[dict[str, Any]]) -> int:
        if not checks:
            return 100
        weights = {"critical": 30, "high": 20, "medium": 10, "low": 5}
        total_weight = sum(weights.get(c.get("severity", "low"), 5) for c in checks)
        if total_weight == 0:
            return 100
        failed_weight = sum(
            weights.get(c.get("severity", "low"), 5)
            for c in checks
            if not c.get("passed")
        )
        return max(0, int(100 - (failed_weight / total_weight) * 100))

    def _check_unencrypted_traffic(self) -> dict[str, Any]:
        from homenetguard.storage import repository
        since = datetime.now(UTC) - timedelta(hours=24)
        flows = repository.get_recent_flows(limit=1000)
        insecure = [f for f in flows if f.get("dst_port") in _INSECURE_PORTS]
        return {
            "check_id": "unencrypted_traffic",
            "description": "No unencrypted traffic on sensitive ports (FTP, Telnet, HTTP, VNC)",
            "passed": len(insecure) == 0,
            "severity": "high",
            "detail": f"{len(insecure)} flows on insecure ports in last 24h",
        }

    def _check_high_risk_countries(self) -> dict[str, Any]:
        from homenetguard.storage import repository
        flows = repository.get_recent_flows(limit=500)
        risky = [
            f for f in flows
            if f.get("dst_country") in _HIGH_RISK_COUNTRIES
            or f.get("src_country") in _HIGH_RISK_COUNTRIES
        ]
        return {
            "check_id": "high_risk_countries",
            "description": "No connections to high-risk country IPs",
            "passed": len(risky) == 0,
            "severity": "medium",
            "detail": f"{len(risky)} connections involving high-risk countries",
        }

    def _check_critical_alert_ratio(self) -> dict[str, Any]:
        from homenetguard.storage import repository
        alerts = repository.get_all_alerts(severity="critical", limit=100)
        since = datetime.now(UTC) - timedelta(hours=24)
        recent = [a for a in alerts if a.get("timestamp", "") >= since.isoformat()]
        passed = len(recent) < 5
        return {
            "check_id": "critical_alert_ratio",
            "description": "Fewer than 5 critical alerts in last 24h",
            "passed": passed,
            "severity": "critical",
            "detail": f"{len(recent)} critical alerts in last 24h",
        }

    def _check_zombie_devices(self) -> dict[str, Any]:
        from homenetguard.storage.database import get_connection
        cutoff = (datetime.now(UTC) - timedelta(days=30)).isoformat()
        with get_connection() as conn:
            zombies = conn.execute(
                "SELECT COUNT(*) FROM devices WHERE last_seen < ? AND is_trusted=0",
                (cutoff,),
            ).fetchone()
        count = zombies[0] if zombies else 0
        return {
            "check_id": "zombie_devices",
            "description": "No untrusted devices inactive for >30 days",
            "passed": count == 0,
            "severity": "low",
            "detail": f"{count} zombie devices found",
        }

    def _check_blacklisted_contacts(self) -> dict[str, Any]:
        from homenetguard.storage import repository
        alerts = repository.get_all_alerts(alert_type="blacklisted_ip", limit=50)
        since = datetime.now(UTC) - timedelta(hours=24)
        recent = [a for a in alerts if a.get("timestamp", "") >= since.isoformat()]
        return {
            "check_id": "blacklisted_ip_contacts",
            "description": "No communication with blacklisted IPs in last 24h",
            "passed": len(recent) == 0,
            "severity": "critical",
            "detail": f"{len(recent)} blacklisted IP contacts in last 24h",
        }
