from __future__ import annotations

import socket
from datetime import UTC, datetime
from typing import Any

import requests

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

_CEF_SEVERITY = {"low": 3, "medium": 5, "high": 7, "critical": 10}


class SIEMExporter:
    def export_alert_cef(self, alert: dict[str, Any]) -> str:
        sev = _CEF_SEVERITY.get(alert.get("severity", "low"), 3)
        ext = " ".join([
            f"src={alert.get('src_ip', '')}",
            f"dst={alert.get('dst_ip', '')}",
            f"msg={alert.get('description', '').replace('=', ':').replace('|', '/')}",
            f"start={alert.get('timestamp', '')}",
        ])
        alert_type = alert.get("alert_type", "unknown")
        return (
            f"CEF:0|HomeNetGuard|HNG|2.0|{alert_type}|"
            f"{alert_type.replace('_', ' ').title()}|{sev}|{ext}"
        )

    def send_syslog(self, message: str, host: str, port: int = 514) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(message.encode("utf-8"), (host, port))
            return True
        except Exception as exc:
            logger.error("Syslog send failed: %s", exc)
            return False

    def send_elastic(self, alert: dict[str, Any], host: str, port: int = 9200) -> bool:
        try:
            idx = f"homenetguard-{datetime.now(UTC).strftime('%Y.%m.%d')}"
            resp = requests.post(
                f"http://{host}:{port}/{idx}/_doc",
                json=alert,
                timeout=5,
            )
            resp.raise_for_status()
            return True
        except Exception as exc:
            logger.error("Elastic send failed: %s", exc)
            return False

    def send_graylog(self, alert: dict[str, Any], host: str, port: int = 12201) -> bool:
        try:
            gelf = {
                "version": "1.1",
                "host": "homenetguard",
                "short_message": alert.get("description", "HNG alert"),
                "timestamp": datetime.now(UTC).timestamp(),
                "level": 4,
                "_alert_type": alert.get("alert_type"),
                "_severity": alert.get("severity"),
                "_src_ip": alert.get("src_ip"),
                "_dst_ip": alert.get("dst_ip"),
            }
            resp = requests.post(
                f"http://{host}:{port}/gelf",
                json=gelf,
                timeout=5,
            )
            resp.raise_for_status()
            return True
        except Exception as exc:
            logger.error("Graylog send failed: %s", exc)
            return False

    def export_batch(self, alerts: list[dict[str, Any]], backend: str = "syslog",
                     host: str = "", port: int = 514) -> dict[str, Any]:
        sent, failed = 0, 0
        for alert in alerts:
            try:
                if backend == "syslog":
                    ok = self.send_syslog(self.export_alert_cef(alert), host, port)
                elif backend == "elastic":
                    ok = self.send_elastic(alert, host, port)
                elif backend == "graylog":
                    ok = self.send_graylog(alert, host, port)
                else:
                    ok = False
                if ok:
                    sent += 1
                else:
                    failed += 1
            except Exception:
                failed += 1
        return {"sent": sent, "failed": failed, "total": len(alerts)}
