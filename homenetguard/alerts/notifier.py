from __future__ import annotations

from typing import Any

from homenetguard.alerts.email_alert import EmailAlert
from homenetguard.alerts.telegram_alert import TelegramAlert
from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class Notifier:
    def __init__(self, config: dict[str, Any]) -> None:
        alerts_cfg = config.get("alerts", {})
        self._email = EmailAlert(alerts_cfg.get("email", {}))
        self._telegram = TelegramAlert(alerts_cfg.get("telegram", {}))
        self._email_min = alerts_cfg.get("email", {}).get("min_severity", "high")
        self._tg_min = alerts_cfg.get("telegram", {}).get("min_severity", "critical")

    def dispatch(
        self,
        alert_type: str,
        severity: str,
        description: str,
        src_ip: str | None = None,
    ) -> None:
        sev_val = _SEVERITY_ORDER.get(severity, 0)
        subject = f"[{severity.upper()}] {alert_type}"
        body = description
        if src_ip:
            body += f"\nSource IP: {src_ip}"

        if sev_val >= _SEVERITY_ORDER.get(self._email_min, 2):
            self._email.send(subject, body)

        if sev_val >= _SEVERITY_ORDER.get(self._tg_min, 3):
            self._telegram.send(f"*{subject}*\n{body}")
