from __future__ import annotations

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)


class EmailAlert:
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config

    def send(self, subject: str, body: str) -> bool:
        cfg = self._cfg
        if not cfg.get("enabled"):
            return False
        required = ("smtp_host", "smtp_port", "smtp_user", "smtp_password", "recipient")
        for field in required:
            if not cfg.get(field):
                logger.warning("Email alert missing config field: %s", field)
                return False
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[HomeNetGuard] {subject}"
            msg["From"] = cfg["smtp_user"]
            msg["To"] = cfg["recipient"]
            msg.attach(MIMEText(body, "plain"))
            with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"]) as server:
                server.ehlo()
                server.starttls()
                server.login(cfg["smtp_user"], cfg["smtp_password"])
                server.send_message(msg)
            logger.info("Email alert sent: %s", subject)
            return True
        except Exception as exc:
            logger.error("Failed to send email: %s", exc)
            return False
