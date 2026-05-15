from __future__ import annotations

from typing import Any

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)


class TelegramAlert:
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config

    def send(self, message: str) -> bool:
        cfg = self._cfg
        if not cfg.get("enabled"):
            return False
        if not cfg.get("bot_token") or not cfg.get("chat_id"):
            logger.warning("Telegram alert missing bot_token or chat_id")
            return False
        try:
            import requests
            resp = requests.post(
                f"https://api.telegram.org/bot{cfg['bot_token']}/sendMessage",
                json={
                    "chat_id": cfg["chat_id"],
                    "text": f"🔒 *HomeNetGuard*\n{message}",
                    "parse_mode": "Markdown",
                },
                timeout=10,
            )
            resp.raise_for_status()
            logger.info("Telegram alert sent")
            return True
        except Exception as exc:
            logger.error("Failed to send Telegram alert: %s", exc)
            return False
