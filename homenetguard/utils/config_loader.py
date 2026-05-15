from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

load_dotenv()

_DEFAULT_CONFIG_PATH = Path("config/config.yaml")
_EXAMPLE_CONFIG_PATH = Path("config/config.example.yaml")

_config: dict[str, Any] | None = None


def load_config(path: Path | None = None) -> dict[str, Any]:
    global _config
    config_path = path or _DEFAULT_CONFIG_PATH

    if not config_path.exists():
        if _EXAMPLE_CONFIG_PATH.exists():
            raise FileNotFoundError(
                f"Config not found at {config_path}. "
                f"Run: cp {_EXAMPLE_CONFIG_PATH} {config_path}"
            )
        raise FileNotFoundError(f"Config not found at {config_path}")

    with open(config_path) as f:
        _config = yaml.safe_load(f)

    _inject_env_secrets(_config)
    return _config


def get_config() -> dict[str, Any]:
    global _config
    if _config is None:
        _config = load_config()
    return _config


def reset_config() -> None:
    global _config
    _config = None


def _inject_env_secrets(cfg: dict[str, Any]) -> None:
    ti = cfg.get("threat_intelligence", {})
    if os.getenv("ABUSEIPDB_API_KEY"):
        ti.setdefault("abuseipdb", {})["api_key"] = os.environ["ABUSEIPDB_API_KEY"]
    if os.getenv("VT_API_KEY"):
        ti.setdefault("virustotal", {})["api_key"] = os.environ["VT_API_KEY"]

    alerts = cfg.get("alerts", {})
    if os.getenv("EMAIL_PASSWORD"):
        alerts.setdefault("email", {})["smtp_password"] = os.environ["EMAIL_PASSWORD"]
    if os.getenv("TELEGRAM_BOT_TOKEN"):
        alerts.setdefault("telegram", {})["bot_token"] = os.environ["TELEGRAM_BOT_TOKEN"]
