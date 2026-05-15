from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any

import requests

from homenetguard.storage import repository
from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

_PRIVATE_RANGES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "::1", "fc", "fd",
)


def is_private_ip(ip: str) -> bool:
    return any(ip.startswith(r) for r in _PRIVATE_RANGES)


class ReputationChecker:
    def __init__(self, config: dict[str, Any]) -> None:
        self._abuse_cfg = config.get("threat_intelligence", {}).get("abuseipdb", {})
        self._cache_hours = self._abuse_cfg.get("cache_hours", 24)

    def check_ip(self, ip: str) -> dict[str, Any] | None:
        if is_private_ip(ip):
            return None

        cached = repository.get_ip_reputation(ip)
        if cached and cached.get("last_checked"):
            try:
                last = datetime.fromisoformat(cached["last_checked"])
                if last.tzinfo is None:
                    last = last.replace(tzinfo=UTC)
                if datetime.now(UTC) - last < timedelta(hours=self._cache_hours):
                    return cached
            except ValueError:
                pass

        if self._abuse_cfg.get("enabled") and self._abuse_cfg.get("api_key"):
            return self._query_abuseipdb(ip)

        return None

    def _query_abuseipdb(self, ip: str) -> dict[str, Any] | None:
        api_key = self._abuse_cfg.get("api_key") or os.getenv("ABUSEIPDB_API_KEY", "")
        if not api_key:
            return None
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            repository.upsert_ip_reputation(
                ip_address=ip,
                abuse_score=score,
                is_blacklisted=score >= 80,
                country=data.get("countryCode"),
                isp=data.get("isp"),
                source="abuseipdb",
            )
            return repository.get_ip_reputation(ip)
        except requests.RequestException as exc:
            logger.error("AbuseIPDB lookup failed for %s: %s", ip, exc)
            return None
