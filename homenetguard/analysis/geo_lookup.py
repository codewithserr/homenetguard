from __future__ import annotations

from pathlib import Path
from typing import Any

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

try:
    import geoip2.database
    import geoip2.errors
    _GEOIP2_AVAILABLE = True
except ImportError:
    _GEOIP2_AVAILABLE = False


class GeoLookup:
    def __init__(self, db_path: str = "config/geoip/GeoLite2-City.mmdb") -> None:
        self._reader: Any = None
        self._available = False
        if not _GEOIP2_AVAILABLE:
            logger.warning("geoip2 not installed — geo lookup disabled")
            return
        path = Path(db_path)
        if not path.exists():
            logger.warning("GeoIP DB not found at %s — run scripts/download_geoip.sh", db_path)
            return
        try:
            self._reader = geoip2.database.Reader(str(path))
            self._available = True
            logger.info("GeoIP DB loaded from %s", db_path)
        except Exception as exc:
            logger.error("Failed to load GeoIP DB: %s", exc)

    def lookup(self, ip: str) -> dict[str, str | None]:
        empty: dict[str, str | None] = {"country": None, "city": None, "country_code": None}
        if not self._available or not self._reader:
            return empty
        try:
            response = self._reader.city(ip)
            return {
                "country": response.country.name,
                "country_code": response.country.iso_code,
                "city": response.city.name,
            }
        except Exception:
            return empty

    def close(self) -> None:
        if self._reader:
            self._reader.close()
