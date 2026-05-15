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

# Country centroid fallback — used when MaxMind DB is unavailable.
# Covers ~180 most common countries. lat/lon are approximate geographic centers.
COUNTRY_CENTROIDS: dict[str, tuple[float, float]] = {
    "US": (37.09, -95.71), "GB": (55.38, -3.44), "DE": (51.17, 10.45),
    "FR": (46.23, 2.21), "JP": (36.20, 138.25), "CN": (35.86, 104.19),
    "RU": (61.52, 105.32), "BR": (-14.24, -51.93), "IN": (20.59, 78.96),
    "AU": (-25.27, 133.78), "CA": (56.13, -106.35), "KR": (35.91, 127.77),
    "NL": (52.13, 5.29), "ES": (40.46, -3.75), "IT": (41.87, 12.57),
    "SE": (60.13, 18.64), "NO": (60.47, 8.47), "CH": (46.82, 8.23),
    "PL": (51.92, 19.15), "UA": (48.38, 31.17), "TR": (38.96, 35.24),
    "MX": (23.63, -102.55), "AR": (-38.42, -63.62), "ZA": (-30.56, 22.94),
    "NG": (9.08, 8.68), "EG": (26.82, 30.80), "SA": (23.89, 45.08),
    "AE": (23.42, 53.85), "SG": (1.35, 103.82), "HK": (22.40, 114.11),
    "TW": (23.70, 120.96), "ID": (-0.79, 113.92), "MY": (4.21, 101.98),
    "TH": (15.87, 100.99), "VN": (14.06, 108.28), "PH": (12.88, 121.77),
    "PK": (30.38, 69.35), "BD": (23.68, 90.36), "IR": (32.43, 53.69),
    "IQ": (33.22, 43.68), "IL": (31.05, 34.85), "PT": (39.40, -8.22),
    "BE": (50.50, 4.47), "AT": (47.52, 14.55), "CZ": (49.82, 15.47),
    "HU": (47.16, 19.50), "RO": (45.94, 24.97), "FI": (61.92, 25.75),
    "DK": (56.26, 9.50), "SK": (48.67, 19.70), "BG": (42.73, 25.49),
    "HR": (45.10, 15.20), "GR": (39.07, 21.82), "LT": (55.17, 23.88),
    "LV": (56.88, 24.60), "EE": (58.60, 25.01), "NZ": (-40.90, 174.89),
    "CO": (4.57, -74.30), "CL": (-35.68, -71.54), "PE": (-9.19, -75.02),
    "VE": (6.42, -66.59), "EC": (-1.83, -78.18), "BO": (-16.29, -63.59),
    "UY": (-32.52, -55.77), "PY": (-23.44, -58.44), "KE": (-0.02, 37.91),
    "GH": (7.95, -1.02), "TZ": (-6.37, 34.89), "ET": (9.15, 40.49),
    "MA": (31.79, -7.09), "DZ": (28.03, 1.66), "TN": (33.89, 9.54),
    "LY": (26.34, 17.23), "SD": (12.86, 30.22), "AO": (-11.20, 17.87),
    "MZ": (-18.67, 35.53), "ZW": (-19.02, 29.15), "CM": (3.85, 11.50),
    "SN": (14.50, -14.45), "CI": (7.54, -5.55), "UZ": (41.38, 64.59),
    "KZ": (48.02, 66.92), "MM": (16.87, 96.19), "AF": (33.93, 67.71),
    "NP": (28.39, 84.12), "LK": (7.87, 80.77), "CU": (21.52, -77.78),
    "DO": (18.74, -70.16), "GT": (15.78, -90.23), "HN": (15.20, -86.24),
    "SV": (13.79, -88.90), "NI": (12.87, -85.21), "CR": (9.75, -83.75),
    "PA": (8.54, -80.78), "JM": (18.11, -77.30), "BY": (53.71, 27.95),
    "RS": (44.02, 21.01), "BA": (43.92, 17.68), "AL": (41.15, 20.17),
    "MK": (41.61, 21.75), "MD": (47.41, 28.37), "GE": (42.32, 43.36),
    "AM": (40.07, 45.04), "AZ": (40.14, 47.58), "KW": (29.31, 47.48),
    "QA": (25.35, 51.18), "BH": (26.07, 50.56), "OM": (21.51, 55.92),
    "YE": (15.55, 48.52), "JO": (30.59, 36.24), "LB": (33.85, 35.86),
    "SY": (34.80, 38.99), "KH": (12.57, 104.99), "LA": (19.86, 102.50),
}


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

    def lookup(self, ip: str) -> dict[str, Any]:
        empty: dict[str, Any] = {
            "country": None, "city": None, "country_code": None,
            "lat": None, "lon": None,
        }
        if not self._available or not self._reader:
            return empty
        try:
            r = self._reader.city(ip)
            lat = r.location.latitude
            lon = r.location.longitude
            # Fall back to country centroid if city has no coordinates
            if (lat is None or lon is None) and r.country.iso_code:
                lat, lon = COUNTRY_CENTROIDS.get(r.country.iso_code, (None, None))
            return {
                "country": r.country.name,
                "country_code": r.country.iso_code,
                "city": r.city.name,
                "lat": lat,
                "lon": lon,
            }
        except Exception:
            return empty

    def lookup_by_country_code(self, country_code: str) -> tuple[float, float] | tuple[None, None]:
        return COUNTRY_CENTROIDS.get(country_code, (None, None))

    def close(self) -> None:
        if self._reader:
            self._reader.close()
