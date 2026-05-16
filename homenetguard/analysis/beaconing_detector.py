from __future__ import annotations

from datetime import datetime
from typing import Any

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)


def analyze_beaconing(
    ip: str,
    flows: list[dict[str, Any]],
    tolerance_pct: float = 10.0,
    min_connections: int = 6,
) -> bool:
    """
    Detect if flows from an IP show regular beacon intervals.
    Uses numpy std-dev of inter-arrival times.
    Returns True if beaconing pattern detected.
    """
    if len(flows) < min_connections:
        return False

    timestamps = _extract_timestamps(flows)
    if len(timestamps) < min_connections:
        return False

    timestamps.sort()
    try:
        import numpy as np
        intervals = np.diff(timestamps)
        if len(intervals) < 3:
            return False
        mean_interval = np.mean(intervals)
        if mean_interval < 1:
            return False
        std_interval = np.std(intervals)
        cv = (std_interval / mean_interval) * 100  # coefficient of variation
        logger.debug("Beaconing check %s: mean=%.1fs cv=%.1f%%", ip, mean_interval, cv)
        return cv <= tolerance_pct
    except ImportError:
        # numpy not available — fallback to stdlib
        return _stdlib_beaconing(timestamps, tolerance_pct)


def _extract_timestamps(flows: list[dict[str, Any]]) -> list[float]:
    timestamps = []
    for f in flows:
        ts = f.get("timestamp")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            timestamps.append(dt.timestamp())
        except (ValueError, TypeError):
            pass
    return timestamps


def _stdlib_beaconing(timestamps: list[float], tolerance_pct: float) -> bool:
    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
    if not intervals:
        return False
    mean = sum(intervals) / len(intervals)
    if mean < 1:
        return False
    variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
    std = variance ** 0.5
    cv = (std / mean) * 100
    return cv <= tolerance_pct
