from __future__ import annotations

import threading
import time
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Any

from homenetguard.storage import repository
from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)


class TrafficAnalyzer:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._byte_window: deque[tuple[float, int]] = deque()
        self._window_seconds = 1.0

    def record_bytes(self, byte_count: int) -> None:
        now = time.monotonic()
        with self._lock:
            self._byte_window.append((now, byte_count))
            cutoff = now - self._window_seconds
            while self._byte_window and self._byte_window[0][0] < cutoff:
                self._byte_window.popleft()

    def get_current_bps(self) -> int:
        with self._lock:
            return sum(b for _, b in self._byte_window)

    def get_top_talkers(self, limit: int = 10, minutes: int = 5) -> list[dict[str, Any]]:
        since = datetime.now(UTC) - timedelta(minutes=minutes)
        return repository.get_top_ips(limit=limit, since=since)

    def get_protocol_distribution(self, minutes: int = 60) -> list[dict[str, Any]]:
        since = datetime.now(UTC) - timedelta(minutes=minutes)
        return repository.get_protocol_distribution(since=since)

    def get_summary_stats(self, minutes: int = 60) -> dict[str, Any]:
        since = datetime.now(UTC) - timedelta(minutes=minutes)
        return repository.get_flow_stats(since=since)

    @staticmethod
    def format_bytes(byte_count: int) -> str:
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if byte_count < 1024:
                return f"{byte_count:.1f} {unit}"
            byte_count //= 1024
        return f"{byte_count:.1f} PB"
