from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
from typing import Any

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)


class FlowCorrelator:
    def __init__(self, timeout_seconds: int = 120) -> None:
        self._sessions: dict[str, dict[str, Any]] = {}
        self._timeout = timeout_seconds

    def process_packet(self, packet: Any) -> str | None:
        """Group packet into a session by 5-tuple. Returns session_id if session closed."""
        try:
            key, direction = self._extract_key(packet)
            if not key:
                return None

            now = time.monotonic()
            pkt_len = len(packet) if hasattr(packet, "__len__") else 0

            if key not in self._sessions:
                self._sessions[key] = {
                    "id": str(uuid.uuid4()),
                    "key": key,
                    "start": now,
                    "last_seen": now,
                    "total_bytes": pkt_len,
                    "total_packets": 1,
                    "upload_bytes": pkt_len if direction == "up" else 0,
                    "download_bytes": pkt_len if direction == "down" else 0,
                }
                return None

            sess = self._sessions[key]
            sess["last_seen"] = now
            sess["total_bytes"] += pkt_len
            sess["total_packets"] += 1
            if direction == "up":
                sess["upload_bytes"] += pkt_len
            else:
                sess["download_bytes"] += pkt_len

            # Detect TCP FIN/RST
            if hasattr(packet, "haslayer") and packet.haslayer("TCP"):
                flags = packet["TCP"].flags
                if flags & 0x01 or flags & 0x04:  # FIN or RST
                    return self._close_session(key)
        except Exception as exc:
            logger.debug("Flow correlator error: %s", exc)
        return None

    def flush_expired(self, timeout_seconds: int | None = None) -> list[dict[str, Any]]:
        """Close and return sessions with no activity beyond timeout."""
        timeout = timeout_seconds or self._timeout
        now = time.monotonic()
        expired_keys = [
            k for k, s in self._sessions.items()
            if now - s["last_seen"] > timeout
        ]
        closed = []
        for k in expired_keys:
            result = self._close_session(k)
            if result:
                closed.append(self._sessions.pop(k, {}))
        return closed

    def _close_session(self, key: str) -> str | None:
        sess = self._sessions.pop(key, None)
        if not sess:
            return None
        try:
            from homenetguard.storage.database import get_connection
            now = datetime.now(UTC).isoformat()
            duration = time.monotonic() - sess["start"]
            parts = key.split(":")
            with get_connection() as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO sessions
                       (id, src_ip, dst_ip, src_port, dst_port, protocol,
                        start_time, end_time, duration_seconds, total_bytes,
                        total_packets, upload_bytes, download_bytes)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        sess["id"], parts[0] if len(parts) > 0 else "",
                        parts[2] if len(parts) > 2 else "",
                        int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None,
                        int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else None,
                        parts[4] if len(parts) > 4 else None,
                        datetime.fromtimestamp(sess["start"], UTC).isoformat(),
                        now, duration,
                        sess["total_bytes"], sess["total_packets"],
                        sess["upload_bytes"], sess["download_bytes"],
                    ),
                )
        except Exception as exc:
            logger.debug("Session persist error: %s", exc)
        return sess["id"]

    def _extract_key(self, packet: Any) -> tuple[str | None, str]:
        try:
            if not packet.haslayer("IP"):
                return None, "up"
            ip = packet["IP"]
            proto = "OTHER"
            sp, dp = 0, 0
            if packet.haslayer("TCP"):
                proto = "TCP"
                sp, dp = packet["TCP"].sport, packet["TCP"].dport
            elif packet.haslayer("UDP"):
                proto = "UDP"
                sp, dp = packet["UDP"].sport, packet["UDP"].dport
            # Normalize direction: smaller IP:port always first
            src, dst = f"{ip.src}:{sp}", f"{ip.dst}:{dp}"
            if src < dst:
                return f"{ip.src}:{sp}:{ip.dst}:{dp}:{proto}", "up"
            else:
                return f"{ip.dst}:{dp}:{ip.src}:{sp}:{proto}", "down"
        except Exception:
            return None, "up"
