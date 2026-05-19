from __future__ import annotations

from pathlib import Path
from typing import Any

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)


class PcapReader:
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config

    def analyze_file(self, file_path: str) -> dict[str, Any]:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"PCAP file not found: {file_path}")

        try:
            import pyshark  # type: ignore[import]
        except ImportError:
            raise RuntimeError("pyshark not installed — install with: pip install pyshark") from None

        stats: dict[str, Any] = {
            "file": str(path),
            "total_packets": 0,
            "total_bytes": 0,
            "protocols": {},
            "top_src_ips": {},
            "top_dst_ips": {},
        }

        try:
            cap = pyshark.FileCapture(str(path), keep_packets=False)
            for pkt in cap:
                stats["total_packets"] += 1
                try:
                    stats["total_bytes"] += int(pkt.length)
                except AttributeError:
                    pass
                try:
                    proto = pkt.highest_layer
                    stats["protocols"][proto] = stats["protocols"].get(proto, 0) + 1
                except AttributeError:
                    pass
                try:
                    src = pkt.ip.src
                    stats["top_src_ips"][src] = stats["top_src_ips"].get(src, 0) + 1
                except AttributeError:
                    pass
                try:
                    dst = pkt.ip.dst
                    stats["top_dst_ips"][dst] = stats["top_dst_ips"].get(dst, 0) + 1
                except AttributeError:
                    pass
            cap.close()
        except Exception as exc:
            logger.error("Error reading PCAP %s: %s", file_path, exc)
            raise

        stats["top_src_ips"] = dict(
            sorted(stats["top_src_ips"].items(), key=lambda x: -x[1])[:20]
        )
        stats["top_dst_ips"] = dict(
            sorted(stats["top_dst_ips"].items(), key=lambda x: -x[1])[:20]
        )
        return stats
