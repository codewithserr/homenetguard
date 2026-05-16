from __future__ import annotations

import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import requests

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

FEEDS: dict[str, dict[str, str]] = {
    "feodo_tracker": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "type": "ip_list",
        "comment_char": "#",
    },
    "abuse_ssl": {
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        "type": "ip_list",
        "comment_char": "#",
    },
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
        "type": "domain_list",
        "comment_char": "#",
    },
}

_STATUS: dict[str, dict[str, Any]] = {}


class FeedManager:
    def __init__(self, feeds_path: str = "config/threat_feeds/") -> None:
        self._feeds_path = Path(feeds_path)
        self._feeds_path.mkdir(parents=True, exist_ok=True)
        self._running = False

    def update_all(self) -> dict[str, Any]:
        results: dict[str, Any] = {}
        for name in FEEDS:
            try:
                results[name] = self.update_feed(name)
            except Exception as exc:
                results[name] = {"error": str(exc)}
        return results

    def update_feed(self, feed_name: str) -> dict[str, Any]:
        if feed_name not in FEEDS:
            raise ValueError(f"Unknown feed: {feed_name}")
        feed = FEEDS[feed_name]
        resp = requests.get(feed["url"], timeout=30)
        resp.raise_for_status()
        lines = resp.text.splitlines()
        comment = feed.get("comment_char", "#")
        entries = [l.strip() for l in lines if l.strip() and not l.startswith(comment)]

        count = 0
        if feed["type"] == "ip_list":
            count = self._load_ips(entries, source=feed_name)
        elif feed["type"] == "domain_list":
            count = self._load_domains(entries, source=feed_name)

        stat = {"feed": feed_name, "entries": count, "updated_at": datetime.now(UTC).isoformat()}
        _STATUS[feed_name] = stat
        cache_path = self._feeds_path / f"{feed_name}.txt"
        cache_path.write_text(resp.text, encoding="utf-8")
        logger.info("Feed %s: %d entries loaded", feed_name, count)
        return stat

    def get_status(self) -> list[dict[str, Any]]:
        return list(_STATUS.values())

    def start_auto_update(self, interval_hours: int = 6) -> None:
        if self._running:
            return
        self._running = True
        threading.Thread(
            target=self._update_loop, args=(interval_hours * 3600,),
            daemon=True, name="feed-manager",
        ).start()

    def stop(self) -> None:
        self._running = False

    def _update_loop(self, interval: int) -> None:
        while self._running:
            try:
                self.update_all()
            except Exception as exc:
                logger.error("Feed update error: %s", exc)
            time.sleep(interval)

    def _load_ips(self, entries: list[str], source: str) -> int:
        from homenetguard.storage import repository
        count = 0
        for ip in entries:
            ip = ip.split()[0].strip()
            if ip and _valid_ip(ip):
                repository.upsert_ip_reputation(ip_address=ip, is_blacklisted=True, source=source)
                count += 1
        return count

    def _load_domains(self, entries: list[str], source: str) -> int:
        from homenetguard.storage.database import get_connection
        count = 0
        with get_connection() as conn:
            for line in entries:
                parts = line.split()
                domain = parts[-1] if parts else ""
                if domain and "." in domain and not domain.startswith("#"):
                    conn.execute(
                        "INSERT OR IGNORE INTO sinkhole_rules (domain, reason, source) VALUES (?,?,?)",
                        (domain.lower(), f"Feed: {source}", source),
                    )
                    count += 1
        return count


def _valid_ip(ip: str) -> bool:
    import socket
    try:
        socket.inet_aton(ip)
        return True
    except OSError:
        return False
