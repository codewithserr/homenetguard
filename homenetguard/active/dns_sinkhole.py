from __future__ import annotations

import socket
import threading
from typing import Any

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)


class DNSSinkhole:
    def __init__(self) -> None:
        self._running = False
        self._thread: threading.Thread | None = None
        self._upstream = "8.8.8.8"
        self._port = 53
        self._blocked: set[str] = set()
        self._sock: socket.socket | None = None
        self._load_from_db()

    def start(self, port: int = 53, upstream: str = "8.8.8.8") -> None:
        if self._running:
            return
        self._port = port
        self._upstream = upstream
        self._running = True
        self._thread = threading.Thread(
            target=self._serve_loop, daemon=True, name="dns-sinkhole"
        )
        self._thread.start()
        logger.info("DNS sinkhole started on port %d (upstream: %s)", port, upstream)

    def stop(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    def add_domain(self, domain: str, reason: str = "", source: str = "manual") -> None:
        domain = domain.lower().rstrip(".")
        from homenetguard.storage.database import get_connection
        with get_connection() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO sinkhole_rules (domain, reason, source) VALUES (?,?,?)",
                (domain, reason, source),
            )
        self._blocked.add(domain)
        logger.info("Sinkhole: blocked %s", domain)

    def remove_domain(self, domain: str) -> None:
        domain = domain.lower().rstrip(".")
        from homenetguard.storage.database import get_connection
        with get_connection() as conn:
            conn.execute("UPDATE sinkhole_rules SET is_active=0 WHERE domain=?", (domain,))
        self._blocked.discard(domain)

    def is_blocked(self, domain: str) -> bool:
        domain = domain.lower().rstrip(".")
        if domain in self._blocked:
            return True
        # Check parent domains
        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self._blocked:
                return True
        return False

    def list_rules(self) -> list[dict[str, Any]]:
        from homenetguard.storage.database import get_connection
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM sinkhole_rules WHERE is_active=1 ORDER BY hits DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def _load_from_db(self) -> None:
        try:
            from homenetguard.storage.database import get_connection
            with get_connection() as conn:
                rows = conn.execute(
                    "SELECT domain FROM sinkhole_rules WHERE is_active=1"
                ).fetchall()
            self._blocked = {r["domain"] for r in rows}
        except Exception:
            pass

    def _serve_loop(self) -> None:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(("0.0.0.0", self._port))
            self._sock.settimeout(1.0)
            while self._running:
                try:
                    data, addr = self._sock.recvfrom(512)
                    response = self._handle_query(data, addr)
                    if response:
                        self._sock.sendto(response, addr)
                except TimeoutError:
                    continue
                except Exception as exc:
                    if self._running:
                        logger.debug("DNS sinkhole recv error: %s", exc)
        except Exception as exc:
            logger.error("DNS sinkhole failed to start: %s", exc)
        finally:
            if self._sock:
                self._sock.close()

    def _handle_query(self, data: bytes, client_addr: tuple) -> bytes | None:
        try:
            import dnslib
            request = dnslib.DNSRecord.parse(data)
            qname = str(request.q.qname).rstrip(".")

            if self.is_blocked(qname):
                self._increment_hits(qname)
                reply = request.reply()
                reply.add_answer(dnslib.RR(
                    qname,
                    dnslib.QTYPE.A,
                    rdata=dnslib.A("0.0.0.0"),
                    ttl=60,
                ))
                logger.info("Sinkhole blocked: %s from %s", qname, client_addr[0])
                return reply.pack()

            # Forward to upstream
            return self._forward(data)
        except Exception as exc:
            logger.debug("DNS handle error: %s", exc)
            return None

    def _forward(self, data: bytes) -> bytes | None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(3)
                s.sendto(data, (self._upstream, 53))
                return s.recv(512)
        except Exception:
            return None

    def _increment_hits(self, domain: str) -> None:
        try:
            from homenetguard.storage.database import get_connection
            with get_connection() as conn:
                conn.execute(
                    "UPDATE sinkhole_rules SET hits = hits + 1 WHERE domain=?", (domain,)
                )
        except Exception:
            pass
