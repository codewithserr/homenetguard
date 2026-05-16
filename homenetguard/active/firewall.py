from __future__ import annotations

import platform
import subprocess
from datetime import UTC, datetime
from typing import Any

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

_HNG_CHAIN = "HNG_BLOCK"


class FirewallManager:
    def __init__(self, backend: str = "iptables") -> None:
        self._backend = backend
        self._os = platform.system()

    def block_ip(self, ip: str, direction: str = "both", reason: str = "", auto: bool = False) -> int:
        if ip in self._get_protected_ips():
            raise ValueError(f"Cannot block protected IP: {ip}")
        self._apply_block(ip, direction)
        return self._save_rule("ip", ip, direction, reason, auto)

    def block_cidr(self, cidr: str, reason: str = "") -> int:
        self._apply_block(cidr, "both")
        return self._save_rule("cidr", cidr, "both", reason, False)

    def block_port(self, port: int, proto: str = "tcp", reason: str = "") -> int:
        self._apply_port_block(port, proto)
        return self._save_rule("port", f"{port}/{proto}", "inbound", reason, False)

    def unblock(self, rule_id: int) -> bool:
        from homenetguard.storage.database import get_connection
        with get_connection() as conn:
            row = conn.execute("SELECT * FROM firewall_rules WHERE id=?", (rule_id,)).fetchone()
            if not row:
                return False
            rule = dict(row)
            conn.execute("UPDATE firewall_rules SET is_active=0 WHERE id=?", (rule_id,))
        self._remove_block(rule["target"], rule["direction"])
        return True

    def flush_hng_rules(self) -> None:
        """Remove only HNG-managed rules."""
        if self._os == "Linux":
            try:
                subprocess.run(["iptables", "-F", _HNG_CHAIN], capture_output=True)
            except Exception as exc:
                logger.warning("flush iptables: %s", exc)
        logger.info("HNG firewall rules flushed")

    def list_rules(self) -> list[dict[str, Any]]:
        from homenetguard.storage.database import get_connection
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM firewall_rules WHERE is_active=1 ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def cleanup_expired(self) -> None:
        from homenetguard.storage.database import get_connection
        now = datetime.now(UTC).isoformat()
        with get_connection() as conn:
            expired = conn.execute(
                "SELECT * FROM firewall_rules WHERE is_active=1 AND expires_at IS NOT NULL AND expires_at < ?",
                (now,),
            ).fetchall()
            for row in expired:
                self.unblock(row["id"])

    def _get_protected_ips(self) -> set[str]:
        protected = {"127.0.0.1", "::1", "0.0.0.0"}
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            protected.add(s.getsockname()[0])
            s.close()
            from homenetguard.network.gateway_monitor import GatewayMonitor
            protected.add(GatewayMonitor().get_gateway_ip())
        except Exception:
            pass
        return protected

    def _apply_block(self, target: str, direction: str) -> None:
        if self._os == "Linux":
            self._ensure_chain()
            cmds = []
            if direction in ("both", "inbound"):
                cmds.append(["iptables", "-A", _HNG_CHAIN, "-s", target, "-j", "DROP"])
            if direction in ("both", "outbound"):
                cmds.append(["iptables", "-A", _HNG_CHAIN, "-d", target, "-j", "DROP"])
            for cmd in cmds:
                try:
                    subprocess.run(cmd, check=True, capture_output=True)
                except subprocess.CalledProcessError as exc:
                    logger.error("iptables error: %s", exc.stderr.decode())
        elif self._os == "Darwin":
            logger.warning("macOS pf blocking not implemented — rule saved to DB only")
        logger.info("Blocked %s (%s)", target, direction)

    def _remove_block(self, target: str, direction: str) -> None:
        if self._os == "Linux":
            for flag, chain_dir in [("-s", "inbound"), ("-d", "outbound")]:
                if direction in ("both", chain_dir):
                    subprocess.run(
                        ["iptables", "-D", _HNG_CHAIN, flag, target, "-j", "DROP"],
                        capture_output=True,
                    )

    def _apply_port_block(self, port: int, proto: str) -> None:
        if self._os == "Linux":
            self._ensure_chain()
            try:
                subprocess.run(
                    ["iptables", "-A", _HNG_CHAIN, "-p", proto, "--dport", str(port), "-j", "DROP"],
                    check=True, capture_output=True,
                )
            except subprocess.CalledProcessError as exc:
                logger.error("iptables port block error: %s", exc.stderr.decode())

    def _ensure_chain(self) -> None:
        result = subprocess.run(["iptables", "-L", _HNG_CHAIN], capture_output=True)
        if result.returncode != 0:
            subprocess.run(["iptables", "-N", _HNG_CHAIN], capture_output=True)
            subprocess.run(["iptables", "-A", "INPUT", "-j", _HNG_CHAIN], capture_output=True)
            subprocess.run(["iptables", "-A", "OUTPUT", "-j", _HNG_CHAIN], capture_output=True)

    def _save_rule(self, rule_type: str, target: str, direction: str, reason: str, auto: bool) -> int:
        from homenetguard.storage.database import get_connection
        with get_connection() as conn:
            cur = conn.execute(
                "INSERT INTO firewall_rules (rule_type, target, direction, reason, auto_added) VALUES (?,?,?,?,?)",
                (rule_type, target, direction, reason, int(auto)),
            )
            return cur.lastrowid  # type: ignore[return-value]
