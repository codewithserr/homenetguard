from __future__ import annotations

import re
import shlex
from typing import Any

# ─── Known commands ───────────────────────────────────────────
_APP_COMMANDS = {
    "block", "unblock",
    "quarantine", "release",
    "sinkhole", "unsinkhole",
    "flows", "alerts", "whois", "devices", "help",
}
_NET_COMMANDS = {"ping", "dig", "nslookup", "traceroute", "nmap"}
_ALL_COMMANDS = _APP_COMMANDS | _NET_COMMANDS

# Characters that suggest shell injection attempts
_SHELL_META = re.compile(r'[;&|><`$\\\n\r]')


class ParseError(ValueError):
    pass


class CommandParser:
    @staticmethod
    def parse(raw: str) -> dict[str, Any]:
        raw = raw.strip()
        if not raw:
            raise ParseError("empty input")
        if _SHELL_META.search(raw):
            raise ParseError("invalid characters in input")
        try:
            tokens = shlex.split(raw)
        except ValueError as exc:
            raise ParseError(f"parse error: {exc}") from exc
        cmd = tokens[0].lower()
        if cmd not in _ALL_COMMANDS:
            raise ParseError(f"unknown command: {cmd!r}")
        # For app commands with a reason (block, sinkhole), rejoin trailing tokens
        args = tokens[1:]
        if cmd == "block" and len(args) > 1:
            args = [args[0], " ".join(args[1:])]
        return {"cmd": cmd, "args": args}


# ─── App command router ───────────────────────────────────────

_HELP_COMMANDS = {
    "block": "block <ip> [reason] — Add firewall rule",
    "unblock": "unblock <ip|rule_id> — Remove firewall rule",
    "quarantine": "quarantine <mac> — Quarantine device",
    "release": "release <mac> — Release from quarantine",
    "sinkhole": "sinkhole <domain> — Add domain to DNS sinkhole",
    "unsinkhole": "unsinkhole <domain> — Remove domain from sinkhole",
    "flows": "flows <ip> — Show recent flows for IP",
    "alerts": "alerts [ip] — Show active alerts",
    "whois": "whois <ip> — Show geo + reputation info",
    "devices": "devices — List known devices",
    "ping": "ping <host> [-c N] — Ping host (max 10 packets)",
    "dig": "dig <domain> [type] — DNS lookup",
    "nslookup": "nslookup <domain> — DNS name resolution",
    "traceroute": "traceroute <host> — Trace network path",
    "nmap": "nmap <ip> [-sn|-sV|-p ports] — Port scan (single IPs only)",
}

# Module-level names imported lazily inside methods but referenced here so
# patches on 'homenetguard.dashboard.terminal.X' resolve correctly at test time.
try:
    from homenetguard.active.firewall import FirewallManager
except Exception:
    FirewallManager = None  # type: ignore[assignment,misc]

try:
    from homenetguard.active.quarantine import QuarantineManager
except Exception:
    QuarantineManager = None  # type: ignore[assignment,misc]

try:
    from homenetguard.active.dns_sinkhole import DNSSinkhole
except Exception:
    DNSSinkhole = None  # type: ignore[assignment,misc]


class AppCommandRouter:
    def __init__(self) -> None:
        pass

    def execute(self, parsed: dict[str, Any]) -> dict[str, Any]:
        cmd = parsed["cmd"]
        args = parsed["args"]
        dispatch = {
            "block": self._block,
            "unblock": self._unblock,
            "quarantine": self._quarantine,
            "release": self._release,
            "sinkhole": self._sinkhole,
            "unsinkhole": self._unsinkhole,
            "flows": self._flows,
            "alerts": self._alerts,
            "whois": self._whois,
            "devices": self._devices,
            "help": self._help,
        }
        handler = dispatch.get(cmd)
        if handler is None:
            return {"ok": False, "error": f"unknown command: {cmd}"}
        try:
            return handler(args)
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    # ── Firewall ──
    def _block(self, args: list[str]) -> dict[str, Any]:
        if not args:
            return {"ok": False, "error": "usage: block <ip> [reason]"}
        ip = args[0]
        reason = args[1] if len(args) > 1 else "terminal"
        rule_id = FirewallManager().block_ip(ip, reason=reason)
        return {"ok": True, "rule_id": rule_id, "msg": f"Rule added — id:{rule_id} · IP blocked: {ip}"}

    def _unblock(self, args: list[str]) -> dict[str, Any]:
        if not args:
            return {"ok": False, "error": "usage: unblock <ip|rule_id>"}
        fw = FirewallManager()
        target = args[0]
        if target.isdigit():
            rule_id = int(target)
        else:
            rules = fw.list_rules()
            match = next((r for r in rules if r.get("target") == target), None)
            if not match:
                return {"ok": False, "error": f"no rule found for {target}"}
            rule_id = match["id"]
        ok = fw.unblock(rule_id)
        return {"ok": ok, "msg": f"Rule {rule_id} removed" if ok else "Rule not found"}

    # ── Quarantine ──
    def _quarantine(self, args: list[str]) -> dict[str, Any]:
        if not args:
            return {"ok": False, "error": "usage: quarantine <mac>"}
        ok = QuarantineManager().quarantine(args[0])
        return {"ok": ok, "msg": f"Device {args[0]} quarantined" if ok else "Quarantine failed"}

    def _release(self, args: list[str]) -> dict[str, Any]:
        if not args:
            return {"ok": False, "error": "usage: release <mac>"}
        ok = QuarantineManager().release(args[0])
        return {"ok": ok, "msg": f"Device {args[0]} released" if ok else "Release failed"}

    # ── DNS Sinkhole ──
    def _sinkhole(self, args: list[str]) -> dict[str, Any]:
        if not args:
            return {"ok": False, "error": "usage: sinkhole <domain>"}
        DNSSinkhole().add_domain(args[0], reason="terminal")
        return {"ok": True, "msg": f"Domain {args[0]} added to sinkhole"}

    def _unsinkhole(self, args: list[str]) -> dict[str, Any]:
        if not args:
            return {"ok": False, "error": "usage: unsinkhole <domain>"}
        DNSSinkhole().remove_domain(args[0])
        return {"ok": True, "msg": f"Domain {args[0]} removed from sinkhole"}

    # ── DB queries ──
    def _flows(self, args: list[str]) -> dict[str, Any]:
        if not args:
            return {"ok": False, "error": "usage: flows <ip>"}
        ip = args[0]
        from homenetguard.storage.database import get_connection
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT timestamp, src_ip, dst_ip, protocol, bytes FROM flows "
                "WHERE src_ip = ? OR dst_ip = ? ORDER BY timestamp DESC LIMIT 20",
                (ip, ip)
            ).fetchall()
        flows = [dict(r) for r in rows]
        return {"ok": True, "flows": flows, "count": len(flows)}

    def _alerts(self, args: list[str]) -> dict[str, Any]:
        from homenetguard.storage import repository
        alerts = repository.get_unacknowledged_alerts(limit=20)
        if args:
            ip = args[0]
            alerts = [a for a in alerts if a.get("src_ip") == ip or a.get("dst_ip") == ip]
        return {"ok": True, "alerts": alerts, "count": len(alerts)}

    def _whois(self, args: list[str]) -> dict[str, Any]:
        if not args:
            return {"ok": False, "error": "usage: whois <ip>"}
        from homenetguard.storage import repository
        rep = repository.get_ip_reputation(args[0])
        if not rep:
            return {"ok": True, "msg": f"No reputation data for {args[0]}"}
        return {"ok": True, "data": rep}

    def _devices(self, _args: list[str]) -> dict[str, Any]:
        from homenetguard.storage.database import get_connection
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT mac_address, ip_address, hostname, vendor, is_trusted FROM devices ORDER BY last_seen DESC LIMIT 30"
            ).fetchall()
        devices = [dict(r) for r in rows]
        return {"ok": True, "devices": devices, "count": len(devices)}

    def _help(self, _args: list[str]) -> dict[str, Any]:
        return {"ok": True, "commands": _HELP_COMMANDS}
