from __future__ import annotations

import re
import shlex
import subprocess
import shutil
from collections.abc import Generator
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


# ─── Network utility runner ───────────────────────────────────

_NET_BINARIES = {"ping", "dig", "nslookup", "traceroute", "nmap"}
_DIG_RECORD_TYPES = {"A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR"}
_NMAP_FLAGS = {"-sn", "-sV", "-sT", "-O", "-p"}
_TIMEOUTS = {"ping": 15, "dig": 15, "nslookup": 15, "traceroute": 30, "nmap": 60}


class NetUtilRunner:
    def _build_argv(self, parsed: dict[str, Any]) -> list[str]:
        cmd = parsed["cmd"]
        args = list(parsed["args"])
        if cmd not in _NET_BINARIES:
            raise ParseError(f"{cmd!r} not allowed")

        # ── Argument validation (before binary check so tests don't need nmap/etc installed) ──

        if cmd == "ping":
            if "-c" in args:
                idx = args.index("-c")
                if idx + 1 >= len(args):
                    raise ParseError("ping -c requires a count value")
                count = min(int(args[idx + 1]), 10)
                args[idx + 1] = str(count)

        elif cmd == "nmap":
            if not args:
                raise ParseError("usage: nmap <ip> [flags]")
            ip = args[0]
            # Reject CIDR ranges
            if "/" in ip:
                raise ParseError("nmap accepts single IP only (no CIDR ranges)")
            # Validate flags
            flags = args[1:]
            i = 0
            while i < len(flags):
                flag = flags[i]
                if flag not in _NMAP_FLAGS:
                    raise ParseError(f"flag not allowed: {flag!r}")
                if flag == "-p":
                    if i + 1 >= len(flags):
                        raise ParseError("nmap -p requires a port specification")
                    port_spec = flags[i + 1]
                    # Allow digits, commas, hyphens, T: U: prefixes only
                    import re as _re
                    if not _re.match(r'^[0-9,\-TU:]{1,100}$', port_spec):
                        raise ParseError(f"invalid port specification: {port_spec!r}")
                    i += 2
                else:
                    i += 1

        elif cmd == "dig":
            if len(args) >= 2:
                rtype = args[1].upper()
                if rtype not in _DIG_RECORD_TYPES:
                    raise ParseError(f"record type {rtype!r} not allowed. Use: {', '.join(sorted(_DIG_RECORD_TYPES))}")
                args[1] = rtype

        # ── Binary lookup (after validation) ──
        binary = shutil.which(cmd)
        if not binary:
            raise ParseError(f"{cmd} not found on this system")

        if cmd == "ping":
            argv = [binary]
            if "-c" not in args and len(args) >= 1:
                # Default -c 4 if not specified
                argv += ["-c", "4"]
            argv += args
            return argv

        if cmd in ("nslookup", "traceroute"):
            # pass args as-is (host only, no flags)
            return [binary, args[0]] if args else [binary]

        return [binary] + args

    def run(self, parsed: dict[str, Any]) -> Generator[dict[str, Any], None, None]:
        import threading
        cmd = parsed["cmd"]
        if cmd not in _NET_BINARIES:
            raise ParseError(f"{cmd!r} not allowed")

        argv = self._build_argv(parsed)
        timeout = _TIMEOUTS.get(cmd, 30)

        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=False,
            env={"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"},
        )
        timer = threading.Timer(timeout, proc.kill)
        timer.start()
        try:
            for line in proc.stdout:
                yield {"line": line.rstrip(), "type": "stdout"}
            proc.wait()
            if proc.returncode == -9:  # killed by timer
                yield {"line": f"[timeout: {cmd} killed after {timeout}s]", "type": "error"}
        except GeneratorExit:
            proc.kill()
            proc.wait()
            return
        finally:
            timer.cancel()
            if proc.poll() is None:
                proc.kill()
                proc.wait()


from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

# ─── SocketIO terminal handler ────────────────────────────────

def register_terminal_handlers(socketio: Any) -> None:
    """Call from app.py after socketio is initialized."""

    @socketio.on("terminal:exec")
    def handle_terminal_exec(data: dict) -> None:
        from flask_socketio import emit
        raw = (data or {}).get("raw", "").strip()
        if not raw:
            emit("terminal:done", {"code": 1, "duration": 0})
            return

        try:
            parsed = CommandParser.parse(raw)
        except ParseError as exc:
            emit("terminal:out", {"line": f"Error: {exc}", "type": "error"})
            emit("terminal:done", {"code": 1, "duration": 0})
            return

        cmd = parsed["cmd"]
        import time
        t0 = time.monotonic()

        if cmd in _NET_BINARIES:
            runner = NetUtilRunner()
            try:
                for event in runner.run(parsed):
                    emit("terminal:out", event)
            except ParseError as exc:
                emit("terminal:out", {"line": f"Error: {exc}", "type": "error"})
                emit("terminal:done", {"code": 1, "duration": round(time.monotonic() - t0, 2)})
                return
        else:
            router = AppCommandRouter()
            result = router.execute(parsed)
            if cmd == "help" and result.get("ok"):
                lines = ["Available commands:", ""]
                for syntax, desc in result["commands"].items():
                    lines.append(f"  {syntax:<35} {desc}")
                for line in lines:
                    emit("terminal:out", {"line": line, "type": "stdout"})
            elif cmd == "devices" and result.get("ok"):
                devs = result.get("devices", [])
                emit("terminal:out", {"line": f"{'MAC':<20} {'IP':<18} {'HOSTNAME':<25} VENDOR", "type": "header"})
                for d in devs:
                    line = f"{d.get('mac_address','--'):<20} {d.get('ip_address','--'):<18} {d.get('hostname') or '--':<25} {d.get('vendor') or '--'}"
                    emit("terminal:out", {"line": line, "type": "stdout"})
            elif cmd == "flows" and result.get("ok"):
                flows = result.get("flows", [])
                emit("terminal:out", {"line": f"{result['count']} flows for that IP", "type": "info"})
                for f in flows:
                    ts = (f.get("timestamp") or "")[:19]
                    line = f"  {ts}  {f.get('src_ip','--')} → {f.get('dst_ip','--')}  {f.get('protocol','--')}  {f.get('bytes',0)}B"
                    emit("terminal:out", {"line": line, "type": "stdout"})
            elif cmd == "alerts" and result.get("ok"):
                alerts = result.get("alerts", [])
                emit("terminal:out", {"line": f"{result['count']} active alerts", "type": "info"})
                for a in alerts:
                    line = f"  [{a.get('severity','?').upper()}] {a.get('alert_type','--')} — {a.get('src_ip','--')}"
                    emit("terminal:out", {"line": line, "type": "stdout"})
            elif cmd == "whois" and result.get("ok"):
                data_out = result.get("data") or {}
                if data_out:
                    for k, v in data_out.items():
                        emit("terminal:out", {"line": f"  {k}: {v}", "type": "stdout"})
                else:
                    emit("terminal:out", {"line": result.get("msg", "no data"), "type": "info"})
            else:
                msg = result.get("msg") or result.get("error") or str(result)
                out_type = "success" if result.get("ok") else "error"
                emit("terminal:out", {"line": msg, "type": out_type})

        emit("terminal:done", {"code": 0, "duration": round(time.monotonic() - t0, 2)})
