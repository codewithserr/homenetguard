# Dashboard Terminal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a slide-up command terminal overlay to the dashboard that executes HomeNetGuard app actions and whitelisted network utilities, with click-to-fill from any data table and Tab autocomplete from the live DB.

**Architecture:** A new `terminal.py` module handles all server-side logic — command parsing, routing to existing managers (FirewallManager, QuarantineManager, DNSSinkhole), and whitelisted subprocess execution. A SocketIO event `terminal:exec` receives typed `{cmd, args}` objects (never raw shell strings) and streams back `terminal:out` / `terminal:done` events. A new `terminal.js` handles the browser-side UI, parser, WebSocket client, autocomplete, and click-to-fill injection.

**Tech Stack:** Python 3.13, Flask-SocketIO (already wired in `app.py`), subprocess (shell=False), pytest, vanilla JS (no new deps)

---

## File Map

| File | Status | Responsibility |
|------|--------|---------------|
| `homenetguard/dashboard/terminal.py` | Create | CommandParser, AppCommandRouter, NetUtilRunner, SocketIO handlers |
| `homenetguard/dashboard/routes.py` | Modify | Add `/api/v1/terminal/suggest` endpoint |
| `homenetguard/dashboard/app.py` | Modify | Import terminal module to register SocketIO handlers |
| `homenetguard/dashboard/templates/partials/terminal.html` | Create | Overlay panel HTML |
| `homenetguard/dashboard/templates/base.html` | Modify | Include terminal partial + CSS + JS |
| `homenetguard/dashboard/static/css/terminal.css` | Create | Overlay panel styles |
| `homenetguard/dashboard/static/js/terminal.js` | Create | Parser, WS client, UI, autocomplete, click-to-fill |
| `homenetguard/dashboard/templates/devices.html` | Modify | Click-to-fill on IP/MAC cells |
| `homenetguard/dashboard/templates/flows.html` | Modify | Click-to-fill on IP cells |
| `homenetguard/dashboard/templates/alerts.html` | Modify | Click-to-fill on IP cells |
| `tests/unit/test_terminal.py` | Create | Unit tests for terminal.py |
| `README.md` | Modify | Terminal section |
| `docs/usage.md` | Modify | Terminal command reference |

---

## Task 1: CommandParser

**Files:**
- Create: `homenetguard/dashboard/terminal.py`
- Create: `tests/unit/test_terminal.py`

- [ ] **Step 1: Write failing tests for CommandParser**

```python
# tests/unit/test_terminal.py
import pytest
from homenetguard.dashboard.terminal import CommandParser, ParseError

def test_parse_block_ip():
    result = CommandParser.parse("block 192.168.1.5")
    assert result == {"cmd": "block", "args": ["192.168.1.5"]}

def test_parse_block_ip_with_reason():
    result = CommandParser.parse("block 192.168.1.5 suspicious traffic")
    assert result == {"cmd": "block", "args": ["192.168.1.5", "suspicious traffic"]}

def test_parse_ping_with_flag():
    result = CommandParser.parse("ping 8.8.8.8 -c 4")
    assert result == {"cmd": "ping", "args": ["8.8.8.8", "-c", "4"]}

def test_parse_empty_raises():
    with pytest.raises(ParseError, match="empty"):
        CommandParser.parse("   ")

def test_parse_unknown_command_raises():
    with pytest.raises(ParseError, match="unknown command"):
        CommandParser.parse("rm -rf /")

def test_parse_rejects_shell_metacharacters():
    for bad in ["block 1.2.3.4 && rm -rf", "ping 8.8.8.8; ls", "dig $(whoami)", "nmap 1.2.3.4 | cat"]:
        with pytest.raises(ParseError, match="invalid"):
            CommandParser.parse(bad)

def test_parse_help():
    result = CommandParser.parse("help")
    assert result == {"cmd": "help", "args": []}

def test_parse_devices():
    result = CommandParser.parse("devices")
    assert result == {"cmd": "devices", "args": []}
```

- [ ] **Step 2: Run to verify FAIL**

```bash
cd /Users/Sergio/Documents/01-Proyectos/01-SW/homeNetGuard
pytest tests/unit/test_terminal.py -v 2>&1 | head -20
```
Expected: `ModuleNotFoundError` or `ImportError` — terminal.py does not exist yet.

- [ ] **Step 3: Implement CommandParser**

Create `homenetguard/dashboard/terminal.py`:

```python
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
_SHELL_META = re.compile(r'[;&|><`$\\]|\$\(')


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
```

- [ ] **Step 4: Run tests to verify PASS**

```bash
pytest tests/unit/test_terminal.py::test_parse_block_ip \
       tests/unit/test_terminal.py::test_parse_empty_raises \
       tests/unit/test_terminal.py::test_parse_rejects_shell_metacharacters \
       tests/unit/test_terminal.py::test_parse_unknown_command_raises \
       tests/unit/test_terminal.py::test_parse_ping_with_flag \
       tests/unit/test_terminal.py::test_parse_help \
       tests/unit/test_terminal.py::test_parse_devices \
       tests/unit/test_terminal.py::test_parse_block_ip_with_reason \
       -v
```
Expected: 8 PASSED.

- [ ] **Step 5: Commit**

```bash
git add homenetguard/dashboard/terminal.py tests/unit/test_terminal.py
git commit -m "feat(terminal): add CommandParser with shell injection protection"
```

---

## Task 2: AppCommandRouter

**Files:**
- Modify: `homenetguard/dashboard/terminal.py`
- Modify: `tests/unit/test_terminal.py`

- [ ] **Step 1: Write failing tests for AppCommandRouter**

Append to `tests/unit/test_terminal.py`:

```python
from unittest.mock import MagicMock, patch
from homenetguard.dashboard.terminal import AppCommandRouter

def test_router_block_calls_firewall(tmp_db):
    with patch("homenetguard.dashboard.terminal.FirewallManager") as MockFW:
        instance = MockFW.return_value
        instance.block_ip.return_value = 42
        router = AppCommandRouter(db_path=tmp_db)
        result = router.execute({"cmd": "block", "args": ["192.168.1.5", "test reason"]})
    assert result["ok"] is True
    assert result["rule_id"] == 42
    instance.block_ip.assert_called_once_with("192.168.1.5", reason="test reason")

def test_router_unblock_by_ip(tmp_db):
    with patch("homenetguard.dashboard.terminal.FirewallManager") as MockFW:
        instance = MockFW.return_value
        instance.list_rules.return_value = [{"id": 7, "target": "10.0.0.1"}]
        instance.unblock.return_value = True
        router = AppCommandRouter(db_path=tmp_db)
        result = router.execute({"cmd": "unblock", "args": ["10.0.0.1"]})
    assert result["ok"] is True
    instance.unblock.assert_called_once_with(7)

def test_router_quarantine_calls_manager(tmp_db):
    with patch("homenetguard.dashboard.terminal.QuarantineManager") as MockQM:
        instance = MockQM.return_value
        instance.quarantine.return_value = True
        router = AppCommandRouter(db_path=tmp_db)
        result = router.execute({"cmd": "quarantine", "args": ["aa:bb:cc:dd:ee:ff"]})
    assert result["ok"] is True
    instance.quarantine.assert_called_once_with("aa:bb:cc:dd:ee:ff")

def test_router_sinkhole_calls_dns(tmp_db):
    with patch("homenetguard.dashboard.terminal.DNSSinkhole") as MockDS:
        instance = MockDS.return_value
        router = AppCommandRouter(db_path=tmp_db)
        result = router.execute({"cmd": "sinkhole", "args": ["evil.com"]})
    assert result["ok"] is True
    instance.add_domain.assert_called_once_with("evil.com", reason="terminal")

def test_router_help_returns_commands(tmp_db):
    router = AppCommandRouter(db_path=tmp_db)
    result = router.execute({"cmd": "help", "args": []})
    assert result["ok"] is True
    assert "commands" in result
    assert "block" in result["commands"]
    assert "ping" in result["commands"]
```

- [ ] **Step 2: Run to verify FAIL**

```bash
pytest tests/unit/test_terminal.py -k "router" -v 2>&1 | head -20
```
Expected: `ImportError` — AppCommandRouter not defined yet.

- [ ] **Step 3: Implement AppCommandRouter**

Append to `homenetguard/dashboard/terminal.py` (after `CommandParser`):

```python
# ─── App command router ───────────────────────────────────────

_HELP_COMMANDS = {
    "block <ip> [reason]": "Add firewall rule",
    "unblock <ip|rule_id>": "Remove firewall rule",
    "quarantine <mac>": "Quarantine device",
    "release <mac>": "Release from quarantine",
    "sinkhole <domain>": "Add domain to DNS sinkhole",
    "unsinkhole <domain>": "Remove domain from sinkhole",
    "flows <ip>": "Show recent flows for IP",
    "alerts [ip]": "Show active alerts",
    "whois <ip>": "Show geo + reputation info",
    "devices": "List known devices",
    "ping <host> [-c N]": "Ping host (max 10 packets)",
    "dig <domain> [type]": "DNS lookup",
    "nslookup <domain>": "DNS name resolution",
    "traceroute <host>": "Trace network path",
    "nmap <ip> [-sn|-sV|-p ports]": "Port scan (single IPs only)",
}


class AppCommandRouter:
    def __init__(self, db_path: str | None = None) -> None:
        self._db_path = db_path

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
        from homenetguard.active.firewall import FirewallManager
        ip = args[0]
        reason = args[1] if len(args) > 1 else "terminal"
        rule_id = FirewallManager().block_ip(ip, reason=reason)
        return {"ok": True, "rule_id": rule_id, "msg": f"Rule added — id:{rule_id} · IP blocked: {ip}"}

    def _unblock(self, args: list[str]) -> dict[str, Any]:
        if not args:
            return {"ok": False, "error": "usage: unblock <ip|rule_id>"}
        from homenetguard.active.firewall import FirewallManager
        fw = FirewallManager()
        target = args[0]
        # Accept rule_id (int) or IP (resolve to rule_id)
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
        from homenetguard.active.quarantine import QuarantineManager
        ok = QuarantineManager().quarantine(args[0])
        return {"ok": ok, "msg": f"Device {args[0]} quarantined" if ok else "Quarantine failed"}

    def _release(self, args: list[str]) -> dict[str, Any]:
        if not args:
            return {"ok": False, "error": "usage: release <mac>"}
        from homenetguard.active.quarantine import QuarantineManager
        ok = QuarantineManager().release(args[0])
        return {"ok": ok, "msg": f"Device {args[0]} released" if ok else "Release failed"}

    # ── DNS Sinkhole ──
    def _sinkhole(self, args: list[str]) -> dict[str, Any]:
        if not args:
            return {"ok": False, "error": "usage: sinkhole <domain>"}
        from homenetguard.active.dns_sinkhole import DNSSinkhole
        DNSSinkhole().add_domain(args[0], reason="terminal")
        return {"ok": True, "msg": f"Domain {args[0]} added to sinkhole"}

    def _unsinkhole(self, args: list[str]) -> dict[str, Any]:
        if not args:
            return {"ok": False, "error": "usage: unsinkhole <domain>"}
        from homenetguard.active.dns_sinkhole import DNSSinkhole
        DNSSinkhole().remove_domain(args[0])
        return {"ok": True, "msg": f"Domain {args[0]} removed from sinkhole"}

    # ── DB queries ──
    def _flows(self, args: list[str]) -> dict[str, Any]:
        if not args:
            return {"ok": False, "error": "usage: flows <ip>"}
        from homenetguard.storage import repository
        flows = repository.get_recent_flows(limit=10)
        ip = args[0]
        filtered = [f for f in flows if f.get("src_ip") == ip or f.get("dst_ip") == ip]
        return {"ok": True, "flows": filtered, "count": len(filtered)}

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
```

- [ ] **Step 4: Run tests to verify PASS**

```bash
pytest tests/unit/test_terminal.py -k "router" -v
```
Expected: 5 PASSED.

- [ ] **Step 5: Commit**

```bash
git add homenetguard/dashboard/terminal.py tests/unit/test_terminal.py
git commit -m "feat(terminal): add AppCommandRouter for all app commands"
```

---

## Task 3: NetUtilRunner

**Files:**
- Modify: `homenetguard/dashboard/terminal.py`
- Modify: `tests/unit/test_terminal.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/unit/test_terminal.py`:

```python
from unittest.mock import patch, MagicMock
from homenetguard.dashboard.terminal import NetUtilRunner, ParseError

def test_netutil_ping_yields_lines():
    runner = NetUtilRunner()
    mock_proc = MagicMock()
    mock_proc.stdout = iter(["PING 8.8.8.8\n", "64 bytes\n"])
    mock_proc.returncode = 0
    mock_proc.__enter__ = lambda s: s
    mock_proc.__exit__ = MagicMock(return_value=False)
    with patch("homenetguard.dashboard.terminal.subprocess.Popen", return_value=mock_proc):
        lines = list(runner.run({"cmd": "ping", "args": ["8.8.8.8", "-c", "2"]}))
    assert any("PING" in l["line"] for l in lines)

def test_netutil_rejects_unknown_binary():
    runner = NetUtilRunner()
    with pytest.raises(ParseError, match="not allowed"):
        list(runner.run({"cmd": "curl", "args": ["http://evil.com"]}))

def test_netutil_ping_count_capped_at_10():
    runner = NetUtilRunner()
    cmd = runner._build_argv({"cmd": "ping", "args": ["8.8.8.8", "-c", "999"]})
    c_idx = cmd.index("-c")
    assert int(cmd[c_idx + 1]) <= 10

def test_netutil_nmap_rejects_range():
    runner = NetUtilRunner()
    with pytest.raises(ParseError, match="single IP"):
        runner._build_argv({"cmd": "nmap", "args": ["192.168.1.0/24"]})

def test_netutil_nmap_rejects_bad_flag():
    runner = NetUtilRunner()
    with pytest.raises(ParseError, match="flag not allowed"):
        runner._build_argv({"cmd": "nmap", "args": ["192.168.1.1", "--script", "vuln"]})

def test_netutil_dig_allows_valid_type():
    runner = NetUtilRunner()
    cmd = runner._build_argv({"cmd": "dig", "args": ["example.com", "MX"]})
    assert "MX" in cmd

def test_netutil_dig_rejects_invalid_type():
    runner = NetUtilRunner()
    with pytest.raises(ParseError, match="record type"):
        runner._build_argv({"cmd": "dig", "args": ["example.com", "AXFR"]})
```

- [ ] **Step 2: Run to verify FAIL**

```bash
pytest tests/unit/test_terminal.py -k "netutil" -v 2>&1 | head -20
```
Expected: `ImportError` — NetUtilRunner not defined yet.

- [ ] **Step 3: Implement NetUtilRunner**

Append to `homenetguard/dashboard/terminal.py`:

```python
import subprocess
import shutil
from collections.abc import Generator

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

        binary = shutil.which(cmd)
        if not binary:
            raise ParseError(f"{cmd} not found on this system")

        if cmd == "ping":
            argv = [binary]
            if "-c" in args:
                idx = args.index("-c")
                count = min(int(args[idx + 1]), 10)
                args[idx + 1] = str(count)
            elif len(args) >= 1:
                # Default -c 4 if not specified
                argv += ["-c", "4"]
            argv += args
            return argv

        if cmd == "nmap":
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
                    i += 2  # skip the ports argument
                else:
                    i += 1
            return [binary] + args

        if cmd == "dig":
            if len(args) >= 2:
                rtype = args[1].upper()
                if rtype not in _DIG_RECORD_TYPES:
                    raise ParseError(f"record type {rtype!r} not allowed. Use: {', '.join(sorted(_DIG_RECORD_TYPES))}")
                args[1] = rtype
            return [binary] + args

        # nslookup, traceroute — pass args as-is (host only, no flags)
        return [binary, args[0]] if args else [binary]

    def run(self, parsed: dict[str, Any]) -> Generator[dict[str, Any], None, None]:
        cmd = parsed["cmd"]
        if cmd not in _NET_BINARIES:
            raise ParseError(f"{cmd!r} not allowed")

        argv = self._build_argv(parsed)
        timeout = _TIMEOUTS.get(cmd, 30)

        with subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=False,
            env={"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"},
        ) as proc:
            try:
                for line in proc.stdout:
                    yield {"line": line.rstrip(), "type": "stdout"}
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                yield {"line": f"[timeout: {cmd} killed after {timeout}s]", "type": "error"}
```

- [ ] **Step 4: Run tests to verify PASS**

```bash
pytest tests/unit/test_terminal.py -k "netutil" -v
```
Expected: 7 PASSED.

- [ ] **Step 5: Commit**

```bash
git add homenetguard/dashboard/terminal.py tests/unit/test_terminal.py
git commit -m "feat(terminal): add NetUtilRunner with subprocess whitelist and streaming"
```

---

## Task 4: SocketIO Handler + Autocomplete Route

**Files:**
- Modify: `homenetguard/dashboard/terminal.py`
- Modify: `homenetguard/dashboard/app.py`
- Modify: `homenetguard/dashboard/routes.py`
- Modify: `tests/unit/test_terminal.py`

- [ ] **Step 1: Write failing test for autocomplete route**

Append to `tests/unit/test_terminal.py`:

```python
import pytest
from homenetguard.dashboard.app import create_app
from homenetguard.storage import database, repository

@pytest.fixture
def cfg_with_db(tmp_path):
    return {
        "storage": {"db_path": str(tmp_path / "test.db"), "reports_path": str(tmp_path / "reports")},
        "dashboard": {"host": "127.0.0.1", "port": 5000, "auto_open_browser": False},
        "geoip": {"enabled": False},
        "threat_intelligence": {"abuseipdb": {"enabled": False}, "virustotal": {"enabled": False}},
        "alerts": {"email": {"enabled": False}, "telegram": {"enabled": False}},
        "logging": {"level": "ERROR", "file": str(tmp_path / "test.log")},
    }

@pytest.fixture
def client_with_db(cfg_with_db, tmp_path):
    database.init_db(str(tmp_path / "test.db"))
    app = create_app(cfg_with_db)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c

def test_suggest_returns_ips(client_with_db):
    res = client_with_db.get("/api/v1/terminal/suggest?q=192&type=ip")
    assert res.status_code == 200
    data = res.get_json()
    assert "suggestions" in data
    assert isinstance(data["suggestions"], list)

def test_suggest_requires_q_param(client_with_db):
    res = client_with_db.get("/api/v1/terminal/suggest")
    assert res.status_code == 400
```

- [ ] **Step 2: Run to verify FAIL**

```bash
pytest tests/unit/test_terminal.py -k "suggest" -v 2>&1 | head -20
```
Expected: 404 or `ImportError`.

- [ ] **Step 3: Add SocketIO handler to terminal.py**

Append to `homenetguard/dashboard/terminal.py`:

```python
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
```

- [ ] **Step 4: Add autocomplete route to routes.py**

Find the last `@bp.route` block in `routes.py` and append:

```python
@bp.route("/api/v1/terminal/suggest")
def api_terminal_suggest():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"error": "q parameter required"}), 400
    suggest_type = request.args.get("type", "ip")
    suggestions: list[str] = []
    try:
        from homenetguard.storage.database import get_connection
        with get_connection() as conn:
            if suggest_type == "ip":
                rows = conn.execute(
                    "SELECT DISTINCT src_ip FROM flows WHERE src_ip LIKE ? LIMIT 10",
                    (f"{q}%",)
                ).fetchall()
                suggestions = [r[0] for r in rows if r[0]]
                if len(suggestions) < 10:
                    rows2 = conn.execute(
                        "SELECT DISTINCT ip_address FROM devices WHERE ip_address LIKE ? LIMIT 10",
                        (f"{q}%",)
                    ).fetchall()
                    for r in rows2:
                        if r[0] and r[0] not in suggestions:
                            suggestions.append(r[0])
            elif suggest_type == "mac":
                rows = conn.execute(
                    "SELECT DISTINCT mac_address FROM devices WHERE mac_address LIKE ? LIMIT 10",
                    (f"{q}%",)
                ).fetchall()
                suggestions = [r[0] for r in rows if r[0]]
            elif suggest_type == "domain":
                rows = conn.execute(
                    "SELECT DISTINCT domain FROM dns_queries WHERE domain LIKE ? LIMIT 10",
                    (f"%{q}%",)
                ).fetchall()
                suggestions = [r[0] for r in rows if r[0]]
    except Exception:
        pass
    return jsonify({"suggestions": suggestions[:10]})
```

- [ ] **Step 5: Register handler in app.py**

In `homenetguard/dashboard/app.py`, after `from homenetguard.dashboard import events  # noqa: F401`, add:

```python
    from homenetguard.dashboard import terminal as _terminal_module  # noqa: F401
    _terminal_module.register_terminal_handlers(socketio)
```

- [ ] **Step 6: Run tests to verify PASS**

```bash
pytest tests/unit/test_terminal.py -k "suggest" -v
```
Expected: 2 PASSED.

- [ ] **Step 7: Run full terminal test suite**

```bash
pytest tests/unit/test_terminal.py -v
```
Expected: all PASSED.

- [ ] **Step 8: Commit**

```bash
git add homenetguard/dashboard/terminal.py homenetguard/dashboard/app.py homenetguard/dashboard/routes.py tests/unit/test_terminal.py
git commit -m "feat(terminal): add SocketIO handler, autocomplete route, and app.py wiring"
```

---

## Task 5: Terminal HTML Partial

**Files:**
- Create: `homenetguard/dashboard/templates/partials/terminal.html`
- Modify: `homenetguard/dashboard/templates/base.html`

- [ ] **Step 1: Create templates/partials/ directory and terminal.html**

```bash
mkdir -p /Users/Sergio/Documents/01-Proyectos/01-SW/homeNetGuard/homenetguard/dashboard/templates/partials
```

Create `homenetguard/dashboard/templates/partials/terminal.html`:

```html
<!-- HNG Terminal Overlay -->
<div id="hng-terminal" class="hng-terminal" aria-hidden="true">
  <div class="hng-terminal-header">
    <div class="hng-terminal-drag-handle" id="hng-terminal-drag"></div>
    <span class="hng-terminal-title">HNG TERMINAL</span>
    <div class="hng-terminal-quick-btns">
      <button class="hng-qbtn" data-cmd="ping 8.8.8.8 -c 4">ping</button>
      <button class="hng-qbtn" data-cmd="block ">block</button>
      <button class="hng-qbtn" data-cmd="nmap ">nmap</button>
      <button class="hng-qbtn" data-cmd="devices">devices</button>
      <button class="hng-qbtn" data-cmd="help">help</button>
    </div>
    <button class="hng-terminal-close" id="hng-terminal-close" aria-label="Close terminal">✕</button>
  </div>
  <div class="hng-terminal-output" id="hng-terminal-output" role="log" aria-live="polite"></div>
  <div class="hng-terminal-input-row">
    <span class="hng-terminal-prompt">HNG&gt;</span>
    <input
      type="text"
      id="hng-terminal-input"
      class="hng-terminal-input"
      autocomplete="off"
      spellcheck="false"
      placeholder="type a command or press Tab to autocomplete..."
      aria-label="Terminal input"
    />
    <div id="hng-autocomplete-list" class="hng-autocomplete-list" hidden></div>
  </div>
</div>
<div id="hng-terminal-backdrop" class="hng-terminal-backdrop" hidden></div>
```

- [ ] **Step 2: Include partial and assets in base.html**

In `base.html`, inside `<head>` after the last `<link rel="stylesheet"...>` line (after `leaflet.css`), add:

```html
  <link rel="stylesheet" href="{{ url_for('static', filename='css/terminal.css') }}"/>
```

Just before `</body>` (after `{% block scripts %}{% endblock %}`), add:

```html
  <script src="{{ url_for('static', filename='js/terminal.js') }}" defer></script>
  {% include "partials/terminal.html" %}
```

- [ ] **Step 3: Verify pages still load**

```bash
pytest tests/unit/test_dashboard_routes.py -v
```
Expected: all PASSED (template include must not break rendering).

- [ ] **Step 4: Commit**

```bash
git add homenetguard/dashboard/templates/partials/terminal.html homenetguard/dashboard/templates/base.html
git commit -m "feat(terminal): add HTML overlay partial and include in base template"
```

---

## Task 6: Terminal CSS

**Files:**
- Create: `homenetguard/dashboard/static/css/terminal.css`

- [ ] **Step 1: Create terminal.css**

```css
/* ══════════════════════════════════════
   HNG TERMINAL OVERLAY
   ══════════════════════════════════════ */

.hng-terminal {
  position: fixed;
  bottom: 0;
  left: 0;
  right: 0;
  height: 40vh;
  min-height: 240px;
  background: var(--surface-container-lowest);
  border-top: 1px solid var(--outline-variant);
  display: flex;
  flex-direction: column;
  z-index: 1000;
  transform: translateY(100%);
  transition: transform 0.25s cubic-bezier(0.4, 0, 0.2, 1);
  font-family: 'JetBrains Mono', monospace;
}

.hng-terminal.is-open {
  transform: translateY(0);
}

.hng-terminal-backdrop {
  position: fixed;
  inset: 0;
  z-index: 999;
  background: transparent;
}

/* ── Header ── */
.hng-terminal-header {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 6px 12px;
  border-bottom: 1px solid var(--outline-variant);
  flex-shrink: 0;
  background: var(--surface-container-low);
}

.hng-terminal-drag-handle {
  width: 32px;
  height: 3px;
  background: var(--outline-variant);
  border-radius: 2px;
  cursor: ns-resize;
  flex-shrink: 0;
}

.hng-terminal-title {
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.12em;
  color: var(--primary);
  flex-shrink: 0;
}

.hng-terminal-quick-btns {
  display: flex;
  gap: 4px;
  flex: 1;
}

.hng-qbtn {
  background: transparent;
  border: 1px solid var(--outline-variant);
  color: var(--outline);
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  padding: 2px 8px;
  cursor: pointer;
  transition: border-color 0.15s, color 0.15s;
}

.hng-qbtn:hover {
  border-color: var(--primary);
  color: var(--primary);
}

.hng-terminal-close {
  background: transparent;
  border: none;
  color: var(--outline);
  font-size: 14px;
  cursor: pointer;
  padding: 2px 6px;
  line-height: 1;
  flex-shrink: 0;
}

.hng-terminal-close:hover { color: var(--error); }

/* ── Output ── */
.hng-terminal-output {
  flex: 1;
  overflow-y: auto;
  padding: 8px 14px;
  font-size: 12px;
  line-height: 1.6;
}

.hng-line              { white-space: pre-wrap; word-break: break-all; }
.hng-line--stdout      { color: var(--on-surface-variant); }
.hng-line--success     { color: var(--primary); }
.hng-line--error       { color: var(--error); }
.hng-line--info        { color: var(--secondary); }
.hng-line--header      { color: var(--outline); font-weight: 700; }
.hng-line--cmd         { color: var(--surface-tint); margin-top: 6px; }

/* ── Input row ── */
.hng-terminal-input-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 14px;
  border-top: 1px solid var(--outline-variant);
  flex-shrink: 0;
  position: relative;
}

.hng-terminal-prompt {
  color: var(--primary);
  font-size: 12px;
  font-weight: 700;
  flex-shrink: 0;
}

.hng-terminal-input {
  flex: 1;
  background: transparent;
  border: none;
  outline: none;
  color: var(--on-surface);
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  caret-color: var(--primary);
}

/* ── Autocomplete dropdown ── */
.hng-autocomplete-list {
  position: absolute;
  bottom: 100%;
  left: 54px;
  right: 14px;
  background: var(--surface-container-high);
  border: 1px solid var(--outline-variant);
  max-height: 160px;
  overflow-y: auto;
  z-index: 1001;
}

.hng-autocomplete-item {
  padding: 5px 12px;
  font-size: 11px;
  color: var(--on-surface-variant);
  cursor: pointer;
}

.hng-autocomplete-item.is-active,
.hng-autocomplete-item:hover {
  background: color-mix(in srgb, var(--primary) 10%, transparent);
  color: var(--primary);
}
```

- [ ] **Step 2: Commit**

```bash
git add homenetguard/dashboard/static/css/terminal.css
git commit -m "feat(terminal): add terminal overlay CSS"
```

---

## Task 7: terminal.js — Core Logic

**Files:**
- Create: `homenetguard/dashboard/static/js/terminal.js`

- [ ] **Step 1: Create terminal.js**

```javascript
/* ──────────────────────────────────────────────
   HNG Terminal — parser, WS client, UI, autocomplete
   ────────────────────────────────────────────── */

(function () {
  'use strict';

  // ── Constants ──────────────────────────────
  const SHELL_META = /[;&|><`$\\]|\$\(/;
  const APP_CMDS = new Set([
    'block','unblock','quarantine','release',
    'sinkhole','unsinkhole','flows','alerts','whois','devices','help'
  ]);
  const NET_CMDS = new Set(['ping','dig','nslookup','traceroute','nmap']);
  const ALL_CMDS = new Set([...APP_CMDS, ...NET_CMDS]);
  const MAX_HISTORY = 50;
  const HISTORY_KEY = 'hng_terminal_history';

  // ── State ──────────────────────────────────
  let _isOpen = false;
  let _socket = null;
  let _history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
  let _historyIndex = -1;
  let _acItems = [];
  let _acIndex = -1;
  let _inputBuffer = '';

  // ── DOM refs (resolved after DOMContentLoaded) ──
  let _panel, _output, _input, _acList, _backdrop;

  // ── Parser ─────────────────────────────────
  function parse(raw) {
    raw = raw.trim();
    if (!raw) return null;
    if (SHELL_META.test(raw)) throw new Error('invalid characters in input');
    const tokens = raw.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) || [];
    if (!tokens.length) return null;
    const cmd = tokens[0].toLowerCase();
    if (!ALL_CMDS.has(cmd)) throw new Error(`unknown command: ${cmd}`);
    const args = tokens.slice(1).map(t => t.replace(/^["']|["']$/g, ''));
    // Rejoin reason for block command
    if (cmd === 'block' && args.length > 1) {
      return { cmd, args: [args[0], args.slice(1).join(' ')] };
    }
    return { cmd, args };
  }

  // ── Output rendering ───────────────────────
  function appendLine(text, type = 'stdout') {
    const el = document.createElement('div');
    el.className = `hng-line hng-line--${type}`;
    el.textContent = text;
    _output.appendChild(el);
    _output.scrollTop = _output.scrollHeight;
  }

  function appendCmdEcho(raw) {
    appendLine(`HNG> ${raw}`, 'cmd');
  }

  // ── History ────────────────────────────────
  function pushHistory(cmd) {
    if (!cmd || _history[0] === cmd) return;
    _history.unshift(cmd);
    if (_history.length > MAX_HISTORY) _history.pop();
    localStorage.setItem(HISTORY_KEY, JSON.stringify(_history));
    _historyIndex = -1;
  }

  // ── Autocomplete ───────────────────────────
  function hideAc() {
    _acList.hidden = true;
    _acItems = [];
    _acIndex = -1;
  }

  function showAc(items) {
    _acList.innerHTML = '';
    _acItems = items;
    _acIndex = -1;
    items.forEach((item, i) => {
      const el = document.createElement('div');
      el.className = 'hng-autocomplete-item';
      el.textContent = item;
      el.addEventListener('mousedown', e => {
        e.preventDefault();
        applyAcItem(i);
      });
      _acList.appendChild(el);
    });
    _acList.hidden = items.length === 0;
  }

  function applyAcItem(idx) {
    const item = _acItems[idx];
    if (!item) return;
    const tokens = _input.value.trim().split(/\s+/);
    tokens[tokens.length - 1] = item;
    _input.value = tokens.join(' ') + ' ';
    hideAc();
    _input.focus();
  }

  async function fetchSuggestions(q, type) {
    if (q.length < 2) { hideAc(); return; }
    try {
      const res = await fetch(`/api/v1/terminal/suggest?q=${encodeURIComponent(q)}&type=${type}`);
      if (!res.ok) return;
      const { suggestions } = await res.json();
      showAc(suggestions);
    } catch { hideAc(); }
  }

  function handleTabAutocomplete() {
    if (_acItems.length > 0) {
      // cycle through items
      _acIndex = (_acIndex + 1) % _acItems.length;
      document.querySelectorAll('.hng-autocomplete-item').forEach((el, i) => {
        el.classList.toggle('is-active', i === _acIndex);
      });
      applyAcItem(_acIndex);
      return;
    }
    const val = _input.value.trim();
    const tokens = val.split(/\s+/);
    const cmd = tokens[0]?.toLowerCase();
    const lastToken = tokens[tokens.length - 1];

    if (tokens.length === 1) {
      // Complete command name
      const matches = [...ALL_CMDS].filter(c => c.startsWith(cmd));
      if (matches.length === 1) { _input.value = matches[0] + ' '; }
      else if (matches.length > 1) { showAc(matches); }
      return;
    }

    // Determine suggest type from command
    let suggestType = 'ip';
    if (cmd === 'quarantine' || cmd === 'release') suggestType = 'mac';
    else if (cmd === 'sinkhole' || cmd === 'unsinkhole' || cmd === 'dig' || cmd === 'nslookup') suggestType = 'domain';

    fetchSuggestions(lastToken, suggestType);
  }

  // ── WebSocket ──────────────────────────────
  function ensureSocket() {
    if (_socket) return;
    // socket.io is loaded globally via vendor/socket.io.min.js
    _socket = io({ transports: ['websocket', 'polling'] });

    _socket.on('terminal:out', ({ line, type }) => {
      appendLine(line, type);
    });

    _socket.on('terminal:done', ({ code, duration }) => {
      if (code !== 0) {
        appendLine(`[exit ${code} · ${duration}s]`, 'error');
      } else {
        appendLine(`[done · ${duration}s]`, 'info');
      }
      _input.disabled = false;
      _input.focus();
    });
  }

  function execCommand(raw) {
    let parsed;
    try {
      parsed = parse(raw);
    } catch (e) {
      appendLine(`Parse error: ${e.message}`, 'error');
      return;
    }
    if (!parsed) return;

    pushHistory(raw);
    appendCmdEcho(raw);
    _input.disabled = true;
    ensureSocket();
    _socket.emit('terminal:exec', { raw });
  }

  // ── Open / Close ───────────────────────────
  function open(prefill) {
    _panel.classList.add('is-open');
    _panel.setAttribute('aria-hidden', 'false');
    _backdrop.hidden = false;
    _isOpen = true;
    _input.focus();
    if (prefill) {
      _input.value = prefill;
    }
  }

  function close() {
    _panel.classList.remove('is-open');
    _panel.setAttribute('aria-hidden', 'true');
    _backdrop.hidden = true;
    _isOpen = false;
    hideAc();
  }

  function toggle(prefill) {
    if (_isOpen && !prefill) { close(); } else { open(prefill); }
  }

  // ── Public API (for click-to-fill) ─────────
  window.hngTerminal = {
    open,
    close,
    toggle,
    fill: (cmd) => open(cmd),
  };

  // ── CMD_SEARCH wiring ──────────────────────
  function wireCmdSearch() {
    const input = document.querySelector('input[placeholder="CMD_SEARCH..."]');
    if (!input) return;
    input.addEventListener('focus', () => {
      input.blur();
      toggle();
    });
    input.addEventListener('click', () => {
      input.blur();
      toggle();
    });
  }

  // ── Keyboard shortcuts ─────────────────────
  document.addEventListener('keydown', e => {
    // Ctrl+` to toggle
    if (e.ctrlKey && e.key === '`') {
      e.preventDefault();
      toggle();
      return;
    }
    if (!_isOpen) return;
    if (e.key === 'Escape') {
      if (_acItems.length > 0) { hideAc(); } else { close(); }
    }
  });

  // ── Input event handlers ───────────────────
  function initInput() {
    _input.addEventListener('keydown', e => {
      if (e.key === 'Enter') {
        e.preventDefault();
        const val = _input.value.trim();
        hideAc();
        if (val) { execCommand(val); }
        _input.value = '';
        _historyIndex = -1;
        return;
      }
      if (e.key === 'Tab') {
        e.preventDefault();
        handleTabAutocomplete();
        return;
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (_history.length === 0) return;
        _historyIndex = Math.min(_historyIndex + 1, _history.length - 1);
        _input.value = _history[_historyIndex];
        return;
      }
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (_historyIndex <= 0) { _historyIndex = -1; _input.value = ''; return; }
        _historyIndex -= 1;
        _input.value = _historyIndex >= 0 ? _history[_historyIndex] : '';
        return;
      }
    });

    // Trigger autocomplete suggestions as user types (for IPs/domains)
    _input.addEventListener('input', () => {
      const val = _input.value;
      const tokens = val.trim().split(/\s+/);
      if (tokens.length < 2) { hideAc(); return; }
      const cmd = tokens[0].toLowerCase();
      const lastToken = tokens[tokens.length - 1];
      if (!lastToken || lastToken.length < 2) { hideAc(); return; }
      let suggestType = 'ip';
      if (cmd === 'quarantine' || cmd === 'release') suggestType = 'mac';
      else if (cmd === 'sinkhole' || cmd === 'unsinkhole' || cmd === 'dig' || cmd === 'nslookup') suggestType = 'domain';
      fetchSuggestions(lastToken, suggestType);
    });
  }

  // ── Quick-cmd buttons ──────────────────────
  function initQuickBtns() {
    document.querySelectorAll('.hng-qbtn').forEach(btn => {
      btn.addEventListener('click', () => {
        const cmd = btn.dataset.cmd;
        open(cmd);
        _input.focus();
      });
    });
  }

  // ── Init ───────────────────────────────────
  document.addEventListener('DOMContentLoaded', () => {
    _panel = document.getElementById('hng-terminal');
    _output = document.getElementById('hng-terminal-output');
    _input = document.getElementById('hng-terminal-input');
    _acList = document.getElementById('hng-autocomplete-list');
    _backdrop = document.getElementById('hng-terminal-backdrop');

    if (!_panel) return; // terminal partial not loaded

    document.getElementById('hng-terminal-close')
      .addEventListener('click', close);

    _backdrop.addEventListener('click', close);

    initInput();
    initQuickBtns();
    wireCmdSearch();

    // Show welcome line on first open
    _panel.addEventListener('transitionend', () => {
      if (_isOpen && _output.children.length === 0) {
        appendLine('HomeNetGuard Terminal — type "help" for commands', 'info');
      }
    }, { once: true });
  });
})();
```

- [ ] **Step 2: Commit**

```bash
git add homenetguard/dashboard/static/js/terminal.js
git commit -m "feat(terminal): add terminal.js — UI, parser, WS client, autocomplete, history"
```

---

## Task 8: Click-to-Fill in Data Tables

**Files:**
- Modify: `homenetguard/dashboard/templates/devices.html`
- Modify: `homenetguard/dashboard/templates/flows.html`
- Modify: `homenetguard/dashboard/templates/alerts.html`

- [ ] **Step 1: Locate IP/MAC render points in devices.html**

```bash
grep -n "ip_address\|mac_address\|ip-address\|td.*ip\|td.*mac" \
  /Users/Sergio/Documents/01-Proyectos/01-SW/homeNetGuard/homenetguard/dashboard/templates/devices.html | head -20
```

- [ ] **Step 2: Add click-to-fill CSS class and data attribute to devices.html**

Find the `<td>` elements that render IP addresses and MAC addresses in the JS-rendered rows (in the inline `<script>` block inside devices.html). Add `data-hng-fill="whois ${d.ip}"` to IP cells and `data-hng-fill="quarantine ${d.mac}"` to MAC cells. Example pattern to apply to each IP `<td>`:

```javascript
// Before (example):
`<td class="ip-address">${d.ip}</td>`

// After:
`<td class="ip-address hng-fillable" data-hng-fill="whois ${d.ip}" title="Click to inspect in terminal">${d.ip}</td>`
```

And for MAC cells:
```javascript
// Before:
`<td class="text-mono">${d.mac}</td>`

// After:
`<td class="text-mono hng-fillable" data-hng-fill="quarantine ${d.mac}" title="Click to quarantine in terminal">${d.mac}</td>`
```

- [ ] **Step 3: Add click-to-fill to flows.html**

In the JS that renders flow rows, add `hng-fillable` to SRC IP and DST IP cells:

```javascript
// Before:
`<td class="ip-address">${f.src_ip || '--'}</td>`

// After:
`<td class="ip-address hng-fillable" data-hng-fill="whois ${f.src_ip}" title="Inspect in terminal">${f.src_ip || '--'}</td>`
```

- [ ] **Step 4: Add click-to-fill to alerts.html**

In the JS that renders alert rows, add `hng-fillable` to the source IP cell:

```javascript
// Before:
`<td class="ip-address">${a.src_ip || '--'}</td>`

// After:
`<td class="ip-address hng-fillable" data-hng-fill="whois ${a.src_ip}" title="Inspect in terminal">${a.src_ip || '--'}</td>`
```

- [ ] **Step 5: Add global click handler and CSS in terminal.css**

Add to `terminal.css`:

```css
/* Click-to-fill cells */
.hng-fillable {
  cursor: pointer;
  transition: color 0.15s;
}
.hng-fillable:hover {
  color: var(--primary) !important;
  text-decoration: underline dotted;
}
```

Add to `terminal.js` (inside the `DOMContentLoaded` block, before closing `}`):

```javascript
    // Global click-to-fill handler (works for dynamically rendered rows)
    document.addEventListener('click', e => {
      const cell = e.target.closest('[data-hng-fill]');
      if (!cell) return;
      const cmd = cell.dataset.hngFill;
      if (cmd) window.hngTerminal.fill(cmd);
    });
```

- [ ] **Step 6: Verify dashboard routes tests still pass**

```bash
pytest tests/unit/test_dashboard_routes.py -v
```
Expected: all PASSED.

- [ ] **Step 7: Commit**

```bash
git add homenetguard/dashboard/templates/devices.html \
        homenetguard/dashboard/templates/flows.html \
        homenetguard/dashboard/templates/alerts.html \
        homenetguard/dashboard/static/css/terminal.css \
        homenetguard/dashboard/static/js/terminal.js
git commit -m "feat(terminal): add click-to-fill on IP/MAC cells in devices, flows, alerts"
```

---

## Task 9: Documentation — README + docs/usage.md

**Files:**
- Modify: `README.md`
- Modify: `docs/usage.md`

- [ ] **Step 1: Add Terminal entry to README features list**

In `README.md`, find the features list (the bullet list starting with `🔍 **Real-time packet capture**`). Add after the last bullet:

```markdown
- ⌨️ **Dashboard Terminal** — Slide-up command terminal in the web UI. Execute firewall, quarantine, sinkhole, and network diagnostic commands directly from any dashboard page. Click any IP/MAC to pre-fill commands. `Ctrl+\`` to open.
```

- [ ] **Step 2: Add Terminal section to README**

Find the `## Dashboard` or `## Usage` section in README.md and append a new section:

```markdown
## Dashboard Terminal

Press **`Ctrl+\``** (or click the `CMD_SEARCH` bar) on any dashboard page to open the terminal overlay.

### App commands

| Command | Description |
|---------|-------------|
| `block <ip> [reason]` | Add firewall block rule |
| `unblock <ip\|rule_id>` | Remove firewall rule |
| `quarantine <mac>` | Quarantine a device |
| `release <mac>` | Release device from quarantine |
| `sinkhole <domain>` | Block domain at DNS level |
| `unsinkhole <domain>` | Remove domain from sinkhole |
| `flows <ip>` | Show recent flows for an IP |
| `alerts [ip]` | Show active alerts |
| `whois <ip>` | Show geo, org, and reputation data |
| `devices` | List all known devices |
| `help` | Show all commands |

### Network utilities

| Command | Description |
|---------|-------------|
| `ping <host> [-c N]` | Ping (max 10 packets) |
| `dig <domain> [type]` | DNS lookup (A/AAAA/MX/TXT/NS) |
| `nslookup <domain>` | DNS name resolution |
| `traceroute <host>` | Trace network path |
| `nmap <ip> [-sn\|-sV\|-p ports]` | Port scan (single IPs only) |

### Shortcuts

| Key | Action |
|-----|--------|
| `Ctrl+\`` | Open / close terminal |
| `Escape` | Close terminal |
| `Tab` | Autocomplete IP / MAC / domain from live DB |
| `↑ / ↓` | Navigate command history |

Click any **IP address**, **MAC address**, or **domain** in the dashboard tables to pre-fill a `whois` or `quarantine` command in the terminal.
```

- [ ] **Step 3: Add terminal section to docs/usage.md**

Read `docs/usage.md` to find the right insertion point, then append a "Terminal de Comandos" section with the full command reference, examples, and security model:

```markdown
## Terminal de Comandos

El terminal de HomeNetGuard es un panel de comandos accesible desde cualquier página del dashboard.

### Abrir el terminal

- **Atajo de teclado:** `Ctrl+\``
- **Barra de búsqueda:** Haz clic en `CMD_SEARCH...` en la barra superior
- **Click-to-fill:** Haz clic en cualquier IP, MAC o dominio en las tablas del dashboard

### Comandos de aplicación

```
block 192.168.1.50 malicious host    # Bloquea IP en el firewall
unblock 192.168.1.50                 # Elimina regla por IP o ID
quarantine aa:bb:cc:dd:ee:ff         # Pone dispositivo en cuarentena
release aa:bb:cc:dd:ee:ff            # Libera cuarentena
sinkhole evil.com                    # Bloquea dominio en DNS sinkhole
unsinkhole evil.com                  # Elimina del sinkhole
flows 192.168.1.50                   # Últimos flows de esa IP
alerts 192.168.1.50                  # Alertas activas (filtradas por IP)
whois 8.8.8.8                        # Geo + organización + reputación
devices                              # Lista dispositivos conocidos
help                                 # Muestra todos los comandos
```

### Utilidades de red

```
ping 8.8.8.8 -c 4                   # Ping (máx. 10 paquetes)
dig example.com MX                   # DNS lookup (A/AAAA/MX/TXT/NS)
nslookup example.com                 # Resolución DNS
traceroute 1.1.1.1                   # Ruta de red
nmap 192.168.1.1 -sn                 # Ping scan (solo IPs individuales)
nmap 192.168.1.1 -p 80,443           # Scan de puertos específicos
```

### Seguridad

El terminal nunca ejecuta comandos de shell directamente. El servidor valida cada comando contra una lista cerrada de operaciones permitidas antes de ejecutar nada. Los caracteres de shell (`&&`, `|`, `;`, `>`, `$(`, `` ` ``) son rechazados tanto en el navegador como en el servidor. Los comandos de red se ejecutan con `subprocess(shell=False)` con argumentos tipados, sin herencia de variables de entorno.
```

- [ ] **Step 4: Commit**

```bash
git add README.md docs/usage.md
git commit -m "docs: add terminal command reference to README and docs/usage.md"
```

---

## Task 10: Final Verification

- [ ] **Step 1: Run full test suite**

```bash
cd /Users/Sergio/Documents/01-Proyectos/01-SW/homeNetGuard
pytest tests/ -v --tb=short 2>&1 | tail -30
```
Expected: all existing tests PASS, new terminal tests PASS.

- [ ] **Step 2: Push to remote**

```bash
git push origin ui-redesign
```

- [ ] **Step 3: Manual smoke test**

Start the dashboard:
```bash
sudo homenetguard start --interface en0
```

Verify in browser (`http://localhost:5000`):
1. `Ctrl+`` opens the terminal overlay
2. Type `help` → shows command list
3. Type `ping 8.8.8.8 -c 2` → streams ping output line by line
4. Type `devices` → shows device table
5. Click any IP in the Flows table → terminal opens pre-filled with `whois <ip>`
6. Tab autocomplete on `block 192` → shows IP suggestions from DB
7. `Escape` closes the terminal
8. Type `rm -rf /` → receives "unknown command" error (no execution)
