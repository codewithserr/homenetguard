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
