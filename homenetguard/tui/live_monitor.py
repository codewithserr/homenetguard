from __future__ import annotations

import time
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Any

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

_PROTO_COLORS = {"TCP": "green", "UDP": "cyan", "ICMP": "yellow", "DNS": "bright_green"}


class LiveMonitor:
    def __init__(self, db_path: str = "data/homenetguard.db") -> None:
        self._db_path = db_path
        self._running = False
        self._paused = False
        self._bps_history: deque[int] = deque([0] * 60, maxlen=60)
        self._show_devices = False
        self._alerts_only = False

    def run(self) -> None:
        try:
            from rich.console import Console
            from rich.layout import Layout  # noqa: F401
            from rich.live import Live
            from rich.panel import Panel  # noqa: F401
        except ImportError:
            print("rich not installed — run: pip install rich")
            return

        from homenetguard.storage import database
        database.init_db(self._db_path)

        self._running = True
        console = Console()

        with Live(self._render(), refresh_per_second=1, screen=True, console=console) as live:
            while self._running:
                try:
                    live.update(self._render())
                    time.sleep(1)
                except KeyboardInterrupt:
                    self._running = False

    def _render(self) -> Any:
        from rich import box
        from rich.layout import Layout
        from rich.panel import Panel
        from rich.table import Table

        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )
        layout["body"].split_row(
            Layout(name="left"),
            Layout(name="center"),
            Layout(name="right"),
        )

        # Header
        now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        layout["header"].update(Panel(
            f"[bold green]HOMENETGUARD[/] [dim]v2[/]  ·  [yellow]{now}[/]  ·  "
            f"[dim]Q=quit  A=alerts  F=pause  D=devices[/]",
            style="bold",
        ))

        # Traffic sparkline
        since = datetime.now(UTC) - timedelta(minutes=1)
        try:
            from homenetguard.storage import repository
            stats = repository.get_flow_stats(since=since)
            bps = stats.get("total_bytes", 0)
            self._bps_history.append(bps)
            flows = repository.get_recent_flows(limit=20)
            alerts = repository.get_unacknowledged_alerts(limit=5)
        except Exception:
            stats = {}
            flows = []
            alerts = []

        spark = self._sparkline(list(self._bps_history))
        left_content = f"[green]{spark}[/]\n"
        left_content += f"Flows/min: [bold]{stats.get('total_flows', 0)}[/]\n"
        left_content += f"Bytes/min: [bold]{self._fmt_bytes(stats.get('total_bytes', 0))}[/]"
        layout["left"].update(Panel(left_content, title="[bold]TRAFFIC[/]"))

        # Protocol table
        proto_table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        proto_table.add_column("PROTO", style="cyan")
        proto_table.add_column("FLOWS", justify="right")
        try:
            from homenetguard.storage import repository as repo
            protos = repo.get_protocol_distribution()
            for p in protos[:6]:
                color = _PROTO_COLORS.get(p["protocol"], "white")
                proto_table.add_row(
                    f"[{color}]{p['protocol']}[/]",
                    str(p["count"]),
                )
        except Exception:
            pass
        layout["center"].update(Panel(proto_table, title="[bold]PROTOCOLS[/]"))

        # Alerts
        sev_colors = {"critical": "red", "high": "dark_orange", "medium": "yellow", "low": "cyan"}
        alert_text = ""
        for a in alerts[:5]:
            c = sev_colors.get(a.get("severity", "low"), "white")
            desc = str(a.get("description", ""))[:40]
            alert_text += f"[{c}]⚠ {a.get('alert_type', '?').upper()}[/]: {desc}\n"
        if not alert_text:
            alert_text = "[green]✓ No active alerts[/]"
        layout["right"].update(Panel(alert_text, title=f"[bold]ALERTS ({len(alerts)})[/]"))

        # Live flows table
        flow_table = Table(box=box.SIMPLE, show_header=True, header_style="bold dim")
        flow_table.add_column("TIME", style="dim", width=8)
        flow_table.add_column("SRC IP", style="cyan", width=15)
        flow_table.add_column("DST IP", style="cyan", width=15)
        flow_table.add_column("PROTO", width=6)
        flow_table.add_column("BYTES", justify="right", width=8)
        for f in flows[:20]:
            ts = str(f.get("timestamp", ""))[-8:]
            proto = f.get("protocol", "?")
            color = _PROTO_COLORS.get(proto, "white")
            flow_table.add_row(
                ts, f.get("src_ip", "?"), f.get("dst_ip", "?"),
                f"[{color}]{proto}[/]",
                self._fmt_bytes(f.get("bytes", 0)),
            )

        body_bottom = Panel(flow_table, title="[bold]LIVE FLOWS[/]")
        layout["body"].update(body_bottom)

        # Footer
        layout["footer"].update(Panel(
            f"DB: {self._db_path}  ·  "
            f"IPs: {stats.get('unique_src_ips', 0)}  ·  "
            f"Press [bold]Q[/] to exit",
            style="dim",
        ))

        return layout

    def _sparkline(self, values: list[int]) -> str:
        chars = "▁▂▃▄▅▆▇█"
        if not values or max(values) == 0:
            return "▁" * 30
        mx = max(values)
        recent = values[-30:]
        return "".join(chars[int((v / mx) * 7)] for v in recent)

    def _fmt_bytes(self, b: int) -> str:
        if b < 1024:
            return f"{b}B"
        if b < 1048576:
            return f"{b//1024}K"
        return f"{b//1048576}M"
