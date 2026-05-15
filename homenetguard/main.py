from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click

from homenetguard.utils.logger import setup_logger

_LEGAL_NOTICE = """
⚠  LEGAL NOTICE: HomeNetGuard is intended for use ONLY on networks you own
   or have explicit written permission to monitor. Unauthorized packet capture
   may violate local laws. The authors assume no liability.
"""


def _load_config(config_path: str | None) -> dict:
    from homenetguard.utils.config_loader import load_config
    path = Path(config_path) if config_path else None
    return load_config(path)


@click.group()
@click.option("--config", "-c", default=None, help="Path to config.yaml")
@click.option("--log-level", default=None, help="Override log level (DEBUG/INFO/WARNING/ERROR)")
@click.pass_context
def cli(ctx: click.Context, config: Optional[str], log_level: Optional[str]) -> None:
    """HomeNetGuard — Open-source network security monitor."""
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config
    ctx.obj["log_level"] = log_level


@cli.command()
@click.option("--interface", "-i", default=None, help="Network interface (default: auto-detect)")
@click.option("--duration", "-d", default=0, type=int, help="Duration in seconds (0 = indefinite)")
@click.option("--output", "-o", default=None, type=click.Path(), help="Save capture to .pcap file")
@click.option("--no-dashboard", is_flag=True, help="Don't start the web dashboard")
@click.pass_context
def start(ctx: click.Context, interface: Optional[str], duration: int, output: Optional[str], no_dashboard: bool) -> None:
    """Start real-time network monitoring."""
    click.echo(_LEGAL_NOTICE)
    cfg = _load_config(ctx.obj.get("config_path"))
    log_cfg = cfg.get("logging", {})
    level = ctx.obj.get("log_level") or log_cfg.get("level", "INFO")
    setup_logger(level=level, log_file=log_cfg.get("file", "logs/homenetguard.log"))

    from homenetguard.utils.permissions import require_capture_permissions
    require_capture_permissions()

    from homenetguard.storage.database import init_db
    init_db(cfg.get("storage", {}).get("db_path", "data/homenetguard.db"))

    from homenetguard.capture.sniffer import Sniffer
    sniffer = Sniffer(cfg)

    import threading
    import time

    if not no_dashboard and cfg.get("dashboard", {}).get("enabled", True):
        from homenetguard.dashboard.app import run_dashboard
        dash_thread = threading.Thread(
            target=run_dashboard, args=(cfg, sniffer), daemon=True, name="dashboard"
        )
        dash_thread.start()

    click.echo(f"Starting capture{' on ' + interface if interface else ''} — press Ctrl+C to stop")
    sniffer.start(interface=interface)

    try:
        if duration > 0:
            time.sleep(duration)
            sniffer.stop()
        else:
            while sniffer.is_running():
                time.sleep(1)
    except KeyboardInterrupt:
        click.echo("\nStopping capture...")
        sniffer.stop()

    stats = sniffer.get_stats()
    click.echo(f"\nCapture complete — {stats['packets_captured']} packets in {stats['uptime_seconds']}s")


@cli.command()
def stop() -> None:
    """Stop active monitoring (sends signal to running process)."""
    click.echo("Use Ctrl+C in the running homenetguard start process to stop capture.")


@cli.command()
@click.option("--file", "-f", "pcap_file", required=True, type=click.Path(exists=True), help="PCAP file to analyze")
@click.option("--report", is_flag=True, help="Generate report from analysis")
@click.pass_context
def analyze(ctx: click.Context, pcap_file: str, report: bool) -> None:
    """Analyze an existing .pcap capture file."""
    cfg = _load_config(ctx.obj.get("config_path"))
    setup_logger(level=cfg.get("logging", {}).get("level", "INFO"))

    from homenetguard.capture.pcap_reader import PcapReader
    reader = PcapReader(cfg)

    click.echo(f"Analyzing {pcap_file}...")
    try:
        stats = reader.analyze_file(pcap_file)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    click.echo(f"\nResults for {stats['file']}:")
    click.echo(f"  Packets : {stats['total_packets']}")
    click.echo(f"  Bytes   : {stats['total_bytes']:,}")
    click.echo(f"\nTop protocols:")
    for proto, count in sorted(stats["protocols"].items(), key=lambda x: -x[1])[:10]:
        click.echo(f"  {proto:15s} {count}")
    click.echo(f"\nTop source IPs:")
    for ip, count in list(stats["top_src_ips"].items())[:10]:
        click.echo(f"  {ip:20s} {count} packets")

    if report:
        from homenetguard.storage.database import init_db
        init_db(cfg.get("storage", {}).get("db_path", "data/homenetguard.db"))
        from homenetguard.reports.report_generator import ReportGenerator
        gen = ReportGenerator(cfg)
        paths = gen.generate(report_type="on-demand")
        click.echo(f"\nReport saved to: {paths[0]}")


@cli.command()
@click.option("--type", "report_type", default="daily", type=click.Choice(["daily", "weekly", "custom"]))
@click.option("--from", "date_from", default=None, help="Start date (YYYY-MM-DD)")
@click.option("--to", "date_to", default=None, help="End date (YYYY-MM-DD)")
@click.option("--format", "fmt", default="html", type=click.Choice(["html", "pdf", "both"]))
@click.option("--output", "-o", default=None, type=click.Path(), help="Output directory")
@click.pass_context
def report(ctx: click.Context, report_type: str, date_from: Optional[str], date_to: Optional[str], fmt: str, output: Optional[str]) -> None:
    """Generate a traffic report."""
    from datetime import UTC, datetime
    cfg = _load_config(ctx.obj.get("config_path"))
    setup_logger(level=cfg.get("logging", {}).get("level", "INFO"))

    if output:
        cfg.setdefault("storage", {})["reports_path"] = output

    from homenetguard.storage.database import init_db
    init_db(cfg.get("storage", {}).get("db_path", "data/homenetguard.db"))

    period_start = datetime.fromisoformat(date_from) if date_from else None
    period_end = datetime.fromisoformat(date_to) if date_to else None

    from homenetguard.reports.report_generator import ReportGenerator
    gen = ReportGenerator(cfg)
    click.echo(f"Generating {report_type} report ({fmt})...")
    paths = gen.generate(report_type=report_type, fmt=fmt, period_start=period_start, period_end=period_end)
    for p in paths:
        click.echo(f"  → {p}")


@cli.command()
@click.option("--port", default=5000, type=int, help="Dashboard port (default: 5000)")
@click.option("--host", default="127.0.0.1", help="Dashboard host (default: 127.0.0.1)")
@click.pass_context
def dashboard(ctx: click.Context, port: int, host: str) -> None:
    """Start the web dashboard only (no packet capture)."""
    cfg = _load_config(ctx.obj.get("config_path"))
    setup_logger(level=cfg.get("logging", {}).get("level", "INFO"))
    cfg.setdefault("dashboard", {})["host"] = host
    cfg["dashboard"]["port"] = port

    from homenetguard.storage.database import init_db
    init_db(cfg.get("storage", {}).get("db_path", "data/homenetguard.db"))

    from homenetguard.dashboard.app import run_dashboard
    click.echo(f"Dashboard at http://{host}:{port}")
    run_dashboard(cfg)


@cli.command()
@click.option("--list", "list_alerts", is_flag=True, help="List unacknowledged alerts")
@click.option("--acknowledge", "ack_id", default=None, type=int, help="Acknowledge alert by ID")
@click.option("--clear-all", is_flag=True, help="Clear all alerts")
@click.pass_context
def alerts(ctx: click.Context, list_alerts: bool, ack_id: Optional[int], clear_all: bool) -> None:
    """Manage alerts."""
    from tabulate import tabulate
    cfg = _load_config(ctx.obj.get("config_path"))
    from homenetguard.storage.database import init_db
    init_db(cfg.get("storage", {}).get("db_path", "data/homenetguard.db"))
    from homenetguard.storage import repository

    if clear_all:
        count = repository.clear_all_alerts()
        click.echo(f"Cleared {count} alerts.")
        return

    if ack_id is not None:
        repository.acknowledge_alert(ack_id)
        click.echo(f"Alert {ack_id} acknowledged.")
        return

    alert_list = repository.get_unacknowledged_alerts(limit=50)
    if not alert_list:
        click.echo("No unacknowledged alerts.")
        return

    rows = [
        [a["id"], a["severity"].upper(), a["alert_type"], a["src_ip"] or "—",
         a["description"][:60], a["timestamp"][:19]]
        for a in alert_list
    ]
    click.echo(tabulate(rows, headers=["ID", "SEV", "TYPE", "SRC IP", "DESCRIPTION", "TIMESTAMP"]))


@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show system status."""
    from tabulate import tabulate
    cfg = _load_config(ctx.obj.get("config_path"))
    from homenetguard.storage.database import init_db
    from datetime import UTC, datetime, timedelta
    init_db(cfg.get("storage", {}).get("db_path", "data/homenetguard.db"))
    from homenetguard.storage import repository

    since = datetime.now(UTC) - timedelta(hours=1)
    stats = repository.get_flow_stats(since=since)
    alert_count = len(repository.get_unacknowledged_alerts(limit=1000))

    from homenetguard.capture.interface_detector import get_active_interface
    iface = cfg.get("network", {}).get("interface", "auto")
    if iface == "auto":
        iface = get_active_interface()

    rows = [
        ["Interface", iface],
        ["Flows (1h)", stats.get("total_flows", 0)],
        ["Bytes (1h)", stats.get("total_bytes", 0)],
        ["Unique IPs (1h)", stats.get("unique_src_ips", 0)],
        ["Unacked Alerts", alert_count],
        ["Dashboard", f"http://{cfg.get('dashboard',{}).get('host','127.0.0.1')}:{cfg.get('dashboard',{}).get('port',5000)}"],
        ["DB Path", cfg.get("storage", {}).get("db_path", "data/homenetguard.db")],
    ]
    click.echo("\nHomeNetGuard Status")
    click.echo("=" * 40)
    click.echo(tabulate(rows, tablefmt="plain"))


@cli.command("config")
@click.option("--show", is_flag=True, help="Show current configuration")
@click.option("--init", "do_init", is_flag=True, help="Create config.yaml from template")
@click.pass_context
def config_cmd(ctx: click.Context, show: bool, do_init: bool) -> None:
    """Manage configuration."""
    import shutil
    if do_init:
        src = Path("config/config.example.yaml")
        dst = Path("config/config.yaml")
        if dst.exists():
            click.echo("config/config.yaml already exists. Remove it first to re-init.")
            return
        if not src.exists():
            click.echo(f"Template not found: {src}", err=True)
            sys.exit(1)
        shutil.copy(src, dst)
        click.echo(f"Created {dst} — edit it to configure HomeNetGuard.")
        return

    if show:
        import yaml
        cfg = _load_config(ctx.obj.get("config_path"))
        safe = cfg.copy()
        for section in ("threat_intelligence", "alerts"):
            if section in safe:
                for sub in safe[section].values():
                    if isinstance(sub, dict):
                        for key in ("api_key", "smtp_password", "bot_token", "password"):
                            if key in sub:
                                sub[key] = "***"
        click.echo(yaml.dump(safe, default_flow_style=False, allow_unicode=True))
        return

    ctx.get_help()
