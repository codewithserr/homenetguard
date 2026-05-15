from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from homenetguard.reports.html_renderer import render_report_html
from homenetguard.reports.pdf_exporter import export_pdf
from homenetguard.storage import repository
from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)


class ReportGenerator:
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config
        self._output_dir = Path(config.get("storage", {}).get("reports_path", "data/reports"))
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        report_type: str = "daily",
        fmt: str = "html",
        period_start: datetime | None = None,
        period_end: datetime | None = None,
    ) -> list[str]:
        now = datetime.now(UTC)
        if period_end is None:
            period_end = now
        if period_start is None:
            if report_type == "weekly":
                period_start = now - timedelta(days=7)
            else:
                period_start = now - timedelta(days=1)

        data = self._collect_data(period_start, period_end)
        data["report_type"] = report_type
        data["period_start"] = period_start.isoformat()
        data["period_end"] = period_end.isoformat()

        stamp = now.strftime("%Y%m%d_%H%M%S")
        outputs: list[str] = []

        if fmt in ("html", "both"):
            html_path = str(self._output_dir / f"report_{stamp}.html")
            html_content = render_report_html(data)
            Path(html_path).write_text(html_content, encoding="utf-8")
            repository.insert_report(
                report_type=report_type,
                file_path=html_path,
                fmt="html",
                period_start=period_start.isoformat(),
                period_end=period_end.isoformat(),
            )
            outputs.append(html_path)
            logger.info("HTML report: %s", html_path)

        if fmt in ("pdf", "both"):
            pdf_path = str(self._output_dir / f"report_{stamp}.pdf")
            if not outputs:
                html_content = render_report_html(data)
            export_pdf(html_content, pdf_path)  # type: ignore[possibly-undefined]
            repository.insert_report(
                report_type=report_type,
                file_path=pdf_path,
                fmt="pdf",
                period_start=period_start.isoformat(),
                period_end=period_end.isoformat(),
            )
            outputs.append(pdf_path)
            logger.info("PDF report: %s", pdf_path)

        return outputs

    def _collect_data(self, since: datetime, until: datetime) -> dict[str, Any]:
        stats = repository.get_flow_stats(since=since)
        top_ips = repository.get_top_ips(limit=20, since=since)
        protocols = repository.get_protocol_distribution(since=since)
        alerts = repository.get_all_alerts(limit=500)
        dns_queries = repository.get_recent_dns_queries(limit=200)

        period_alerts = [
            a for a in alerts
            if since.isoformat() <= a.get("timestamp", "") <= until.isoformat()
        ]

        alert_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for a in period_alerts:
            sev = a.get("severity", "low")
            alert_counts[sev] = alert_counts.get(sev, 0) + 1

        return {
            "stats": stats,
            "top_ips": top_ips,
            "protocols": protocols,
            "alerts": period_alerts,
            "alert_counts": alert_counts,
            "dns_queries": dns_queries,
            "recommendations": _build_recommendations(period_alerts),
        }


def _build_recommendations(alerts: list[dict[str, Any]]) -> list[str]:
    recs: list[str] = []
    types = {a.get("alert_type") for a in alerts}
    if "port_scan" in types:
        recs.append("Investigate IPs performing port scans — consider blocking at firewall level.")
    if "flood" in types:
        recs.append("Traffic flood detected — review bandwidth limits and DDoS protection measures.")
    if "blacklisted_ip" in types:
        recs.append("Communication with blacklisted IPs — audit outbound connections and check for malware.")
    if "dns_anomaly" in types:
        recs.append("Suspicious DNS activity detected — possible DNS tunneling or data exfiltration attempt.")
    if "arp_spoofing" in types:
        recs.append("ARP spoofing detected — possible man-in-the-middle attack on local network.")
    if not recs:
        recs.append("No significant threats detected during this period. Continue monitoring.")
    return recs
