from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta

from flask import Blueprint, current_app, jsonify, render_template, request

from homenetguard.storage import repository

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    return render_template("index.html")


@bp.route("/alerts")
def alerts_view():
    return render_template("alerts.html")


@bp.route("/flows")
def flows_view():
    return render_template("flows.html")


@bp.route("/dns")
def dns_view():
    return render_template("dns.html")


@bp.route("/reports")
def reports_view():
    return render_template("reports.html")


@bp.route("/config")
def config_view():
    cfg = current_app.config.get("HNG_CONFIG", {})
    return render_template("config.html", config=_sanitize_config(cfg))


@bp.route("/api/stats")
def api_stats():
    since = datetime.now(UTC) - timedelta(minutes=60)
    stats = repository.get_flow_stats(since=since)
    alerts = repository.get_unacknowledged_alerts(limit=5)
    sniffer = current_app.config.get("HNG_SNIFFER")
    sniffer_stats = sniffer.get_stats() if sniffer else {}
    return jsonify({**stats, "alerts": alerts, "sniffer": sniffer_stats})


@bp.route("/api/flows")
def api_flows():
    limit = min(int(request.args.get("limit", 100)), 500)
    offset = int(request.args.get("offset", 0))
    return jsonify(repository.get_recent_flows(limit=limit, offset=offset))


@bp.route("/api/alerts")
def api_alerts():
    severity = request.args.get("severity")
    alert_type = request.args.get("type")
    return jsonify(repository.get_all_alerts(severity=severity, alert_type=alert_type))


@bp.route("/api/alerts/<int:alert_id>/acknowledge", methods=["POST"])
def api_ack_alert(alert_id: int):
    repository.acknowledge_alert(alert_id)
    return jsonify({"ok": True})


@bp.route("/api/alerts/clear", methods=["POST"])
def api_clear_alerts():
    count = repository.clear_all_alerts()
    return jsonify({"cleared": count})


@bp.route("/api/dns")
def api_dns():
    return jsonify(repository.get_recent_dns_queries(limit=200))


@bp.route("/api/top-ips")
def api_top_ips():
    since = datetime.now(UTC) - timedelta(minutes=5)
    return jsonify(repository.get_top_ips(limit=10, since=since))


@bp.route("/api/protocols")
def api_protocols():
    since = datetime.now(UTC) - timedelta(minutes=60)
    return jsonify(repository.get_protocol_distribution(since=since))


@bp.route("/api/reports")
def api_reports():
    return jsonify(repository.get_reports())


@bp.route("/api/reports/generate", methods=["POST"])
def api_generate_report():
    from homenetguard.reports.report_generator import ReportGenerator
    cfg = current_app.config.get("HNG_CONFIG", {})
    data = request.get_json(silent=True) or {}
    report_type = data.get("type", "daily")
    fmt = data.get("format", "html")
    try:
        gen = ReportGenerator(cfg)
        paths = gen.generate(report_type=report_type, fmt=fmt)
        return jsonify({"ok": True, "files": paths})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/api/geo-data")
def api_geo_data():
    flows = repository.get_recent_flows(limit=200)
    geo_points: dict[str, dict] = {}
    for f in flows:
        for ip_key, country_key, city_key in [
            ("dst_ip", "dst_country", "dst_city"),
            ("src_ip", "src_country", "src_city"),
        ]:
            ip = f.get(ip_key)
            country = f.get(country_key)
            if ip and country and ip not in geo_points:
                rep = repository.get_ip_reputation(ip)
                status = "malicious" if (rep and rep.get("is_blacklisted")) else "normal"
                geo_points[ip] = {
                    "ip": ip,
                    "country": country,
                    "city": f.get(city_key),
                    "bytes": f.get("bytes", 0),
                    "status": status,
                }
    return jsonify(list(geo_points.values()))


def _sanitize_config(cfg: dict) -> dict:
    safe = copy.deepcopy(cfg)
    for section in ("threat_intelligence", "alerts"):
        if section in safe:
            for subsection in safe[section].values():
                if isinstance(subsection, dict):
                    for key in ("api_key", "smtp_password", "bot_token", "password"):
                        if key in subsection:
                            subsection[key] = "***"
    return safe
