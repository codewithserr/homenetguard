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


@bp.route("/api/reports/<int:report_id>/content")
def api_report_content(report_id: int):
    """Return raw HTML of a generated report for inline viewing."""
    reports = repository.get_reports(limit=200)
    report = next((r for r in reports if r["id"] == report_id), None)
    if not report:
        return "Report not found", 404
    file_path = report.get("file_path", "")
    fmt = report.get("format", "html")
    if fmt != "html" or not file_path:
        # For PDF reports, regenerate HTML on-the-fly for viewing
        from homenetguard.reports.report_generator import ReportGenerator
        from homenetguard.reports.html_renderer import render_report_html
        from datetime import UTC, datetime
        cfg = current_app.config.get("HNG_CONFIG", {})
        period_start = report.get("period_start")
        period_end = report.get("period_end")
        since = datetime.fromisoformat(period_start) if period_start else datetime.now(UTC)
        gen = ReportGenerator(cfg)
        data = gen._collect_data(since, datetime.fromisoformat(period_end) if period_end else datetime.now(UTC))
        data.update({"report_type": report.get("report_type", "daily"),
                     "period_start": period_start or "", "period_end": period_end or ""})
        html = render_report_html(data)
        from flask import Response
        return Response(html, mimetype="text/html")

    from pathlib import Path
    from flask import Response
    path = Path(file_path)
    if not path.exists():
        return "Report file not found on disk", 404
    return Response(path.read_text(encoding="utf-8"), mimetype="text/html")


@bp.route("/api/alerts/<int:alert_id>/detail")
def api_alert_detail(alert_id: int):
    """Return enriched alert detail with geo + reputation data."""
    import json
    alerts = repository.get_all_alerts(limit=1000)
    alert = next((a for a in alerts if a["id"] == alert_id), None)
    if not alert:
        return jsonify({"error": "Not found"}), 404

    detail = dict(alert)

    # Parse raw_data JSON
    raw = detail.get("raw_data")
    if raw:
        try:
            detail["raw_data_parsed"] = json.loads(raw)
        except (ValueError, TypeError):
            detail["raw_data_parsed"] = {}
    else:
        detail["raw_data_parsed"] = {}

    # Enrich with reputation + geo for src/dst IPs
    for ip_key in ("src_ip", "dst_ip"):
        ip = detail.get(ip_key)
        if ip:
            rep = repository.get_ip_reputation(ip)
            detail[f"{ip_key}_reputation"] = rep

    return jsonify(detail)


@bp.route("/api/geo-data")
def api_geo_data():
    from homenetguard.analysis.geo_lookup import GeoLookup, COUNTRY_CENTROIDS
    from homenetguard.analysis.reputation import is_private_ip

    cfg = current_app.config.get("HNG_CONFIG", {})
    geo = GeoLookup(cfg.get("geoip", {}).get("db_path", "config/geoip/GeoLite2-City.mmdb"))

    flows = repository.get_recent_flows(limit=500)
    geo_points: dict[str, dict] = {}

    for f in flows:
        for ip_key, country_key, city_key in [
            ("dst_ip", "dst_country", "dst_city"),
            ("src_ip", "src_country", "src_city"),
        ]:
            ip = f.get(ip_key)
            if not ip or ip in geo_points or is_private_ip(ip):
                continue

            country = f.get(country_key)
            city = f.get(city_key)

            geo_data = geo.lookup(ip)
            lat = geo_data.get("lat")
            lon = geo_data.get("lon")
            country = country or geo_data.get("country")
            city = city or geo_data.get("city")
            country_code = geo_data.get("country_code")

            if (lat is None or lon is None) and country_code:
                lat, lon = COUNTRY_CENTROIDS.get(country_code, (None, None))

            rep = repository.get_ip_reputation(ip)
            status = "malicious" if (rep and rep.get("is_blacklisted")) else "normal"

            existing = geo_points.get(ip)
            rep_org = (rep.get("org") or rep.get("isp")) if rep else None
            geo_points[ip] = {
                "ip": ip,
                "country": country,
                "city": city,
                "lat": lat,
                "lon": lon,
                "bytes": (existing["bytes"] if existing else 0) + (f.get("bytes") or 0),
                "flows": (existing["flows"] if existing else 0) + 1,
                "status": status,
                "org": rep_org,
                "asn": rep.get("asn") if rep else None,
                "abuse_score": rep.get("abuse_score") if rep else None,
            }

    geo.close()

    # IPs still missing coordinates → batch-query ip-api.com (free, no key needed)
    missing = [ip for ip, p in geo_points.items() if p["lat"] is None]
    if missing:
        _enrich_via_ipapi(missing, geo_points)

    return jsonify([p for p in geo_points.values() if p["lat"] is not None])


def _enrich_via_ipapi(ips: list[str], geo_points: dict[str, dict]) -> None:
    """Batch-query ip-api.com for geo + ownership data (free tier, no API key)."""
    import requests as req
    from homenetguard.analysis.geo_lookup import COUNTRY_CENTROIDS

    fields = "query,country,countryCode,city,lat,lon,isp,org,as,status"
    try:
        batch = [{"query": ip, "fields": fields} for ip in ips[:100]]
        resp = req.post("http://ip-api.com/batch", json=batch, timeout=5)
        resp.raise_for_status()
        for entry in resp.json():
            ip = entry.get("query")
            if not ip or ip not in geo_points:
                continue
            if entry.get("status") != "success":
                continue
            lat = entry.get("lat")
            lon = entry.get("lon")
            if lat is None or lon is None:
                cc = entry.get("countryCode")
                if cc:
                    lat, lon = COUNTRY_CENTROIDS.get(cc, (None, None))
            org = entry.get("org") or entry.get("isp")
            asn = entry.get("as", "").split()[0] if entry.get("as") else None
            geo_points[ip].update({
                "lat": lat,
                "lon": lon,
                "country": geo_points[ip]["country"] or entry.get("country"),
                "city": geo_points[ip]["city"] or entry.get("city"),
                "org": org,
                "asn": asn,
                "isp": entry.get("isp"),
            })
            # Persist org/asn to reputation table for offline use
            if org:
                repository.upsert_ip_reputation(
                    ip_address=ip,
                    country=entry.get("country"),
                    isp=entry.get("isp"),
                    org=org,
                    asn=asn,
                    source="ip-api",
                )
    except Exception:
        pass  # ip-api.com is best-effort; map degrades gracefully


@bp.route("/api/ip-ownership")
def api_ip_ownership():
    """Return org/ISP/ASN for all unique public IPs seen in recent flows."""
    from homenetguard.analysis.reputation import is_private_ip
    import requests as req

    flows = repository.get_recent_flows(limit=500)
    seen: set[str] = set()
    for f in flows:
        for key in ("src_ip", "dst_ip"):
            ip = f.get(key)
            if ip and not is_private_ip(ip):
                seen.add(ip)

    result: dict[str, dict] = {}

    # First: check local reputation cache
    uncached: list[str] = []
    for ip in seen:
        rep = repository.get_ip_reputation(ip)
        if rep and (rep.get("org") or rep.get("isp")):
            result[ip] = {
                "ip": ip,
                "org": rep.get("org") or rep.get("isp"),
                "isp": rep.get("isp"),
                "asn": rep.get("asn"),
                "country": rep.get("country"),
                "is_blacklisted": bool(rep.get("is_blacklisted")),
                "abuse_score": rep.get("abuse_score"),
            }
        else:
            uncached.append(ip)

    # Batch-query ip-api.com for uncached IPs
    if uncached:
        fields = "query,isp,org,as,country,countryCode,status"
        try:
            batch = [{"query": ip, "fields": fields} for ip in uncached[:100]]
            resp = req.post("http://ip-api.com/batch", json=batch, timeout=6)
            resp.raise_for_status()
            for entry in resp.json():
                ip = entry.get("query")
                if not ip or entry.get("status") != "success":
                    continue
                org = entry.get("org") or entry.get("isp")
                asn_raw = entry.get("as", "")
                asn = asn_raw.split()[0] if asn_raw else None
                rep = repository.get_ip_reputation(ip)
                if org:
                    repository.upsert_ip_reputation(
                        ip_address=ip,
                        country=entry.get("country"),
                        isp=entry.get("isp"),
                        org=org,
                        asn=asn,
                        source="ip-api",
                        is_blacklisted=bool(rep and rep.get("is_blacklisted")),
                        abuse_score=rep.get("abuse_score") if rep else None,
                    )
                result[ip] = {
                    "ip": ip,
                    "org": org,
                    "isp": entry.get("isp"),
                    "asn": asn,
                    "country": entry.get("country"),
                    "is_blacklisted": bool(rep and rep.get("is_blacklisted")),
                    "abuse_score": rep.get("abuse_score") if rep else None,
                }
        except Exception:
            pass

    return jsonify(result)


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
