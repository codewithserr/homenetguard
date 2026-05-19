from __future__ import annotations

import copy
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from flask import Blueprint, current_app, jsonify, render_template, request

from homenetguard.storage import repository

# ─── Cyber Academy curriculum loader ─────────────────────────
_CURRICULUM_PATH = Path(__file__).parent / "static" / "data" / "curriculum.json"
_curriculum_cache: dict | None = None

def _load_curriculum() -> dict:
    global _curriculum_cache
    if _curriculum_cache is None:
        try:
            with open(_CURRICULUM_PATH, encoding="utf-8") as f:
                _curriculum_cache = json.load(f)
        except Exception:
            _curriculum_cache = {"topics": [], "categories": {}, "learning_paths": [], "tooltip_terms": {}}
    return _curriculum_cache

def _find_topic(slug: str) -> dict | None:
    cur = _load_curriculum()
    return next((t for t in cur.get("topics", []) if t["slug"] == slug), None)

def _run_live_query(query: str) -> str | None:
    """Execute a read-only SQLite query and return first cell as string."""
    if not query or not query.strip().upper().startswith("SELECT"):
        return None
    try:
        from homenetguard.storage.database import get_connection
        with get_connection() as conn:
            row = conn.execute(query).fetchone()
        if row:
            val = row[0]
            if val is None:
                return "0"
            if isinstance(val, float):
                return f"{val:.1f}"
            return str(val)
        return "0"
    except Exception:
        return None

# ─── Docs loader ─────────────────────────────────────
_DOCS_PATH = Path(__file__).parent / "static" / "data" / "docs_content.json"
_docs_cache: dict | None = None

def _load_docs() -> dict:
    global _docs_cache
    if _docs_cache is None:
        try:
            with open(_DOCS_PATH, encoding="utf-8") as f:
                _docs_cache = json.load(f)
        except Exception:
            _docs_cache = {"sections": [], "version": "1.0.0"}
    return _docs_cache

def _find_docs_article(section_id: str, article_id: str) -> tuple[dict | None, dict | None]:
    docs = _load_docs()
    section = next((s for s in docs.get("sections", []) if s["id"] == section_id), None)
    if not section:
        return None, None
    article = next((a for a in section.get("articles", []) if a["id"] == article_id), None)
    return section, article

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


# ─── v2 routes ───────────────────────────────────────────────────────────────

@bp.route("/devices")
def devices_view():
    return render_template("devices.html")


@bp.route("/firewall")
def firewall_view():
    return render_template("firewall.html")


@bp.route("/intelligence")
def intelligence_view():
    return render_template("intelligence.html")


@bp.route("/forensics")
def forensics_view():
    return render_template("forensics.html")


@bp.route("/wifi")
def wifi_view():
    return render_template("wifi.html")


# ─── Docs routes ─────────────────────────────────────────────

@bp.route("/docs")
def docs_index():
    docs = _load_docs()
    return render_template("docs/index.html", docs=docs)


@bp.route("/docs/<section_id>")
def docs_section(section_id: str):
    docs = _load_docs()
    section = next((s for s in docs.get("sections", []) if s["id"] == section_id), None)
    if not section:
        return render_template("docs/index.html", docs=docs), 404
    return render_template("docs/section.html", docs=docs, section=section)


@bp.route("/docs/<section_id>/<article_id>")
def docs_article(section_id: str, article_id: str):
    docs = _load_docs()
    section, article = _find_docs_article(section_id, article_id)
    if not article:
        return render_template("docs/index.html", docs=docs), 404
    articles = section.get("articles", [])
    idx = next((i for i, a in enumerate(articles) if a["id"] == article_id), None)
    prev_article = articles[idx - 1] if idx and idx > 0 else None
    next_article = articles[idx + 1] if idx is not None and idx < len(articles) - 1 else None
    return render_template(
        "docs/article.html",
        docs=docs,
        section=section,
        article=article,
        prev_article=prev_article,
        next_article=next_article,
    )


@bp.route("/api/v1/docs/content")
def api_docs_content():
    return jsonify(_load_docs())


@bp.route("/api/v1/docs/search")
def api_docs_search():
    q = request.args.get("q", "").lower().strip()
    if not q:
        return jsonify([])
    docs = _load_docs()
    results = []
    for section in docs.get("sections", []):
        for article in section.get("articles", []):
            if (q in article["title"].lower()
                    or q in (article.get("description") or "").lower()
                    or any(q in t for t in article.get("tags", []))):
                results.append({
                    "section_id": section["id"],
                    "section_title": section["title"],
                    "article_id": article["id"],
                    "title": article["title"],
                    "description": article.get("description", ""),
                    "url": f"/docs/{section['id']}/{article['id']}",
                })
    return jsonify(results[:10])


@bp.route("/learn")
def learn_index():
    return render_template("learn/index.html")


@bp.route("/learn/path/<path_id>")
def learn_path(path_id: str):
    cur = _load_curriculum()
    path = next((p for p in cur.get("learning_paths", []) if p["id"] == path_id), None)
    if not path:
        return render_template("learn/index.html")
    # Redirect to first topic of the path
    topics = path.get("topics", [])
    if topics:
        from flask import redirect
        return redirect(f"/learn/{topics[0]}")
    return render_template("learn/index.html")


@bp.route("/learn/<slug>")
def learn_topic(slug: str):
    topic = _find_topic(slug)
    cur = _load_curriculum()
    all_topics = cur.get("topics", [])

    # Find prev/next in flat list
    idx = next((i for i, t in enumerate(all_topics) if t["slug"] == slug), None)
    prev_topic = all_topics[idx - 1] if idx and idx > 0 else None
    next_topic = all_topics[idx + 1] if idx is not None and idx < len(all_topics) - 1 else None

    # Execute live queries for each live_example section
    live_data: dict[int, str | None] = {}
    if topic:
        for i, section in enumerate(topic.get("sections", [])):
            if section.get("type") == "live_example" and section.get("query"):
                live_data[i] = _run_live_query(section["query"])

    return render_template(
        "learn/topic.html",
        topic=topic,
        slug=slug,
        live_data=live_data,
        prev_topic=prev_topic,
        next_topic=next_topic,
    )


# ─── Cyber Academy API ────────────────────────────────────────

@bp.route("/api/v1/learn/topics")
def api_learn_topics():
    return jsonify(_load_curriculum())


@bp.route("/api/v1/learn/tooltip/<term>")
def api_learn_tooltip(term: str):
    cur = _load_curriculum()
    info = cur.get("tooltip_terms", {}).get(term)
    if not info:
        return jsonify({"error": "not found"}), 404
    return jsonify(info)


# ── v2 API endpoints ──────────────────────────────────────────────────────────

@bp.route("/api/v2/devices")
def api_v2_devices():
    from homenetguard.storage.database import get_connection
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC LIMIT 200").fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route("/api/v2/devices/<mac>/trust", methods=["POST"])
def api_v2_trust_device(mac: str):
    from homenetguard.storage.database import get_connection
    with get_connection() as conn:
        conn.execute("UPDATE devices SET is_trusted=1 WHERE mac_address=?", (mac.upper(),))
    return jsonify({"ok": True})


@bp.route("/api/v2/devices/<mac>/quarantine", methods=["POST"])
def api_v2_quarantine_device(mac: str):
    from homenetguard.active.quarantine import QuarantineManager
    ok = QuarantineManager().quarantine(mac)
    return jsonify({"ok": ok})


@bp.route("/api/v2/devices/<mac>/quarantine", methods=["DELETE"])
def api_v2_release_device(mac: str):
    from homenetguard.active.quarantine import QuarantineManager
    ok = QuarantineManager().release(mac)
    return jsonify({"ok": ok})


@bp.route("/api/v2/firewall/rules")
def api_v2_firewall_rules():
    from homenetguard.active.firewall import FirewallManager
    return jsonify(FirewallManager().list_rules())


@bp.route("/api/v2/firewall/rules", methods=["POST"])
def api_v2_firewall_add():
    from homenetguard.active.firewall import FirewallManager
    data = request.get_json(silent=True) or {}
    fw = FirewallManager()
    try:
        rule_id = fw.block_ip(
            data["target"],
            direction=data.get("direction", "both"),
            reason=data.get("reason", "dashboard"),
        )
        return jsonify({"ok": True, "rule_id": rule_id})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@bp.route("/api/v2/firewall/rules/<int:rule_id>", methods=["DELETE"])
def api_v2_firewall_delete(rule_id: int):
    from homenetguard.active.firewall import FirewallManager
    ok = FirewallManager().unblock(rule_id)
    return jsonify({"ok": ok})


@bp.route("/api/v2/sinkhole/rules")
def api_v2_sinkhole_rules():
    from homenetguard.active.dns_sinkhole import DNSSinkhole
    return jsonify(DNSSinkhole().list_rules())


@bp.route("/api/v2/sinkhole/rules", methods=["POST"])
def api_v2_sinkhole_add():
    from homenetguard.active.dns_sinkhole import DNSSinkhole
    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "")
    if not domain:
        return jsonify({"error": "domain required"}), 400
    DNSSinkhole().add_domain(domain, reason=data.get("reason", "dashboard"))
    return jsonify({"ok": True})


@bp.route("/api/v2/intelligence/feeds")
def api_v2_feeds():
    from homenetguard.intelligence.feed_manager import FeedManager
    return jsonify(FeedManager().get_status())


@bp.route("/api/v2/intelligence/feeds/update", methods=["POST"])
def api_v2_feeds_update():
    import threading
    from homenetguard.intelligence.feed_manager import FeedManager
    threading.Thread(target=FeedManager().update_all, daemon=True).start()
    return jsonify({"ok": True, "message": "Update started"})


@bp.route("/api/v2/intelligence/mitre")
def api_v2_mitre():
    from homenetguard.intelligence.mitre_mapper import MITRE_MAPPING, get_all_tactics
    alerts = repository.get_all_alerts(limit=500)
    tactic_hits: dict[str, int] = {}
    for a in alerts:
        mapping = MITRE_MAPPING.get(a.get("alert_type", ""))
        if mapping:
            t = mapping["tactic"]
            tactic_hits[t] = tactic_hits.get(t, 0) + 1
    return jsonify({
        "mapping": MITRE_MAPPING,
        "tactic_hits": tactic_hits,
        "tactics": get_all_tactics(),
    })


@bp.route("/api/v2/compliance")
def api_v2_compliance():
    from homenetguard.intelligence.compliance_checker import ComplianceChecker
    checker = ComplianceChecker()
    checks = checker.run_checks()
    return jsonify({"checks": checks, "score": checker.generate_score(checks)})


@bp.route("/api/v2/forensics")
def api_v2_forensics():
    ip = request.args.get("ip", "")
    mac = request.args.get("mac", "")
    from homenetguard.storage.database import get_connection
    events: list[dict] = []
    with get_connection() as conn:
        if ip:
            flows = conn.execute(
                "SELECT 'flow' as type, timestamp, src_ip, dst_ip, protocol, bytes FROM flows "
                "WHERE src_ip=? OR dst_ip=? ORDER BY timestamp DESC LIMIT 100",
                (ip, ip),
            ).fetchall()
            events.extend(dict(r) for r in flows)
            alerts_q = conn.execute(
                "SELECT 'alert' as type, timestamp, alert_type, severity, description FROM alerts "
                "WHERE src_ip=? OR dst_ip=? ORDER BY timestamp DESC LIMIT 50",
                (ip, ip),
            ).fetchall()
            events.extend(dict(r) for r in alerts_q)
        if mac:
            dev = conn.execute(
                "SELECT * FROM devices WHERE mac_address=?", (mac.upper(),)
            ).fetchone()
            if dev:
                history = conn.execute(
                    "SELECT 'ip_change' as type, seen_at as timestamp, ip_address FROM device_ip_history "
                    "WHERE mac_address=? ORDER BY seen_at DESC LIMIT 50",
                    (mac.upper(),),
                ).fetchall()
                events.extend(dict(r) for r in history)
    events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return jsonify(events[:200])


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
