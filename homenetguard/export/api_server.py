from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from flask import request
from flask_restx import Api, Namespace, Resource, fields

from homenetguard.storage import repository
from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

_API_KEY: str | None = None


def _check_api_key() -> bool:
    import os
    global _API_KEY
    if _API_KEY is None:
        _API_KEY = os.getenv("API_KEY", "")
    if not _API_KEY:
        return True  # no key configured = open
    return request.headers.get("X-API-Key") == _API_KEY


def create_api(app: Any) -> Api:
    api = Api(
        app,
        version="1.0",
        title="HomeNetGuard API",
        description="REST API for HomeNetGuard network security monitor",
        doc="/api/docs",
        prefix="/api/v1",
    )

    # ── Status ──────────────────────────────────────────────────
    ns_status = Namespace("status", description="System status")
    api.add_namespace(ns_status)

    @ns_status.route("")
    class Status(Resource):
        def get(self):
            since = datetime.now(UTC) - timedelta(hours=1)
            stats = repository.get_flow_stats(since=since)
            alerts = repository.get_unacknowledged_alerts(limit=5)
            return {
                "status": "running",
                "version": "2.0",
                "timestamp": datetime.now(UTC).isoformat(),
                "stats_1h": stats,
                "active_alerts": len(alerts),
            }

    # ── Flows ────────────────────────────────────────────────────
    ns_flows = Namespace("flows", description="Network flows")
    api.add_namespace(ns_flows)

    @ns_flows.route("")
    class FlowList(Resource):
        def get(self):
            page = int(request.args.get("page", 1))
            per_page = min(int(request.args.get("per_page", 50)), 200)
            offset = (page - 1) * per_page
            flows = repository.get_recent_flows(limit=per_page, offset=offset)
            return {"page": page, "per_page": per_page, "flows": flows}

    @ns_flows.route("/<int:flow_id>")
    class FlowDetail(Resource):
        def get(self, flow_id):
            from homenetguard.storage.database import get_connection
            with get_connection() as conn:
                row = conn.execute("SELECT * FROM flows WHERE id=?", (flow_id,)).fetchone()
            return dict(row) if row else ({"error": "not found"}, 404)

    # ── Alerts ──────────────────────────────────────────────────
    ns_alerts = Namespace("alerts", description="Security alerts")
    api.add_namespace(ns_alerts)

    @ns_alerts.route("")
    class AlertList(Resource):
        def get(self):
            severity = request.args.get("severity")
            alert_type = request.args.get("type")
            alerts = repository.get_all_alerts(severity=severity, alert_type=alert_type)
            return alerts

    @ns_alerts.route("/<int:alert_id>/ack")
    class AlertAck(Resource):
        def post(self, alert_id):
            repository.acknowledge_alert(alert_id)
            return {"ok": True}

    # ── Devices ─────────────────────────────────────────────────
    ns_devices = Namespace("devices", description="Network devices")
    api.add_namespace(ns_devices)

    @ns_devices.route("")
    class DeviceList(Resource):
        def get(self):
            from homenetguard.storage.database import get_connection
            with get_connection() as conn:
                rows = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
            return [dict(r) for r in rows]

    @ns_devices.route("/<string:mac>/trust")
    class DeviceTrust(Resource):
        def post(self, mac):
            from homenetguard.storage.database import get_connection
            with get_connection() as conn:
                conn.execute("UPDATE devices SET is_trusted=1 WHERE mac_address=?", (mac.upper(),))
            return {"ok": True}

    @ns_devices.route("/<string:mac>/quarantine")
    class DeviceQuarantine(Resource):
        def post(self, mac):
            from homenetguard.active.quarantine import QuarantineManager
            ok = QuarantineManager().quarantine(mac)
            return {"ok": ok}

        def delete(self, mac):
            from homenetguard.active.quarantine import QuarantineManager
            ok = QuarantineManager().release(mac)
            return {"ok": ok}

    # ── Firewall ─────────────────────────────────────────────────
    ns_fw = Namespace("firewall", description="Firewall rules")
    api.add_namespace(ns_fw)

    @ns_fw.route("/rules")
    class FirewallRules(Resource):
        def get(self):
            from homenetguard.active.firewall import FirewallManager
            return FirewallManager().list_rules()

        def post(self):
            data = request.get_json(silent=True) or {}
            from homenetguard.active.firewall import FirewallManager
            fw = FirewallManager()
            rule_type = data.get("type", "ip")
            target = data.get("target", "")
            if not target:
                return {"error": "target required"}, 400
            if rule_type == "ip":
                rule_id = fw.block_ip(target, direction=data.get("direction", "both"), reason=data.get("reason", ""))
            elif rule_type == "port":
                rule_id = fw.block_port(int(target), proto=data.get("proto", "tcp"), reason=data.get("reason", ""))
            else:
                return {"error": f"unknown type: {rule_type}"}, 400
            return {"ok": True, "rule_id": rule_id}

    @ns_fw.route("/rules/<int:rule_id>")
    class FirewallRule(Resource):
        def delete(self, rule_id):
            from homenetguard.active.firewall import FirewallManager
            ok = FirewallManager().unblock(rule_id)
            return {"ok": ok}

    # ── Sinkhole ─────────────────────────────────────────────────
    ns_sink = Namespace("sinkhole", description="DNS sinkhole rules")
    api.add_namespace(ns_sink)

    @ns_sink.route("/rules")
    class SinkholeRules(Resource):
        def get(self):
            from homenetguard.active.dns_sinkhole import DNSSinkhole
            return DNSSinkhole().list_rules()

        def post(self):
            data = request.get_json(silent=True) or {}
            domain = data.get("domain", "")
            if not domain:
                return {"error": "domain required"}, 400
            from homenetguard.active.dns_sinkhole import DNSSinkhole
            DNSSinkhole().add_domain(domain, reason=data.get("reason", ""))
            return {"ok": True}

    @ns_sink.route("/rules/<int:rule_id>")
    class SinkholeRule(Resource):
        def delete(self, rule_id):
            from homenetguard.storage.database import get_connection
            with get_connection() as conn:
                conn.execute("UPDATE sinkhole_rules SET is_active=0 WHERE id=?", (rule_id,))
            return {"ok": True}

    # ── Intelligence ─────────────────────────────────────────────
    ns_intel = Namespace("intelligence", description="Threat intelligence")
    api.add_namespace(ns_intel)

    @ns_intel.route("/feeds")
    class Feeds(Resource):
        def get(self):
            from homenetguard.intelligence.feed_manager import FeedManager
            return FeedManager().get_status()

    @ns_intel.route("/feeds/update")
    class FeedsUpdate(Resource):
        def post(self):
            from homenetguard.intelligence.feed_manager import FeedManager
            import threading
            fm = FeedManager()
            t = threading.Thread(target=fm.update_all, daemon=True)
            t.start()
            return {"ok": True, "message": "Feed update started in background"}

    # ── ML ───────────────────────────────────────────────────────
    ns_ml = Namespace("ml", description="ML anomaly detection")
    api.add_namespace(ns_ml)

    @ns_ml.route("/status")
    class MLStatus(Resource):
        def get(self):
            from homenetguard.analysis.anomaly_detector import get_detector
            return get_detector().status()

    @ns_ml.route("/train")
    class MLTrain(Resource):
        def post(self):
            from homenetguard.analysis.anomaly_detector import get_detector
            import threading
            def _train():
                try:
                    get_detector().train()
                except Exception as exc:
                    logger.error("ML train error: %s", exc)
            threading.Thread(target=_train, daemon=True).start()
            return {"ok": True, "message": "Training started in background"}

    return api
