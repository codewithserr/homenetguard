from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from homenetguard.storage.database import get_connection
from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)


def insert_flow(flow: dict[str, Any]) -> int:
    sql = """
    INSERT INTO flows (timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                       bytes, packets, direction, interface, src_country, dst_country,
                       src_city, dst_city)
    VALUES (:timestamp, :src_ip, :dst_ip, :src_port, :dst_port, :protocol,
            :bytes, :packets, :direction, :interface, :src_country, :dst_country,
            :src_city, :dst_city)
    """
    defaults: dict[str, Any] = {
        "src_port": None, "dst_port": None, "packets": 1, "bytes": 0,
        "direction": None, "interface": None, "src_country": None,
        "dst_country": None, "src_city": None, "dst_city": None,
    }
    row = {**defaults, **flow}
    with get_connection() as conn:
        cur = conn.execute(sql, row)
        return cur.lastrowid  # type: ignore[return-value]


def get_recent_flows(limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM flows ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return [dict(r) for r in rows]


def get_flow_stats(since: datetime) -> dict[str, Any]:
    sql = """
    SELECT COUNT(*) as total_flows,
           COALESCE(SUM(bytes), 0) as total_bytes,
           COUNT(DISTINCT src_ip) as unique_src_ips,
           COUNT(DISTINCT dst_ip) as unique_dst_ips
    FROM flows WHERE timestamp >= ?
    """
    with get_connection() as conn:
        row = conn.execute(sql, (since.isoformat(),)).fetchone()
    return dict(row)


def get_top_ips(limit: int = 10, since: datetime | None = None) -> list[dict[str, Any]]:
    where = "WHERE timestamp >= ?" if since else ""
    params: list[Any] = [since.isoformat()] if since else []
    sql = f"""
    SELECT src_ip as ip, SUM(bytes) as total_bytes, COUNT(*) as flow_count
    FROM flows {where}
    GROUP BY src_ip ORDER BY total_bytes DESC LIMIT ?
    """
    params.append(limit)
    with get_connection() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def get_protocol_distribution(since: datetime | None = None) -> list[dict[str, Any]]:
    where = "WHERE timestamp >= ?" if since else ""
    params: list[Any] = [since.isoformat()] if since else []
    sql = f"""
    SELECT protocol, COUNT(*) as count, SUM(bytes) as total_bytes
    FROM flows {where} GROUP BY protocol ORDER BY count DESC
    """
    with get_connection() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def insert_alert(
    alert_type: str,
    severity: str,
    description: str,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    raw_data: dict[str, Any] | None = None,
    timestamp: str | None = None,
) -> int:
    ts = timestamp or datetime.now(UTC).isoformat()
    sql = """
    INSERT INTO alerts (timestamp, alert_type, severity, src_ip, dst_ip, description, raw_data)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """
    raw_json = json.dumps(raw_data) if raw_data else None
    with get_connection() as conn:
        cur = conn.execute(sql, (ts, alert_type, severity, src_ip, dst_ip, description, raw_json))
        logger.warning("ALERT [%s/%s] %s", severity.upper(), alert_type, description)
        return cur.lastrowid  # type: ignore[return-value]


def get_unacknowledged_alerts(limit: int = 100) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE acknowledged=0 ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_all_alerts(
    severity: str | None = None,
    alert_type: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    conditions: list[str] = []
    params: list[Any] = []
    if severity:
        conditions.append("severity=?")
        params.append(severity)
    if alert_type:
        conditions.append("alert_type=?")
        params.append(alert_type)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params.append(limit)
    with get_connection() as conn:
        rows = conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY timestamp DESC LIMIT ?", params
        ).fetchall()
    return [dict(r) for r in rows]


def acknowledge_alert(alert_id: int) -> None:
    with get_connection() as conn:
        conn.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))


def clear_all_alerts() -> int:
    with get_connection() as conn:
        cur = conn.execute("DELETE FROM alerts")
        return cur.rowcount  # type: ignore[return-value]


def insert_dns_query(
    timestamp: str,
    src_ip: str,
    queried_domain: str,
    query_type: str | None = None,
    response_ip: str | None = None,
    is_suspicious: bool = False,
) -> int:
    sql = """
    INSERT INTO dns_queries (timestamp, src_ip, queried_domain, query_type, response_ip, is_suspicious)
    VALUES (?, ?, ?, ?, ?, ?)
    """
    with get_connection() as conn:
        cur = conn.execute(
            sql,
            (timestamp, src_ip, queried_domain, query_type, response_ip, int(is_suspicious)),
        )
        return cur.lastrowid  # type: ignore[return-value]


def get_recent_dns_queries(limit: int = 100) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM dns_queries ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def upsert_ip_reputation(
    ip_address: str,
    abuse_score: int | None = None,
    is_blacklisted: bool = False,
    country: str | None = None,
    isp: str | None = None,
    org: str | None = None,
    asn: str | None = None,
    source: str = "local",
) -> None:
    sql = """
    INSERT INTO ip_reputation (ip_address, abuse_score, is_blacklisted, country, isp, org, asn, source, last_checked)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(ip_address) DO UPDATE SET
        abuse_score=COALESCE(excluded.abuse_score, abuse_score),
        is_blacklisted=excluded.is_blacklisted,
        country=COALESCE(excluded.country, country),
        isp=COALESCE(excluded.isp, isp),
        org=COALESCE(excluded.org, org),
        asn=COALESCE(excluded.asn, asn),
        source=excluded.source,
        last_checked=excluded.last_checked
    """
    with get_connection() as conn:
        conn.execute(
            sql,
            (ip_address, abuse_score, int(is_blacklisted), country, isp, org, asn, source,
             datetime.now(UTC).isoformat()),
        )


def get_ip_reputation(ip_address: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM ip_reputation WHERE ip_address=?", (ip_address,)
        ).fetchone()
    return dict(row) if row else None


def insert_report(
    report_type: str,
    file_path: str,
    fmt: str,
    period_start: str | None = None,
    period_end: str | None = None,
) -> int:
    sql = """
    INSERT INTO reports (report_type, period_start, period_end, file_path, format)
    VALUES (?, ?, ?, ?, ?)
    """
    with get_connection() as conn:
        cur = conn.execute(sql, (report_type, period_start, period_end, file_path, fmt))
        return cur.lastrowid  # type: ignore[return-value]


def get_reports(limit: int = 50) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM reports ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def purge_old_data(retention_days: int) -> None:
    if retention_days <= 0:
        return
    cutoff = f"datetime('now', '-{retention_days} days')"
    with get_connection() as conn:
        conn.execute(f"DELETE FROM flows WHERE created_at < {cutoff}")
        conn.execute(f"DELETE FROM alerts WHERE created_at < {cutoff}")
        conn.execute(f"DELETE FROM dns_queries WHERE created_at < {cutoff}")
    logger.info("Purged data older than %d days", retention_days)
